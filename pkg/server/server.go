// Package server provides IsisServer, the embeddable IS-IS instance that
// backs both goisisd and library consumers.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/takehaya/goisis/internal/version"
	"github.com/takehaya/goisis/pkg/datalink"
	"github.com/takehaya/goisis/pkg/fib"
	"github.com/takehaya/goisis/pkg/packet"
)

// ErrServerStopped is returned by management operations issued after the
// Serve loop has exited.
var ErrServerStopped = errors.New("goisis: server stopped")

// IsisServer is the top-level IS-IS instance. Every management operation and
// protocol event is serialized onto the Serve loop, so there is exactly one
// goroutine that mutates protocol state (circuits, adjacencies, the LSDB).
type IsisServer struct {
	logger    *slog.Logger
	systemID  packet.SystemID
	areaAddrs []packet.AreaAddress
	hostname  string
	locators  []SRv6LocatorConfig
	flexAlgos []FlexAlgoConfig

	mgmtCh  chan *mgmtOp
	eventCh chan event
	done    chan struct{}

	// The following are owned by the Serve loop after Serve starts.
	circuits      []*circuit
	dbs           map[packet.Level]*lsdb
	levelCap      levelSet // union of circuit levels, for the LSP IS-Type field
	fib           fib.FIB
	metrics       Metrics
	rib           map[netip.Prefix]RouteInfo
	l1Export      map[netip.Prefix]uint32 // L1-reachable prefixes advertised in our L2 LSP
	connected     map[netip.Prefix]bool   // directly-connected prefixes, derived (never installed)
	fibPending    map[netip.Prefix]bool   // routes whose last FIB write failed; retried
	fibInstalled  map[netip.Prefix]bool   // routes currently written to the FIB (gated by fibFilter)
	spfDirty      bool                    // a topology change needs an SPF recompute
	lspGenPending bool                    // a protocol event asked for an own-LSP regeneration
	nextLSPGen    time.Time               // earliest time drainLSPGen may honor that request
	watchers      map[*watcher]struct{}   // WatchEvent subscribers
	algoWarned    edgeLog[algoKey]        // (level,algo) whose unsupported metric-type was logged
	endXSIDs      map[endXKey]endXSID     // SRv6 End.X SIDs, one per (locator, adjacency)
	seqWrapUntil  map[lspKey]time.Time    // LSP IDs held down after sequence exhaustion (see exhaustSeq)
	endXNoNexthop map[endXAdjKey]bool     // adjacencies whose missing End.X next hop was warned about
	sidPending    map[netip.Addr]bool     // local SIDs whose removal failed; retried from housekeeping
	sidFailed     edgeLog[netip.Addr]     // local SIDs whose failed FIB write was already logged

	overloadOnStartup time.Duration             // set the OL bit this long after startup
	overloadUntil     time.Time                 // OL bit is set while now < this (zero = not set)
	overloadManual    bool                      // OL bit set by hand (SetOverload), independent of the startup window
	authKeys          map[packet.Level]authSpec // LSP/SNP authentication per level
	advertiseFilter   AdvertiseFilter           // export policy for originated prefixes (nil = advertise all)
	fibFilter         FIBFilter                 // FIB policy for computed routes (nil = program all)
	lsdbEntryLimit    int                       // per-level cap on stored LSPs (0 = unlimited)
	lsdbLimitWarned   edgeLog[packet.Level]     // levels whose entry-limit drop was already logged
	oversizeWarned    edgeLog[oversizeKey]      // (circuit,LSP) that does not fit the circuit MTU
	dupSystemIDWarned edgeLog[string]           // circuits that heard a hello carrying our own System ID
	adjLimitWarned    edgeLog[string]           // circuits that turned a station away at their adjacency limit
	txFailWarned      edgeLog[txFailKey]        // (circuit,step) whose transmit failure was already logged
	ticks             uint64                    // housekeeping ticks run, for work that is not due every tick
	lspBufferSize     int                       // largest own LSP we originate (see WithLSPMTU)

	// What this node originates has exactly two owners: optionPrefixes, the
	// prefixes the configuration and AddPrefix name (with their metric), and
	// circuitPrefixes, the connected subnets each circuit contributes (keyed by
	// circuit name, originated at that circuit's metric). The advertised set is
	// derived from both at every origination (originatedPrefixes) and the
	// directly-connected set from circuitPrefixes plus optionConnected
	// (setCircuitPrefixes), so neither depends on who advertised a prefix
	// first. See SetCircuitAddresses.
	circuitPrefixes map[string][]netip.Prefix
	optionPrefixes  map[netip.Prefix]AdvertisedPrefix
	optionConnected map[netip.Prefix]bool
}

// spfHold is the SPF back-off interval (RFC 8405): after a recompute, further
// changes are held this long and coalesced into a single recompute.
const spfHold = 200 * time.Millisecond

// markDirty requests an SPF/RIB recompute. Called from LSDB mutations on the
// Serve goroutine; the loop decides when to run it (see the back-off in Serve).
func (s *IsisServer) markDirty() { s.spfDirty = true }

type mgmtOp struct {
	f     func() error
	errCh chan error
}

// NewIsisServer returns a stopped IS-IS instance. Call Serve to run it.
func NewIsisServer(opts ...ServerOption) (*IsisServer, error) {
	o := options{logger: slog.Default()}
	for _, opt := range opts {
		opt(&o)
	}
	s := &IsisServer{
		logger:            o.logger,
		systemID:          o.systemID,
		areaAddrs:         o.areaAddrs,
		hostname:          o.hostname,
		locators:          o.locators,
		flexAlgos:         o.flexAlgos,
		mgmtCh:            make(chan *mgmtOp, 1),
		eventCh:           make(chan event, 256),
		done:              make(chan struct{}),
		dbs:               map[packet.Level]*lsdb{},
		fib:               o.fib,
		metrics:           o.metrics,
		rib:               map[netip.Prefix]RouteInfo{},
		connected:         map[netip.Prefix]bool{},
		fibPending:        map[netip.Prefix]bool{},
		fibInstalled:      map[netip.Prefix]bool{},
		watchers:          map[*watcher]struct{}{},
		endXSIDs:          map[endXKey]endXSID{},
		seqWrapUntil:      map[lspKey]time.Time{},
		endXNoNexthop:     map[endXAdjKey]bool{},
		sidPending:        map[netip.Addr]bool{},
		overloadOnStartup: o.overloadOnStartup,
		authKeys:          map[packet.Level]authSpec{},
		advertiseFilter:   o.advertiseFilter,
		fibFilter:         o.fibFilter,
		lsdbEntryLimit:    o.lsdbEntryLimit,
		circuitPrefixes:   map[string][]netip.Prefix{},
		optionPrefixes:    map[netip.Prefix]AdvertisedPrefix{},
		optionConnected:   map[netip.Prefix]bool{},
	}
	if err := requirePrimaryPassword("goisis: area authentication", o.areaAuth.Secret, o.areaAuth.AcceptSecrets); err != nil {
		return nil, err
	}
	if err := requirePrimaryPassword("goisis: domain authentication", o.domainAuth.Secret, o.domainAuth.AcceptSecrets); err != nil {
		return nil, err
	}
	if spec := o.areaAuth.spec(); spec.on() {
		s.authKeys[packet.Level1] = spec
	}
	if spec := o.domainAuth.spec(); spec.on() {
		s.authKeys[packet.Level2] = spec
	}
	if s.fib == nil {
		s.fib = fib.Noop{}
	}
	if s.metrics == nil {
		s.metrics = NoopMetrics{}
	}
	// Prefixes named by an option belong to the configuration, not to a
	// circuit: a circuit whose addresses later change must leave them alone.
	for _, p := range o.prefixes {
		masked := p.Prefix.Masked()
		s.optionPrefixes[masked] = AdvertisedPrefix{Prefix: masked, Metric: p.Metric}
	}
	// The connected set is derived; setCircuitPrefixes rebuilds it from the
	// circuits plus this option set, so seed it here for the server whose
	// circuits contribute nothing.
	for _, p := range o.connected {
		s.optionConnected[p] = true
		s.connected[p] = true
	}
	participated := map[uint8]bool{}
	for _, fa := range o.flexAlgos {
		if fa.Algo < 128 {
			return nil, fmt.Errorf("goisis: Flex-Algo %d is reserved; use 128-255", fa.Algo)
		}
		if participated[fa.Algo] {
			return nil, fmt.Errorf("goisis: duplicate Flex-Algo %d configuration", fa.Algo)
		}
		participated[fa.Algo] = true
	}
	for _, lc := range o.locators {
		if a := lc.Prefix.Addr(); !a.Is6() || a.Is4In6() {
			return nil, fmt.Errorf("goisis: SRv6 locator %s must be IPv6", lc.Prefix)
		}
		// A non-zero-algorithm locator is only reachable if the node also
		// participates in that Flex-Algo (advertises it in SR-Algorithm and
		// computes its topology); otherwise the locator is an unreachable black
		// hole. Require explicit participation rather than advertising silently.
		if lc.Algo != 0 && !participated[lc.Algo] {
			return nil, fmt.Errorf("goisis: SRv6 locator %s is bound to Flex-Algo %d but the node does not participate in it (add WithFlexAlgo)", lc.Prefix, lc.Algo)
		}
	}
	// Pseudonode octets are a single byte and must be nonzero and unique
	// per box, so at most 255 circuits can be assigned distinct octets.
	if len(o.circuits) > 255 {
		return nil, fmt.Errorf("goisis: %d circuits exceeds the 255 pseudonode limit", len(o.circuits))
	}
	for i := range o.circuits {
		cfg := o.circuits[i]
		if err := cfg.applyDefaults(); err != nil {
			return nil, err
		}
		// Pseudonode / extended-circuit IDs must be nonzero and unique
		// per box; the 1-based circuit index serves both.
		c := newCircuit(cfg, uint8(i+1), uint32(i+1)) //nolint:gosec // bounded by the 255 check above
		s.circuits = append(s.circuits, c)
		s.setCircuitPrefixes(cfg.Name, maskedSet(cfg.ConnectedPrefixes))
		for _, l := range cfg.levels() {
			s.levelCap.add(l)
			if s.dbs[l] == nil {
				s.dbs[l] = newLSDB(l)
			}
		}
	}
	// Size our own LSPs so every circuit can actually transmit them. A
	// fragment a circuit cannot send is retried forever and its content never
	// reaches that peer, and a transit node cannot re-fragment what it
	// receives, so the sizing has to happen here, at origination.
	s.lspBufferSize = packet.ReceiveLSPBufferSize
	if o.lspMTU > 0 && o.lspMTU < s.lspBufferSize {
		s.lspBufferSize = o.lspMTU
	}
	for _, c := range s.circuits {
		if mtu := c.cfg.Transport.MTU() - 3; mtu < s.lspBufferSize { // 3 = LLC header
			s.lspBufferSize = mtu
		}
	}
	if s.lspBufferSize < minLSPMTU {
		return nil, fmt.Errorf("goisis: LSP MTU %d is below the %d-octet minimum", s.lspBufferSize, minLSPMTU)
	}
	return s, nil
}

// Serve runs the management and protocol event loop until ctx is cancelled.
// It may be called at most once per IsisServer. On exit Serve closes every
// circuit's transport (taking ownership of the injected transports) and
// waits for the reader goroutines to finish, so a cancelled Serve leaks
// neither goroutines nor sockets.
func (s *IsisServer) Serve(ctx context.Context) error {
	defer close(s.done)
	s.logger.Info("goisis server started",
		"net", s.netString(), "circuits", len(s.circuits))

	// One reader goroutine per circuit feeds decoded frames to the loop.
	var readers sync.WaitGroup
	for _, c := range s.circuits {
		readers.Add(1)
		go func(c *circuit) {
			defer readers.Done()
			s.readLoop(ctx, c)
		}(c)
	}

	// Send an initial hello burst and originate our LSPs so neighbors and
	// their databases learn about us promptly.
	now := time.Now()
	if s.overloadOnStartup > 0 {
		s.overloadUntil = now.Add(s.overloadOnStartup)
	}
	for _, c := range s.circuits {
		s.sendHellos(c, now)
	}
	s.regenerateLSPs(false, now)

	// Drop any routes a previous incarnation left in the FIB but that we have
	// not (yet) recomputed. Retain our own local End SID /128s: they are
	// statically derived from config and reinstalled below, so deleting them
	// here would needlessly withdraw seg6local forwarding mid-startup.
	ownSIDs := map[netip.Prefix]bool{}
	for _, sid := range s.localSIDs() {
		ownSIDs[netip.PrefixFrom(sid, 128)] = true
	}
	if err := s.fib.Sweep(func(p netip.Prefix) bool {
		if _, ok := s.rib[p]; ok {
			return true
		}
		return ownSIDs[p]
	}); err != nil {
		s.logger.Error("fib startup sweep", "error", err)
	}

	// Instantiate the local End SID for each advertised SRv6 locator.
	// Housekeeping re-asserts them, so a SID removed out-of-band (or one whose
	// install failed) is repaired without a restart.
	s.installLocalSIDs()

	ticker := time.NewTicker(housekeepInterval)
	defer ticker.Stop()

	// SPF back-off (RFC 8405), with two states instead of three: QUIET, where a
	// change recomputes immediately, and HOLD, where changes are coalesced into
	// one recompute at the end of the hold. RFC 8405's LONG_WAIT escalation is
	// deliberately omitted — a single short hold already absorbs the bursts we
	// see (a flapping adjacency, a stream of LSPs arriving one per iteration),
	// and a second threshold would only delay convergence further.
	// The timer is its own select arm so a hold really is spfHold rather than
	// being rounded up to the next housekeeping tick.
	hold := time.NewTimer(spfHold)
	hold.Stop()
	defer hold.Stop()
	holding := false

	for {
		select {
		case <-ctx.Done():
			s.shutdown(&readers)
			return nil
		case op := <-s.mgmtCh:
			op.errCh <- op.f()
		case ev := <-s.eventCh:
			s.handleEvent(ev)
		case t := <-ticker.C:
			s.housekeeping(t)
		case <-hold.C:
			holding = false // leave HOLD; the check below picks up any change
		}
		// Coalesce the regenerations protocol events asked for, before the SPF
		// check below, so an LSP generated here feeds the same recompute.
		s.drainLSPGen(time.Now())
		// Recompute routes promptly after a topology change, rather than
		// waiting for the next housekeeping tick — then hold, so a burst
		// spread over several iterations costs one more recompute, not one
		// per event.
		if s.spfDirty && !holding {
			s.spfDirty = false
			s.updateRIB(time.Now())
			// holding is true exactly while the timer is armed, so this only
			// ever resets a stopped or already-received one.
			hold.Reset(spfHold)
			holding = true
		}
	}
}

// localSIDs returns every SID this node instantiates locally: the End SID of
// each advertised SRv6 locator, plus the End.X SID of each adjacency.
func (s *IsisServer) localSIDs() []netip.Addr {
	out := make([]netip.Addr, 0, len(s.locators)+len(s.endXSIDs))
	for _, lc := range s.locators {
		out = append(out, lc.endSID())
	}
	for _, e := range s.endXSIDs {
		out = append(out, e.sid)
	}
	return out
}

// sidReassertTicks is how many housekeeping ticks pass between full re-asserts
// of the local SIDs.
const sidReassertTicks = 30

// installLocalSIDs (re-)programs the local End SID for every advertised SRv6
// locator and every allocated End.X SID. AddLocalSID is idempotent
// (RouteReplace), so this is safe to call repeatedly; it both retries a failed
// initial install and repairs a SID deleted out-of-band while the daemon runs.
func (s *IsisServer) installLocalSIDs() {
	for _, lc := range s.locators {
		s.programSID(fib.LocalSID{SID: lc.endSID(), Behavior: fib.BehaviorEnd})
	}
	s.installEndXSIDs()
}

// removeLocalSIDs withdraws every local SID this node installed, so a clean
// shutdown leaves no orphaned seg6local routes in the kernel.
func (s *IsisServer) removeLocalSIDs() {
	for _, sid := range s.localSIDs() {
		s.unprogramSID(sid)
	}
}

// programSID writes one local SID to the FIB. Every local SID write goes
// through here (or unprogramSID) so that the counter and the log cannot drift
// apart: a failure is always counted, so a FIB that cannot program SIDs shows
// in goisis_fib_errors_total and not only in the log, and the log is
// edge-triggered per SID because installs are re-asserted from housekeeping —
// a failure that persists (no seg6local support in the kernel, no dummy device
// to install the SID on) would otherwise be logged once per tick. The daemon
// keeps running either way: a SID that cannot be programmed does not stop us
// from routing. attrs are extra log attributes naming what the SID is for.
func (s *IsisServer) programSID(sid fib.LocalSID, attrs ...any) {
	// The SID is wanted again, so a removal of it that failed earlier is moot.
	delete(s.sidPending, sid.SID)
	if err := s.fib.AddLocalSID(sid); err != nil {
		s.metrics.FIBError(fibOpAddSID)
		s.sidFailed.warn(sid.SID, func() {
			s.logger.Error("install local SID", append([]any{"sid", sid.SID, "error", err}, attrs...)...)
		})
		return
	}
	s.sidFailed.recovered(sid.SID, func() {
		s.logger.Info("local SID installed after an earlier failure", "sid", sid.SID)
	})
}

// unprogramSID removes one local SID, and keeps a failed removal in
// s.sidPending for housekeeping to retry. The caller drops its own record of
// the SID (a locator, an endXSIDs entry) either way, so without the pending
// set nothing would ever ask for that SID again and its seg6local route would
// sit in the kernel until a restart. RemoveLocalSID reports a route that is
// already gone as success, so the retry stops once the kernel agrees.
func (s *IsisServer) unprogramSID(sid netip.Addr, attrs ...any) {
	if err := s.fib.RemoveLocalSID(sid); err != nil {
		s.metrics.FIBError(fibOpRemoveSID)
		s.sidPending[sid] = true
		s.sidFailed.warn(sid, func() {
			s.logger.Error("remove local SID", append([]any{"sid", sid, "error", err}, attrs...)...)
		})
		return
	}
	delete(s.sidPending, sid)
	s.sidFailed.recovered(sid, func() {
		s.logger.Info("local SID removed after an earlier failure", "sid", sid)
	})
}

// overloaded reports whether the overload bit should be set in our own LSP.
func (s *IsisServer) overloaded(now time.Time) bool {
	return s.overloadManual || (!s.overloadUntil.IsZero() && now.Before(s.overloadUntil))
}

// purgeOwnLSPs floods a purge for every LSP this node originated, so neighbors
// drop us immediately on a clean shutdown instead of waiting out the lifetime.
func (s *IsisServer) purgeOwnLSPs(now time.Time) {
	for level, db := range s.dbs {
		for id, e := range db.entries {
			if e.own && e.purgedAt.IsZero() {
				s.purgeOwn(level, id, now)
			}
		}
	}
}

// shutdown purges our own LSPs and flushes them, closes transports (unblocking
// the reader goroutines' Recv), removes local SIDs, waits for the readers to
// exit, and fails any queued management ops.
func (s *IsisServer) shutdown(readers *sync.WaitGroup) {
	// Purge our own LSPs and flush the purges on the wire before the transports
	// close, so neighbors reconverge without us promptly (clean shutdown).
	now := time.Now()
	s.purgeOwnLSPs(now)
	s.floodTransmit(now)
	for _, c := range s.circuits {
		_ = c.cfg.Transport.Close()
	}
	s.removeLocalSIDs()
	s.closeWatchers()
	readers.Wait()
	for {
		select {
		case op := <-s.mgmtCh:
			op.errCh <- ErrServerStopped
		default:
			s.logger.Info("goisis server stopped")
			return
		}
	}
}

// readerRetryDelay paces the retries after a transient Recv error, so a
// circuit whose socket keeps failing does not spin.
const readerRetryDelay = time.Second

// readLoop receives frames on a circuit and forwards them to the event loop
// until the transport closes or the context is cancelled. Any other Recv
// error is treated as transient and retried: returning would leave the
// circuit sending hellos it can never hear an answer to until a restart.
func (s *IsisServer) readLoop(ctx context.Context, c *circuit) {
	var warned edgeLog[string]
	for {
		frame, err := c.cfg.Transport.Recv()
		if err != nil {
			if errors.Is(err, datalink.ErrClosed) {
				return
			}
			// Warn once per outage, not once per retry: a link that stays
			// down would otherwise fill the log for as long as it is down.
			warned.warn(c.cfg.Name, func() {
				s.logger.Warn("circuit receive error, retrying", "circuit", c.cfg.Name, "error", err)
			})
			// Counting it on the loop, like the frames: an outage that stays
			// inside one warning is otherwise invisible to a scraper.
			select {
			case s.eventCh <- &rxErrEvent{circuit: c}:
			case <-ctx.Done():
				return
			}
			select {
			case <-time.After(readerRetryDelay):
			case <-ctx.Done():
				return
			}
			continue
		}
		warned.clear(c.cfg.Name)
		select {
		case s.eventCh <- &rxEvent{circuit: c, frame: frame}:
		case <-ctx.Done():
			return
		}
	}
}

// housekeeping runs periodic maintenance: hello transmission, holding-time
// expiry, LSP aging/refresh, and flooding transmission.
func (s *IsisServer) housekeeping(now time.Time) {
	s.ticks++
	for _, c := range s.circuits {
		if !now.Before(c.nextHello) {
			s.sendHellos(c, now)
		}
		s.expireAdjacencies(c, now)
	}
	// Clear the startup overload bit once its timer elapses (one re-origination
	// drops the OL flag and floods the change).
	if !s.overloadUntil.IsZero() && !now.Before(s.overloadUntil) {
		s.overloadUntil = time.Time{}
		s.logger.Info("clearing startup overload bit")
		s.regenerateLSPs(false, now)
	}
	s.drainLSPGen(now)
	s.ageLSPs(now)
	s.refreshOwnLSPs(now)
	s.floodTransmit(now)
	// Re-assert the local SIDs. This is a self-heal for a SID deleted
	// out-of-band, not a retry path, and it costs one synchronous netlink write
	// per locator and per adjacency — at every tick that is a steady load
	// proportional to the adjacency count — so it sweeps every
	// sidReassertTicks. A SID whose last write failed is not one we believe
	// fine: while any is outstanding the sweep runs every tick, so a FIB that
	// comes back is picked up within the second.
	if (len(s.locators) > 0 || len(s.endXSIDs) > 0) &&
		(s.sidFailed.any() || s.ticks%sidReassertTicks == 0) {
		s.installLocalSIDs()
	}
	// Retry the removals that failed. Unlike an install, nothing else re-asserts
	// these: the SID is already out of s.locators and s.endXSIDs.
	for sid := range s.sidPending {
		s.unprogramSID(sid)
	}
	for level, db := range s.dbs {
		s.metrics.LSDBSize(levelLabel(level), len(db.entries))
	}
	// Report every configured circuit and level, not just those holding an
	// adjacency, so losing the last neighbor shows as 0 rather than as a gauge
	// that simply stops moving.
	for _, c := range s.circuits {
		for _, l := range c.cfg.levels() {
			s.metrics.AdjacencyCount(c.cfg.Name, levelLabel(l), c.upAdjacencyCount(l))
		}
	}
	// Retry the writes the FIB rejected. Nothing else drives them: the pending
	// set is only revisited by a recompute, and in a quiet network the next one
	// is the LSP refresh, up to fifteen minutes away. programFIB against the
	// current RIB is the whole retry — the desired set is unchanged, so every
	// other route short-circuits as installed and nothing is withdrawn or
	// re-emitted. The tick is the back-off: one attempt per second, which for a
	// netlink socket that is either there or not beats a schedule to maintain.
	if len(s.fibPending) > 0 {
		s.programFIB(s.rib)
	}
	s.metrics.FIBPending(len(s.fibPending))
	s.metrics.EventQueueDepth(len(s.eventCh))
}

// mgmtOperation runs f on the Serve loop and waits for its result. State
// owned by the loop must only be touched from inside f.
func (s *IsisServer) mgmtOperation(ctx context.Context, f func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	errCh := make(chan error, 1)
	select {
	case s.mgmtCh <- &mgmtOp{f: f, errCh: errCh}:
	case <-ctx.Done():
		return ctx.Err()
	case <-s.done:
		return ErrServerStopped
	}
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-s.done:
		select {
		case err := <-errCh:
			return err
		default:
			return ErrServerStopped
		}
	}
}

// Global is a snapshot of instance-wide state.
type Global struct {
	Version  string
	SystemID packet.SystemID
	// Overload is the effective overload bit: set by hand or by the startup
	// window.
	Overload bool
}

// GetGlobal returns a snapshot of instance-wide state.
func (s *IsisServer) GetGlobal(ctx context.Context) (Global, error) {
	var g Global
	err := s.mgmtOperation(ctx, func() error {
		g = Global{Version: version.Version, SystemID: s.systemID, Overload: s.overloaded(time.Now())}
		return nil
	})
	return g, err
}

// ListCircuits returns a snapshot of the configured circuits.
func (s *IsisServer) ListCircuits(ctx context.Context) ([]CircuitInfo, error) {
	var out []CircuitInfo
	err := s.mgmtOperation(ctx, func() error {
		for _, c := range s.circuits {
			out = append(out, c.info())
		}
		return nil
	})
	return out, err
}

// hostnameIndex maps a system ID to the dynamic hostname (TLV 137, RFC 5301)
// its live fragment-0 LSP advertises. Levels are not kept apart: the name
// identifies the system, not its level, so a node that is in both databases
// resolves to the same name either way. Serve-loop state; call it from inside
// a management operation.
func (s *IsisServer) hostnameIndex(now time.Time) map[packet.SystemID]string {
	out := map[packet.SystemID]string{}
	for _, db := range s.dbs {
		for id, e := range db.entries {
			if id.FragmentID() != 0 || !e.purgedAt.IsZero() || e.remaining(now) == 0 {
				continue
			}
			for _, tlv := range e.lsp.TLVs {
				if h, ok := tlv.(*packet.DynamicHostnameTLV); ok {
					out[id.NodeID().SystemID()] = displayString(h.Hostname)
					break
				}
			}
		}
	}
	return out
}

// ListLSDB returns a snapshot of the link-state database for every level,
// with LSPInfo.TLVs left empty. Use ListLSDBDetail to get the rendered text.
func (s *IsisServer) ListLSDB(ctx context.Context) ([]LSPInfo, error) {
	return s.listLSDB(ctx, false)
}

// ListLSDBDetail is ListLSDB with LSPInfo.TLVs rendered. The rendering runs in
// the caller's goroutine once the snapshot is out of the management operation,
// so its cost is the caller's and not the Serve loop's.
func (s *IsisServer) ListLSDBDetail(ctx context.Context) ([]LSPInfo, error) {
	return s.listLSDB(ctx, true)
}

func (s *IsisServer) listLSDB(ctx context.Context, detail bool) ([]LSPInfo, error) {
	var out []LSPInfo
	err := s.mgmtOperation(ctx, func() error {
		now := time.Now()
		hostnames := s.hostnameIndex(now)
		for _, db := range s.dbs {
			out = append(out, db.snapshot(now, hostnames)...)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if detail {
		renderTLVs(out)
	}
	return out, nil
}

// ListAdjacencies returns a snapshot of all adjacencies across all circuits.
func (s *IsisServer) ListAdjacencies(ctx context.Context) ([]AdjacencyInfo, error) {
	var out []AdjacencyInfo
	err := s.mgmtOperation(ctx, func() error {
		hostnames := s.hostnameIndex(time.Now())
		for _, c := range s.circuits {
			for _, a := range c.adjacencyInfos() {
				a.Hostname = hostnames[a.SystemID]
				out = append(out, a)
			}
		}
		return nil
	})
	return out, err
}

// LocatorInfo describes an advertised SRv6 locator.
type LocatorInfo struct {
	Prefix    netip.Prefix
	Algorithm uint8
	EndSID    netip.Addr
	// EndXSIDs are the adjacency-scoped End.X SIDs allocated from this
	// locator, one per Up adjacency.
	EndXSIDs []EndXSIDInfo
}

// ListLocators returns the SRv6 locators this node advertises.
func (s *IsisServer) ListLocators(ctx context.Context) ([]LocatorInfo, error) {
	var out []LocatorInfo
	err := s.mgmtOperation(ctx, func() error {
		for _, lc := range s.locators {
			out = append(out, LocatorInfo{
				Prefix:    lc.Prefix.Masked(),
				Algorithm: lc.Algo,
				EndSID:    lc.endSID(),
				EndXSIDs:  s.endXSIDInfos(lc.Prefix.Masked()),
			})
		}
		return nil
	})
	return out, err
}

// netString renders the server's NET for diagnostics.
func (s *IsisServer) netString() string {
	if len(s.areaAddrs) == 0 {
		return fmt.Sprintf("(no area).%s.00", s.systemID)
	}
	return fmt.Sprintf("%s.%s.00", s.areaAddrs[0], s.systemID)
}
