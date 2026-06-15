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
	prefixes  []AdvertisedPrefix
	locators  []SRv6LocatorConfig

	mgmtCh  chan *mgmtOp
	eventCh chan event
	done    chan struct{}

	// The following are owned by the Serve loop after Serve starts.
	circuits   []*circuit
	dbs        map[packet.Level]*lsdb
	levelCap   levelSet // union of circuit levels, for the LSP IS-Type field
	fib        fib.FIB
	rib        map[netip.Prefix]RouteInfo
	connected  map[netip.Prefix]bool // directly-connected prefixes (never installed)
	fibPending map[netip.Prefix]bool // routes whose last FIB write failed; retried
	spfDirty   bool                  // a topology change needs an SPF recompute
	watchers   map[*watcher]struct{} // WatchEvent subscribers
}

// markDirty requests an SPF/RIB recompute on the next loop iteration. Called
// from LSDB mutations on the Serve goroutine.
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
		logger:     o.logger,
		systemID:   o.systemID,
		areaAddrs:  o.areaAddrs,
		hostname:   o.hostname,
		prefixes:   o.prefixes,
		locators:   o.locators,
		mgmtCh:     make(chan *mgmtOp, 1),
		eventCh:    make(chan event, 256),
		done:       make(chan struct{}),
		dbs:        map[packet.Level]*lsdb{},
		fib:        o.fib,
		rib:        map[netip.Prefix]RouteInfo{},
		connected:  map[netip.Prefix]bool{},
		fibPending: map[netip.Prefix]bool{},
		watchers:   map[*watcher]struct{}{},
	}
	if s.fib == nil {
		s.fib = fib.Noop{}
	}
	for _, p := range o.connected {
		s.connected[p] = true
	}
	for _, lc := range o.locators {
		if a := lc.Prefix.Addr(); !a.Is6() || a.Is4In6() {
			return nil, fmt.Errorf("goisis: SRv6 locator %s must be IPv6", lc.Prefix)
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
		for _, l := range cfg.levels() {
			s.levelCap.add(l)
			if s.dbs[l] == nil {
				s.dbs[l] = newLSDB(l)
			}
		}
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
	for _, c := range s.circuits {
		s.sendHellos(c, now)
	}
	s.regenerateLSPs(false, now)

	// Drop any routes a previous incarnation left in the FIB but that we have
	// not (yet) recomputed.
	if err := s.fib.Sweep(func(p netip.Prefix) bool { _, ok := s.rib[p]; return ok }); err != nil {
		s.logger.Error("fib startup sweep", "error", err)
	}

	// Instantiate the local End SID for each advertised SRv6 locator. This is
	// re-asserted on every housekeeping tick so a SID removed out-of-band (or
	// one whose initial install failed) is repaired without a restart.
	s.installLocalSIDs()

	ticker := time.NewTicker(housekeepInterval)
	defer ticker.Stop()

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
		}
		// Recompute routes promptly after any topology change, rather than
		// waiting for the next housekeeping tick.
		if s.spfDirty {
			s.spfDirty = false
			s.updateRIB(time.Now())
		}
	}
}

// installLocalSIDs (re-)programs the local End SID for every advertised SRv6
// locator. AddLocalSID is idempotent (RouteReplace), so this is safe to call
// repeatedly; it both retries a failed initial install and repairs a SID
// deleted out-of-band while the daemon runs.
func (s *IsisServer) installLocalSIDs() {
	for _, lc := range s.locators {
		sid := lc.endSID()
		if err := s.fib.AddLocalSID(fib.LocalSID{SID: sid, Behavior: fib.BehaviorEnd}); err != nil {
			s.logger.Error("install local End SID", "sid", sid, "error", err)
		}
	}
}

// removeLocalSIDs withdraws every local End SID this node installed, so a clean
// shutdown leaves no orphaned seg6local routes in the kernel.
func (s *IsisServer) removeLocalSIDs() {
	for _, lc := range s.locators {
		sid := lc.endSID()
		if err := s.fib.RemoveLocalSID(sid); err != nil {
			s.logger.Error("remove local End SID", "sid", sid, "error", err)
		}
	}
}

// shutdown closes transports (unblocking the reader goroutines' Recv), removes
// local SIDs, waits for the readers to exit, and fails any queued management
// ops.
func (s *IsisServer) shutdown(readers *sync.WaitGroup) {
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

// readLoop receives frames on a circuit and forwards them to the event loop
// until the transport closes or the context is cancelled.
func (s *IsisServer) readLoop(ctx context.Context, c *circuit) {
	for {
		frame, err := c.cfg.Transport.Recv()
		if err != nil {
			return
		}
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
	for _, c := range s.circuits {
		if !now.Before(c.nextHello) {
			s.sendHellos(c, now)
		}
		s.expireAdjacencies(c, now)
	}
	s.ageLSPs(now)
	s.refreshOwnLSPs(now)
	s.floodTransmit(now)
	if len(s.locators) > 0 {
		s.installLocalSIDs()
	}
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
}

// GetGlobal returns a snapshot of instance-wide state.
func (s *IsisServer) GetGlobal(ctx context.Context) (Global, error) {
	var g Global
	err := s.mgmtOperation(ctx, func() error {
		g = Global{Version: version.Version, SystemID: s.systemID}
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

// ListLSDB returns a snapshot of the link-state database for every level.
func (s *IsisServer) ListLSDB(ctx context.Context) ([]LSPInfo, error) {
	var out []LSPInfo
	err := s.mgmtOperation(ctx, func() error {
		now := time.Now()
		for _, db := range s.dbs {
			out = append(out, db.snapshot(now)...)
		}
		return nil
	})
	return out, err
}

// ListAdjacencies returns a snapshot of all adjacencies across all circuits.
func (s *IsisServer) ListAdjacencies(ctx context.Context) ([]AdjacencyInfo, error) {
	var out []AdjacencyInfo
	err := s.mgmtOperation(ctx, func() error {
		for _, c := range s.circuits {
			out = append(out, c.adjacencyInfos()...)
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
