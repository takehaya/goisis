package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"time"
)

// ErrUnknownCircuit classifies the refusal of a call that names a circuit this
// instance does not have. The daemon's interface watcher needs it: it follows
// netlink, which reports every interface on the box, so an event for one we do
// not run is the ordinary case rather than a fault, and telling the two apart
// is what keeps an unrelated NIC out of the warning log.
//
// DeleteCircuit is deliberately not this. A call that asks a circuit to be gone
// and finds it gone is the node already being in the state the call asks for,
// which is what lets a refused reload be retried whole (ErrAlreadyInState); a
// call that asks something *of* a circuit has nothing to work on and means it.
// Every mutator of the second kind answers this one.
var ErrUnknownCircuit = errors.New("goisis: no such circuit")

// SetCircuitAddresses replaces a circuit's interface addresses (CircuitConfig
// IPv4Addrs / IPv6Addrs — pass all of them, the hello and the LSP take the
// parts each needs) and its directly-connected subnets, then tells the
// neighbors at once instead of at the next scheduled hello. Only the prefixes this circuit
// contributed are replaced: prefixes named by an option, or still connected on
// another circuit, are left alone.
//
// The daemon drives this from its netlink watcher (pkg/config.WatchInterfaces);
// an embedder owns the event source and calls it itself. Passing the addresses
// the circuit already has is a no-op, so a caller may re-read and push on every
// event it sees rather than diffing first.
func (s *IsisServer) SetCircuitAddresses(ctx context.Context, name string, v4, v6 []netip.Addr, connected []netip.Prefix) error {
	return s.mgmtOperation(ctx, func() error {
		c := s.circuitNamed(name)
		if c == nil {
			return fmt.Errorf("%w: %q", ErrUnknownCircuit, name)
		}
		// Compare as sets, not as slices: the kernel is free to hand the same
		// addresses back in another order, and an interface carrying two
		// addresses in one subnet (a SLAAC and a privacy address in one /64 is
		// the everyday case) yields the same prefix twice where the stored
		// list holds it once. Either made the no-op check fail forever, so
		// every netlink message re-sent hellos and re-originated.
		v4, v6, masked := sortedSet(v4), sortedSet(v6), maskedSet(connected)
		if slices.Equal(c.cfg.IPv4Addrs, v4) && slices.Equal(c.cfg.IPv6Addrs, v6) &&
			slices.Equal(s.circuitPrefixes[name], masked) {
			return nil
		}
		c.cfg.IPv4Addrs, c.cfg.IPv6Addrs = v4, v6
		s.setCircuitPrefixes(name, masked)

		s.sendHellos(c, s.clock.Now())
		s.requestLSPRegen()
		return nil
	})
}

// SetCircuitLinkState reports whether a circuit's link is usable. A link going
// down tears its adjacencies down immediately and silences its hellos, rather
// than letting each side wait out the neighbor's holding time (30s by default);
// coming back up resumes hellos at once so the adjacency re-forms without
// waiting for the hello timer.
func (s *IsisServer) SetCircuitLinkState(ctx context.Context, name string, up bool) error {
	return s.mgmtOperation(ctx, func() error {
		c := s.circuitNamed(name)
		if c == nil {
			return fmt.Errorf("%w: %q", ErrUnknownCircuit, name)
		}
		if c.linkDown == !up {
			return nil
		}
		c.linkDown = !up
		s.logger.Info("circuit link state change", "circuit", name, "up", up)
		now := s.clock.Now()
		if !up {
			s.dropAdjacencies(c, "adjacency down: circuit link down", func(*adjacency) bool { return true })
			return nil
		}
		// The segment may have been re-cabled while it was down, so a duplicate
		// system ID heard after this is news again.
		s.dupSystemIDWarned.clear(name)
		s.sendHellos(c, now)
		return nil
	})
}

// AddCircuit adds a circuit at runtime, the counterpart of DeleteCircuit: the
// circuit joins the flooding set and this node's LSPs, contributes its
// connected subnets, starts receiving, and sends its first hello at once
// instead of at the next housekeeping tick.
//
// A name that is already configured is refused rather than replaced -- that
// would orphan the running circuit's transport with its reader goroutine still
// on it. Refused as ErrAlreadyInState when the running circuit is the one this
// call asks for, so a caller replaying a batch can tell the retry of an
// addition that already landed from a refusal; refused with an error naming
// the fields that differ when it is not, because then the caller is asking for
// a circuit the node does not have and a reload would report applied over the
// old hello key and the old level (see ErrAlreadyInState, and
// circuitDifferences for what identity is).
//
// The caller opens the transport and puts it in cfg (applyDefaults refuses a
// nil one). It is deliberately not opened here: net.InterfaceByName, a
// packet.Listen and the membership setsockopts behind it would run on the Serve
// goroutine, where every other circuit's hellos and the LSP aging would wait
// behind them.
//
// The transport is this instance's from the moment it is handed over, on every
// path: a circuit that is added runs on it until DeleteCircuit or Serve's exit
// closes it, and one that is not has it closed here. The caller must not close
// it, and cannot -- a management operation's context bounds the caller's wait
// and not the operation (mgmtOperationQueued), so an addition whose caller
// gave up may still be queued, and a caller closing on that error would close
// the socket this instance is about to run a circuit on: goisis circuit would
// report it up and it could never transmit, for the life of the process.
func (s *IsisServer) AddCircuit(ctx context.Context, cfg CircuitConfig) error {
	queued, err := s.mgmtOperationQueued(ctx, func() error {
		err := s.addCircuit(cfg, s.clock.Now())
		if err != nil {
			closeUnaddedTransport(s.logger, cfg)
		}
		return err
	})
	// What the loop never ran is the loop's to close only if it will run it,
	// so the two cases where it never will are this call's: an operation that
	// was not queued at all, and one a stopping instance answered without
	// running (both in mgmtOperationQueued).
	if !queued || errors.Is(err, ErrServerStopped) {
		closeUnaddedTransport(s.logger, cfg)
	}
	return err
}

// closeUnaddedTransport closes a transport AddCircuit was handed and did not
// run a circuit on. It reads no state the Serve loop owns, so AddCircuit can
// call it from either goroutine.
func closeUnaddedTransport(logger *slog.Logger, cfg CircuitConfig) {
	if cfg.Transport == nil { // applyDefaults refuses one, before anything has been taken
		return
	}
	if err := cfg.Transport.Close(); err != nil {
		logger.Warn("close the transport of a circuit that was not added", "circuit", cfg.Name, "error", err)
	}
}

// addCircuit is AddCircuit's body, on the Serve goroutine.
//
// Every check runs before the first mutation. There is no unwind path here or
// anywhere else in this package — a reload applies what it can and reports what
// it could not (pkg/config.Reload) — so a circuit half-added is a circuit that
// stays half-added.
func (s *IsisServer) addCircuit(cfg CircuitConfig, now time.Time) error {
	if err := cfg.applyDefaults(); err != nil {
		return err
	}
	if cur := s.circuitNamed(cfg.Name); cur != nil {
		// The connected subnets are taken from the running set and not from
		// cur.cfg, which nothing writes after the addition: SetCircuitAddresses
		// replaces s.circuitPrefixes instead, so cur.cfg's copy is the one the
		// circuit was added with and would read as a difference for good.
		running := cur.cfg
		running.ConnectedPrefixes = s.circuitPrefixes[cfg.Name]
		if diffs := circuitDifferences(running, cfg); len(diffs) > 0 {
			// The fields and never their values: several of them are HMAC keys
			// and this reaches the daemon's log (pkg/config.Reload).
			return fmt.Errorf("goisis: circuit %s is already configured and differs in %s; delete it before adding it again",
				cfg.Name, strings.Join(diffs, ", "))
		}
		return fmt.Errorf("goisis: circuit %s is already configured: %w", cfg.Name, ErrAlreadyInState)
	}
	// setLSPBufferSize only ever lowers the size, and the size is at or above
	// the minimum already (NewIsisServer refuses less and deleteCircuit only
	// raises it), so this circuit's own MTU is the one way it can go under.
	if mtu := cfg.Transport.MTU() - 3; mtu < minLSPMTU { // 3 = LLC header
		return fmt.Errorf("goisis: circuit %s would hold this node's LSPs to %d octets, below the %d-octet minimum",
			cfg.Name, mtu, minLSPMTU)
	}
	pseudonode, extCircID, err := s.allocCircuitIDs()
	if err != nil {
		return err
	}

	c := newCircuit(cfg, pseudonode, extCircID)
	// At the end, never anywhere else: endXAdjs walks s.circuits in order and
	// that order is what hands out End.X function values, so slotting a circuit
	// in ahead of another moves the SIDs of circuits that did not change and
	// points traffic at SIDs the neighbors have not learned.
	s.circuits = append(s.circuits, c)
	s.setCircuitPrefixes(cfg.Name, maskedSet(cfg.ConnectedPrefixes))
	for _, l := range cfg.levels() {
		// The database before the level, not after: a level in levelCap is a
		// level regenerateLSPs originates at, and originate dereferences
		// s.dbs[level] with no nil check.
		if s.dbs[l] == nil {
			s.dbs[l] = newLSDB(l)
		}
		s.levelCap.add(l)
	}
	s.setLSPBufferSize()
	// Before Serve runs there is nothing to start a reader with, and nothing to
	// start one for: Serve starts one per circuit in s.circuits, so a circuit
	// added ahead of it is not left without one.
	if s.serveCtx != nil {
		s.startReader(c)
	}
	s.logger.Info("circuit added", "circuit", cfg.Name, "pseudonode", pseudonode)
	s.sendHellos(c, now)
	// Directly rather than through requestLSPRegen, because both halves of what
	// an addition can change are wrong until it runs. A narrower circuit lowers
	// the buffer, and originate drops an over-budget fragment and returns
	// instead of storing it (see the size check there) — so the database would
	// keep the oversize fragments and this circuit would flood what it cannot
	// send, once per transmission interval, until the throttle let a
	// regeneration through. A level this circuit is the first at has no node
	// LSP at all until then. Neither is the flap minLSPGenInterval exists to
	// absorb.
	s.regenerateLSPs(false, now)
	return nil
}

// circuitDifferences names the CircuitConfig fields two configurations differ
// in, in declaration order, and returns none when they are identical -- the
// "present and identical in every field" ErrAlreadyInState promises. Both
// sides must have been through applyDefaults, so a field a caller left unset
// reads as the value the circuit runs with rather than as a difference.
//
// The fields are walked rather than listed because what this is for is a field
// nobody compared: the name-only check it replaced was exactly that, and a
// field added to CircuitConfig later is compared here without anyone having to
// remember this. Transport is skipped, and skipped by name rather than by
// being absent from a list: it is an open socket, so the one a call carries is
// never the one the running circuit was opened on, and no comparison of the
// two says anything about whether the circuits match. The addresses and
// subnets are compared in the canonical form the server keeps them in
// (SetCircuitAddresses), so the kernel handing the same addresses back in
// another order is not a difference either.
func circuitDifferences(a, b CircuitConfig) []string {
	canonical := func(c CircuitConfig) CircuitConfig {
		c.IPv4Addrs, c.IPv6Addrs = sortedSet(c.IPv4Addrs), sortedSet(c.IPv6Addrs)
		c.ConnectedPrefixes = maskedSet(c.ConnectedPrefixes)
		return c
	}
	av, bv := reflect.ValueOf(canonical(a)), reflect.ValueOf(canonical(b))
	var diffs []string
	for i, t := 0, av.Type(); i < t.NumField(); i++ {
		f := t.Field(i)
		if f.Name == "Transport" {
			continue
		}
		if !reflect.DeepEqual(av.Field(i).Interface(), bv.Field(i).Interface()) {
			diffs = append(diffs, f.Name)
		}
	}
	return diffs
}

// allocCircuitIDs reserves the two identifiers a circuit needs. Both come off
// the allocation order and not off the index in s.circuits, because a removal
// must not renumber what stays: a pseudonode octet is half of a pseudonode LSP
// ID, so moving it orphans that LSP area-wide (see deleteCircuit), and an
// extended circuit ID is what a p2p neighbor echoes, so moving it takes every
// p2p adjacency down (processP2PHello, RFC 5303 3.2).
//
// The two then want opposite policies. An extended circuit ID is never reused:
// an adjacency comes Up the moment a hello echoes (our system ID, our extended
// circuit ID), so a hello still in flight from a circuit that is gone would
// complete the handshake of whichever circuit inherited the number. Thirty-two
// bits make never reusing it free.
//
// A pseudonode octet is one byte, so it has to be reusable, and what protects a
// reuse is ISO 10589 7.3.16.4 b) rather than a hold-down. The purge
// deleteCircuit left is not that protection, because a reuse needs a full sweep
// of the cursor to reach it: an octet comes back at allocation 254, four
// minutes on a box taking one SIGHUP a second, against a ZeroAgeLifetime of 60
// seconds. By then our own copy has aged out and originate restarts the reused
// ID at sequence 1 (the reuse inside the minute is the exception, and there
// seq = purge + 1 does come out of our own database). What covers the rest is
// the reclaim: a peer that missed the purge — partitioned while it flooded —
// still holds the old copy at a higher sequence number and floods it back, and
// because we originate that LSP ID again handleOwnSystemID takes the b) branch
// and reoriginateOwn re-issues above what the peer held. One exchange, from
// whichever direction the stale copy arrives. The cursor is not the protection
// either; it only means a freed octet comes back after a full sweep rather than
// immediately.
//
// ponytail: it is 255 allocations, not 255 concurrent circuits — circuitChanges
// turns any field change into a delete plus an add, so a two-circuit box burns
// an octet per SIGHUP that touches one and wraps within minutes. A free list
// timestamped against ZeroAgeLifetime is the upgrade if the reclaim exchange is
// ever not enough.
func (s *IsisServer) allocCircuitIDs() (pseudonode uint8, extCircID uint32, err error) {
	used := make(map[uint8]bool, len(s.circuits))
	for _, c := range s.circuits {
		used[c.pseudonodeID] = true
	}
	// A full sweep leaves the cursor where it started, so a refusal here
	// changes nothing — which is what lets this run as the last step before the
	// mutations rather than needing an unwind.
	for range 255 {
		s.pseudonodeCursor = s.pseudonodeCursor%255 + 1 // 1..255; 0 names the node itself
		if !used[s.pseudonodeCursor] {
			s.nextExtCircID++
			return s.pseudonodeCursor, s.nextExtCircID, nil
		}
	}
	return 0, 0, fmt.Errorf("goisis: all 255 pseudonode octets are in use")
}

// DeleteCircuit removes a circuit at runtime. It is the rest of what
// SetCircuitLinkState(false) already does on the wire — hellos stop, received
// frames are refused, the circuit leaves the flooding set and this node's LSPs,
// its End.X SIDs are released and the adjacency loss reconverges SPF, the RIB
// and the FIB — plus what only a removal owes: the pseudonode LSPs the circuit
// owned are purged, its connected subnets are withdrawn, its transport is
// closed, and its metric label series are retired (Metrics.ForgetCircuit).
// Deleting a circuit that is not configured is refused as ErrAlreadyInState:
// the node is in the state the call asks for, and a reload refused part way
// re-issues its whole batch on the next signal, its deletions included, so
// without that classification the file could never be adopted.
//
// The circuit's pseudonode octet and extended circuit ID are not handed back to
// anything. There is nothing to hand them to: the allocator reads the octets in
// use straight off s.circuits, and never reuses an extended circuit ID at all
// (allocCircuitIDs).
func (s *IsisServer) DeleteCircuit(ctx context.Context, name string) error {
	return s.mgmtOperation(ctx, func() error { return s.deleteCircuit(name, s.clock.Now()) })
}

// deleteCircuit is DeleteCircuit's body, on the Serve goroutine.
//
// It is one management operation from end to end on purpose: between two
// operations the loop drains the pending LSP regeneration (drainLSPGen), which
// would re-originate the pseudonode LSP purged half way through.
func (s *IsisServer) deleteCircuit(name string, now time.Time) error {
	c := s.circuitNamed(name)
	if c == nil {
		return fmt.Errorf("goisis: circuit %s is not configured: %w", name, ErrAlreadyInState)
	}
	// Refuse the events its reader has already queued, before anything else
	// makes acting on them wrong (see circuit.detached).
	c.detached = true
	// Purge the pseudonode LSPs while the circuit is still in s.circuits: once
	// it is out, regeneratePseudonodeLSPs never visits its octet again, so the
	// entry would sit in the database own, unpurged, and past a refresh
	// deadline nothing can advance — and refreshOwnLSPs re-originates this
	// node's whole own LSP set whenever one own entry is past its deadline (ISO
	// 10589 10.1). That is silent until the deadline passes and a per-tick
	// re-flood of every own LSP afterwards.
	for _, l := range c.cfg.levels() {
		s.purgeStaleFragments(l, c.pseudonodeID, 0, now)
	}
	// The IS-Type this node advertises is the union of its circuits' levels
	// (isType), so losing the last circuit at a level loses the level. Its own
	// node LSP needs the same purge as the pseudonode above, and for the same
	// reason: regenerateLSPs walks levelCap and will not visit it again. The
	// level set is computed from the other circuits rather than after the
	// removal, so that both purges are issued while this circuit can still
	// carry them.
	var kept levelSet
	for _, other := range s.circuits {
		if other == c {
			continue
		}
		for _, l := range other.cfg.levels() {
			kept.add(l)
		}
	}
	for _, l := range s.levelCap.levels() {
		if !kept.has(l) {
			s.purgeStaleFragments(l, 0, 0, now)
		}
	}
	// Flush both purges onto this circuit before it goes, exactly as a clean
	// shutdown does (shutdown): the purges above set SRM on every circuit at
	// the level, and this is the only one that reaches the segment this circuit
	// was on. Without it the neighbors hold our pseudonode LSP until MaxAge —
	// harmless, because our node LSP no longer points at it and SPF ignores it,
	// but twenty minutes of a database entry for a segment we have left. A
	// level losing its last circuit has nowhere else to send its node LSP's
	// purge at all, so for that one this is the only flush there will ever be.
	//
	// It runs before the adjacencies go down, not after: floodReady gates a
	// point-to-point circuit on an Up adjacency, so a teardown first makes this
	// send nothing at all on exactly the circuits where the level-loss purge
	// has no other way out. A clean shutdown flushes with its adjacencies up
	// for the same reason.
	for _, l := range c.cfg.levels() {
		s.drainSRM(c, l, now)
	}
	// Every adjacency goes down, with the watch events, the metrics, the DIS
	// re-election and the re-origination that a neighbor loss owes. Adjacencies
	// still in Init are reported Down too, pairing with the event their Init
	// transition emitted.
	s.dropAdjacencies(c, "adjacency down: circuit deleted", func(*adjacency) bool { return true })
	s.circuits = slices.DeleteFunc(s.circuits, func(other *circuit) bool { return other == c })
	// Without this the circuit's subnets stay directly connected forever, and a
	// prefix marked connected is never installed — so a legitimate advertiser
	// of one could never put a route in.
	s.setCircuitPrefixes(name, nil)
	s.levelCap = kept
	// ponytail: s.dbs keeps the database of a level no circuit is at any more,
	// and ageLSPs empties it within MaxAge. Dropping it here would instead make
	// the s.dbs[level] dereferences that carry no nil check (purgeOwn,
	// exhaustSeq) depend on levelCap gating to stay off a nil map.

	before := s.lspBufferSize
	s.setLSPBufferSize()
	// Re-arm every warning keyed on this circuit, so a circuit configured under
	// the same name later is not silent about a condition this one logged.
	s.txSucceeded(c)
	s.oversizeWarned.clearFunc(func(k oversizeKey) bool { return k.circuit == name })
	s.dupSystemIDWarned.clear(name)
	s.adjLimitWarned.clear(name)
	s.refusedWarned.clearFunc(func(k refusedKey) bool { return k.circuit == name })
	// Closing is the whole termination and we must not wait for anything: this
	// runs on the Serve goroutine, so nothing drains eventCh while it does, and
	// a wait would deadlock on exactly the busy circuit being removed. The
	// reader is parked in Recv, which now returns ErrClosed, or on a send that
	// completes once this returns; either way it exits within readerRetryDelay,
	// and c.detached makes the interval harmless. It closes only after the
	// circuit is out of s.circuits: a send attempted on a closed transport
	// would report PDUTxError and put this circuit's metric labels back.
	if err := c.cfg.Transport.Close(); err != nil {
		s.logger.Warn("close circuit transport", "circuit", name, "error", err)
	}
	s.logger.Info("circuit deleted", "circuit", name)
	if s.lspBufferSize != before {
		// A wider buffer re-packs the fragments; going through the throttle
		// would leave the old packing in the database for up to
		// minLSPGenInterval.
		s.regenerateLSPs(false, now)
	} else {
		s.requestLSPRegen()
	}
	// Last, after every report this removal owes (the adjacencies going down,
	// the flush above) and after the re-origination that follows it: the sink
	// keys its series on the circuit name, so anything reported for this name
	// afterwards builds them again. The reader goroutine outlives this call and
	// has events queued; c.detached is what keeps them off Metrics (handleEvent).
	// Without this the adjacency gauge — re-set for every circuit on every
	// housekeeping tick — holds its last value for as long as the process runs,
	// which is the stale reading its own contract exists to rule out.
	s.metrics.ForgetCircuit(name)
	return nil
}

// circuitNamed returns the circuit with the given name, or nil.
func (s *IsisServer) circuitNamed(name string) *circuit {
	for _, c := range s.circuits {
		if c.cfg.Name == name {
			return c
		}
	}
	return nil
}

// sortedSet returns addresses in a canonical order without repeats, so two
// reads of the same interface compare equal however the kernel ordered them.
func sortedSet(addrs []netip.Addr) []netip.Addr {
	out := slices.Clone(addrs)
	slices.SortFunc(out, func(a, b netip.Addr) int { return a.Compare(b) })
	return slices.Compact(out)
}

// maskedSet returns prefixes in masked form — the key the RIB, the FIB and the
// sweep agree on — keeping the given order and dropping repeats (the same
// subnet listed twice on one circuit).
func maskedSet(prefixes []netip.Prefix) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(prefixes))
	for _, p := range prefixes {
		if p = p.Masked(); !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	slices.SortFunc(out, func(a, b netip.Prefix) int { return a.Masked().Addr().Compare(b.Masked().Addr()) })
	return out
}

// setCircuitPrefixes replaces the connected subnets recorded against a circuit
// (already masked) and rebuilds the directly-connected set from every circuit
// plus the option set. A subnet is connected because a circuit or an option has
// it, never because of who advertises it: what goes into the LSP is derived
// separately (originatedPrefixes), so an advertisement can neither withdraw
// another owner's prefix nor take the never-install guard with it.
func (s *IsisServer) setCircuitPrefixes(name string, masked []netip.Prefix) {
	if len(masked) == 0 {
		delete(s.circuitPrefixes, name)
	} else {
		s.circuitPrefixes[name] = masked
	}
	s.connected = make(map[netip.Prefix]bool, len(s.connected))
	for p := range s.optionConnected {
		s.connected[p] = true
	}
	for _, ps := range s.circuitPrefixes {
		for _, p := range ps {
			s.connected[p] = true
		}
	}
}
