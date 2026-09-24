package server

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"time"
)

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
			return fmt.Errorf("goisis: unknown circuit %q", name)
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

		s.sendHellos(c, time.Now())
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
			return fmt.Errorf("goisis: unknown circuit %q", name)
		}
		if c.linkDown == !up {
			return nil
		}
		c.linkDown = !up
		s.logger.Info("circuit link state change", "circuit", name, "up", up)
		now := time.Now()
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

// DeleteCircuit removes a circuit at runtime. It is the rest of what
// SetCircuitLinkState(false) already does on the wire — hellos stop, received
// frames are refused, the circuit leaves the flooding set and this node's LSPs,
// its End.X SIDs are released and the adjacency loss reconverges SPF, the RIB
// and the FIB — plus what only a removal owes: the pseudonode LSPs the circuit
// owned are purged, its connected subnets are withdrawn, and its transport is
// closed. Deleting a circuit that is not configured is an error: a caller that
// issues the same delete twice has a bug, and a reload derives its deletions
// from a difference, so it cannot issue one.
//
// The circuit's pseudonode octet is not handed back to anything. Nothing
// allocates one at runtime yet (see NewIsisServer), so there is nobody to hand
// it to.
func (s *IsisServer) DeleteCircuit(ctx context.Context, name string) error {
	return s.mgmtOperation(ctx, func() error { return s.deleteCircuit(name, time.Now()) })
}

// deleteCircuit is DeleteCircuit's body, on the Serve goroutine.
//
// It is one management operation from end to end on purpose: between two
// operations the loop drains the pending LSP regeneration (drainLSPGen), which
// would re-originate the pseudonode LSP purged half way through.
func (s *IsisServer) deleteCircuit(name string, now time.Time) error {
	c := s.circuitNamed(name)
	if c == nil {
		return fmt.Errorf("goisis: circuit %s is not configured", name)
	}
	// Refuse the events its reader has already queued, before anything else
	// makes acting on them wrong (see circuit.detached).
	c.detached = true
	// Every adjacency goes down, with the watch events, the metrics, the DIS
	// re-election and the re-origination that a neighbor loss owes. Adjacencies
	// still in Init are reported Down too, pairing with the event their Init
	// transition emitted.
	s.dropAdjacencies(c, "adjacency down: circuit deleted", func(*adjacency) bool { return true })
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
	// the level, and this is the only one that reaches the LAN this circuit was
	// on. Without it the members hold our pseudonode LSP until MaxAge —
	// harmless, because our node LSP no longer points at it and SPF ignores it,
	// but twenty minutes of a database entry for a LAN we have left. A level
	// losing its last circuit has nowhere else to send its node LSP's purge at
	// all, so for that one this is the only flush there will ever be.
	for _, l := range c.cfg.levels() {
		s.transmitSRM(c, l, now)
	}
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
