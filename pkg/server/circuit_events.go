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

		now := time.Now()
		s.sendHellos(c, now)
		s.regenerateLSPs(false, now)
		s.markDirty()
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
