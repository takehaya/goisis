package server

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"time"
)

// SetCircuitAddresses replaces a circuit's hello source addresses (TLV 132 /
// 232) and its directly-connected subnets, then tells the neighbors at once
// instead of at the next scheduled hello. Only the prefixes this circuit
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
		masked := make([]netip.Prefix, 0, len(connected))
		for _, p := range connected {
			masked = append(masked, p.Masked())
		}
		if slices.Equal(c.cfg.IPv4Addrs, v4) && slices.Equal(c.cfg.IPv6Addrs, v6) &&
			slices.Equal(s.circuitPrefixes[name], masked) {
			return nil
		}
		c.cfg.IPv4Addrs, c.cfg.IPv6Addrs = v4, v6
		s.removeCircuitPrefixes(name)
		s.addCircuitPrefixes(name, c.cfg.Metric, masked)

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

// addCircuitPrefixes originates a circuit's connected subnets at its metric and
// records them against the circuit. A prefix another origin already advertises
// is recorded but not advertised twice.
func (s *IsisServer) addCircuitPrefixes(name string, metric uint32, prefixes []netip.Prefix) {
	for _, p := range prefixes {
		p = p.Masked()
		if slices.Contains(s.circuitPrefixes[name], p) {
			continue // the same subnet listed twice on one circuit
		}
		if !s.prefixContributed(p, name) {
			s.prefixes = append(s.prefixes, AdvertisedPrefix{Prefix: p, Metric: metric})
			s.connected[p] = true
		}
		s.circuitPrefixes[name] = append(s.circuitPrefixes[name], p)
	}
}

// removeCircuitPrefixes withdraws the connected subnets recorded against a
// circuit, keeping the ones another circuit or an option still contributes.
func (s *IsisServer) removeCircuitPrefixes(name string) {
	old := s.circuitPrefixes[name]
	delete(s.circuitPrefixes, name)
	for _, p := range old {
		if s.prefixContributed(p, name) {
			continue
		}
		delete(s.connected, p)
		s.prefixes = slices.DeleteFunc(s.prefixes, func(a AdvertisedPrefix) bool { return a.Prefix == p })
	}
}

// prefixContributed reports whether an option or a circuit other than except
// still wants the prefix originated.
func (s *IsisServer) prefixContributed(p netip.Prefix, except string) bool {
	if s.optionPrefixes[p] {
		return true
	}
	for name, ps := range s.circuitPrefixes {
		if name != except && slices.Contains(ps, p) {
			return true
		}
	}
	return false
}
