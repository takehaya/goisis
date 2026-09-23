package server

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/takehaya/goisis/pkg/fib"
	"github.com/takehaya/goisis/pkg/packet"
)

// participatesInAlgo reports whether this node computes paths for the given
// algorithm: algorithm 0 (normal SPF) is always computed, and a Flexible
// Algorithm is computed only when it appears in the node's configuration.
func (s *IsisServer) participatesInAlgo(algo uint8) bool {
	if algo == 0 {
		return true
	}
	for _, fa := range s.flexAlgos {
		if fa.Algo == algo {
			return true
		}
	}
	return false
}

// AddLocator advertises a new SRv6 locator at runtime. It mirrors the
// validation NewIsisServer applies (IPv6 only, and a non-zero algorithm
// requires participation in that Flex-Algo), installs the local End SID, and
// re-originates this node's LSPs. Adding a locator whose prefix is already
// advertised is rejected.
func (s *IsisServer) AddLocator(ctx context.Context, cfg SRv6LocatorConfig) error {
	return s.mgmtOperation(ctx, func() error {
		if a := cfg.Prefix.Addr(); !a.Is6() || a.Is4In6() {
			return fmt.Errorf("goisis: SRv6 locator %s must be IPv6", cfg.Prefix)
		}
		if cfg.Algo != 0 && !s.participatesInAlgo(cfg.Algo) {
			return fmt.Errorf("goisis: SRv6 locator %s is bound to Flex-Algo %d but the node does not participate in it (AddFlexAlgo first)", cfg.Prefix, cfg.Algo)
		}
		want := cfg.Prefix.Masked()
		for _, lc := range s.locators {
			if lc.Prefix.Masked() == want {
				return fmt.Errorf("goisis: SRv6 locator %s is already advertised", want)
			}
		}
		s.locators = append(s.locators, cfg)
		if err := s.fib.AddLocalSID(fib.LocalSID{SID: cfg.endSID(), Behavior: fib.BehaviorEnd}); err != nil {
			s.logger.Error("install local End SID", "sid", cfg.endSID(), "error", err)
			s.metrics.FIBError(fibOpAddSID)
		}
		s.regenerateLSPs(false, time.Now())
		s.markDirty()
		return nil
	})
}

// DeleteLocator withdraws a previously advertised SRv6 locator (matched on its
// masked prefix), removes its local End SID, and re-originates this node's LSPs.
func (s *IsisServer) DeleteLocator(ctx context.Context, prefix netip.Prefix) error {
	return s.mgmtOperation(ctx, func() error {
		want := prefix.Masked()
		idx := -1
		for i, lc := range s.locators {
			if lc.Prefix.Masked() == want {
				idx = i
				break
			}
		}
		if idx < 0 {
			return fmt.Errorf("goisis: SRv6 locator %s is not advertised", want)
		}
		removed := s.locators[idx]
		s.locators = append(s.locators[:idx], s.locators[idx+1:]...)
		delete(s.endSIDFailed, removed.endSID())
		if err := s.fib.RemoveLocalSID(removed.endSID()); err != nil {
			s.logger.Error("remove local End SID", "sid", removed.endSID(), "error", err)
			s.metrics.FIBError(fibOpRemoveSID)
		}
		s.regenerateLSPs(false, time.Now())
		s.markDirty()
		return nil
	})
}

// AddFlexAlgo makes this node participate in a Flexible Algorithm at runtime
// (and advertise its definition when configured). The algorithm number must be
// in the Flex-Algo range (128-255) and not already configured.
func (s *IsisServer) AddFlexAlgo(ctx context.Context, cfg FlexAlgoConfig) error {
	return s.mgmtOperation(ctx, func() error {
		if cfg.Algo < 128 {
			return fmt.Errorf("goisis: Flex-Algo %d is reserved; use 128-255", cfg.Algo)
		}
		if s.participatesInAlgo(cfg.Algo) {
			return fmt.Errorf("goisis: Flex-Algo %d is already configured", cfg.Algo)
		}
		s.flexAlgos = append(s.flexAlgos, cfg)
		s.regenerateLSPs(false, time.Now())
		s.markDirty()
		return nil
	})
}

// DeleteFlexAlgo stops this node participating in a Flexible Algorithm. It is
// rejected while an SRv6 locator is still bound to the algorithm (delete the
// locator first), since the locator would otherwise become an unreachable
// black hole.
func (s *IsisServer) DeleteFlexAlgo(ctx context.Context, algo uint8) error {
	return s.mgmtOperation(ctx, func() error {
		idx := -1
		for i, fa := range s.flexAlgos {
			if fa.Algo == algo {
				idx = i
				break
			}
		}
		if idx < 0 {
			return fmt.Errorf("goisis: Flex-Algo %d is not configured", algo)
		}
		for _, lc := range s.locators {
			if lc.Algo == algo {
				return fmt.Errorf("goisis: Flex-Algo %d still has SRv6 locator %s bound; delete the locator first", algo, lc.Prefix.Masked())
			}
		}
		s.flexAlgos = append(s.flexAlgos[:idx], s.flexAlgos[idx+1:]...)
		// Re-arm the unsupported-metric-type warning for this algo across levels,
		// so a future re-add logs it again.
		for _, level := range []packet.Level{packet.Level1, packet.Level2} {
			delete(s.algoWarned, algoKey{level: level, algo: algo})
		}
		s.regenerateLSPs(false, time.Now())
		s.markDirty()
		return nil
	})
}

// AddPrefix originates a new prefix in this node's LSP (TLV 135/236) at
// runtime. The prefix must be valid, routable, and not already named by the
// configuration or an earlier AddPrefix (matched on its masked form, the key
// the RIB and FIB agree on). A subnet a circuit already has connected may be
// named here: the prefix is still advertised once, at the metric given here.
func (s *IsisServer) AddPrefix(ctx context.Context, cfg AdvertisedPrefix) error {
	return s.mgmtOperation(ctx, func() error {
		if !cfg.Prefix.IsValid() {
			return fmt.Errorf("goisis: prefix %s is not a valid prefix", cfg.Prefix)
		}
		want := cfg.Prefix.Masked()
		// This is the trust boundary the management API sits on: whatever is
		// accepted here is flooded area-wide and installed by every peer.
		// Prefixes that no unicast forwarding entry can ever serve are refused
		// rather than advertised. The default route is not one of them:
		// default-information origination is legitimate, and suppressing it is
		// policy.advertise's job.
		if a := want.Addr(); a.Is4In6() || a.IsMulticast() || a.IsLinkLocalUnicast() || (a.IsUnspecified() && want.Bits() != 0) {
			return fmt.Errorf("goisis: prefix %s is not routable; multicast, unspecified, link-local and IPv4-mapped prefixes are never originated", want)
		}
		// RFC 5305 §4: a metric at or above the ceiling means "not reachable",
		// so advertising one would be a black hole no SPF would ever use.
		if cfg.Metric >= maxPathMetric {
			return fmt.Errorf("goisis: prefix %s metric %d is at or above the reachability ceiling %d", want, cfg.Metric, uint32(maxPathMetric))
		}
		if _, ok := s.optionPrefixes[want]; ok {
			return fmt.Errorf("goisis: prefix %s is already advertised", want)
		}
		s.optionPrefixes[want] = AdvertisedPrefix{Prefix: want, Metric: cfg.Metric}
		s.regenerateLSPs(false, time.Now())
		s.markDirty()
		return nil
	})
}

// DeletePrefix withdraws a prefix the configuration or AddPrefix named (matched
// on its masked prefix). A circuit that has the same subnet connected keeps
// originating it at the circuit's metric, and a subnet only a circuit
// contributes is refused: withdrawing it here would last until that circuit's
// next address event, and suppressing an advertisement is the export policy's
// job (WithAdvertiseFilter / policy.advertise). Either way the subnet stays
// marked directly connected, so goisis never programs over the kernel's own
// connected route.
func (s *IsisServer) DeletePrefix(ctx context.Context, prefix netip.Prefix) error {
	return s.mgmtOperation(ctx, func() error {
		want := prefix.Masked()
		if _, ok := s.optionPrefixes[want]; !ok {
			for _, c := range s.circuits {
				if slices.Contains(s.circuitPrefixes[c.cfg.Name], want) {
					return fmt.Errorf("goisis: %s is connected on %s; remove the address or use policy.advertise", want, c.cfg.Name)
				}
			}
			return fmt.Errorf("goisis: prefix %s is not advertised", want)
		}
		delete(s.optionPrefixes, want)
		s.regenerateLSPs(false, time.Now())
		s.markDirty()
		return nil
	})
}

// SetOverload sets or clears the overload bit in this node's own LSP by hand,
// for maintenance: peers keep reaching our own prefixes but route no transit
// traffic through us. It is independent of the startup overload window, which
// still applies while it runs.
func (s *IsisServer) SetOverload(ctx context.Context, on bool) error {
	return s.mgmtOperation(ctx, func() error {
		s.overloadManual = on
		s.logger.Info("manual overload bit", "set", on)
		s.regenerateLSPs(false, time.Now())
		s.markDirty()
		return nil
	})
}

// ClearAdjacency tears down adjacencies on a circuit so hellos re-form them:
// every adjacency on the circuit, or only the one to systemID when it is
// non-nil. Clearing an adjacency that does not exist is a no-op, so a repeated
// clear is harmless.
func (s *IsisServer) ClearAdjacency(ctx context.Context, circuit string, systemID *packet.SystemID) error {
	return s.mgmtOperation(ctx, func() error {
		c := s.circuitByName(circuit)
		if c == nil {
			return fmt.Errorf("goisis: circuit %s is not configured", circuit)
		}
		if c.cfg.P2P {
			if adj := c.p2pAdj; adj != nil && (systemID == nil || *systemID == adj.systemID) {
				s.teardownP2PAdj(c, adj, "p2p adjacency cleared")
				c.p2pAdj = nil
			}
			return nil
		}
		changed := false
		for _, level := range c.cfg.levels() {
			for id, adj := range c.adjs[level] {
				if systemID != nil && *systemID != id {
					continue
				}
				s.logger.Info("adjacency cleared", "circuit", c.cfg.Name, "level", level, "neighbor", id)
				s.emitAdjacencyDown(c, adj, level)
				delete(c.adjs[level], id)
				s.electDIS(c, level)
				changed = true
			}
		}
		if changed {
			s.regenerateLSPs(false, time.Now())
		}
		return nil
	})
}

// circuitByName returns the configured circuit with the given interface name,
// or nil if there is none.
func (s *IsisServer) circuitByName(name string) *circuit {
	for _, c := range s.circuits {
		if c.cfg.Name == name {
			return c
		}
	}
	return nil
}
