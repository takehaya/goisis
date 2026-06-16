package server

import (
	"context"
	"fmt"
	"net/netip"
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
		if err := s.fib.RemoveLocalSID(removed.endSID()); err != nil {
			s.logger.Error("remove local End SID", "sid", removed.endSID(), "error", err)
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
