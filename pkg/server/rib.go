package server

import (
	"context"
	"net/netip"
	"sort"
	"time"

	"github.com/takehaya/goisis/pkg/fib"
	"github.com/takehaya/goisis/pkg/packet"
)

// NextHopInfo is a resolved next hop for a RIB route.
type NextHopInfo struct {
	Interface string
	Gateway   netip.Addr
}

// RouteInfo is one computed route in the RIB.
type RouteInfo struct {
	Prefix   netip.Prefix
	Metric   uint32
	Level    packet.Level
	NextHops []NextHopInfo
}

// updateRIB recomputes SPF for all levels, resolves next hops, and programs
// the difference into the FIB. Level 1 routes are preferred over Level 2 for
// the same prefix (ISO 10589 / RFC 1195 route preference).
func (s *IsisServer) updateRIB(now time.Time) {
	// Compute per level, then overlay L1 onto L2 so L1 wins.
	merged := map[netip.Prefix]route{}
	if _, ok := s.dbs[packet.Level2]; ok {
		for p, r := range s.computeSPF(packet.Level2, now) {
			merged[p] = r
		}
	}
	if _, ok := s.dbs[packet.Level1]; ok {
		for p, r := range s.computeSPF(packet.Level1, now) {
			merged[p] = r // L1 preferred
		}
	}

	next := make(map[netip.Prefix]RouteInfo, len(merged))
	for p, r := range merged {
		if s.connected[p.Masked()] {
			continue // directly connected: the kernel already has this route
		}
		nhs := s.resolveNextHops(p, r.nextHops)
		if len(nhs) == 0 {
			continue // unresolvable (no neighbor address of the right family)
		}
		next[p] = RouteInfo{Prefix: p, Metric: r.metric, Level: r.level, NextHops: nhs}
	}

	// s.rib always holds the DESIRED route set: the diff, withdrawals, and
	// change-events are computed against it. FIB-install failures are tracked
	// separately in s.fibPending and retried, so a transient netlink error
	// neither loses the withdraw bookkeeping nor re-emits change events.
	s.programFIB(next)
	s.rib = next
}

// resolveNextHops maps first-hop system IDs to concrete (interface, gateway)
// next hops, using the neighbor addresses learned from hellos and matching
// the address family of the destination prefix.
func (s *IsisServer) resolveNextHops(prefix netip.Prefix, hops []packet.SystemID) []NextHopInfo {
	v4 := prefix.Addr().Is4()
	var out []NextHopInfo
	seen := map[string]bool{}
	for _, h := range hops {
		adj, c := s.findAdjacency(h)
		if adj == nil {
			continue
		}
		var gw netip.Addr
		if v4 {
			if len(adj.neighborIPv4) > 0 {
				gw = adj.neighborIPv4[0]
			}
		} else if len(adj.neighborIPv6) > 0 {
			gw = adj.neighborIPv6[0]
		}
		if !gw.IsValid() {
			continue
		}
		key := c.cfg.Name + "|" + gw.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, NextHopInfo{Interface: c.cfg.Name, Gateway: gw})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Interface != out[j].Interface {
			return out[i].Interface < out[j].Interface
		}
		return out[i].Gateway.String() < out[j].Gateway.String()
	})
	return out
}

// findAdjacency returns the Up adjacency to a system ID and its circuit, if
// any (searching every circuit and level).
func (s *IsisServer) findAdjacency(id packet.SystemID) (*adjacency, *circuit) {
	for _, c := range s.circuits {
		if c.cfg.P2P {
			if a := c.p2pAdj; a != nil && a.state == AdjUp && a.systemID == id {
				return a, c
			}
			continue
		}
		for _, level := range c.cfg.levels() {
			if a := c.adjs[level][id]; a != nil && a.state == AdjUp {
				return a, c
			}
		}
	}
	return nil, nil
}

// programFIB applies the difference between the desired route set and the
// current RIB to the FIB. A route whose change is new emits a watch event and
// is written; a route whose previous write failed (in s.fibPending) is
// re-written without re-emitting; withdrawn routes are removed.
func (s *IsisServer) programFIB(next map[netip.Prefix]RouteInfo) {
	for p, r := range next {
		old, ok := s.rib[p]
		changed := !ok || !sameRoute(old, r)
		if changed {
			// Notify watchers of the routing decision regardless of whether
			// the kernel write succeeds (watch-only consumers program their
			// own dataplane).
			r := r
			s.emitRoute(&r, false)
		}
		if !changed && !s.fibPending[p] {
			continue // unchanged and previously installed
		}
		nhs := make([]fib.Nexthop, len(r.NextHops))
		for i, nh := range r.NextHops {
			nhs[i] = fib.Nexthop{Interface: nh.Interface, Gateway: nh.Gateway}
		}
		if err := s.fib.Update(p, nhs); err != nil {
			s.logger.Error("fib update", "prefix", p, "error", err)
			s.fibPending[p] = true // retry next recompute
		} else {
			delete(s.fibPending, p)
		}
	}
	for p := range s.rib {
		if _, ok := next[p]; !ok {
			old := s.rib[p]
			s.emitRoute(&old, true)
			if err := s.fib.Withdraw(p); err != nil {
				s.logger.Error("fib withdraw", "prefix", p, "error", err)
			}
			delete(s.fibPending, p)
		}
	}
}

func (s *IsisServer) emitRoute(r *RouteInfo, withdrawn bool) {
	if len(s.watchers) > 0 {
		s.emit(Event{Route: r, Withdrawn: withdrawn})
	}
}

func sameRoute(a, b RouteInfo) bool {
	if a.Metric != b.Metric || len(a.NextHops) != len(b.NextHops) {
		return false
	}
	for i := range a.NextHops {
		if a.NextHops[i] != b.NextHops[i] {
			return false
		}
	}
	return true
}

// ListRoutes returns a snapshot of the RIB.
func (s *IsisServer) ListRoutes(ctx context.Context) ([]RouteInfo, error) {
	var out []RouteInfo
	err := s.mgmtOperation(ctx, func() error {
		for _, r := range s.rib {
			out = append(out, r)
		}
		return nil
	})
	return out, err
}
