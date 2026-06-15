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
	Prefix    netip.Prefix
	Metric    uint32
	Level     packet.Level
	Algorithm uint8
	NextHops  []NextHopInfo
}

// updateRIB recomputes SPF for every level and algorithm, resolves next hops,
// and programs the difference into the FIB. Level 1 routes are preferred over
// Level 2 for the same prefix (ISO 10589 / RFC 1195). Algorithm 0 and each
// Flexible Algorithm advertise disjoint prefixes (plain reachability vs.
// per-algorithm SRv6 locators), so they do not contend for the same key.
func (s *IsisServer) updateRIB(now time.Time) {
	merged := map[netip.Prefix]route{}
	algos := s.routingAlgos()
	// L2 first so L1 overlays it (L1 preferred for the same prefix).
	for _, level := range []packet.Level{packet.Level2, packet.Level1} {
		if _, ok := s.dbs[level]; !ok {
			continue
		}
		var state map[uint8]*FlexAlgoInfo
		for _, algo := range algos {
			if algo != 0 {
				if state == nil {
					state = s.flexAlgoState(level, now)
				}
				fi := state[algo]
				// No-fallback (RFC 9350): compute a Flex-Algo only when a
				// definition is elected and its metric-type is supported; an
				// unreachable Flex-Algo prefix is simply not installed, never
				// routed via algorithm 0.
				if fi == nil || fi.Definition == nil {
					continue
				}
				if fi.Definition.MetricType != packet.FlexAlgoMetricIGP {
					// Edge-triggered, keyed per (level, algo) because each level
					// elects its FAD independently: warn once until the
					// metric-type becomes supported again so a persistent
					// misconfiguration does not re-log on every recompute.
					key := algoKey{level: level, algo: algo}
					if !s.algoWarned[key] {
						s.logger.Warn("flex-algo metric-type unsupported; not computing routes",
							"algo", algo, "level", level, "metric_type", fi.Definition.MetricType)
						s.algoWarned[key] = true
					}
					continue
				}
				delete(s.algoWarned, algoKey{level: level, algo: algo}) // re-arm
			}
			for p, r := range s.computeSPF(level, algo, now) {
				// Algorithm 0 and each Flex-Algo normally advertise disjoint
				// prefixes, but a shared/anycast prefix claimed by two
				// algorithms could collide here. Resolve deterministically by
				// preferring the lower algorithm (plain reachability over a
				// Flex-Algo) rather than depending on iteration order.
				if cur, ok := merged[p]; ok && cur.algo <= r.algo && cur.level == level {
					continue
				}
				merged[p] = r
			}
		}
	}

	next := make(map[netip.Prefix]RouteInfo, len(merged))
	for p, r := range merged {
		if s.connected[p.Masked()] {
			continue // directly connected: the kernel already has this route
		}
		nhs := s.resolveNextHops(p, r.nextHops)
		if len(nhs) == 0 {
			// No neighbor address of the prefix's family was learned from
			// hellos (e.g. an SRv6/IPv6 locator over a link with no IPv6
			// interface address). Surface it rather than dropping silently.
			s.logger.Warn("route has no resolvable next hop",
				"prefix", p, "level", r.level, "algo", r.algo, "family", addrFamily(p))
			continue
		}
		next[p] = RouteInfo{Prefix: p, Metric: r.metric, Level: r.level, Algorithm: r.algo, NextHops: nhs}
	}

	// s.rib always holds the DESIRED route set: the diff, withdrawals, and
	// change-events are computed against it. FIB-install failures are tracked
	// separately in s.fibPending and retried, so a transient netlink error
	// neither loses the withdraw bookkeeping nor re-emits change events.
	s.programFIB(next)
	s.rib = next
}

// algoKey identifies a (level, Flex-Algo) pair, used to de-dup the
// unsupported-metric-type warning per level (each level elects independently).
type algoKey struct {
	level packet.Level
	algo  uint8
}

// routingAlgos returns the algorithms to compute: algorithm 0 plus every
// Flexible Algorithm this node participates in (deduplicated, ascending).
func (s *IsisServer) routingAlgos() []uint8 {
	seen := map[uint8]bool{0: true}
	algos := []uint8{0}
	for _, fa := range s.flexAlgos {
		if !seen[fa.Algo] {
			seen[fa.Algo] = true
			algos = append(algos, fa.Algo)
		}
	}
	sort.Slice(algos, func(i, j int) bool { return algos[i] < algos[j] })
	return algos
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

// addrFamily names the address family of a prefix for diagnostics.
func addrFamily(p netip.Prefix) string {
	if p.Addr().Is4() {
		return "ipv4"
	}
	return "ipv6"
}

func sameRoute(a, b RouteInfo) bool {
	if a.Metric != b.Metric || a.Algorithm != b.Algorithm || len(a.NextHops) != len(b.NextHops) {
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
