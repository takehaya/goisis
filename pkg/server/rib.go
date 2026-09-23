package server

import (
	"context"
	"maps"
	"net/netip"
	"slices"
	"sort"
	"strconv"
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
// and programs the difference into the FIB. When the same prefix is computed
// more than once, betterRoute picks the winner (L1 over L2, then the lower
// algorithm; see its doc for the rationale).
func (s *IsisServer) updateRIB(now time.Time) {
	merged := map[netip.Prefix]route{}
	algos := s.routingAlgos()
	// Iteration order is immaterial: betterRoute alone decides which route wins
	// when the same prefix is computed at both levels or under two algorithms.
	for _, level := range []packet.Level{packet.Level1, packet.Level2} {
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
				if cur, ok := merged[p]; ok && !betterRoute(r, cur) {
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
			// Two causes, two levels. No Up adjacency to any first hop is a
			// transient the protocol repairs itself: a peer LSP (or a LAN
			// pseudonode we do not originate) still lists a neighbor whose
			// adjacency is gone, and the next flooding round drops it. Warning
			// per prefix would turn one lost neighbor into a log flood on the
			// management loop. An adjacency that IS Up but yielded no gateway
			// stands until an operator acts: the neighbor announced no address
			// of this family (TLV 132/232, e.g. an SRv6/IPv6 locator over a
			// link with no IPv6 interface address) or does not route it
			// (TLV 129).
			if slices.ContainsFunc(r.nextHops, func(h packet.SystemID) bool {
				adj, _ := s.findAdjacency(h)
				return adj != nil
			}) {
				s.logger.Warn("route has no resolvable next hop",
					"prefix", p, "level", r.level, "algo", r.algo, "family", addrFamily(p))
			} else {
				s.logger.Debug("route first hop has no adjacency",
					"prefix", p, "level", r.level, "algo", r.algo)
			}
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

	// Report every (level, algorithm) this node computes, not just those that
	// produced a route, so a level or Flex-Algo that loses its last route
	// reports 0 instead of leaving a stale gauge behind.
	counts := map[algoKey]int{}
	for _, r := range next {
		counts[algoKey{level: r.Level, algo: r.Algorithm}]++
	}
	for level := range s.dbs {
		for _, algo := range algos {
			key := algoKey{level: level, algo: algo}
			s.metrics.RouteCount(levelLabel(level), strconv.Itoa(int(algo)), counts[key])
		}
	}

	// ISO 10589 7.2.9 / RFC 1195 §3.1: an L1L2 IS advertises the prefixes
	// reachable inside its Level-1 area in its Level-2 LSP. The regeneration
	// marks dirty, so a later iteration recomputes; the export set is unchanged
	// then and the cascade stops after that one extra pass.
	if export := s.l1ExportSet(merged); !maps.Equal(export, s.l1Export) {
		s.l1Export = export
		s.requestLSPRegen()
	}
}

// l1ExportSet returns the Level-1 prefixes this IS propagates upward into its
// Level-2 LSP, keyed by masked prefix to the total Level-1 path metric. Only an
// L1L2 IS exports anything; for anyone else the set is empty.
func (s *IsisServer) l1ExportSet(merged map[netip.Prefix]route) map[netip.Prefix]uint32 {
	if !s.levelCap.has(packet.Level1) || !s.levelCap.has(packet.Level2) {
		return nil
	}
	own := map[netip.Prefix]bool{}
	for _, p := range s.prefixes {
		own[p.Prefix.Masked()] = true
	}
	for p := range s.connected {
		own[p] = true
	}
	for _, lc := range s.locators {
		own[lc.Prefix.Masked()] = true
	}
	var export map[netip.Prefix]uint32
	for p, r := range merged {
		switch {
		case r.level != packet.Level1 || r.algo != 0:
			continue // only intra-area algorithm-0 reachability propagates
		case r.down:
			continue // leaked down from L2 already; sending it back up would loop
		case p == defaultV4 || p == defaultV6:
			continue // a default is not area reachability, whatever produced it
		case own[p]:
			continue // regenerateNodeLSP already originates this one at both levels
		}
		if export == nil {
			export = map[netip.Prefix]uint32{}
		}
		export[p] = r.metric
	}
	return export
}

// betterRoute reports whether candidate should replace incumbent as the route
// for one prefix. The precedence, highest first:
//
//  1. Level: a Level 1 route is preferred over a Level 2 route for the same
//     prefix (ISO 10589 / RFC 1195: intra-area routes take precedence over
//     inter-area routes). Level dominates the algorithm, so an L1 Flex-Algo
//     route displaces an L2 algorithm-0 route.
//  2. Algorithm: within a level, the lower algorithm wins. Algorithm 0 and
//     each Flex-Algo normally advertise disjoint prefixes, but a shared/anycast
//     prefix claimed by two algorithms could collide; prefer plain reachability
//     (algorithm 0) over a Flex-Algo, deterministically.
//
// On a full tie the incumbent stays.
func betterRoute(candidate, incumbent route) bool {
	if candidate.level != incumbent.level {
		return candidate.level == packet.Level1
	}
	return candidate.algo < incumbent.algo
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
		if !routesFamily(adj.nlpids, v4) {
			continue // the neighbor does not route this family
		}
		var gw netip.Addr
		if v4 {
			gw = pickGateway(adj.neighborIPv4, true, s.connected)
		} else {
			gw = pickGateway(adj.neighborIPv6, false, s.connected)
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

// routesFamily reports whether a neighbor advertising these NLPIDs (TLV 129)
// routes the given family. An absent TLV is permissive: RFC 1195 3.1 requires
// it, but a route pointed at a silent peer is better than no route at all.
func routesFamily(nlpids []byte, v4 bool) bool {
	if len(nlpids) == 0 {
		return true
	}
	want := byte(packet.NLPIDIPv6)
	if v4 {
		want = packet.NLPIDIPv4
	}
	return slices.Contains(nlpids, want)
}

// pickGateway chooses the next-hop address among the ones a neighbor listed in
// its hello. TLV 132 carries every address of the peer's interface, so the
// first one may not even be on this link; an off-subnet gateway makes the
// kernel reject the route with ENETUNREACH. For IPv6 the gateway must be
// link-local (RFC 5308 2 and 3), but a peer that also lists a global address
// must not push it to the front. Falling back to the first address keeps a
// neighbor whose addressing we cannot corroborate reachable.
func pickGateway(addrs []netip.Addr, v4 bool, connected map[netip.Prefix]bool) netip.Addr {
	for _, a := range addrs {
		if v4 {
			for p := range connected {
				if p.Addr().Is4() && p.Contains(a) {
					return a
				}
			}
		} else if a.IsLinkLocalUnicast() {
			return a
		}
	}
	if len(addrs) > 0 {
		return addrs[0]
	}
	return netip.Addr{}
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
			// Notify watchers of the routing decision regardless of whether the
			// route is programmed or the kernel write succeeds (watch-only
			// consumers, and FIB-filtered routes, are still surfaced).
			r := r
			s.emitRoute(&r, false)
		}
		// FIB policy: a rejected route stays in the RIB but is not written to
		// the forwarding plane. If it was installed before (filter flipped, or
		// the route changed across the policy boundary), withdraw it.
		if s.fibFilter != nil && !s.fibFilter(r) {
			if s.fibInstalled[p] {
				if err := s.fib.Withdraw(p); err != nil {
					s.logger.Error("fib withdraw", "prefix", p, "error", err)
					s.metrics.FIBError(fibOpWithdraw)
				}
				delete(s.fibInstalled, p)
			}
			delete(s.fibPending, p)
			continue
		}
		if !changed && s.fibInstalled[p] && !s.fibPending[p] {
			continue // unchanged and already installed
		}
		nhs := make([]fib.Nexthop, len(r.NextHops))
		for i, nh := range r.NextHops {
			nhs[i] = fib.Nexthop{Interface: nh.Interface, Gateway: nh.Gateway}
		}
		if err := s.fib.Update(p, nhs); err != nil {
			s.logger.Error("fib update", "prefix", p, "error", err)
			s.metrics.FIBError(fibOpUpdate)
			s.fibPending[p] = true // retry next recompute
		} else {
			delete(s.fibPending, p)
			s.fibInstalled[p] = true
		}
	}
	for p := range s.rib {
		if _, ok := next[p]; !ok {
			old := s.rib[p]
			s.emitRoute(&old, true)
			if s.fibInstalled[p] {
				if err := s.fib.Withdraw(p); err != nil {
					s.logger.Error("fib withdraw", "prefix", p, "error", err)
					s.metrics.FIBError(fibOpWithdraw)
				}
				delete(s.fibInstalled, p)
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
