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
	Prefix netip.Prefix
	Metric uint32
	Level  packet.Level
	// Preference is the RFC 5302 §3.2 class this route was selected on
	// (preferenceClass), which is ranked ahead of the metric — so a route with
	// the worse metric can be the one in the RIB, and this is the field that
	// says why.
	//
	// The class is reported rather than the up/down bit preferenceClass reads
	// it from. The bit alone does not explain the ranking: at Level 2 it is
	// deliberately ignored (RFC 5302 §3.3), so reporting it there would invite
	// exactly the wrong conclusion, and the ATT-derived default carries it as a
	// marker rather than as a decoded advertisement (addAttachedDefault) — an
	// operator reading that bit would go looking for a neighbor's LSP that does
	// not exist. The class is true of every route: 3 says "ranked below
	// anything advertised intra-area", which is precisely what that fallback is.
	Preference uint8
	Algorithm  uint8
	NextHops   []NextHopInfo
}

// updateRIB recomputes SPF for every level and algorithm, resolves next hops,
// and programs the difference into the FIB. When the same prefix is computed
// more than once, betterRoute picks the winner (RFC 5302 §3.2 preference class, then
// the lower algorithm; see its doc for the rationale).
func (s *IsisServer) updateRIB(now time.Time) {
	merged := map[netip.Prefix]route{}
	// The Level-2 algorithm-0 route set, kept aside as the leak candidates:
	// merged only holds the winner per prefix, and a prefix the area also has
	// intra-area is won by Level 1 (betterRoute), which is exactly the prefix
	// l2LeakSet still has to look at to decide it is intra-area.
	var l2Reach map[netip.Prefix]route
	// RFC 9350 §5.3: a node that stops computing a Flexible Algorithm "MUST
	// NOT announce participation" in it either, because §13 has every other
	// router prune a non-participant out of its topology for that algorithm —
	// so the announcement is the one thing steering algorithm-K traffic into a
	// node holding no algorithm-K forwarding state. The refusal is decided
	// here, per (level, algo); recording it is what lets origination say the
	// same thing without re-deriving the condition.
	refused := map[algoKey]bool{}
	algos := s.routingAlgos()
	// Iteration order is immaterial: betterRoute alone decides which route wins
	// when the same prefix is computed at both levels or under two algorithms.
	for _, level := range []packet.Level{packet.Level1, packet.Level2} {
		if _, ok := s.dbs[level]; !ok {
			continue
		}
		var state map[uint8]*FlexAlgoInfo
		for _, algo := range algos {
			var aff flexAlgoAffinity
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
					refused[algoKey{level: level, algo: algo}] = true
					// Edge-triggered, keyed per (level, algo) because each level
					// elects its FAD independently: warn once until the
					// metric-type becomes supported again so a persistent
					// misconfiguration does not re-log on every recompute.
					s.algoWarned.warn(algoKey{level: level, algo: algo}, func() {
						s.logger.Warn("flex-algo metric-type unsupported; not computing routes, not participating",
							"algo", algo, "level", level, "metric_type", fi.Definition.MetricType)
					})
					continue
				}
				// The same refusal for a constraint that cannot be evaluated:
				// admin groups are pruned on, an SRLG or an unknown
				// sub-sub-TLV is not, and computing the algorithm anyway would
				// install paths over links the definition excluded.
				var err error
				if aff, err = flexAlgoAffinityOf(fi.Definition); err != nil {
					refused[algoKey{level: level, algo: algo}] = true
					s.algoWarned.warn(algoKey{level: level, algo: algo}, func() {
						s.logger.Warn("flex-algo constraint unsupported; not computing routes, not participating",
							"algo", algo, "level", level, "error", err)
					})
					continue
				}
				s.algoWarned.clear(algoKey{level: level, algo: algo}) // re-arm
			}
			computed := s.computeSPF(level, algo, aff, now)
			if level == packet.Level2 && algo == 0 {
				l2Reach = computed
			}
			for p, r := range computed {
				if cur, ok := merged[p]; ok && !betterRoute(r, cur) {
					continue
				}
				merged[p] = r
			}
		}
	}

	// Withdrawing the announcement is a change to our own LSP, taken at the
	// next drain the way the inter-level sets below are, and through the flag
	// rather than requestLSPRegen for the same one-extra-pass reason: the
	// re-origination marks dirty, and the pass that follows it finds the
	// refusal unchanged.
	if !maps.Equal(refused, s.flexAlgoRefused) {
		s.flexAlgoRefused = refused
		s.lspGenPending = true
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
		next[p] = RouteInfo{Prefix: p, Metric: r.metric, Level: r.level,
			Preference: preferenceClass(r), Algorithm: r.algo, NextHops: nhs}
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
	// reachable inside its Level-1 area in its Level-2 LSP. Originating the new
	// export set marks dirty, so a later iteration recomputes; the export set is
	// unchanged then and the cascade stops after that one extra pass. The flag
	// is set here rather than through requestLSPRegen precisely so that one pass
	// is all it costs: marking dirty from inside the recompute buys another one
	// for every iteration the generation throttle holds the LSP back.
	if export := s.l1ExportSet(merged); !maps.Equal(export, s.l1Export) {
		s.l1Export = export
		s.lspGenPending = true
	}
	// The other direction, and the same one-extra-pass argument: our own
	// prefixes are skipped by computeSPF, so the leak we originate never
	// re-enters our own route set and the second pass finds the set unchanged.
	if leak := s.l2LeakSet(merged, l2Reach); !maps.Equal(leak, s.l2Leak) {
		s.l2Leak = leak
		s.lspGenPending = true
	}
	// Reported on every recompute for the same reason RouteCount is: a node
	// that stops leaking or exporting has to report 0 rather than leave its
	// last count behind.
	s.metrics.InterLevelPrefixes(dirL2ToL1, len(s.l2Leak))
	s.metrics.InterLevelPrefixes(dirL1ToL2, len(s.l1Export))
}

// l1ExportSet returns the Level-1 prefixes this IS propagates upward into its
// Level-2 LSP, keyed by masked prefix to the total Level-1 path metric. Only an
// L1L2 IS exports anything; for anyone else the set is empty.
func (s *IsisServer) l1ExportSet(merged map[netip.Prefix]route) map[netip.Prefix]uint32 {
	if !s.levelCap.has(packet.Level1) || !s.levelCap.has(packet.Level2) {
		return nil
	}
	own := s.ownAdvertised()
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

// l2LeakSet returns the Level-2 prefixes this IS leaks down into its Level-1
// LSP, keyed by masked prefix to the total Level-2 path metric. An L1-only node
// adds its own Level-1 distance to us on top, so the metric composes the same
// way the upward export does. Leaking is off unless an operator installs a leak
// policy: pushing a whole Level-2 table into an area is a decision, not a
// default. l2 holds only algorithm-0 Level-2 routes, so there is no algorithm
// to test here.
//
// The up/down bit of the Level-2 advertisement is not tested either: RFC 5302
// §3.3 RECOMMENDS ignoring it in a Level-2 LSP and accepting the prefix
// whichever way it is set, because the bit is defined for a Level-1
// advertisement (RFC 5305 §4.1) and means nothing at Level 2 until IS-IS grows
// a third level. No loop prevention is lost with it, because the bit was never
// doing any: a leak lands in a Level-1 LSP, so a leaked prefix is neither in
// the Level-2 route table the candidates come from nor outside the "already
// has" test below. What cuts this direction's loop is that the leaked copy
// never travels back up to Level 2, where it would become a candidate again --
// l1ExportSet drops a down-marked route, per the same §4.1.
func (s *IsisServer) l2LeakSet(merged, l2 map[netip.Prefix]route) map[netip.Prefix]uint32 {
	if s.l2LeakFilter == nil || !s.levelCap.has(packet.Level1) || !s.levelCap.has(packet.Level2) {
		return nil
	}
	own := s.ownAdvertised()
	var leak map[netip.Prefix]uint32
	for p, r := range l2 {
		switch {
		case p == defaultV4 || p == defaultV6:
			continue // a default is not reachability to leak; the ATT bit carries that
		case own[p]:
			continue // regenerateNodeLSP already originates this one at both levels
		}
		// Reachability the area already has is not leaked. Another L1L2 IS
		// leaking the same prefix is not that, and must not make us stand down:
		// RFC 5305 §4.1 expects several border routers to leak the same prefix,
		// and the bit, not suppression, is what stops the loop. That needs no
		// exception here: p is reachable at Level 2, so a leaked Level-1 copy
		// of it is preference class 3 against that route's class 2 and never
		// won merged in the first place.
		//
		// "Already has" means algorithm 0, which is what a leaked prefix
		// competes with. A Flex-Algo prefix is reachable only for the nodes
		// participating in that algorithm and only over its constrained path
		// (RFC 9350 §14.2), and an area can be partitioned for a Flex-Algorithm
		// while the base algorithm still has continuity (RFC 9350 §13.1): a
		// locator the area reaches under algorithm 128 alone gives it no plain
		// path, so it must not suppress the leak that would.
		if cur, ok := merged[p]; ok && cur.level == packet.Level1 && cur.algo == 0 {
			continue
		}
		// The metric is not clamped here: it is clamped where it goes on the
		// wire (regenerateNodeLSP), as the upward export's is.
		if !s.l2LeakFilter(AdvertisedPrefix{Prefix: p, Metric: r.metric}) {
			continue
		}
		if leak == nil {
			leak = map[netip.Prefix]uint32{}
		}
		leak[p] = r.metric
	}
	return leak
}

// ownAdvertised returns the prefixes this node originates itself, at every
// level it is enabled for: the prefixes an option or AddPrefix named, the
// subnets its circuits have connected, and its SRv6 locators. Every circuit
// subnet originatedPrefixes derives is connected by definition, so these sets
// cover the advertised list without rebuilding its sorted form here. Both
// inter-level transfers subtract it, so neither re-advertises a prefix this
// node claims as its own.
func (s *IsisServer) ownAdvertised() map[netip.Prefix]bool {
	own := map[netip.Prefix]bool{}
	for p := range s.optionPrefixes {
		own[p] = true
	}
	for p := range s.connected {
		own[p] = true
	}
	for _, lc := range s.locators {
		own[lc.Prefix.Masked()] = true
	}
	return own
}

// betterRoute reports whether candidate should replace incumbent as the route
// for one prefix. The precedence, highest first:
//
//  1. Preference class (preferenceClass, RFC 5302 §3.2). The class dominates the
//     algorithm, so a class-1 Flex-Algo route displaces a class-2 algorithm-0
//     route.
//  2. Algorithm: within a class, the lower algorithm wins. Algorithm 0 and
//     each Flex-Algo normally advertise disjoint prefixes, but a shared/anycast
//     prefix claimed by two algorithms could collide; prefer plain reachability
//     (algorithm 0) over a Flex-Algo, deterministically.
//
// On a full tie the incumbent stays.
func betterRoute(candidate, incumbent route) bool {
	if c, i := preferenceClass(candidate), preferenceClass(incumbent); c != i {
		return c < i
	}
	return candidate.algo < incumbent.algo
}

// preferenceClass returns the RFC 5302 §3.2 route preference class, lowest
// preferred:
//
//  1. Level-1 intra-area.
//  2. Level-2 intra-area, together with Level-1-to-Level-2 inter-area: a
//     Level-2 LSP does not distinguish the two, and the RFC ranks them equal.
//  3. Level-2-to-Level-1 inter-area, which is what the up/down bit marks.
//
// Classes 4 to 6 are the external-metric equivalents of 1 to 3. Routes are
// computed from wide-metric reachability (TLV 135/236) and SRv6 locators alone
// (buildTopology), neither of which carries an external-metric bit, so nothing
// lands in them.
//
// Class 3 below class 2 is the half of the up/down bit that lives in the
// forwarding plane: without it, two L1L2 border routers leaking the same prefix
// into their area each prefer the other's leaked copy over their own Level-2
// path, and forward to each other until the TTL runs out.
func preferenceClass(r route) uint8 {
	switch {
	case r.level == packet.Level2:
		// The up/down bit is defined for a Level-1 advertisement (RFC 5305
		// §4.1); whatever a Level-2 LSP carries in it says nothing about class.
		return 2
	case r.down:
		return 3
	default:
		return 1
	}
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
