package server

import (
	"net/netip"
	"slices"
	"sort"
	"time"

	"github.com/takehaya/goisis/pkg/packet"
)

// maxPathMetric is the reachability ceiling (RFC 5305): a prefix or link at or
// above this is not used in SPF.
const maxPathMetric = 0xfe000000

// spfNode is a topology vertex derived from one LSP: its IS-reachability
// edges, its advertised prefixes, its overload bit, and its ATT bit.
type spfNode struct {
	id       packet.NodeID
	edges    []spfEdge
	prefixes []spfPrefix
	overload bool
	attached bool
}

type spfEdge struct {
	to     packet.NodeID
	metric uint32
}

type spfPrefix struct {
	prefix netip.Prefix
	metric uint32
	// down is the up/down bit of the advertisement (RFC 5305 §4.1 / RFC 5308
	// §2, and the SRv6 locator D-flag): the prefix was leaked down from a
	// higher level and must never travel back up.
	down bool
}

// route is one computed prefix reachability: the total metric, the algorithm it
// was computed under, and the set of first-hop neighbor system IDs (resolved to
// interfaces/gateways at FIB time).
type route struct {
	metric   uint32
	level    packet.Level
	algo     uint8
	down     bool
	nextHops []packet.SystemID
}

// buildTopology extracts the SPF graph for a level and algorithm from the LSDB.
//
// For algorithm 0 (normal SPF) every node is included and the prefixes are the
// node's IP reachability (TLV 135/236) plus its algorithm-0 SRv6 locators. For
// a Flexible Algorithm (RFC 9350) only participating real nodes are kept
// (pseudonodes are transit and always kept), and the only prefixes are SRv6
// locators advertised for that algorithm — there is no fallback to plain IP
// reachability. Constraint-based link pruning (admin groups, SRLG) needs ASLA
// link attributes and is deferred; only node participation is enforced here.
func (s *IsisServer) buildTopology(level packet.Level, algo uint8, now time.Time) map[packet.NodeID]*spfNode {
	db := s.dbs[level]
	if db == nil {
		return nil
	}
	live := func(e *lspEntry, now time.Time) bool {
		return e.purgedAt.IsZero() && e.remaining(now) != 0
	}

	// Pass 1: admit a node from its fragment-0 LSP, which carries the node's
	// header flags (overload, ATT) and, for a Flex-Algo, its SR-Algorithm
	// participation (Router Capability TLV 242, fragment 0). A node with no
	// live fragment 0 is not in the topology.
	nodes := map[packet.NodeID]*spfNode{}
	have := map[packet.NodeID]map[netip.Prefix]bool{} // plain IP reach, for prefer-prefix-reachability
	var locs []struct {
		nid packet.NodeID
		p   spfPrefix
	}
	for id, e := range db.entries {
		if id.FragmentID() != 0 || !live(e, now) {
			continue
		}
		nid := id.NodeID()
		if algo != 0 && nid.PseudonodeID() == 0 && !lspParticipatesInAlgo(e, algo) {
			continue // Flex-Algo prunes non-participating real nodes (pseudonodes are transit)
		}
		nodes[nid] = &spfNode{id: nid, overload: e.lsp.Overload, attached: e.lsp.AttDefault}
		have[nid] = map[netip.Prefix]bool{}
	}

	// Pass 2: accumulate edges and prefixes from EVERY fragment of an admitted
	// node (a large node splits its reachability across fragments 1..255).
	// Prefixes are masked to their bit length so the dedup key, the RIB key, and
	// the masked prefix the FIB installs all agree (a peer may leave host bits
	// set in a non-byte-aligned prefix; the startup sweep keys on the masked
	// kernel prefix and would otherwise reap our own routes).
	for id, e := range db.entries {
		if !live(e, now) {
			continue
		}
		nid := id.NodeID()
		n := nodes[nid]
		if n == nil {
			continue // node not admitted (no live fragment 0, or Flex-Algo-pruned)
		}
		for _, tlv := range e.lsp.TLVs {
			switch t := tlv.(type) {
			case *packet.ExtendedISReachabilityTLV:
				for _, nb := range t.Neighbors {
					if nb.Metric < maxPathMetric {
						n.edges = append(n.edges, spfEdge{to: nb.NeighborID, metric: nb.Metric})
					}
				}
			case *packet.ExtendedIPReachabilityTLV:
				if algo != 0 {
					continue // plain IP reachability belongs to algorithm 0 only
				}
				for _, p := range t.Prefixes {
					if p.Metric < maxPathMetric {
						pfx := p.Prefix.Masked()
						n.prefixes = append(n.prefixes, spfPrefix{prefix: pfx, metric: p.Metric, down: p.Down})
						have[nid][pfx] = true
					}
				}
			case *packet.IPv6ReachabilityTLV:
				if algo != 0 {
					continue
				}
				for _, p := range t.Prefixes {
					if p.Metric < maxPathMetric {
						pfx := p.Prefix.Masked()
						n.prefixes = append(n.prefixes, spfPrefix{prefix: pfx, metric: p.Metric, down: p.Down})
						have[nid][pfx] = true
					}
				}
			case *packet.SRv6LocatorTLV:
				for _, loc := range t.Locators {
					if loc.Algorithm == algo && loc.Metric < maxPathMetric {
						locs = append(locs, struct {
							nid packet.NodeID
							p   spfPrefix
						}{nid, spfPrefix{prefix: loc.Locator.Masked(), metric: loc.Metric, down: loc.Flags&0x80 != 0}}) // D-flag (RFC 9352 §7.1)
					}
				}
			}
		}
	}

	// Pass 3: ISO 10589 7.2.7 computes the paths leaving this system from the
	// adjacency database. Our own LSP — and any pseudonode LSP we originate as
	// DIS — is only the wire copy of it, and its regeneration is deliberately
	// held back by minLSPGenInterval, so for up to that long after an adjacency
	// goes down our copy still lists the dead neighbor. Believing it makes
	// Dijkstra pick the dead path; resolveNextHops then resolves nothing and the
	// prefix is withdrawn instead of rerouted over a live alternate.
	for id, n := range nodes {
		if id.SystemID() != s.systemID {
			continue // only the LSPs we originate ourselves
		}
		n.edges = slices.DeleteFunc(n.edges, func(e spfEdge) bool { return !s.edgeHasAdjacency(level, e.to) })
	}

	// Add SRv6 locator prefixes a node didn't also advertise as plain IP
	// reachability (prefer-prefix-reachability rule, RFC 9352).
	for _, l := range locs {
		if !have[l.nid][l.p.prefix] {
			nodes[l.nid].prefixes = append(nodes[l.nid].prefixes, l.p)
		}
	}
	return nodes
}

// edgeHasAdjacency reports whether an IS-reachability edge out of an LSP we
// originate ourselves is still backed by a live adjacency: a real neighbor
// needs an Up adjacency at this level, a LAN pseudonode needs the circuit that
// elected it to still have one (which member is DIS is a separate election),
// and the edge a pseudonode LSP has back to us is always live.
func (s *IsisServer) edgeHasAdjacency(level packet.Level, to packet.NodeID) bool {
	if to.PseudonodeID() != 0 {
		for _, c := range s.circuits {
			if !c.cfg.P2P && c.dis[level] == to && c.upAdjacencyCount(level) > 0 {
				return true
			}
		}
		return false
	}
	if to.SystemID() == s.systemID {
		return true
	}
	for _, c := range s.circuits {
		if c.cfg.P2P {
			if a := c.p2pAdj; a != nil && a.state == AdjUp && a.levels.has(level) && a.systemID == to.SystemID() {
				return true
			}
			continue
		}
		if a := c.adjs[level][to.SystemID()]; a != nil && a.state == AdjUp {
			return true
		}
	}
	return false
}

// lspParticipatesInAlgo reports whether an LSP advertises the given algorithm
// in its SR-Algorithm sub-TLV (Router Capability TLV 242).
func lspParticipatesInAlgo(e *lspEntry, algo uint8) bool {
	for _, tlv := range e.lsp.TLVs {
		rc, ok := tlv.(*packet.RouterCapabilityTLV)
		if !ok {
			continue
		}
		for _, sub := range rc.SubTLVs {
			sa, ok := sub.(*packet.SRAlgorithmSubTLV)
			if !ok {
				continue
			}
			for _, a := range sa.Algorithms {
				if a == algo {
					return true
				}
			}
		}
	}
	return false
}

// tentEntry is a node under consideration in the Dijkstra TENT set.
type tentEntry struct {
	id       packet.NodeID
	distance uint32
	// firstHops are the directly-adjacent neighbor system IDs on the shortest
	// path(s) to this node (empty for self and for pseudonodes reached
	// directly from self before a real hop).
	firstHops map[packet.SystemID]bool
}

// computeSPF runs a Dijkstra shortest-path-first over the level's topology for
// an algorithm and returns prefix routes keyed by prefix. The two-way
// connectivity check, the overload bit (no transit through an overloaded node),
// and ECMP are honored.
func (s *IsisServer) computeSPF(level packet.Level, algo uint8, now time.Time) map[netip.Prefix]route {
	// The wall clock, not s.clock: this is a stopwatch over the computation
	// itself, and what it reports has to stay the real cost of the run even
	// when the caller drives the server's own time (see Clock). now, which
	// the topology is read against, is the server's.
	t0 := time.Now()
	defer func() { s.metrics.SPFRun(levelLabel(level), time.Since(t0)) }()
	nodes := s.buildTopology(level, algo, now)
	self := nodeID(s.systemID, 0)
	if nodes[self] == nil {
		return nil
	}

	dist := map[packet.NodeID]uint32{}
	hops := map[packet.NodeID]map[packet.SystemID]bool{}
	done := map[packet.NodeID]bool{}
	tent := map[packet.NodeID]*tentEntry{
		self: {id: self, distance: 0, firstHops: map[packet.SystemID]bool{}},
	}

	for len(tent) > 0 {
		cur := popMin(tent)
		done[cur.id] = true
		dist[cur.id] = cur.distance
		hops[cur.id] = cur.firstHops

		node := nodes[cur.id]
		if node == nil {
			continue
		}
		// Do not transit an overloaded node (its own prefixes stay reachable,
		// but we don't route through it). Self is never "overloaded" for our
		// own relaxation.
		if node.overload && cur.id != self {
			continue
		}
		for _, e := range node.edges {
			if done[e.to] {
				continue
			}
			if !twoWay(nodes, cur.id, e.to) {
				continue // require bidirectional connectivity
			}
			nd := cur.distance + e.metric
			if nd >= maxPathMetric {
				continue
			}
			fh := firstHopsFor(cur, e.to)
			relax(tent, e.to, nd, fh)
		}
	}

	// Collect prefix routes from every reachable node.
	routes := map[netip.Prefix]route{}
	for id := range done {
		if id == self {
			continue // our own prefixes are directly connected
		}
		node := nodes[id]
		if node == nil {
			continue
		}
		nh := sortedHops(hops[id])
		if len(nh) == 0 {
			continue // no resolvable first hop (e.g. only self)
		}
		base := dist[id]
		for _, p := range node.prefixes {
			// Add in 64-bit: a near-ceiling base plus a large (legal 32-bit)
			// prefix metric would otherwise wrap below maxPathMetric and
			// install a bogus short route.
			sum := uint64(base) + uint64(p.metric)
			if sum >= maxPathMetric {
				continue
			}
			addRoute(routes, p.prefix, route{metric: uint32(sum), level: level, algo: algo, down: p.down, nextHops: nh})
		}
	}

	// RFC 1195 §3.2 / ISO 10589 7.2.9.2: a Level-1-only IS has no topology
	// outside its area, so everything else goes toward the nearest reachable
	// IS whose L1 LSP has the ATT bit set. An L1L2 IS sets that bit itself and
	// reaches other areas through its own L2 SPF, so it must not do this.
	if level == packet.Level1 && algo == 0 && !s.levelCap.has(packet.Level2) {
		addAttachedDefault(routes, nodes, done, dist, hops)
	}
	return routes
}

// defaultV4 and defaultV6 are the ATT-derived default routes, one per address
// family. resolveNextHops picks a gateway of the prefix's family, so an
// attached IS reachable over IPv4 only simply yields no IPv6 default.
var (
	defaultV4 = netip.MustParsePrefix("0.0.0.0/0")
	defaultV6 = netip.MustParsePrefix("::/0")
)

// addAttachedDefault adds a default route toward the nearest attached IS,
// with every equidistant attached IS contributing its first hops (ECMP).
//
// The synthesized route carries the down bit, which is what puts it in RFC 5302
// §3.2 preference class 3 — below every advertised route. That is deliberate
// and not a hack: an attached IS "is effectively injecting a default route
// without metric information into the L1 area", and the computation this node
// performs on it is "similarly suboptimal" (RFC 5302 §1.1), while RFC 1195
// §3.10.1 scopes the fallback to destinations "not reachable within an area" at
// all. Domain-wide prefix distribution exists to replace the heuristic with
// metric-bearing reachability, so the heuristic must never outrank it. The bit
// also describes the route honestly — see route.down: this is reachability that
// came down from Level 2 and must never travel back up.
func addAttachedDefault(routes map[netip.Prefix]route, nodes map[packet.NodeID]*spfNode,
	done map[packet.NodeID]bool, dist map[packet.NodeID]uint32, hops map[packet.NodeID]map[packet.SystemID]bool,
) {
	var best uint32
	var nh map[packet.SystemID]bool
	for id := range done {
		n := nodes[id]
		// A pseudonode has no ATT bit of its own; an overloaded IS asks not to
		// carry transit traffic, which is exactly what an exit would do.
		if n == nil || id.PseudonodeID() != 0 || !n.attached || n.overload {
			continue
		}
		if len(hops[id]) == 0 {
			continue // self, or no resolvable first hop
		}
		switch {
		case nh == nil || dist[id] < best:
			best, nh = dist[id], cloneHops(hops[id])
		case dist[id] == best:
			for h := range hops[id] {
				nh[h] = true
			}
		}
	}
	if nh == nil {
		return
	}
	for _, p := range []netip.Prefix{defaultV4, defaultV6} {
		addRoute(routes, p, route{metric: best, level: packet.Level1, algo: 0, down: true, nextHops: sortedHops(nh)})
	}
}

// addRoute merges one computed route for a prefix into the route set: the
// better preference class wins at any metric (RFC 5302 §3.2, which ranks class
// before metric), within a class a lower total metric wins outright, and an
// equal one merges the first-hop sets (ECMP).
//
// So the route's up/down bit is the WINNING advertisement's own, and every
// reader of it — l1ExportSet, l2LeakSet, preferenceClass — wants exactly that.
// Merging it stickily ("down when any contributing advertisement was") would be
// the conservative answer to "a leaked copy re-originated without the bit is
// indistinguishable from independent reachability", but it costs far more than
// it buys: a prefix the area genuinely owns that any border also leaks would
// stop being exported upward, black-holing it for the rest of the domain, and
// since a border only leaks what it cannot see inside the area, two borders
// latch each other into that state with no way out.
func addRoute(routes map[netip.Prefix]route, p netip.Prefix, r route) {
	cur, ok := routes[p]
	if !ok {
		routes[p] = r
		return
	}
	switch rc, cc := preferenceClass(r), preferenceClass(cur); {
	case rc != cc:
		if rc < cc {
			cur = r
		}
	case r.metric < cur.metric:
		cur = r
	case r.metric == cur.metric:
		cur.nextHops = mergeHops(cur.nextHops, r.nextHops)
	}
	routes[p] = cur
}

// firstHopsFor returns the first-hop set for neighbor `to` reached from cur.
// A pseudonode is transparent: the real first hop is the member behind it.
func firstHopsFor(cur *tentEntry, to packet.NodeID) map[packet.SystemID]bool {
	if len(cur.firstHops) > 0 {
		// Already past the first real hop: inherit.
		return cur.firstHops
	}
	// cur is self or a pseudonode directly attached to self.
	if to.PseudonodeID() == 0 {
		// `to` is the first real router on the path.
		return map[packet.SystemID]bool{to.SystemID(): true}
	}
	// `to` is a pseudonode: still no real hop yet.
	return map[packet.SystemID]bool{}
}

// twoWay reports whether both a->b and b->a edges exist in the topology.
func twoWay(nodes map[packet.NodeID]*spfNode, a, b packet.NodeID) bool {
	nb := nodes[b]
	if nb == nil {
		return false
	}
	for _, e := range nb.edges {
		if e.to == a {
			return true
		}
	}
	return false
}

// relax updates the tentative distance/first-hops for a node.
func relax(tent map[packet.NodeID]*tentEntry, id packet.NodeID, d uint32, fh map[packet.SystemID]bool) {
	e, ok := tent[id]
	if !ok {
		tent[id] = &tentEntry{id: id, distance: d, firstHops: cloneHops(fh)}
		return
	}
	switch {
	case d < e.distance:
		e.distance = d
		e.firstHops = cloneHops(fh)
	case d == e.distance:
		for h := range fh {
			e.firstHops[h] = true
		}
	}
}

// popMin removes and returns the minimum-distance entry from tent.
//
// This is a linear scan (O(V) per pop, O(V^2) overall), chosen deliberately:
// for a single-area L2 MVP the vertex count is small and the constant factors
// beat a heap. Swap in a priority queue only if profiling on large areas shows
// SPF as a bottleneck.
func popMin(tent map[packet.NodeID]*tentEntry) *tentEntry {
	var best *tentEntry
	for _, e := range tent {
		if best == nil || e.distance < best.distance {
			best = e
		}
	}
	delete(tent, best.id)
	return best
}

func cloneHops(h map[packet.SystemID]bool) map[packet.SystemID]bool {
	out := make(map[packet.SystemID]bool, len(h))
	for k := range h {
		out[k] = true
	}
	return out
}

func sortedHops(h map[packet.SystemID]bool) []packet.SystemID {
	out := make([]packet.SystemID, 0, len(h))
	for k := range h {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

func mergeHops(a []packet.SystemID, b []packet.SystemID) []packet.SystemID {
	set := map[packet.SystemID]bool{}
	for _, x := range a {
		set[x] = true
	}
	for _, x := range b {
		set[x] = true
	}
	return sortedHops(set)
}
