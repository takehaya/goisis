package server

import (
	"net/netip"
	"sort"
	"time"

	"github.com/takehaya/goisis/pkg/packet"
)

// maxPathMetric is the reachability ceiling (RFC 5305): a prefix or link at or
// above this is not used in SPF.
const maxPathMetric = 0xfe000000

// spfNode is a topology vertex derived from one LSP: its IS-reachability
// edges, its advertised prefixes, and its overload bit.
type spfNode struct {
	id       packet.NodeID
	edges    []spfEdge
	prefixes []spfPrefix
	overload bool
}

type spfEdge struct {
	to     packet.NodeID
	metric uint32
}

type spfPrefix struct {
	prefix netip.Prefix
	metric uint32
}

// route is one computed prefix reachability: the total metric and the set of
// first-hop neighbor system IDs (resolved to interfaces/gateways at FIB time).
type route struct {
	metric   uint32
	level    packet.Level
	nextHops []packet.SystemID
}

// buildTopology extracts the SPF graph for a level from the LSDB.
func (s *IsisServer) buildTopology(level packet.Level, now time.Time) map[packet.NodeID]*spfNode {
	db := s.dbs[level]
	if db == nil {
		return nil
	}
	nodes := map[packet.NodeID]*spfNode{}
	for id, e := range db.entries {
		if !e.purgedAt.IsZero() || e.remaining(now) == 0 {
			continue // purged or expired
		}
		if id.FragmentID() != 0 {
			continue // only fragment 0 carries the node's edges/flags (M4)
		}
		n := &spfNode{id: id.NodeID(), overload: e.lsp.Overload}
		// have tracks prefixes advertised as plain IP reachability (TLV
		// 135/236) so an SRv6 locator (TLV 27) for the same prefix is not
		// added twice; prefix reachability wins (RFC 9352). Prefixes are
		// masked to their bit length so the dedup key, the RIB key, and the
		// masked prefix the FIB installs all agree (a peer may leave host bits
		// set in a non-byte-aligned prefix; the startup sweep keys on the
		// masked kernel prefix and would otherwise reap our own routes).
		have := map[netip.Prefix]bool{}
		var locPrefixes []spfPrefix
		for _, tlv := range e.lsp.TLVs {
			switch t := tlv.(type) {
			case *packet.ExtendedISReachabilityTLV:
				for _, nb := range t.Neighbors {
					if nb.Metric < maxPathMetric {
						n.edges = append(n.edges, spfEdge{to: nb.NeighborID, metric: nb.Metric})
					}
				}
			case *packet.ExtendedIPReachabilityTLV:
				for _, p := range t.Prefixes {
					if p.Metric < maxPathMetric {
						pfx := p.Prefix.Masked()
						n.prefixes = append(n.prefixes, spfPrefix{prefix: pfx, metric: p.Metric})
						have[pfx] = true
					}
				}
			case *packet.IPv6ReachabilityTLV:
				for _, p := range t.Prefixes {
					if p.Metric < maxPathMetric {
						pfx := p.Prefix.Masked()
						n.prefixes = append(n.prefixes, spfPrefix{prefix: pfx, metric: p.Metric})
						have[pfx] = true
					}
				}
			case *packet.SRv6LocatorTLV:
				for _, loc := range t.Locators {
					if loc.Metric < maxPathMetric {
						locPrefixes = append(locPrefixes, spfPrefix{prefix: loc.Locator.Masked(), metric: loc.Metric})
					}
				}
			}
		}
		// Add SRv6 locator prefixes the node didn't also advertise as plain IP
		// reachability (prefer-prefix-reachability rule).
		for _, lp := range locPrefixes {
			if !have[lp.prefix] {
				n.prefixes = append(n.prefixes, lp)
			}
		}
		nodes[id.NodeID()] = n
	}
	return nodes
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

// computeSPF runs a Dijkstra shortest-path-first over the level's topology and
// returns prefix routes keyed by prefix. The two-way connectivity check, the
// overload bit (no transit through an overloaded node), and ECMP are honored.
func (s *IsisServer) computeSPF(level packet.Level, now time.Time) map[netip.Prefix]route {
	nodes := s.buildTopology(level, now)
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
			total := uint32(sum)
			cur, ok := routes[p.prefix]
			if !ok || total < cur.metric {
				routes[p.prefix] = route{metric: total, level: level, nextHops: nh}
			} else if total == cur.metric {
				routes[p.prefix] = route{metric: total, level: level, nextHops: mergeHops(cur.nextHops, nh)}
			}
		}
	}
	return routes
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
