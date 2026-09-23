package server

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/takehaya/goisis/pkg/datalink"
	"github.com/takehaya/goisis/pkg/packet"
)

// spfTestServer returns a server with one L2 circuit, suitable for installing
// a synthetic LSDB and running computeSPF.
func spfTestServer(t *testing.T, self packet.SystemID) *IsisServer {
	t.Helper()
	tr := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xff}, 1500)
	return mustServer(t,
		WithSystemID(self),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(CircuitConfig{Name: "c", Transport: tr, Level2: true, Padding: ptrFalse()}),
	)
}

type edge struct {
	to     packet.NodeID
	metric uint32
}

// installNode inserts a synthetic LSP into the L2 LSDB.
func installNode(s *IsisServer, id packet.NodeID, overload bool, edges []edge, prefixes []packet.ExtendedIPReachEntry) {
	var reach []packet.ExtendedISReachEntry
	for _, e := range edges {
		reach = append(reach, packet.ExtendedISReachEntry{NeighborID: e.to, Metric: e.metric})
	}
	tlvs := []packet.TLV{&packet.ExtendedISReachabilityTLV{Neighbors: reach}}
	if len(prefixes) > 0 {
		tlvs = append(tlvs, &packet.ExtendedIPReachabilityTLV{Prefixes: prefixes})
	}
	seedImpliedAdjacencies(s, packet.Level2, id, tlvs)
	lid := packet.LSPID(append(append([]byte{}, id[:]...), 0)) //nolint:gocritic // build 8-byte LSP ID
	s.dbs[packet.Level2].entries[lid] = &lspEntry{
		lsp:      &packet.LSP{Level: packet.Level2, LSPID: lid, SequenceNumber: 1, Overload: overload, TLVs: tlvs},
		inserted: time.Now(),
		lifetime: 1000,
	}
}

func nid(last byte, pseudonode uint8) packet.NodeID {
	return nodeID(packet.SystemID{0, 0, 0, 0, 0, last}, pseudonode)
}

func v4(p string, metric uint32) packet.ExtendedIPReachEntry {
	return packet.ExtendedIPReachEntry{Prefix: netip.MustParsePrefix(p), Metric: metric}
}

func TestSPFLANPseudonode(t *testing.T) {
	// A (self, .1) is DIS; pseudonode A.7 connects A and B (.2). B advertises
	// 10.2.0.0/24. Expect a route via first-hop B.
	self := packet.SystemID{0, 0, 0, 0, 0, 1}
	s := spfTestServer(t, self)
	pn := nid(1, 7)
	installNode(s, nid(1, 0), false, []edge{{pn, 10}}, nil)
	installNode(s, pn, false, []edge{{nid(1, 0), 0}, {nid(2, 0), 0}}, nil)
	installNode(s, nid(2, 0), false, []edge{{pn, 10}}, []packet.ExtendedIPReachEntry{v4("10.2.0.0/24", 5)})

	routes := s.computeSPF(packet.Level2, 0, time.Now())
	r, ok := routes[netip.MustParsePrefix("10.2.0.0/24")]
	if !ok {
		t.Fatalf("no route to 10.2.0.0/24; routes=%v", routes)
	}
	if r.metric != 15 {
		t.Errorf("metric = %d, want 15", r.metric)
	}
	if len(r.nextHops) != 1 || r.nextHops[0] != (packet.SystemID{0, 0, 0, 0, 0, 2}) {
		t.Errorf("nextHops = %v, want [..02]", r.nextHops)
	}
}

func TestSPFP2PChain(t *testing.T) {
	// A(.1) - B(.2) - C(.3), p2p. C advertises 10.3.0.0/24 at metric 5.
	self := packet.SystemID{0, 0, 0, 0, 0, 1}
	s := spfTestServer(t, self)
	installNode(s, nid(1, 0), false, []edge{{nid(2, 0), 10}}, nil)
	installNode(s, nid(2, 0), false, []edge{{nid(1, 0), 10}, {nid(3, 0), 10}}, nil)
	installNode(s, nid(3, 0), false, []edge{{nid(2, 0), 10}}, []packet.ExtendedIPReachEntry{v4("10.3.0.0/24", 5)})

	routes := s.computeSPF(packet.Level2, 0, time.Now())
	r, ok := routes[netip.MustParsePrefix("10.3.0.0/24")]
	if !ok {
		t.Fatal("no route to 10.3.0.0/24")
	}
	if r.metric != 25 { // 10 (A->B) + 10 (B->C) + 5 (prefix)
		t.Errorf("metric = %d, want 25", r.metric)
	}
	if len(r.nextHops) != 1 || r.nextHops[0] != (packet.SystemID{0, 0, 0, 0, 0, 2}) {
		t.Errorf("nextHops = %v, want first-hop B(..02)", r.nextHops)
	}
}

func TestSPFTwoWayCheck(t *testing.T) {
	// A(.1) -> B(.2) but B does NOT list A: B must be unreachable.
	self := packet.SystemID{0, 0, 0, 0, 0, 1}
	s := spfTestServer(t, self)
	installNode(s, nid(1, 0), false, []edge{{nid(2, 0), 10}}, nil)
	installNode(s, nid(2, 0), false, nil, []packet.ExtendedIPReachEntry{v4("10.2.0.0/24", 5)})

	routes := s.computeSPF(packet.Level2, 0, time.Now())
	if _, ok := routes[netip.MustParsePrefix("10.2.0.0/24")]; ok {
		t.Error("route installed despite failing the two-way check")
	}
}

func TestSPFECMP(t *testing.T) {
	// A(.1) reaches C(.3) via B1(.2) and B2(.4) at equal cost.
	self := packet.SystemID{0, 0, 0, 0, 0, 1}
	s := spfTestServer(t, self)
	installNode(s, nid(1, 0), false, []edge{{nid(2, 0), 10}, {nid(4, 0), 10}}, nil)
	installNode(s, nid(2, 0), false, []edge{{nid(1, 0), 10}, {nid(3, 0), 10}}, nil)
	installNode(s, nid(4, 0), false, []edge{{nid(1, 0), 10}, {nid(3, 0), 10}}, nil)
	installNode(s, nid(3, 0), false, []edge{{nid(2, 0), 10}, {nid(4, 0), 10}}, []packet.ExtendedIPReachEntry{v4("10.3.0.0/24", 0)})

	routes := s.computeSPF(packet.Level2, 0, time.Now())
	r, ok := routes[netip.MustParsePrefix("10.3.0.0/24")]
	if !ok {
		t.Fatal("no route to 10.3.0.0/24")
	}
	if len(r.nextHops) != 2 {
		t.Errorf("nextHops = %v, want 2 ECMP first-hops", r.nextHops)
	}
}

func TestSPFAnycastPrefixMergesNextHops(t *testing.T) {
	// B(.2) and C(.3) both advertise the SAME prefix (anycast) at equal total
	// cost via disjoint first hops from A(.1): the route must carry the sorted
	// union of both next-hop sets, not just whichever advertiser was folded in
	// first (this is prefix-level ECMP across routers, distinct from node-level
	// ECMP toward one router).
	self := packet.SystemID{0, 0, 0, 0, 0, 1}
	s := spfTestServer(t, self)
	anycast := v4("10.7.0.0/24", 5)
	installNode(s, nid(1, 0), false, []edge{{nid(2, 0), 10}, {nid(3, 0), 10}}, nil)
	installNode(s, nid(2, 0), false, []edge{{nid(1, 0), 10}}, []packet.ExtendedIPReachEntry{anycast})
	installNode(s, nid(3, 0), false, []edge{{nid(1, 0), 10}}, []packet.ExtendedIPReachEntry{anycast})

	routes := s.computeSPF(packet.Level2, 0, time.Now())
	r, ok := routes[netip.MustParsePrefix("10.7.0.0/24")]
	if !ok {
		t.Fatal("no route to anycast prefix 10.7.0.0/24")
	}
	if r.metric != 15 {
		t.Errorf("metric = %d, want 15", r.metric)
	}
	want := []packet.SystemID{{0, 0, 0, 0, 0, 2}, {0, 0, 0, 0, 0, 3}}
	if len(r.nextHops) != 2 || r.nextHops[0] != want[0] || r.nextHops[1] != want[1] {
		t.Errorf("nextHops = %v, want sorted union [..02 ..03]", r.nextHops)
	}
}

func TestSPFAnycastPrefixPrefersCheaperAdvertiser(t *testing.T) {
	// Same anycast topology, but C(.3) advertises the prefix at a higher total
	// cost: only the cheaper advertiser's first hop is used, no merge.
	self := packet.SystemID{0, 0, 0, 0, 0, 1}
	s := spfTestServer(t, self)
	installNode(s, nid(1, 0), false, []edge{{nid(2, 0), 10}, {nid(3, 0), 10}}, nil)
	installNode(s, nid(2, 0), false, []edge{{nid(1, 0), 10}}, []packet.ExtendedIPReachEntry{v4("10.7.0.0/24", 5)})
	installNode(s, nid(3, 0), false, []edge{{nid(1, 0), 10}}, []packet.ExtendedIPReachEntry{v4("10.7.0.0/24", 50)})

	routes := s.computeSPF(packet.Level2, 0, time.Now())
	r, ok := routes[netip.MustParsePrefix("10.7.0.0/24")]
	if !ok {
		t.Fatal("no route to anycast prefix 10.7.0.0/24")
	}
	if r.metric != 15 {
		t.Errorf("metric = %d, want 15 (cheaper advertiser)", r.metric)
	}
	if len(r.nextHops) != 1 || r.nextHops[0] != (packet.SystemID{0, 0, 0, 0, 0, 2}) {
		t.Errorf("nextHops = %v, want only the cheaper advertiser's hop [..02]", r.nextHops)
	}
}

func TestSPFNoMetricOverflow(t *testing.T) {
	// A long chain of near-max edges pushes the accumulated distance close to
	// the reachability ceiling; a large (legal 32-bit) prefix metric must not
	// wrap below the ceiling and install a bogus short route.
	self := packet.SystemID{0, 0, 0, 0, 0, 1}
	s := spfTestServer(t, self)
	// Two-hop chain A(.1) -> B(.2) -> C(.3) with max 24-bit edges.
	installNode(s, nid(1, 0), false, []edge{{nid(2, 0), 0xffffff}}, nil)
	installNode(s, nid(2, 0), false, []edge{{nid(1, 0), 0xffffff}, {nid(3, 0), 0xffffff}}, nil)
	// C advertises a prefix at a metric that, added to the ~0x1fffffe base,
	// would wrap a uint32 below maxPathMetric if not added in 64 bits.
	installNode(s, nid(3, 0), false, []edge{{nid(2, 0), 0xffffff}},
		[]packet.ExtendedIPReachEntry{{Prefix: netip.MustParsePrefix("10.99.0.0/24"), Metric: 0xfdffffff}})

	routes := s.computeSPF(packet.Level2, 0, time.Now())
	if _, ok := routes[netip.MustParsePrefix("10.99.0.0/24")]; ok {
		t.Error("prefix above the reachability ceiling should be unreachable (metric overflow)")
	}
}

func TestSPFOverloadNoTransit(t *testing.T) {
	// A(.1) - B(.2, overload) - C(.3). B's prefix is reachable; C is not
	// (no transit through an overloaded node).
	self := packet.SystemID{0, 0, 0, 0, 0, 1}
	s := spfTestServer(t, self)
	installNode(s, nid(1, 0), false, []edge{{nid(2, 0), 10}}, nil)
	installNode(s, nid(2, 0), true, []edge{{nid(1, 0), 10}, {nid(3, 0), 10}}, []packet.ExtendedIPReachEntry{v4("10.2.0.0/24", 5)})
	installNode(s, nid(3, 0), false, []edge{{nid(2, 0), 10}}, []packet.ExtendedIPReachEntry{v4("10.3.0.0/24", 5)})

	routes := s.computeSPF(packet.Level2, 0, time.Now())
	if _, ok := routes[netip.MustParsePrefix("10.2.0.0/24")]; !ok {
		t.Error("overloaded node's own prefix should remain reachable")
	}
	if _, ok := routes[netip.MustParsePrefix("10.3.0.0/24")]; ok {
		t.Error("transit through an overloaded node should be avoided")
	}
}

// attServer returns an IS whose single circuit is Level 1, and Level 2 too
// when l1l2 is set: levelCap is what tells computeSPF whether we are the
// L1-only IS that consumes the ATT bit.
func attServer(t *testing.T, l1l2 bool) *IsisServer {
	t.Helper()
	tr := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xff}, 1500)
	return mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(CircuitConfig{Name: "c", Transport: tr, Level1: true, Level2: l1l2, Padding: ptrFalse()}),
	)
}

// isReachMetric is isReach for a single neighbor at an explicit metric.
func isReachMetric(nb packet.SystemID, metric uint32) packet.TLV {
	return &packet.ExtendedISReachabilityTLV{Neighbors: []packet.ExtendedISReachEntry{{NeighborID: nodeID(nb, 0), Metric: metric}}}
}

// injectL1 installs a synthetic L1 fragment-0 LSP carrying the header flags.
func injectL1(s *IsisServer, id packet.SystemID, att, overload bool, tlvs []packet.TLV, now time.Time) {
	injectLSPAt(s, packet.Level1, id, tlvs, now)
	lsp := s.dbs[packet.Level1].entries[lspID(id, 0)].lsp
	lsp.AttDefault = att
	lsp.Overload = overload
}

// attDefaults returns the two default routes, failing if either is missing.
func attDefaults(t *testing.T, routes map[netip.Prefix]route) (v4, v6 route) {
	t.Helper()
	for _, p := range []netip.Prefix{defaultV4, defaultV6} {
		if _, ok := routes[p]; !ok {
			t.Fatalf("no default route for %s; routes=%v", p, routes)
		}
	}
	return routes[defaultV4], routes[defaultV6]
}

// A Level-1-only IS installs a default route toward the nearest IS that set the
// ATT bit: B at metric 10, not C at 20 (RFC 1195 §3.2).
func TestL1OnlyNodeInstallsDefaultViaNearestAttachedIS(t *testing.T) {
	s := attServer(t, false)
	now := time.Now()
	self := packet.SystemID{0, 0, 0, 0, 0, 1}
	b := packet.SystemID{0, 0, 0, 0, 0, 2}
	c := packet.SystemID{0, 0, 0, 0, 0, 3}

	injectL1(s, self, false, false, []packet.TLV{isReach(b)}, now)
	injectL1(s, b, true, false, []packet.TLV{isReach(self, c)}, now)
	injectL1(s, c, true, false, []packet.TLV{isReach(b)}, now)

	v4r, v6r := attDefaults(t, s.computeSPF(packet.Level1, 0, now))
	for _, r := range []route{v4r, v6r} {
		if r.metric != 10 {
			t.Errorf("metric = %d, want 10 (distance to the nearest attached IS)", r.metric)
		}
		if len(r.nextHops) != 1 || r.nextHops[0] != b {
			t.Errorf("nextHops = %v, want [..02]", r.nextHops)
		}
		if r.level != packet.Level1 || r.algo != 0 {
			t.Errorf("route = (level %v, algo %d), want (Level1, 0)", r.level, r.algo)
		}
	}
}

// The ATT bit of an overloaded IS is ignored: an IS that asks not to carry
// transit traffic is not an exit either, so the farther C wins.
func TestAttachedISWithOverloadBitIsNotUsedAsExit(t *testing.T) {
	s := attServer(t, false)
	now := time.Now()
	self := packet.SystemID{0, 0, 0, 0, 0, 1}
	b := packet.SystemID{0, 0, 0, 0, 0, 2}
	c := packet.SystemID{0, 0, 0, 0, 0, 3}

	injectL1(s, self, false, false, []packet.TLV{isReach(b, c)}, now)
	injectL1(s, b, true, true, []packet.TLV{isReach(self)}, now)
	injectL1(s, c, true, false, []packet.TLV{isReach(self)}, now)

	v4r, _ := attDefaults(t, s.computeSPF(packet.Level1, 0, now))
	if len(v4r.nextHops) != 1 || v4r.nextHops[0] != c {
		t.Errorf("nextHops = %v, want [..03] (the overloaded B is not an exit)", v4r.nextHops)
	}
}

// An L1L2 IS is itself attached and reaches other areas through its own L2
// SPF, so it must not follow someone else's ATT bit.
func TestL1L2NodeDoesNotInstallDefaultFromATT(t *testing.T) {
	s := attServer(t, true)
	now := time.Now()
	self := packet.SystemID{0, 0, 0, 0, 0, 1}
	b := packet.SystemID{0, 0, 0, 0, 0, 2}

	injectL1(s, self, true, false, []packet.TLV{isReach(b)}, now)
	injectL1(s, b, true, false, []packet.TLV{isReach(self)}, now)

	routes := s.computeSPF(packet.Level1, 0, now)
	if r, ok := routes[defaultV4]; ok {
		t.Errorf("L1L2 IS installed an ATT default route %v", r)
	}
	if r, ok := routes[defaultV6]; ok {
		t.Errorf("L1L2 IS installed an ATT default route %v", r)
	}
}

// An explicitly advertised default competes with the ATT default under the
// ordinary prefix rule: a lower metric wins outright, an equal one merges.
func TestExplicitDefaultWithLowerMetricBeatsATTDefault(t *testing.T) {
	self := packet.SystemID{0, 0, 0, 0, 0, 1}
	b := packet.SystemID{0, 0, 0, 0, 0, 2}
	d := packet.SystemID{0, 0, 0, 0, 0, 4}

	// B is attached at distance 10; D is dLink away and advertises 0.0.0.0/0
	// at metric 0, so the explicit default's total metric is dLink.
	defaultVia := func(t *testing.T, dLink uint32) route {
		t.Helper()
		s := attServer(t, false)
		now := time.Now()
		injectL1(s, self, false, false, []packet.TLV{isReach(b), isReachMetric(d, dLink)}, now)
		injectL1(s, b, true, false, []packet.TLV{isReach(self)}, now)
		injectL1(s, d, false, false, []packet.TLV{isReach(self),
			&packet.ExtendedIPReachabilityTLV{Prefixes: []packet.ExtendedIPReachEntry{v4("0.0.0.0/0", 0)}}}, now)
		routes := s.computeSPF(packet.Level1, 0, now)
		r, ok := routes[defaultV4]
		if !ok {
			t.Fatalf("no default route; routes=%v", routes)
		}
		return r
	}

	r := defaultVia(t, 5)
	if r.metric != 5 {
		t.Errorf("metric = %d, want 5 (the cheaper explicit default)", r.metric)
	}
	if len(r.nextHops) != 1 || r.nextHops[0] != d {
		t.Errorf("nextHops = %v, want [..04] only", r.nextHops)
	}

	r = defaultVia(t, 10)
	if r.metric != 10 {
		t.Errorf("metric = %d, want 10", r.metric)
	}
	if len(r.nextHops) != 2 || r.nextHops[0] != b || r.nextHops[1] != d {
		t.Errorf("nextHops = %v, want the merged [..02 ..04] at equal metric", r.nextHops)
	}
}

// Equidistant attached ISs all contribute their first hops to the default.
func TestEquidistantAttachedISsGiveECMPDefault(t *testing.T) {
	s := attServer(t, false)
	now := time.Now()
	self := packet.SystemID{0, 0, 0, 0, 0, 1}
	b := packet.SystemID{0, 0, 0, 0, 0, 2}
	c := packet.SystemID{0, 0, 0, 0, 0, 3}

	injectL1(s, self, false, false, []packet.TLV{isReach(b, c)}, now)
	injectL1(s, b, true, false, []packet.TLV{isReach(self)}, now)
	injectL1(s, c, true, false, []packet.TLV{isReach(self)}, now)

	v4r, v6r := attDefaults(t, s.computeSPF(packet.Level1, 0, now))
	for _, r := range []route{v4r, v6r} {
		if r.metric != 10 {
			t.Errorf("metric = %d, want 10", r.metric)
		}
		if len(r.nextHops) != 2 || r.nextHops[0] != b || r.nextHops[1] != c {
			t.Errorf("nextHops = %v, want [..02 ..03]", r.nextHops)
		}
	}
}

// ownISReach returns the IS-reachability neighbors an LSP we originate
// currently advertises at Level 2.
func ownISReach(t *testing.T, s *IsisServer, node packet.NodeID) []packet.NodeID {
	t.Helper()
	var out []packet.NodeID
	for id, e := range s.dbs[packet.Level2].entries {
		if id.NodeID() != node || !e.purgedAt.IsZero() {
			continue
		}
		for _, tlv := range e.lsp.TLVs {
			if r, ok := tlv.(*packet.ExtendedISReachabilityTLV); ok {
				for _, nb := range r.Neighbors {
					out = append(out, nb.NeighborID)
				}
			}
		}
	}
	return out
}

// isReachTo builds an Extended IS Reachability TLV with one edge to a node ID
// (a pseudonode, unlike isReach/isReachMetric).
func isReachTo(node packet.NodeID, metric uint32) packet.TLV {
	return &packet.ExtendedISReachabilityTLV{Neighbors: []packet.ExtendedISReachEntry{{NeighborID: node, Metric: metric}}}
}

// p2pMetricCircuit is a p2p Level-2 circuit with an explicit metric.
func p2pMetricCircuit(name string, snpa byte, metric uint32) CircuitConfig {
	return CircuitConfig{
		Name:      name,
		Transport: datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, snpa}, 1500),
		P2P:       true,
		Level2:    true,
		Metric:    metric,
		Padding:   ptrFalse(),
	}
}

// Losing an adjacency inside the LSP-regeneration hold reroutes the prefix over
// the surviving path instead of withdrawing it. ISO 10589 7.2.7 computes the
// paths out of this system from the adjacency database; the LSP we originate is
// only its wire copy, and drainLSPGen deliberately holds a re-origination back
// for minLSPGenInterval. B (via c1, metric 10) and C (via c2, metric 20) both
// advertise P; B's adjacency goes down 100 ms after a regeneration, so our own
// LSP still lists B when SPF runs.
func TestSPFReroutesWhenAdjacencyIsLostInsideRegenerationHold(t *testing.T) {
	self := packet.SystemID{0, 0, 0, 0, 0, 1}
	peerB := packet.SystemID{0, 0, 0, 0, 0, 2}
	peerC := packet.SystemID{0, 0, 0, 0, 0, 3}
	p := netip.MustParsePrefix("10.7.0.0/24")

	s := mustServer(t,
		WithSystemID(self),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(p2pMetricCircuit("c1", 0x11, 10)),
		WithCircuit(p2pMetricCircuit("c2", 0x12, 20)),
	)
	seedAdjacency(s.circuits[0], packet.Level2, peerB)
	seedAdjacency(s.circuits[1], packet.Level2, peerC)

	now := time.Now()
	for _, peer := range []packet.SystemID{peerB, peerC} {
		injectLSP(s, peer, []packet.TLV{isReach(self),
			&packet.ExtendedIPReachabilityTLV{Prefixes: []packet.ExtendedIPReachEntry{v4(p.String(), 0)}}}, now)
	}

	// Originate our own LSP from both live adjacencies; the next regeneration
	// is now held until now+minLSPGenInterval.
	s.requestLSPRegen()
	s.drainLSPGen(now)
	s.updateRIB(now)
	if r, ok := s.rib[p]; !ok || len(r.NextHops) != 1 || r.NextHops[0].Interface != "c1" {
		t.Fatalf("before the loss: rib[%s] = %+v, want one next hop on c1", p, r)
	}

	// B goes down inside the hold, so the regeneration is deferred.
	s.circuits[0].p2pAdj = nil
	s.requestLSPRegen()
	later := now.Add(100 * time.Millisecond)
	s.drainLSPGen(later)
	if !slices.Contains(ownISReach(t, s, nodeID(self, 0)), nodeID(peerB, 0)) {
		t.Fatal("our own LSP no longer lists B: the regeneration hold this test needs did not happen")
	}

	s.updateRIB(later)
	r, ok := s.rib[p]
	if !ok {
		t.Fatalf("route to %s withdrawn although C still advertises it", p)
	}
	if len(r.NextHops) != 1 || r.NextHops[0].Interface != "c2" {
		t.Errorf("next hops = %+v, want one on c2", r.NextHops)
	}
}

// The same guarantee for a pseudonode LSP we originate as DIS. D keeps the LAN
// alive, so our own node LSP legitimately still points at the pseudonode: the
// stale edge SPF must not follow is the pseudonode's own edge to B.
func TestSPFReroutesWhenLANAdjacencyIsLostInsideRegenerationHold(t *testing.T) {
	self := packet.SystemID{0, 0, 0, 0, 0, 1}
	peerB := packet.SystemID{0, 0, 0, 0, 0, 2}
	peerC := packet.SystemID{0, 0, 0, 0, 0, 3}
	peerD := packet.SystemID{0, 0, 0, 0, 0, 4}
	p := netip.MustParsePrefix("10.7.0.0/24")
	reachP := &packet.ExtendedIPReachabilityTLV{Prefixes: []packet.ExtendedIPReachEntry{v4(p.String(), 0)}}

	s := mustServer(t,
		WithSystemID(self),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(CircuitConfig{
			Name:      "c1",
			Transport: datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xff}, 1500),
			Level2:    true,
			Metric:    10,
			Padding:   ptrFalse(),
		}),
		WithCircuit(p2pMetricCircuit("c2", 0x12, 20)),
	)
	lan, p2p := s.circuits[0], s.circuits[1]
	seedAdjacency(lan, packet.Level2, peerB)
	seedAdjacency(lan, packet.Level2, peerD)
	seedAdjacency(p2p, packet.Level2, peerC)
	s.electDIS(lan, packet.Level2) // we win: the seeded adjacencies have priority 0
	pn := lan.dis[packet.Level2]
	if pn != nodeID(self, lan.pseudonodeID) {
		t.Fatalf("DIS = %v, want our own pseudonode", pn)
	}

	now := time.Now()
	injectLSP(s, peerB, []packet.TLV{isReachTo(pn, 10), reachP}, now)
	injectLSP(s, peerD, []packet.TLV{isReachTo(pn, 10)}, now)
	injectLSP(s, peerC, []packet.TLV{isReach(self), reachP}, now)

	s.requestLSPRegen()
	s.drainLSPGen(now)
	s.updateRIB(now)
	if r, ok := s.rib[p]; !ok || len(r.NextHops) != 1 || r.NextHops[0].Interface != "c1" {
		t.Fatalf("before the loss: rib[%s] = %+v, want one next hop on c1", p, r)
	}

	// B leaves the LAN inside the hold; D keeps the circuit (and the
	// pseudonode) up, so only the pseudonode's edge to B goes stale.
	delete(lan.adjs[packet.Level2], peerB)
	s.requestLSPRegen()
	later := now.Add(100 * time.Millisecond)
	s.drainLSPGen(later)
	if !slices.Contains(ownISReach(t, s, pn), nodeID(peerB, 0)) {
		t.Fatal("our pseudonode LSP no longer lists B: the regeneration hold this test needs did not happen")
	}

	s.updateRIB(later)
	r, ok := s.rib[p]
	if !ok {
		t.Fatalf("route to %s withdrawn although C still advertises it", p)
	}
	if len(r.NextHops) != 1 || r.NextHops[0].Interface != "c2" {
		t.Errorf("next hops = %+v, want one on c2", r.NextHops)
	}
}

// TestRouteIsDownWhenAnyContributingAdvertisementWas pins addRoute's merge
// policy, which the L1→L2 export depends on: the up/down bit is sticky across
// every advertisement of a prefix, including one whose path lost on metric.
// RFC 5305 §4.1 forbids re-advertising a down-marked prefix upward, and the
// LSDB cannot tell an independently reachable copy from the same leaked prefix
// re-originated without the bit, so the conservative answer is the safe one.
func TestRouteIsDownWhenAnyContributingAdvertisementWas(t *testing.T) {
	p := netip.MustParsePrefix("10.1.0.0/24")
	up := packet.SystemID{0, 0, 0, 0, 0, 2}
	dn := packet.SystemID{0, 0, 0, 0, 0, 3}

	for _, tc := range []struct {
		name       string
		first      route
		second     route
		wantMetric uint32
		wantHops   int
	}{
		{
			name:       "the down copy wins on metric",
			first:      route{metric: 20, nextHops: []packet.SystemID{up}},
			second:     route{metric: 10, down: true, nextHops: []packet.SystemID{dn}},
			wantMetric: 10, wantHops: 1,
		},
		{
			name:       "the down copy loses on metric and still marks the route",
			first:      route{metric: 10, nextHops: []packet.SystemID{up}},
			second:     route{metric: 20, down: true, nextHops: []packet.SystemID{dn}},
			wantMetric: 10, wantHops: 1,
		},
		{
			name:       "equal metrics merge first hops and the bit",
			first:      route{metric: 10, nextHops: []packet.SystemID{up}},
			second:     route{metric: 10, down: true, nextHops: []packet.SystemID{dn}},
			wantMetric: 10, wantHops: 2,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Both insertion orders: the policy is a property of the set, not
			// of the order the LSDB happened to be walked in.
			for _, rs := range [][]route{{tc.first, tc.second}, {tc.second, tc.first}} {
				routes := map[netip.Prefix]route{}
				for _, r := range rs {
					addRoute(routes, p, r)
				}
				got := routes[p]
				if !got.down {
					t.Errorf("down = false, want true")
				}
				if got.metric != tc.wantMetric {
					t.Errorf("metric = %d, want %d", got.metric, tc.wantMetric)
				}
				if len(got.nextHops) != tc.wantHops {
					t.Errorf("nextHops = %v, want %d of them", got.nextHops, tc.wantHops)
				}
			}
		})
	}
}
