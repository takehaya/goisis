package server

import (
	"net/netip"
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

	routes := s.computeSPF(packet.Level2, time.Now())
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

	routes := s.computeSPF(packet.Level2, time.Now())
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

	routes := s.computeSPF(packet.Level2, time.Now())
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

	routes := s.computeSPF(packet.Level2, time.Now())
	r, ok := routes[netip.MustParsePrefix("10.3.0.0/24")]
	if !ok {
		t.Fatal("no route to 10.3.0.0/24")
	}
	if len(r.nextHops) != 2 {
		t.Errorf("nextHops = %v, want 2 ECMP first-hops", r.nextHops)
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

	routes := s.computeSPF(packet.Level2, time.Now())
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

	routes := s.computeSPF(packet.Level2, time.Now())
	if _, ok := routes[netip.MustParsePrefix("10.2.0.0/24")]; !ok {
		t.Error("overloaded node's own prefix should remain reachable")
	}
	if _, ok := routes[netip.MustParsePrefix("10.3.0.0/24")]; ok {
		t.Error("transit through an overloaded node should be avoided")
	}
}
