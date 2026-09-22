package server

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/takehaya/goisis/pkg/datalink"
	"github.com/takehaya/goisis/pkg/packet"
)

var (
	l1l2Self  = packet.SystemID{0, 0, 0, 0, 0, 1}
	l1l2PeerB = packet.SystemID{0, 0, 0, 0, 0, 2}
)

// l1l2Server returns an IS (system ID ..01) whose single p2p circuit is Level 1,
// and Level 2 too when l1l2, with a fabricated Up adjacency to B (..02) at every
// enabled level. The circuit is p2p so the topology stays self-consistent across
// a re-origination: regenerateNodeLSP derives our IS reachability straight from
// the adjacency, so our own LSP still lists B after updateRIB re-originates it.
func l1l2Server(t *testing.T, l1l2 bool, extra ...ServerOption) *IsisServer {
	t.Helper()
	opts := append([]ServerOption{
		WithSystemID(l1l2Self),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(CircuitConfig{
			Name:      "c",
			Transport: datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 1}, 1500),
			P2P:       true,
			Level1:    true,
			Level2:    l1l2,
			Padding:   ptrFalse(),
		}),
	}, extra...)
	s := mustServer(t, opts...)
	c := s.circuits[0]
	var lv levelSet
	for _, l := range c.cfg.levels() {
		lv.add(l)
	}
	c.p2pAdj = &adjacency{
		systemID:     l1l2PeerB,
		state:        AdjUp,
		levels:       lv,
		neighborIPv4: []netip.Addr{netip.MustParseAddr("10.0.0.2")},
		neighborIPv6: []netip.Addr{netip.MustParseAddr("fe80::2")},
	}
	return s
}

// l2OwnReach collects the IP reachability this node originates in its own
// Level-2 LSP, as prefix -> every metric advertised for it (a slice, so a prefix
// advertised twice is visible).
func l2OwnReach(t *testing.T, s *IsisServer) map[netip.Prefix][]uint32 {
	t.Helper()
	db := s.dbs[packet.Level2]
	if db == nil {
		t.Fatal("no Level-2 LSDB")
	}
	out := map[netip.Prefix][]uint32{}
	for id, e := range db.entries {
		if id.NodeID() != nodeID(s.systemID, 0) || !e.purgedAt.IsZero() {
			continue
		}
		for _, tlv := range e.lsp.TLVs {
			switch tl := tlv.(type) {
			case *packet.ExtendedIPReachabilityTLV:
				for _, p := range tl.Prefixes {
					out[p.Prefix] = append(out[p.Prefix], p.Metric)
				}
			case *packet.IPv6ReachabilityTLV:
				for _, p := range tl.Prefixes {
					out[p.Prefix] = append(out[p.Prefix], p.Metric)
				}
			}
		}
	}
	return out
}

// l2OwnSeq returns the sequence number of this node's own Level-2 LSP.
func l2OwnSeq(t *testing.T, s *IsisServer) uint32 {
	t.Helper()
	e := s.dbs[packet.Level2].entries[lspID(s.systemID, 0)]
	if e == nil {
		t.Fatal("no own Level-2 LSP")
	}
	return e.lsp.SequenceNumber
}

// injectB installs B's Level-1 LSP: reachable back to us, plus the given
// reachability TLVs.
func injectB(s *IsisServer, now time.Time, tlvs ...packet.TLV) {
	injectLSPAt(s, packet.Level1, l1l2PeerB, append([]packet.TLV{isReach(l1l2Self)}, tlvs...), now)
}

// A Level-1/Level-2 IS advertises the prefixes reachable inside its Level-1
// area in its Level-2 LSP, at the total Level-1 path metric (ISO 10589 7.2.9 /
// RFC 1195 §3.1). A prefix B marked down came from Level 2 already and must not
// be sent back up (RFC 5305 §4.1).
func TestL1L2NodeAdvertisesL1PrefixesInL2LSP(t *testing.T) {
	s := l1l2Server(t, true)
	now := time.Now()
	injectB(s, now,
		&packet.ExtendedIPReachabilityTLV{Prefixes: []packet.ExtendedIPReachEntry{
			{Prefix: netip.MustParsePrefix("10.1.0.0/24"), Metric: 5},
			{Prefix: netip.MustParsePrefix("10.2.0.0/24"), Metric: 5, Down: true},
		}},
		&packet.IPv6ReachabilityTLV{Prefixes: []packet.IPv6ReachEntry{
			{Prefix: netip.MustParsePrefix("2001:db8:1::/64"), Metric: 5},
		}},
	)
	s.regenerateLSPs(false, now) // our own L1 LSP, listing B across the p2p circuit
	s.updateRIB(now)

	got := l2OwnReach(t, s)
	for _, p := range []string{"10.1.0.0/24", "2001:db8:1::/64"} {
		pfx := netip.MustParsePrefix(p)
		// 10 (the circuit metric to B) + 5 (B's metric for the prefix).
		if want := []uint32{15}; !slices.Equal(got[pfx], want) {
			t.Errorf("L2 LSP metrics for %s = %v, want %v", p, got[pfx], want)
		}
	}
	if m, ok := got[netip.MustParsePrefix("10.2.0.0/24")]; ok {
		t.Errorf("a down-marked prefix was propagated upward at metric %v", m)
	}

	// Re-originating marks dirty, so the loop recomputes once more; that pass
	// must find the same export set and leave the LSP alone.
	seq := l2OwnSeq(t, s)
	s.updateRIB(now)
	if got := l2OwnSeq(t, s); got != seq {
		t.Errorf("own L2 LSP re-originated on an unchanged export set (seq %d -> %d)", seq, got)
	}
}

// When the Level-1 route goes away, so does the Level-2 advertisement.
func TestL1ExportIsWithdrawnWhenTheL1RouteDisappears(t *testing.T) {
	s := l1l2Server(t, true)
	now := time.Now()
	p := netip.MustParsePrefix("10.1.0.0/24")
	injectB(s, now, &packet.ExtendedIPReachabilityTLV{
		Prefixes: []packet.ExtendedIPReachEntry{{Prefix: p, Metric: 5}},
	})
	s.regenerateLSPs(false, now)
	s.updateRIB(now)
	if _, ok := l2OwnReach(t, s)[p]; !ok {
		t.Fatalf("%s was not exported to Level 2 in the first place", p)
	}
	seq := l2OwnSeq(t, s)

	delete(s.dbs[packet.Level1].entries, lspID(l1l2PeerB, 0))
	s.updateRIB(now)

	if m, ok := l2OwnReach(t, s)[p]; ok {
		t.Errorf("%s still advertised at metric %v after its Level-1 route went away", p, m)
	}
	if got := l2OwnSeq(t, s); got <= seq {
		t.Errorf("own L2 LSP sequence number = %d, want > %d (the withdrawal must be flooded)", got, seq)
	}
}

// A prefix this node originates itself is advertised once — its own entry —
// even when a Level-1 neighbor advertises it too.
func TestOwnPrefixesAreNotDuplicatedIntoL2Export(t *testing.T) {
	p := netip.MustParsePrefix("10.1.0.0/24")
	s := l1l2Server(t, true, WithAdvertisedPrefix(p, 7))
	now := time.Now()
	injectB(s, now, &packet.ExtendedIPReachabilityTLV{
		Prefixes: []packet.ExtendedIPReachEntry{{Prefix: p, Metric: 5}},
	})
	s.regenerateLSPs(false, now)
	s.updateRIB(now)

	if want := []uint32{7}; !slices.Equal(l2OwnReach(t, s)[p], want) {
		t.Errorf("L2 LSP metrics for %s = %v, want %v (our own advertisement, once)",
			p, l2OwnReach(t, s)[p], want)
	}
}

// A default route is not area reachability: whoever advertised it, it is never
// propagated upward.
func TestDefaultRouteIsNotExportedToL2(t *testing.T) {
	s := l1l2Server(t, true)
	now := time.Now()
	injectB(s, now, &packet.ExtendedIPReachabilityTLV{Prefixes: []packet.ExtendedIPReachEntry{
		{Prefix: defaultV4, Metric: 5},
		{Prefix: netip.MustParsePrefix("10.1.0.0/24"), Metric: 5},
	}})
	s.regenerateLSPs(false, now)
	s.updateRIB(now)

	got := l2OwnReach(t, s)
	if m, ok := got[defaultV4]; ok {
		t.Errorf("default route propagated into the L2 LSP at metric %v", m)
	}
	if _, ok := got[netip.MustParsePrefix("10.1.0.0/24")]; !ok {
		t.Error("the ordinary Level-1 prefix was not exported; the topology under test is wrong")
	}
}

// A Level-1-only IS has no Level-2 LSP to export into, and exports nothing.
func TestL1OnlyNodeDoesNotExport(t *testing.T) {
	s := l1l2Server(t, false)
	now := time.Now()
	injectB(s, now, &packet.ExtendedIPReachabilityTLV{
		Prefixes: []packet.ExtendedIPReachEntry{{Prefix: netip.MustParsePrefix("10.1.0.0/24"), Metric: 5}},
	})
	s.regenerateLSPs(false, now)
	s.updateRIB(now)

	if s.dbs[packet.Level2] != nil {
		t.Error("a Level-1-only IS must not hold a Level-2 LSDB")
	}
	if len(s.l1Export) != 0 {
		t.Errorf("l1Export = %v, want empty on a Level-1-only IS", s.l1Export)
	}
}
