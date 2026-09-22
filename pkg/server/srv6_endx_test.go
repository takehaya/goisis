package server

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/takehaya/goisis/pkg/datalink"
	"github.com/takehaya/goisis/pkg/fib"
	"github.com/takehaya/goisis/pkg/packet"
)

// ownEndXSubTLVs returns the End.X (43) and LAN End.X (44) sub-TLVs this
// server carries in the IS reachability TLVs of its own Level-2 LSP.
func ownEndXSubTLVs(t *testing.T, s *IsisServer) ([]*packet.SRv6EndXSIDSubTLV, []*packet.SRv6LANEndXSIDSubTLV) {
	t.Helper()
	var p2p []*packet.SRv6EndXSIDSubTLV
	var lan []*packet.SRv6LANEndXSIDSubTLV
	for _, tlv := range ownLSPTLVs(t, s) {
		r, ok := tlv.(*packet.ExtendedISReachabilityTLV)
		if !ok {
			continue
		}
		for _, n := range r.Neighbors {
			for _, sub := range n.SubTLVs {
				switch e := sub.(type) {
				case *packet.SRv6EndXSIDSubTLV:
					p2p = append(p2p, e)
				case *packet.SRv6LANEndXSIDSubTLV:
					lan = append(lan, e)
				}
			}
		}
	}
	return p2p, lan
}

// TestSRv6EndXOnP2PAdjacency: a point-to-point adjacency gets one End.X SID per
// locator, at function 1 of each locator's function space. The SID is
// advertised as sub-TLV 43 of the neighbor's IS reachability entry and
// programmed as a local End.X SID towards the neighbor's link-local; both go
// away when the neighbor does.
func TestSRv6EndXOnP2PAdjacency(t *testing.T) {
	ta := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xa1}, 1500)
	tb := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xb2}, 1500)
	datalink.Link(ta, tb)

	area := packet.AreaAddress{0x49, 0x00, 0x01}
	loc1 := netip.MustParsePrefix("fc00:0:1::/48")
	loc2 := netip.MustParsePrefix("fc00:0:2::/48")
	bLL := netip.MustParseAddr("fe80::b2")
	idB := packet.SystemID{0, 0, 0, 0, 0, 2}

	cfgA := CircuitConfig{Name: "a", Transport: ta, P2P: true, Level2: true, Padding: ptrFalse(),
		IPv6Addrs: []netip.Addr{netip.MustParseAddr("fe80::a1")}}
	cfgB := CircuitConfig{Name: "b", Transport: tb, P2P: true, Level2: true, Padding: ptrFalse(),
		IPv6Addrs: []netip.Addr{bLL}}
	fastHello(&cfgA)
	fastHello(&cfgB)

	afib := newRecordFIB()
	a := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}), WithAreaAddresses(area),
		WithCircuit(cfgA), WithSRv6Locator(loc1), WithSRv6Locator(loc2), WithFIB(afib),
	)
	b := mustServer(t, WithSystemID(idB), WithAreaAddresses(area), WithCircuit(cfgB))

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	bctx, cancelB := context.WithCancel(ctx)
	defer cancelB()
	go a.Serve(ctx)  //nolint:errcheck // ctx shutdown
	go b.Serve(bctx) //nolint:errcheck // ctx shutdown

	// Function 1 of each locator: function 0 is the locator's own End SID.
	sid1 := netip.MustParseAddr("fc00:0:1:1::")
	sid2 := netip.MustParseAddr("fc00:0:2:1::")

	waitFor(t, "a advertises an End.X SID per locator", func() bool {
		p2p, _ := ownEndXSubTLVs(t, a)
		return len(p2p) == 2
	})
	p2p, lan := ownEndXSubTLVs(t, a)
	if len(lan) != 0 {
		t.Errorf("point-to-point adjacency advertised %d LAN End.X SIDs", len(lan))
	}
	for i, want := range []netip.Addr{sid1, sid2} {
		if p2p[i].SID != want {
			t.Errorf("End.X SID %d = %s, want %s", i, p2p[i].SID, want)
		}
		if p2p[i].Behavior != packet.SRv6BehaviorEndX {
			t.Errorf("End.X SID %d behavior = %d, want %d", i, p2p[i].Behavior, packet.SRv6BehaviorEndX)
		}
		if p2p[i].Algorithm != 0 || p2p[i].Weight != 0 || p2p[i].Flags != 0 {
			t.Errorf("End.X SID %d = %+v, want algorithm/weight/flags 0", i, p2p[i])
		}
		if s := p2p[i].Structure; s == nil || s.Function != 16 {
			t.Errorf("End.X SID %d structure = %+v, want a 16-bit function", i, s)
		}
	}

	// Both SIDs are programmed towards B's link-local on the circuit A learned
	// it on.
	waitFor(t, "a programmed both End.X SIDs", func() bool {
		for _, sid := range []netip.Addr{sid1, sid2} {
			e, ok := afib.getSID(sid)
			if !ok || e.Behavior != fib.BehaviorEndX || e.Nexthop != bLL || e.Interface != "a" {
				return false
			}
		}
		return true
	})

	// ListLocators reports the End.X SIDs under their locator.
	locs, err := a.ListLocators(ctx)
	if err != nil {
		t.Fatalf("ListLocators: %v", err)
	}
	if len(locs) != 2 {
		t.Fatalf("got %d locators, want 2", len(locs))
	}
	for i, want := range []netip.Addr{sid1, sid2} {
		got := locs[i].EndXSIDs
		if len(got) != 1 || got[0].SID != want || got[0].Neighbor != idB || got[0].Interface != "a" {
			t.Errorf("locator %s End.X SIDs = %+v, want one %s to %s on a", locs[i].Prefix, got, want, idB)
		}
	}

	// The neighbor goes away: the advertisement is withdrawn and the SIDs are
	// released from the FIB.
	cancelB()
	waitFor(t, "a withdrew the End.X SIDs", func() bool {
		p2p, _ := ownEndXSubTLVs(t, a)
		if len(p2p) != 0 {
			return false
		}
		_, ok1 := afib.getSID(sid1)
		_, ok2 := afib.getSID(sid2)
		return !ok1 && !ok2
	})
	// The locator's own End SID is not an adjacency SID and stays installed.
	if _, ok := afib.getSID(loc1.Addr()); !ok {
		t.Error("the locator's End SID was released along with the End.X SIDs")
	}
}

// TestSRv6LANEndXOnBroadcastAdjacency: on a broadcast circuit the IS
// reachability entry points at the pseudonode, so the SID is advertised as a
// LAN End.X sub-TLV (44) naming the neighbor it forwards to.
func TestSRv6LANEndXOnBroadcastAdjacency(t *testing.T) {
	ta := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xa1}, 1500)
	tb := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xb2}, 1500)
	datalink.Link(ta, tb)

	area := packet.AreaAddress{0x49, 0x00, 0x01}
	loc := netip.MustParsePrefix("fc00:0:1::/48")
	bLL := netip.MustParseAddr("fe80::b2")
	idB := packet.SystemID{0, 0, 0, 0, 0, 2}

	cfgA := CircuitConfig{Name: "a", Transport: ta, Level2: true, Padding: ptrFalse(),
		IPv6Addrs: []netip.Addr{netip.MustParseAddr("fe80::a1")}}
	cfgB := CircuitConfig{Name: "b", Transport: tb, Level2: true, Padding: ptrFalse(),
		IPv6Addrs: []netip.Addr{bLL}}
	fastHello(&cfgA)
	fastHello(&cfgB)

	afib := newRecordFIB()
	a := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}), WithAreaAddresses(area),
		WithCircuit(cfgA), WithSRv6Locator(loc), WithFIB(afib),
	)
	b := mustServer(t, WithSystemID(idB), WithAreaAddresses(area), WithCircuit(cfgB))

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go a.Serve(ctx) //nolint:errcheck // ctx shutdown
	go b.Serve(ctx) //nolint:errcheck // ctx shutdown

	sid := netip.MustParseAddr("fc00:0:1:1::")
	waitFor(t, "a advertises a LAN End.X SID for b", func() bool {
		_, lan := ownEndXSubTLVs(t, a)
		return len(lan) == 1
	})
	p2p, lan := ownEndXSubTLVs(t, a)
	if len(p2p) != 0 {
		t.Errorf("broadcast adjacency advertised %d point-to-point End.X SIDs", len(p2p))
	}
	if lan[0].Neighbor != idB {
		t.Errorf("LAN End.X neighbor = %s, want %s", lan[0].Neighbor, idB)
	}
	if lan[0].SID != sid || lan[0].Behavior != packet.SRv6BehaviorEndX {
		t.Errorf("LAN End.X SID = %s behavior %d, want %s behavior %d",
			lan[0].SID, lan[0].Behavior, sid, packet.SRv6BehaviorEndX)
	}
	waitFor(t, "a programmed the LAN End.X SID", func() bool {
		e, ok := afib.getSID(sid)
		return ok && e.Behavior == fib.BehaviorEndX && e.Nexthop == bLL && e.Interface == "a"
	})
}

// TestSRv6EndXSubTLVsIgnoredBySPF: End.X sub-TLVs ride along in the IS
// reachability entries a peer floods; they must not disturb the topology SPF
// builds from those entries.
func TestSRv6EndXSubTLVsIgnoredBySPF(t *testing.T) {
	mock := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 1}, 1500)
	s := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(CircuitConfig{Name: "c", Transport: mock, Level2: true, Padding: ptrFalse()}),
	)
	now := time.Now()
	self := packet.SystemID{0, 0, 0, 0, 0, 1}
	peer := packet.SystemID{0, 0, 0, 0, 0, 2}
	prefix := netip.MustParsePrefix("fc00:0:9::/48")
	endX := func(sid string) packet.SubTLV {
		return &packet.SRv6EndXSIDSubTLV{
			Behavior:  packet.SRv6BehaviorEndX,
			SID:       netip.MustParseAddr(sid),
			Structure: &packet.SIDStructure{LocatorBlock: 32, LocatorNode: 16, Function: 16},
		}
	}

	injectLSP(s, self, []packet.TLV{&packet.ExtendedISReachabilityTLV{Neighbors: []packet.ExtendedISReachEntry{
		{NeighborID: nodeID(peer, 0), Metric: 10, SubTLVs: []packet.SubTLV{endX("fc00:0:1:1::")}},
	}}}, now)
	injectLSP(s, peer, []packet.TLV{
		&packet.ExtendedISReachabilityTLV{Neighbors: []packet.ExtendedISReachEntry{
			{NeighborID: nodeID(self, 0), Metric: 10, SubTLVs: []packet.SubTLV{endX("fc00:0:2:1::")}},
		}},
		&packet.IPv6ReachabilityTLV{Prefixes: []packet.IPv6ReachEntry{{Metric: 5, Prefix: prefix}}},
	}, now)

	routes := s.computeSPF(packet.Level2, 0, now)
	if r, ok := routes[prefix]; !ok || r.metric != 15 {
		t.Errorf("route to %s = %+v (present %v), want metric 15", prefix, r, ok)
	}
}

// TestSRv6EndXEntrySplitting: an adjacency with more End.X SIDs than fit one
// IS reachability entry's 255-octet sub-TLV area is emitted as several entries
// for the same neighbor, each serializable.
func TestSRv6EndXEntrySplitting(t *testing.T) {
	id := nodeID(packet.SystemID{0, 0, 0, 0, 0, 2}, 0)
	var subs []packet.SubTLV
	for i := range 20 {
		subs = append(subs, &packet.SRv6EndXSIDSubTLV{
			Behavior:  packet.SRv6BehaviorEndX,
			SID:       netip.AddrFrom16([16]byte{0xfc, 0, 0, 0, 0, 1, 0, byte(i)}),
			Structure: &packet.SIDStructure{LocatorBlock: 32, LocatorNode: 16, Function: 16},
		})
	}
	entries := appendISReach(nil, id, 10, subs)
	if len(entries) < 2 {
		t.Fatalf("got %d entries, want the sub-TLVs split across several", len(entries))
	}
	total := 0
	for _, e := range entries {
		if e.NeighborID != id || e.Metric != 10 {
			t.Errorf("split entry lost its neighbor or metric: %+v", e)
		}
		total += len(e.SubTLVs)
	}
	if total != len(subs) {
		t.Errorf("split kept %d of %d sub-TLVs", total, len(subs))
	}
	if _, err := (&packet.ExtendedISReachabilityTLV{Neighbors: entries[:1]}).Serialize(); err != nil {
		t.Errorf("split entry does not serialize: %v", err)
	}
}
