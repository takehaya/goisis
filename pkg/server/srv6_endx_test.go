package server

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
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
	// End.X forwards to the neighbor's global on-link address, never to its
	// link-local (see endXNexthop), so both ends carry one on the link's /64.
	bLL := netip.MustParseAddr("fe80::b2")
	bGlobal := netip.MustParseAddr("2001:db8::b2")
	subnet := netip.MustParsePrefix("2001:db8::/64")
	idB := packet.SystemID{0, 0, 0, 0, 0, 2}

	cfgA := CircuitConfig{Name: "a", Transport: ta, P2P: true, Level2: true, Padding: ptrFalse(),
		IPv6Addrs:         []netip.Addr{netip.MustParseAddr("fe80::a1"), netip.MustParseAddr("2001:db8::a1")},
		ConnectedPrefixes: []netip.Prefix{subnet}}
	cfgB := CircuitConfig{Name: "b", Transport: tb, P2P: true, Level2: true, Padding: ptrFalse(),
		IPv6Addrs:         []netip.Addr{bLL, bGlobal},
		ConnectedPrefixes: []netip.Prefix{subnet}}
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

	// Both SIDs are programmed towards B's global on-link address, on the
	// circuit A learned it on.
	waitFor(t, "a programmed both End.X SIDs", func() bool {
		for _, sid := range []netip.Addr{sid1, sid2} {
			e, ok := afib.getSID(sid)
			if !ok || e.Behavior != fib.BehaviorEndX || e.Nexthop != bGlobal || e.Interface != "a" {
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
//
// On the fake clock, because the two things it waits for — a DIS election and
// a SID reaching the FIB — are both several hellos and a housekeeping tick
// deep, and on the wall clock that is a race with the test's own deadline
// under load rather than a statement about the protocol. It flaked there, and
// a flaky test does worse than fail: during round 5 it reported a mutation
// caught that was not.
func TestSRv6LANEndXOnBroadcastAdjacency(t *testing.T) {
	loc := netip.MustParsePrefix("fc00:0:1::/48")
	bGlobal := netip.MustParseAddr("2001:db8::b2")
	subnet := netip.MustParsePrefix("2001:db8::/64")
	idB := packet.SystemID{0, 0, 0, 0, 0, 2}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	afib := newRecordFIB()
	a, _, clk := lanPair(t, ctx, func(cfgA, cfgB *CircuitConfig) {
		cfgA.IPv6Addrs = []netip.Addr{netip.MustParseAddr("fe80::a1"), netip.MustParseAddr("2001:db8::a1")}
		cfgA.ConnectedPrefixes = []netip.Prefix{subnet}
		cfgB.IPv6Addrs = []netip.Addr{netip.MustParseAddr("fe80::b2"), bGlobal}
		cfgB.ConnectedPrefixes = []netip.Prefix{subnet}
	}, WithSRv6Locator(loc), WithFIB(afib))

	sid := netip.MustParseAddr("fc00:0:1:1::")
	waitClock(t, clk, "a advertises a LAN End.X SID for b", func() bool {
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
	waitClock(t, clk, "a programmed the LAN End.X SID", func() bool {
		e, ok := afib.getSID(sid)
		return ok && e.Behavior == fib.BehaviorEndX && e.Nexthop == bGlobal && e.Interface == "a"
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

	routes := s.computeSPF(packet.Level2, 0, flexAlgoAffinity{}, now)
	if r, ok := routes[prefix]; !ok || r.metric != 15 {
		t.Errorf("route to %s = %+v (present %v), want metric 15", prefix, r, ok)
	}
}

// TestSRv6EndXEntrySplitting: an adjacency with more End.X SIDs than fit one
// IS reachability entry's 255-octet sub-TLV area is emitted as several entries
// for the same neighbor, each serializable — and the link's own attributes
// repeat on every one of them, so a receiver that reads an entry as one SPF
// edge does not see an uncolored parallel link beside the colored one.
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
	asla := &packet.ASLASubTLV{
		SABM:       []byte{packet.ASLAAppFlexAlgo},
		SubSubTLVs: []packet.SubTLV{&packet.AdminGroupSubTLV{Groups: []uint32{0x4}}},
	}
	entries := appendISReach(nil, id, 10, []packet.SubTLV{asla}, subs)
	if len(entries) < 2 {
		t.Fatalf("got %d entries, want the sub-TLVs split across several", len(entries))
	}
	total := 0
	for _, e := range entries {
		if e.NeighborID != id || e.Metric != 10 {
			t.Errorf("split entry lost its neighbor or metric: %+v", e)
		}
		if got := flexAlgoLinkColors(e.SubTLVs); !slices.Equal(got, []uint32{0x4}) {
			t.Errorf("split entry colors = %v, want the link's 0x4 on every entry", got)
		}
		total += len(e.SubTLVs) - 1 // minus the repeated ASLA
	}
	if total != len(subs) {
		t.Errorf("split kept %d of %d sub-TLVs", total, len(subs))
	}
	if _, err := (&packet.ExtendedISReachabilityTLV{Neighbors: entries[:1]}).Serialize(); err != nil {
		t.Errorf("split entry does not serialize: %v", err)
	}
}

// endXNeighbor is the neighbor an End.X next-hop test holds an adjacency to.
var endXNeighbor = packet.SystemID{0, 0, 0, 0, 0, 2}

// endXServer builds a server with one SRv6 locator on a point-to-point circuit
// whose connected subnet is 2001:db8::/64, holding an Up adjacency to
// endXNeighbor that listed helloAddrs in its hellos (TLV 232). Serve is not
// started: the tests drive syncEndXSIDs directly, as the regeneration path does.
func endXServer(t *testing.T, logs io.Writer, helloAddrs []netip.Addr, opts ...ServerOption) (*IsisServer, *recordFIB) {
	t.Helper()
	rf := newRecordFIB()
	s := mustServer(t, append([]ServerOption{
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(CircuitConfig{
			Name: "a", Transport: datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xa1}, 1500),
			P2P: true, Level2: true, Padding: ptrFalse(),
			IPv6Addrs:         []netip.Addr{netip.MustParseAddr("fe80::a1"), netip.MustParseAddr("2001:db8::1")},
			ConnectedPrefixes: []netip.Prefix{netip.MustParsePrefix("2001:db8::/64")},
		}),
		WithSRv6Locator(netip.MustParsePrefix("fc00:0:1::/48")),
		WithFIB(rf),
		WithLogger(slog.New(slog.NewTextHandler(logs, nil))),
	}, opts...)...)
	var lv levelSet
	lv.add(packet.Level2)
	s.circuits[0].p2pAdj = &adjacency{systemID: endXNeighbor, state: AdjUp, levels: lv, neighborIPv6: helloAddrs}
	return s, rf
}

// TestEndXUsesGlobalOnLinkNexthopAndWithholdsWithoutOne: an End.X SID is
// allocated, advertised and programmed only when the neighbor announces a
// global IPv6 address inside one of the circuit's connected subnets — from its
// hellos, or failing that from its fragment-0 LSP (FRR lists only link-locals
// in hellos, as RFC 5308 3 requires, and its globals in the LSP). Linux
// resolves an End.X next hop with seg6_lookup_any_nexthop, which confines a
// link-local destination to the ingress interface, so a link-local next hop
// drops every transit packet: with no global on-link address there is nothing
// worth advertising, and the adjacency is warned about exactly once.
func TestEndXUsesGlobalOnLinkNexthopAndWithholdsWithoutOne(t *testing.T) {
	linkLocal := netip.MustParseAddr("fe80::b2")
	onLink := netip.MustParseAddr("2001:db8::2")
	offLink := netip.MustParseAddr("2001:db8:ffff::2")
	sid := netip.MustParseAddr("fc00:0:1:1::")

	tests := []struct {
		name    string
		hello   []netip.Addr
		lsp     []netip.Addr // TLV 232 of the neighbor's fragment-0 LSP
		nexthop netip.Addr   // invalid: no SID at all
	}{
		{name: "global on-link address in the hello", hello: []netip.Addr{linkLocal, onLink}, nexthop: onLink},
		{name: "global on-link address only in the neighbor LSP", hello: []netip.Addr{linkLocal}, lsp: []netip.Addr{linkLocal, onLink}, nexthop: onLink},
		{name: "link-local only", hello: []netip.Addr{linkLocal}},
		{name: "global address off this link", hello: []netip.Addr{linkLocal, offLink}, lsp: []netip.Addr{offLink}},
		{name: "no addresses at all"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var logs syncBuf
			now := time.Now()
			s, rf := endXServer(t, &logs, tc.hello)
			if tc.lsp != nil {
				injectLSP(s, endXNeighbor, []packet.TLV{&packet.IPv6InterfaceAddressesTLV{Addresses: tc.lsp}}, now)
			}
			s.syncEndXSIDs(now)
			s.syncEndXSIDs(now) // idempotent, and the warning is edge-triggered

			subs := s.endXSubTLVs(s.circuits[0], s.circuits[0].p2pAdj)
			entry, programmed := rf.getSID(sid)
			warnings := strings.Count(logs.String(), "no on-link global IPv6 address")

			if !tc.nexthop.IsValid() {
				if len(subs) != 0 {
					t.Errorf("advertised %d End.X sub-TLVs, want none", len(subs))
				}
				if programmed {
					t.Errorf("programmed End.X SID %s, want none", sid)
				}
				if warnings != 1 {
					t.Errorf("warnings about the missing next hop = %d, want 1", warnings)
				}
				return
			}
			if len(subs) != 1 || subs[0].(*packet.SRv6EndXSIDSubTLV).SID != sid {
				t.Fatalf("End.X sub-TLVs = %+v, want one advertising %s", subs, sid)
			}
			if !programmed || entry.Behavior != fib.BehaviorEndX || entry.Nexthop != tc.nexthop || entry.Interface != "a" {
				t.Errorf("programmed End.X SID = %+v (present %v), want next hop %s on a", entry, programmed, tc.nexthop)
			}
			if warnings != 0 {
				t.Errorf("warned %d times about a next hop that exists", warnings)
			}
		})
	}
}

// TestEndXAppearsWhenNeighborAnnouncesGlobalAddressLater: a neighbor with only
// a link-local address gets no End.X SID, and the address change that later
// gives it a global on-link one is itself what triggers the regeneration that
// allocates, advertises and programs a SID.
func TestEndXAppearsWhenNeighborAnnouncesGlobalAddressLater(t *testing.T) {
	ta := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xa1}, 1500)
	tb := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xb2}, 1500)
	datalink.Link(ta, tb)

	area := packet.AreaAddress{0x49, 0x00, 0x01}
	subnet := netip.MustParsePrefix("2001:db8::/64")
	bLL := netip.MustParseAddr("fe80::b2")
	bGlobal := netip.MustParseAddr("2001:db8::b2")

	cfgA := CircuitConfig{Name: "a", Transport: ta, P2P: true, Level2: true, Padding: ptrFalse(),
		IPv6Addrs:         []netip.Addr{netip.MustParseAddr("fe80::a1"), netip.MustParseAddr("2001:db8::a1")},
		ConnectedPrefixes: []netip.Prefix{subnet}}
	cfgB := CircuitConfig{Name: "b", Transport: tb, P2P: true, Level2: true, Padding: ptrFalse(),
		IPv6Addrs: []netip.Addr{bLL}}
	fastHello(&cfgA)
	fastHello(&cfgB)

	afib := newRecordFIB()
	a := mustServer(t, WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}), WithAreaAddresses(area),
		WithCircuit(cfgA), WithSRv6Locator(netip.MustParsePrefix("fc00:0:1::/48")), WithFIB(afib))
	b := mustServer(t, WithSystemID(endXNeighbor), WithAreaAddresses(area), WithCircuit(cfgB))

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go a.Serve(ctx) //nolint:errcheck // ctx shutdown
	go b.Serve(ctx) //nolint:errcheck // ctx shutdown

	// Wait past the regeneration the adjacency coming Up asks for, so the SID
	// below can only come from the address change itself.
	waitFor(t, "a advertises its adjacency to b", func() bool {
		for _, tlv := range ownLSPTLVs(t, a) {
			if r, ok := tlv.(*packet.ExtendedISReachabilityTLV); ok && len(r.Neighbors) > 0 {
				return true
			}
		}
		return false
	})
	if p2p, _ := ownEndXSubTLVs(t, a); len(p2p) != 0 {
		t.Fatalf("advertised %d End.X SIDs towards a link-local-only neighbor, want none", len(p2p))
	}

	// Only b's addresses change. Its hellos keep carrying just the link-local
	// (RFC 5308 3); what reaches a is b's re-originated LSP, whose TLV 232 now
	// names the global. b advertises no connected prefix, so nothing else about
	// it changes.
	if err := b.SetCircuitAddresses(ctx, "b", nil, []netip.Addr{bLL, bGlobal}, nil); err != nil {
		t.Fatalf("SetCircuitAddresses: %v", err)
	}
	sid := netip.MustParseAddr("fc00:0:1:1::")
	waitFor(t, "a advertises and programs the End.X SID", func() bool {
		p2p, _ := ownEndXSubTLVs(t, a)
		if len(p2p) != 1 || p2p[0].SID != sid {
			return false
		}
		e, ok := afib.getSID(sid)
		return ok && e.Nexthop == bGlobal && e.Interface == "a"
	})
}

// TestEndXFollowsNeighborFragmentZeroLSP: a neighbor that lists only a
// link-local in its hellos publishes its global addresses in TLV 232 of its
// fragment-0 LSP (FRR does). Installing that fragment asks for a regeneration,
// so the End.X SID appears as soon as the LSP arrives; an LSP from a system we
// hold no adjacency to asks for nothing.
func TestEndXFollowsNeighborFragmentZeroLSP(t *testing.T) {
	var logs syncBuf
	s, rf := endXServer(t, &logs, []netip.Addr{netip.MustParseAddr("fe80::b2")})
	c := s.circuits[0]
	now := time.Now()
	s.syncEndXSIDs(now) // settles with no next hop and nothing advertised
	s.lspGenPending = false

	lsp := func(id packet.SystemID, tlvs ...packet.TLV) (*packet.LSP, []byte) {
		t.Helper()
		l := &packet.LSP{Level: packet.Level2, RemainingTime: maxAgeSeconds, LSPID: lspID(id, 0),
			SequenceNumber: 1, ISType: 2, TLVs: tlvs}
		raw, err := l.Serialize()
		if err != nil {
			t.Fatalf("serialize LSP: %v", err)
		}
		return l, raw
	}

	stranger, raw := lsp(packet.SystemID{0, 0, 0, 0, 0, 9})
	s.processLSP(c, raw, stranger, nil, now)
	if s.lspGenPending {
		t.Error("an LSP from a system we hold no adjacency to asked for a regeneration")
	}

	onLink := netip.MustParseAddr("2001:db8::2")
	neighbor, raw := lsp(endXNeighbor, &packet.IPv6InterfaceAddressesTLV{Addresses: []netip.Addr{onLink}})
	s.processLSP(c, raw, neighbor, nil, now)
	if !s.lspGenPending {
		t.Fatal("the neighbor's fragment 0 did not ask for a regeneration")
	}
	s.drainLSPGen(now)
	sid := netip.MustParseAddr("fc00:0:1:1::")
	if e, ok := rf.getSID(sid); !ok || e.Nexthop != onLink {
		t.Errorf("programmed End.X SID = %+v (present %v), want next hop %s", e, ok, onLink)
	}
}

// TestEndXSIDsFormBetweenTwoGoisisNodes: two goisis nodes on a link with a
// global /64 give each other an End.X SID. The hellos carry only the
// link-locals (RFC 5308 3), so the next hop can only come from the peer's
// fragment-0 TLV 232 — without one the pair is exactly the "no on-link global
// IPv6 address" case endXNexthop refuses to program.
func TestEndXSIDsFormBetweenTwoGoisisNodes(t *testing.T) {
	ta := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xa1}, 1500)
	tb := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xb2}, 1500)
	datalink.Link(ta, tb)

	area := packet.AreaAddress{0x49, 0x00, 0x01}
	subnet := netip.MustParsePrefix("2001:db8::/64")
	aLL, aGlobal := netip.MustParseAddr("fe80::a1"), netip.MustParseAddr("2001:db8::a1")
	bLL, bGlobal := netip.MustParseAddr("fe80::b2"), netip.MustParseAddr("2001:db8::b2")
	idA, idB := packet.SystemID{0, 0, 0, 0, 0, 1}, packet.SystemID{0, 0, 0, 0, 0, 2}
	locA := netip.MustParsePrefix("fc00:0:1::/48")
	locB := netip.MustParsePrefix("fc00:0:2::/48")

	cfgA := CircuitConfig{Name: "a", Transport: ta, P2P: true, Level2: true, Padding: ptrFalse(),
		IPv6Addrs:         []netip.Addr{aLL, aGlobal},
		ConnectedPrefixes: []netip.Prefix{subnet}}
	cfgB := CircuitConfig{Name: "b", Transport: tb, P2P: true, Level2: true, Padding: ptrFalse(),
		IPv6Addrs:         []netip.Addr{bLL, bGlobal},
		ConnectedPrefixes: []netip.Prefix{subnet}}
	fastHello(&cfgA)
	fastHello(&cfgB)

	afib, bfib := newRecordFIB(), newRecordFIB()
	a := mustServer(t, WithSystemID(idA), WithAreaAddresses(area),
		WithCircuit(cfgA), WithSRv6Locator(locA), WithFIB(afib))
	b := mustServer(t, WithSystemID(idB), WithAreaAddresses(area),
		WithCircuit(cfgB), WithSRv6Locator(locB), WithFIB(bfib))

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go a.Serve(ctx) //nolint:errcheck // ctx shutdown
	go b.Serve(ctx) //nolint:errcheck // ctx shutdown

	// Function 1 of each node's own locator: function 0 is its End SID.
	sidA := netip.MustParseAddr("fc00:0:1:1::")
	sidB := netip.MustParseAddr("fc00:0:2:1::")
	for _, tc := range []struct {
		name    string
		s       *IsisServer
		f       *recordFIB
		sid     netip.Addr
		nexthop netip.Addr
		circuit string
	}{
		{"a", a, afib, sidA, bGlobal, "a"},
		{"b", b, bfib, sidB, aGlobal, "b"},
	} {
		waitFor(t, tc.name+" advertises and programs an End.X SID towards its peer", func() bool {
			p2p, _ := ownEndXSubTLVs(t, tc.s)
			if len(p2p) != 1 || p2p[0].SID != tc.sid {
				return false
			}
			e, ok := tc.f.getSID(tc.sid)
			return ok && e.Behavior == fib.BehaviorEndX && e.Nexthop == tc.nexthop && e.Interface == tc.circuit
		})
	}

	// The hellos told each side only the link-local, so the global above came
	// from the peer's LSP.
	var learned []netip.Addr
	if err := a.mgmtOperation(ctx, func() error {
		learned = a.circuits[0].p2pAdj.neighborIPv6
		return nil
	}); err != nil {
		t.Fatalf("mgmtOperation: %v", err)
	}
	if !slices.Equal(learned, []netip.Addr{bLL}) {
		t.Errorf("a learned %v from b's hellos, want only the link-local %s", learned, bLL)
	}
}

// TestEndXFIBFailureIsCountedAndRepairedByHousekeeping: a FIB that refuses an
// End.X SID is visible in the fib_error counter and not only in the log; the
// log line is edge-triggered, so a failure that persists does not repeat once
// per housekeeping tick; and housekeeping both re-asserts a failed install and
// retries a failed removal, so neither a missing SID nor the kernel route a
// failed removal leaves behind survives until a restart.
func TestEndXFIBFailureIsCountedAndRepairedByHousekeeping(t *testing.T) {
	sid := netip.MustParseAddr("fc00:0:1:1::")
	now := time.Now()
	var logs syncBuf
	m := newCountingMetrics()
	s, rf := endXServer(t, &logs,
		[]netip.Addr{netip.MustParseAddr("fe80::b2"), netip.MustParseAddr("2001:db8::2")},
		WithMetrics(m))
	// Housekeeping expires an adjacency it has not heard from; keep this one.
	s.circuits[0].p2pAdj.holding, s.circuits[0].p2pAdj.lastHeard = 30, now

	rf.failSID(sid, true, false)
	s.syncEndXSIDs(now)
	installErrors := m.count("fib_error", fibOpAddSID)
	if installErrors == 0 {
		t.Fatal("a failed End.X SID install was not counted as a FIB error")
	}
	for range 2 {
		s.housekeeping(now)
	}
	if n := m.count("fib_error", fibOpAddSID); n <= installErrors {
		t.Errorf("add_sid FIB errors = %d after two housekeeping ticks, want more than the %d at install: the counter carries the rate", n, installErrors)
	}
	if n := strings.Count(logs.String(), "install local SID"); n != 1 {
		t.Errorf("the failed install was logged %d times, want 1: the log is edge-triggered", n)
	}

	rf.failSID(sid, false, false)
	s.housekeeping(now)
	if _, ok := rf.getSID(sid); !ok {
		t.Fatal("housekeeping did not reinstall the End.X SID after the FIB recovered")
	}
	if n := strings.Count(logs.String(), "local SID installed after an earlier failure"); n != 1 {
		t.Errorf("the recovery was logged %d times, want 1", n)
	}

	// The adjacency goes away while the FIB refuses the removal. Its endXSIDs
	// entry is gone, so only a pending-removal set can get the seg6local route
	// out of the kernel.
	rf.failSID(sid, false, true)
	s.circuits[0].p2pAdj = nil
	s.syncEndXSIDs(now)
	if n := m.count("fib_error", fibOpRemoveSID); n != 1 {
		t.Errorf("remove_sid FIB errors = %d, want 1", n)
	}
	if !s.sidPending[sid] {
		t.Fatal("a failed End.X SID removal was forgotten; the kernel route leaks until a restart")
	}
	rf.failSID(sid, false, false)
	s.housekeeping(now)
	if _, ok := rf.getSID(sid); ok {
		t.Error("housekeeping did not retry the failed End.X SID removal")
	}
	if s.sidPending[sid] {
		t.Error("a removal that succeeded on retry is still pending")
	}
}

// TestFlexAlgoLocatorAllocatesEndXOnlyTowardParticipants: an End.X SID carries
// its locator's algorithm (RFC 9352 §8.1), so a Flex-Algo locator hands one out
// only towards a neighbor that advertises the algorithm — the participation SPF
// prunes the topology on. The algorithm-0 locator has nothing to check and
// always gets one; the Flex-Algo SID appears once the neighbor's fragment 0
// lists the algorithm and is released again when it stops.
func TestFlexAlgoLocatorAllocatesEndXOnlyTowardParticipants(t *testing.T) {
	var logs syncBuf
	onLink := netip.MustParseAddr("2001:db8::2")
	s, rf := endXServer(t, &logs, []netip.Addr{netip.MustParseAddr("fe80::b2"), onLink},
		WithFlexAlgo(FlexAlgoConfig{Algo: 128}),
		WithSRv6LocatorForAlgo(netip.MustParsePrefix("fc00:0:128::/48"), 128))
	now := time.Now()

	algo0SID := netip.MustParseAddr("fc00:0:1:1::")
	algo128SID := netip.MustParseAddr("fc00:0:128:1::")

	srAlgo := func(algos ...uint8) packet.TLV {
		return &packet.RouterCapabilityTLV{SubTLVs: []packet.SubTLV{&packet.SRAlgorithmSubTLV{Algorithms: algos}}}
	}
	advertised := func() []netip.Addr {
		var out []netip.Addr
		for _, sub := range s.endXSubTLVs(s.circuits[0], s.circuits[0].p2pAdj) {
			e := sub.(*packet.SRv6EndXSIDSubTLV)
			if e.SID == algo128SID && e.Algorithm != 128 {
				t.Errorf("End.X SID %s advertised for algorithm %d, want 128", e.SID, e.Algorithm)
			}
			out = append(out, e.SID)
		}
		return out
	}

	// The neighbor participates in algorithm 0 only.
	injectLSP(s, endXNeighbor, []packet.TLV{srAlgo(0)}, now)
	s.syncEndXSIDs(now)
	if got := advertised(); !slices.Equal(got, []netip.Addr{algo0SID}) {
		t.Errorf("End.X SIDs towards a non-participant = %v, want only %s", got, algo0SID)
	}
	if _, ok := rf.getSID(algo128SID); ok {
		t.Errorf("programmed algo-128 End.X SID %s towards a neighbor outside the algorithm", algo128SID)
	}

	// It starts advertising algorithm 128: the Flex-Algo locator hands out a SID.
	injectLSP(s, endXNeighbor, []packet.TLV{srAlgo(0, 128)}, now)
	s.syncEndXSIDs(now)
	if got := advertised(); !slices.Equal(got, []netip.Addr{algo0SID, algo128SID}) {
		t.Errorf("End.X SIDs towards a participant = %v, want %s and %s", got, algo0SID, algo128SID)
	}
	if e, ok := rf.getSID(algo128SID); !ok || e.Nexthop != onLink || e.Interface != "a" {
		t.Errorf("programmed algo-128 End.X SID = %+v (present %v), want next hop %s on a", e, ok, onLink)
	}

	// And stops again: the SID is withdrawn and released from the FIB.
	injectLSP(s, endXNeighbor, []packet.TLV{srAlgo(0)}, now)
	s.syncEndXSIDs(now)
	if got := advertised(); !slices.Equal(got, []netip.Addr{algo0SID}) {
		t.Errorf("End.X SIDs after the neighbor left the algorithm = %v, want only %s", got, algo0SID)
	}
	if _, ok := rf.getSID(algo128SID); ok {
		t.Errorf("algo-128 End.X SID %s survived the neighbor leaving the algorithm", algo128SID)
	}
}

// TestLocalSIDReassertRunsOnTheSlowCadence: re-asserting every local SID costs
// one synchronous netlink write per locator and per adjacency, so housekeeping
// sweeps them every sidReassertTicks instead of every tick — the sweep repairs
// a SID deleted out-of-band, which is rare, and is not the retry path for a
// write that failed (that one still runs every tick, see
// TestEndXFIBFailureIsCountedAndRepairedByHousekeeping).
func TestLocalSIDReassertRunsOnTheSlowCadence(t *testing.T) {
	now := time.Now()
	sid := netip.MustParseAddr("fc00:0:1:1::")
	s, rf := endXServer(t, io.Discard, []netip.Addr{netip.MustParseAddr("2001:db8::2")})
	// Housekeeping expires an adjacency it has not heard from; keep this one.
	s.circuits[0].p2pAdj.holding, s.circuits[0].p2pAdj.lastHeard = 30, now

	s.syncEndXSIDs(now)
	if _, ok := rf.getSID(sid); !ok {
		t.Fatal("the End.X SID was not installed when it was allocated")
	}
	// Someone removes the seg6local route behind our back.
	if err := rf.RemoveLocalSID(sid); err != nil {
		t.Fatalf("RemoveLocalSID: %v", err)
	}
	for range sidReassertTicks - 1 {
		s.housekeeping(now)
	}
	if _, ok := rf.getSID(sid); ok {
		t.Errorf("the local SIDs were re-asserted within %d ticks: that is a netlink write per SID per second", sidReassertTicks)
	}
	s.housekeeping(now)
	if _, ok := rf.getSID(sid); !ok {
		t.Errorf("the re-assert on the %dth tick did not repair a SID deleted out-of-band", sidReassertTicks)
	}
}
