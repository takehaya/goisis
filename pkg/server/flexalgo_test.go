package server

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/takehaya/goisis/pkg/datalink"
	"github.com/takehaya/goisis/pkg/packet"
)

// TestFlexAlgoAdvertised checks a participating node advertises the
// SR-Algorithm sub-TLV (algo 0 plus its Flex-Algos) and a FAD per advertised
// definition in its Router Capability TLV.
func TestFlexAlgoAdvertised(t *testing.T) {
	mock := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 1}, 1500)
	s := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(CircuitConfig{Name: "c", Transport: mock, Level2: true, Padding: ptrFalse()}),
		WithFlexAlgo(FlexAlgoConfig{Algo: 128, MetricType: packet.FlexAlgoMetricIGP, Priority: 100, AdvertiseDefinition: true}),
		WithFlexAlgo(FlexAlgoConfig{Algo: 129, Priority: 50}), // participate only
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Serve(ctx) //nolint:errcheck // ctx shutdown

	waitFor(t, "own LSP carries SR-Algorithm + FAD", func() bool {
		var sa *packet.SRAlgorithmSubTLV
		var fads []*packet.FlexAlgoDefinitionSubTLV
		for _, tlv := range ownLSPTLVs(t, s) {
			rc, ok := tlv.(*packet.RouterCapabilityTLV)
			if !ok {
				continue
			}
			for _, sub := range rc.SubTLVs {
				switch st := sub.(type) {
				case *packet.SRAlgorithmSubTLV:
					sa = st
				case *packet.FlexAlgoDefinitionSubTLV:
					fads = append(fads, st)
				}
			}
		}
		if sa == nil || len(fads) != 1 {
			return false
		}
		has := map[uint8]bool{}
		for _, a := range sa.Algorithms {
			has[a] = true
		}
		return has[0] && has[128] && has[129] &&
			fads[0].FlexAlgo == 128 && fads[0].Priority == 100 && fads[0].MetricType == packet.FlexAlgoMetricIGP
	})
}

// TestFlexAlgoElectionHighestPriority asserts the FAD with the highest priority
// wins regardless of advertiser System ID.
func TestFlexAlgoElectionHighestPriority(t *testing.T) {
	s := electionServer(t)
	now := time.Now()
	injectLSP(s, packet.SystemID{0, 0, 0, 0, 0, 2}, []packet.TLV{fadCap(100)}, now)
	injectLSP(s, packet.SystemID{0, 0, 0, 0, 0, 3}, []packet.TLV{fadCap(100)}, now)
	injectLSP(s, packet.SystemID{0, 0, 0, 0, 0, 4}, []packet.TLV{fadCap(200)}, now) // highest priority

	fi := s.flexAlgoState(packet.Level2, now)[128]
	if fi == nil || fi.Definition == nil {
		t.Fatal("no winner elected for algo 128")
	}
	if fi.Definition.Priority != 200 || fi.Definition.Advertiser != (packet.SystemID{0, 0, 0, 0, 0, 4}) {
		t.Errorf("winner = prio %d adv %s, want prio 200 adv ...04", fi.Definition.Priority, fi.Definition.Advertiser)
	}
	if len(fi.Participants) != 3 {
		t.Errorf("participants = %d, want 3", len(fi.Participants))
	}
}

// TestFlexAlgoElectionTieBreak asserts that equal priorities are broken by the
// highest advertising System ID.
func TestFlexAlgoElectionTieBreak(t *testing.T) {
	s := electionServer(t)
	now := time.Now()
	injectLSP(s, packet.SystemID{0, 0, 0, 0, 0, 2}, []packet.TLV{fadCap(100)}, now)
	injectLSP(s, packet.SystemID{0, 0, 0, 0, 0, 7}, []packet.TLV{fadCap(100)}, now) // highest System ID
	injectLSP(s, packet.SystemID{0, 0, 0, 0, 0, 5}, []packet.TLV{fadCap(100)}, now)

	fi := s.flexAlgoState(packet.Level2, now)[128]
	if fi == nil || fi.Definition == nil {
		t.Fatal("no winner elected")
	}
	if fi.Definition.Advertiser != (packet.SystemID{0, 0, 0, 0, 0, 7}) {
		t.Errorf("tie-break winner = %s, want ...07 (highest System ID)", fi.Definition.Advertiser)
	}
}

// TestFlexAlgoParticipateWithoutDefinition checks a node that lists an algo in
// SR-Algorithm but advertises no FAD appears as a participant with no elected
// definition.
func TestFlexAlgoParticipateWithoutDefinition(t *testing.T) {
	s := electionServer(t)
	now := time.Now()
	injectLSP(s, packet.SystemID{0, 0, 0, 0, 0, 2}, []packet.TLV{
		&packet.RouterCapabilityTLV{SubTLVs: []packet.SubTLV{&packet.SRAlgorithmSubTLV{Algorithms: []uint8{0, 130}}}},
	}, now)

	fi := s.flexAlgoState(packet.Level2, now)[130]
	if fi == nil {
		t.Fatal("algo 130 not tracked")
	}
	if fi.Definition != nil {
		t.Errorf("unexpected definition for algo 130: %+v", fi.Definition)
	}
	if len(fi.Participants) != 1 {
		t.Errorf("participants = %d, want 1", len(fi.Participants))
	}
}

// TestFlexAlgoParticipantDedup: a node carrying the algorithm in two Router
// Capability TLVs is counted once.
func TestFlexAlgoParticipantDedup(t *testing.T) {
	s := electionServer(t)
	now := time.Now()
	injectLSP(s, packet.SystemID{0, 0, 0, 0, 0, 2}, []packet.TLV{
		&packet.RouterCapabilityTLV{SubTLVs: []packet.SubTLV{&packet.SRAlgorithmSubTLV{Algorithms: []uint8{0, 128}}}},
		&packet.RouterCapabilityTLV{SubTLVs: []packet.SubTLV{&packet.SRAlgorithmSubTLV{Algorithms: []uint8{0, 128, 128}}}},
	}, now)
	fi := s.flexAlgoState(packet.Level2, now)[128]
	if fi == nil || len(fi.Participants) != 1 {
		t.Fatalf("participants = %+v, want exactly 1 (deduped)", fi)
	}
}

// TestFlexAlgoConfigValidation covers the construction-time guards: a reserved
// algo, a duplicate Flex-Algo, and a flex-algo locator without participation
// are all rejected; the matching valid config is accepted.
func TestFlexAlgoConfigValidation(t *testing.T) {
	base := func() []ServerOption {
		return []ServerOption{
			WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
			WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
			WithCircuit(CircuitConfig{Name: "c", Transport: datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 1}, 1500), Level2: true, Padding: ptrFalse()}),
		}
	}
	loc := netip.MustParsePrefix("fc00:128::/48")

	if _, err := NewIsisServer(append(base(), WithFlexAlgo(FlexAlgoConfig{Algo: 5}))...); err == nil {
		t.Error("expected error for reserved Flex-Algo (<128)")
	}
	if _, err := NewIsisServer(append(base(), WithFlexAlgo(FlexAlgoConfig{Algo: 128}), WithFlexAlgo(FlexAlgoConfig{Algo: 128}))...); err == nil {
		t.Error("expected error for duplicate Flex-Algo")
	}
	if _, err := NewIsisServer(append(base(), WithSRv6LocatorForAlgo(loc, 128))...); err == nil {
		t.Error("expected error for flex-algo locator without participation")
	}
	if _, err := NewIsisServer(append(base(), WithFlexAlgo(FlexAlgoConfig{Algo: 128}), WithSRv6LocatorForAlgo(loc, 128))...); err != nil {
		t.Errorf("valid flex-algo + locator config rejected: %v", err)
	}
}

func electionServer(t *testing.T) *IsisServer {
	t.Helper()
	return mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(CircuitConfig{Name: "c", Transport: datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 1}, 1500), Level2: true, Padding: ptrFalse()}),
	)
}

// fadCap builds a Router Capability TLV advertising algo 128 (participation +
// definition) at the given priority.
func fadCap(prio uint8) packet.TLV {
	return &packet.RouterCapabilityTLV{SubTLVs: []packet.SubTLV{
		&packet.SRAlgorithmSubTLV{Algorithms: []uint8{0, 128}},
		&packet.FlexAlgoDefinitionSubTLV{FlexAlgo: 128, MetricType: packet.FlexAlgoMetricIGP, Priority: prio},
	}}
}

// partCap advertises participation in algorithms 0 and 128.
func partCap() packet.TLV {
	return &packet.RouterCapabilityTLV{SubTLVs: []packet.SubTLV{
		&packet.SRAlgorithmSubTLV{Algorithms: []uint8{0, 128}},
	}}
}

// isReach builds an Extended IS Reachability TLV with metric-10 edges to each
// neighbor.
func isReach(neighbors ...packet.SystemID) packet.TLV {
	var nbs []packet.ExtendedISReachEntry
	for _, n := range neighbors {
		nbs = append(nbs, packet.ExtendedISReachEntry{NeighborID: nodeID(n, 0), Metric: 10})
	}
	return &packet.ExtendedISReachabilityTLV{Neighbors: nbs}
}

// algoLocTLV builds an SRv6 Locator TLV with one locator bound to algo.
func algoLocTLV(algo uint8, p netip.Prefix) packet.TLV {
	return &packet.SRv6LocatorTLV{Locators: []packet.SRv6Locator{{Algorithm: algo, Locator: p}}}
}

// TestFlexAlgoSPFIsolatesAlgo: a flex-algo locator is reachable under its
// algorithm but never leaks into algorithm 0 (disjoint prefix space, no
// fallback).
func TestFlexAlgoSPFIsolatesAlgo(t *testing.T) {
	s := electionServer(t)
	now := time.Now()
	self := packet.SystemID{0, 0, 0, 0, 0, 1}
	peer := packet.SystemID{0, 0, 0, 0, 0, 2}
	loc := netip.MustParsePrefix("fc00:128:2::/48")

	injectLSP(s, self, []packet.TLV{partCap(), isReach(peer)}, now)
	injectLSP(s, peer, []packet.TLV{partCap(), isReach(self), algoLocTLV(128, loc)}, now)

	if _, ok := s.computeSPF(packet.Level2, 128, now)[loc]; !ok {
		t.Error("algo 128 did not reach the flex-algo locator")
	}
	if _, ok := s.computeSPF(packet.Level2, 0, now)[loc]; ok {
		t.Error("algorithm-0 SPF leaked a flex-algo locator")
	}
}

// TestFlexAlgoSPFPrunesNonParticipant: a flex-algo path must not transit a node
// that does not participate in the algorithm; once that node participates, the
// path appears (proving the prune, not some other break, blocked it).
func TestFlexAlgoSPFPrunesNonParticipant(t *testing.T) {
	s := electionServer(t)
	now := time.Now()
	self := packet.SystemID{0, 0, 0, 0, 0, 1}
	mid := packet.SystemID{0, 0, 0, 0, 0, 2}
	far := packet.SystemID{0, 0, 0, 0, 0, 3}
	loc := netip.MustParsePrefix("fc00:128:3::/48")

	injectLSP(s, self, []packet.TLV{partCap(), isReach(mid)}, now)
	injectLSP(s, far, []packet.TLV{partCap(), isReach(mid), algoLocTLV(128, loc)}, now)

	// mid does NOT participate: far is behind it, so unreachable in algo 128.
	injectLSP(s, mid, []packet.TLV{isReach(self, far)}, now)
	if _, ok := s.computeSPF(packet.Level2, 128, now)[loc]; ok {
		t.Error("flex-algo route leaked through a non-participating transit node")
	}

	// mid now participates: the path becomes valid.
	injectLSP(s, mid, []packet.TLV{partCap(), isReach(self, far)}, now)
	if _, ok := s.computeSPF(packet.Level2, 128, now)[loc]; !ok {
		t.Error("flex-algo route not found once the transit node participates")
	}
}

// TestFlexAlgo3NodeSelfInterop is the SRv6 x Flex-Algo self-interop check the
// plan calls for: three goisis nodes in a line A-B-C, all participating in algo
// 128, where C advertises an algo-128 SRv6 locator. A must install C's locator
// via the multi-hop algo-128 path with B as its next hop, and tag it algo 128.
func TestFlexAlgo3NodeSelfInterop(t *testing.T) {
	// Two point-to-point links: A<->B and B<->C.
	taB := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0xa, 1}, 1500)
	tbA := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0xb, 1}, 1500)
	datalink.Link(taB, tbA)
	tbC := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0xb, 2}, 1500)
	tcB := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0xc, 1}, 1500)
	datalink.Link(tbC, tcB)

	area := packet.AreaAddress{0x49, 0x00, 0x01}
	loc := netip.MustParsePrefix("fc00:128:3::/48")
	bToA := netip.MustParseAddr("fe80::b1") // B's address on the A-B link = A's next hop

	p2p := func(name string, tr datalink.Transport, ll netip.Addr) CircuitConfig {
		c := CircuitConfig{Name: name, Transport: tr, P2P: true, Level2: true, Padding: ptrFalse(), IPv6Addrs: []netip.Addr{ll}}
		fastHello(&c)
		return c
	}
	fa := func(advertise bool) ServerOption {
		return WithFlexAlgo(FlexAlgoConfig{Algo: 128, MetricType: packet.FlexAlgoMetricIGP, Priority: 100, AdvertiseDefinition: advertise})
	}

	afib := newRecordFIB()
	a := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}), WithAreaAddresses(area),
		WithCircuit(p2p("a", taB, netip.MustParseAddr("fe80::a1"))), fa(false), WithFIB(afib),
	)
	b := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 2}), WithAreaAddresses(area),
		WithCircuit(p2p("b1", tbA, bToA)), WithCircuit(p2p("b2", tbC, netip.MustParseAddr("fe80::b2"))), fa(false),
	)
	c := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 3}), WithAreaAddresses(area),
		WithCircuit(p2p("c", tcB, netip.MustParseAddr("fe80::c1"))), fa(true), WithSRv6LocatorForAlgo(loc, 128),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for _, s := range []*IsisServer{a, b, c} {
		go s.Serve(ctx) //nolint:errcheck // ctx shutdown
	}

	waitFor(t, "A installs C's flex-algo locator via B", func() bool {
		nh, ok := afib.get(loc)
		return ok && len(nh) == 1 && nh[0].Gateway == bToA && nh[0].Interface == "a"
	})
	waitFor(t, "A's RIB tags the route algorithm 128", func() bool {
		routes, err := a.ListRoutes(context.Background())
		if err != nil {
			return false
		}
		for _, r := range routes {
			if r.Prefix == loc {
				return r.Algorithm == 128
			}
		}
		return false
	})
}

// TestFlexAlgoLocatorInstalled drives the full per-algo path between two linked
// servers: both participate in algo 128, A advertises an algo-128 locator and
// the definition, and B installs the locator route tagged with algorithm 128.
func TestFlexAlgoLocatorInstalled(t *testing.T) {
	ta := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xa1}, 1500)
	tb := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xb2}, 1500)
	datalink.Link(ta, tb)

	area := packet.AreaAddress{0x49, 0x00, 0x01}
	loc := netip.MustParsePrefix("fc00:128:1::/48")
	aLL := netip.MustParseAddr("fe80::a1")

	cfgA := CircuitConfig{Name: "a", Transport: ta, Level2: true, Padding: ptrFalse(), IPv6Addrs: []netip.Addr{aLL}}
	cfgB := CircuitConfig{Name: "b", Transport: tb, Level2: true, Padding: ptrFalse(), IPv6Addrs: []netip.Addr{netip.MustParseAddr("fe80::b2")}}
	fastHello(&cfgA)
	fastHello(&cfgB)

	a := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}), WithAreaAddresses(area), WithCircuit(cfgA),
		WithFlexAlgo(FlexAlgoConfig{Algo: 128, MetricType: packet.FlexAlgoMetricIGP, Priority: 100, AdvertiseDefinition: true}),
		WithSRv6LocatorForAlgo(loc, 128),
	)
	bfib := newRecordFIB()
	b := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 2}), WithAreaAddresses(area), WithCircuit(cfgB), WithFIB(bfib),
		WithFlexAlgo(FlexAlgoConfig{Algo: 128, MetricType: packet.FlexAlgoMetricIGP, Priority: 50}), // participate only
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx) //nolint:errcheck // ctx shutdown
	go b.Serve(ctx) //nolint:errcheck // ctx shutdown

	waitFor(t, "b installs the flex-algo locator via A", func() bool {
		nh, ok := bfib.get(loc)
		return ok && len(nh) == 1 && nh[0].Gateway == aLL && nh[0].Interface == "b"
	})
	waitFor(t, "b's RIB tags the route algorithm 128", func() bool {
		routes, err := b.ListRoutes(context.Background())
		if err != nil {
			return false
		}
		for _, r := range routes {
			if r.Prefix == loc {
				return r.Algorithm == 128
			}
		}
		return false
	})
}
