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

// TestSRv6LocatorAdvertisedAndLearned drives the full SRv6 locator path between
// two linked servers: the originator installs its local End SID, and the peer
// learns the locator prefix (via the TLV 236 mirror / TLV 27) and programs it
// with the originator's link-local next hop.
func TestSRv6LocatorAdvertisedAndLearned(t *testing.T) {
	ta := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xa1}, 1500)
	tb := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xb2}, 1500)
	datalink.Link(ta, tb)

	area := packet.AreaAddress{0x49, 0x00, 0x01}
	locator := netip.MustParsePrefix("fc00:0:1::/48")
	aLL := netip.MustParseAddr("fe80::a1") // A's link-local, advertised in hellos

	cfgA := CircuitConfig{Name: "a", Transport: ta, Level2: true, Padding: ptrFalse(), IPv6Addrs: []netip.Addr{aLL}}
	cfgB := CircuitConfig{Name: "b", Transport: tb, Level2: true, Padding: ptrFalse(), IPv6Addrs: []netip.Addr{netip.MustParseAddr("fe80::b2")}}
	fastHello(&cfgA)
	fastHello(&cfgB)

	afib := newRecordFIB()
	a := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}), WithAreaAddresses(area),
		WithCircuit(cfgA), WithSRv6Locator(locator), WithFIB(afib),
	)
	bfib := newRecordFIB()
	b := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 2}), WithAreaAddresses(area),
		WithCircuit(cfgB), WithFIB(bfib),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx) //nolint:errcheck // ctx shutdown
	go b.Serve(ctx) //nolint:errcheck // ctx shutdown

	// A instantiates the local End SID at the locator's base address.
	waitFor(t, "a installed local End SID", func() bool {
		s, ok := afib.getSID(locator.Masked().Addr())
		return ok && s.Behavior == fib.BehaviorEnd
	})

	// B learns the locator prefix with A as the resolved next hop.
	waitFor(t, "b learned locator route", func() bool {
		nh, ok := bfib.get(locator)
		return ok && len(nh) == 1 && nh[0].Gateway == aLL && nh[0].Interface == "b"
	})

	// A's own LSP must carry the Router Capability TLV (SRv6 caps) and the
	// SRv6 Locator TLV.
	waitFor(t, "a LSP advertises SRv6 TLVs", func() bool {
		caps, locTLV := false, false
		for _, tlv := range ownLSPTLVs(t, a) {
			switch tlv.(type) {
			case *packet.RouterCapabilityTLV:
				caps = true
			case *packet.SRv6LocatorTLV:
				locTLV = true
			}
		}
		return caps && locTLV
	})
}

// ownLSPTLVs returns the decoded TLVs of this server's own fragment-0 LSP at a
// level (white-box access to the LSDB on the Serve goroutine).
func ownLSPTLVs(t *testing.T, s *IsisServer) []packet.TLV {
	t.Helper()
	var tlvs []packet.TLV
	if err := s.mgmtOperation(context.Background(), func() error {
		if e := s.dbs[packet.Level2].get(lspID(s.systemID, 0)); e != nil {
			tlvs = e.lsp.TLVs
		}
		return nil
	}); err != nil {
		t.Fatalf("mgmtOperation: %v", err)
	}
	return tlvs
}

// TestSRv6LocatorSPFPreferPrefixReachability checks that when a node advertises
// the same prefix in both IPv6 reachability (TLV 236) and the SRv6 Locator TLV
// (27), SPF uses the prefix-reachability entry (its metric wins, the locator is
// not double-counted), and that a locator-only prefix is still installed.
func TestSRv6LocatorSPFPreferPrefixReachability(t *testing.T) {
	mock := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 1}, 1500)
	s := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(CircuitConfig{Name: "c", Transport: mock, Level2: true, Padding: ptrFalse()}),
	)
	now := time.Now()
	self := packet.SystemID{0, 0, 0, 0, 0, 1}
	peer := packet.SystemID{0, 0, 0, 0, 0, 2}

	mirrored := netip.MustParsePrefix("fc00:0:1::/48") // in both 236 and 27
	locOnly := netip.MustParsePrefix("fc00:0:2::/48")  // in 27 only

	// Self LSP: an edge to the peer at metric 10.
	injectLSP(s, self, []packet.TLV{
		&packet.ExtendedISReachabilityTLV{Neighbors: []packet.ExtendedISReachEntry{{NeighborID: nodeID(peer, 0), Metric: 10}}},
	}, now)
	// Peer LSP: edge back to self, plus the mirrored prefix at metric 5 in TLV
	// 236 and both locators in TLV 27 at metric 0.
	injectLSP(s, peer, []packet.TLV{
		&packet.ExtendedISReachabilityTLV{Neighbors: []packet.ExtendedISReachEntry{{NeighborID: nodeID(self, 0), Metric: 10}}},
		&packet.IPv6ReachabilityTLV{Prefixes: []packet.IPv6ReachEntry{{Metric: 5, Prefix: mirrored}}},
		&packet.SRv6LocatorTLV{Locators: []packet.SRv6Locator{
			{Metric: 0, Locator: mirrored},
			{Metric: 0, Locator: locOnly},
		}},
	}, now)

	routes := s.computeSPF(packet.Level2, 0, now)

	// The mirrored prefix uses the TLV 236 metric (10 + 5), not the locator's
	// 0; the locator entry must not be double-counted as a cheaper route.
	r, ok := routes[mirrored]
	if !ok {
		t.Fatalf("mirrored prefix %s not reachable", mirrored)
	}
	if r.metric != 15 {
		t.Errorf("mirrored prefix metric = %d, want 15 (prefer prefix reachability)", r.metric)
	}
	// The locator-only prefix is reachable via TLV 27 (10 + 0).
	r2, ok := routes[locOnly]
	if !ok {
		t.Fatalf("locator-only prefix %s not reachable", locOnly)
	}
	if r2.metric != 10 {
		t.Errorf("locator-only prefix metric = %d, want 10", r2.metric)
	}
}

// TestSRv6SPFMasksHostBits is a regression for the route-reaping bug: a peer
// that leaves host bits set in a locator/prefix must still produce a canonical
// (masked) RIB key, matching the masked prefix the FIB installs into the kernel
// (otherwise the startup sweep, which keys on the kernel prefix, deletes the
// route).
func TestSRv6SPFMasksHostBits(t *testing.T) {
	mock := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 1}, 1500)
	s := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(CircuitConfig{Name: "c", Transport: mock, Level2: true, Padding: ptrFalse()}),
	)
	now := time.Now()
	self := packet.SystemID{0, 0, 0, 0, 0, 1}
	peer := packet.SystemID{0, 0, 0, 0, 0, 2}

	// A non-canonical prefix (host bits set beyond the /48).
	noncanon := netip.MustParsePrefix("fc00:0:1:abcd::/48")
	canon := noncanon.Masked()

	injectLSP(s, self, []packet.TLV{
		&packet.ExtendedISReachabilityTLV{Neighbors: []packet.ExtendedISReachEntry{{NeighborID: nodeID(peer, 0), Metric: 10}}},
	}, now)
	injectLSP(s, peer, []packet.TLV{
		&packet.ExtendedISReachabilityTLV{Neighbors: []packet.ExtendedISReachEntry{{NeighborID: nodeID(self, 0), Metric: 10}}},
		&packet.IPv6ReachabilityTLV{Prefixes: []packet.IPv6ReachEntry{{Metric: 5, Prefix: noncanon}}},
	}, now)

	routes := s.computeSPF(packet.Level2, 0, now)
	if _, ok := routes[canon]; !ok {
		t.Errorf("route key not canonicalized: want %s in %v", canon, keys(routes))
	}
	if _, ok := routes[noncanon]; ok {
		t.Errorf("non-canonical prefix %s leaked into RIB keys", noncanon)
	}
}

func keys(m map[netip.Prefix]route) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestSRv6LocalSIDLifecycle covers install (idempotent) and the shutdown
// removal of the local End SID (regression for the seg6local leak).
func TestSRv6LocalSIDLifecycle(t *testing.T) {
	rf := newRecordFIB()
	loc := netip.MustParsePrefix("fc00:0:1::/48")
	s := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(CircuitConfig{Name: "c", Transport: datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 1}, 1500), Level2: true, Padding: ptrFalse()}),
		WithSRv6Locator(loc), WithFIB(rf),
	)
	sid := loc.Masked().Addr()

	s.installLocalSIDs()
	s.installLocalSIDs() // idempotent
	if got, ok := rf.getSID(sid); !ok || got.Behavior != fib.BehaviorEnd {
		t.Fatalf("End SID not installed: ok=%v %+v", ok, got)
	}
	s.removeLocalSIDs()
	if _, ok := rf.getSID(sid); ok {
		t.Error("End SID leaked: still present after removeLocalSIDs")
	}
}

// TestSIDStructureClamp checks the SID Structure never exceeds 128 bits, even
// for long locators where the 16-bit function would not fit.
func TestSIDStructureClamp(t *testing.T) {
	for _, tc := range []struct {
		prefix          string
		block, node, fn uint8
	}{
		{"fc00:0:1::/48", 32, 16, 16},
		{"fc00::/32", 32, 0, 16},
		{"fc00::/120", 32, 88, 8},
		{"fc00::/128", 32, 96, 0},
		{"fc00::/16", 16, 0, 16},
	} {
		s := SRv6LocatorConfig{Prefix: netip.MustParsePrefix(tc.prefix)}.sidStructure()
		if s.LocatorBlock != tc.block || s.LocatorNode != tc.node || s.Function != tc.fn {
			t.Errorf("%s: structure = {block:%d node:%d func:%d}, want {%d %d %d}",
				tc.prefix, s.LocatorBlock, s.LocatorNode, s.Function, tc.block, tc.node, tc.fn)
		}
		if total := int(s.LocatorBlock) + int(s.LocatorNode) + int(s.Function) + int(s.Argument); total > 128 {
			t.Errorf("%s: structure total %d bits exceeds 128", tc.prefix, total)
		}
	}
}

// injectLSP installs a synthetic fragment-0 L2 LSP into the LSDB for tests.
func injectLSP(s *IsisServer, id packet.SystemID, tlvs []packet.TLV, now time.Time) {
	lid := lspID(id, 0)
	lsp := &packet.LSP{
		Level:          packet.Level2,
		RemainingTime:  maxAgeSeconds,
		LSPID:          lid,
		SequenceNumber: 1,
		ISType:         2,
		TLVs:           tlvs,
	}
	s.dbs[packet.Level2].entries[lid] = &lspEntry{lsp: lsp, inserted: now, lifetime: maxAgeSeconds}
}
