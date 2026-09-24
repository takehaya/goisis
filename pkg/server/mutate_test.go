package server

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/takehaya/goisis/pkg/datalink"
	"github.com/takehaya/goisis/pkg/fib"
	"github.com/takehaya/goisis/pkg/packet"
)

// hasLocatorTLV reports whether this node's own LSP advertises the given
// locator prefix in an SRv6 Locator TLV.
func hasLocatorTLV(t *testing.T, s *IsisServer, p netip.Prefix) bool {
	t.Helper()
	for _, tlv := range ownLSPTLVs(t, s) {
		lt, ok := tlv.(*packet.SRv6LocatorTLV)
		if !ok {
			continue
		}
		for _, l := range lt.Locators {
			if l.Locator.Masked() == p.Masked() {
				return true
			}
		}
	}
	return false
}

// hasSRAlgo reports whether this node's own LSP advertises participation in the
// given algorithm in its SR-Algorithm sub-TLV.
func hasSRAlgo(t *testing.T, s *IsisServer, algo uint8) bool {
	t.Helper()
	for _, tlv := range ownLSPTLVs(t, s) {
		rc, ok := tlv.(*packet.RouterCapabilityTLV)
		if !ok {
			continue
		}
		for _, st := range rc.SubTLVs {
			sa, ok := st.(*packet.SRAlgorithmSubTLV)
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

// mutateServer returns a single running server with a recording FIB.
func mutateServer(t *testing.T) (*IsisServer, *recordFIB, context.CancelFunc) {
	t.Helper()
	cfg := CircuitConfig{Name: "c", Transport: datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 1}, 1500), Level2: true, Padding: ptrFalse()}
	fastHello(&cfg)
	rf := newRecordFIB()
	s := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(cfg), WithFIB(rf),
	)
	ctx, cancel := context.WithCancel(context.Background())
	go s.Serve(ctx) //nolint:errcheck // ctx shutdown
	return s, rf, cancel
}

func TestAddDeleteLocator(t *testing.T) {
	s, rf, cancel := mutateServer(t)
	defer cancel()
	ctx := context.Background()
	loc := netip.MustParsePrefix("fc00:0:1::/48")

	if err := s.AddLocator(ctx, SRv6LocatorConfig{Prefix: loc}); err != nil {
		t.Fatalf("AddLocator: %v", err)
	}
	// The local End SID is installed and the locator is advertised.
	waitFor(t, "End SID installed", func() bool {
		sid, ok := rf.getSID(loc.Masked().Addr())
		return ok && sid.Behavior == fib.BehaviorEnd
	})
	waitFor(t, "locator advertised", func() bool { return hasLocatorTLV(t, s, loc) })

	// Re-adding the same locator is rejected.
	if err := s.AddLocator(ctx, SRv6LocatorConfig{Prefix: loc}); err == nil {
		t.Error("expected error re-adding an existing locator")
	}
	// A non-IPv6 locator is rejected.
	if err := s.AddLocator(ctx, SRv6LocatorConfig{Prefix: netip.MustParsePrefix("10.0.0.0/24")}); err == nil {
		t.Error("expected error for non-IPv6 locator")
	}

	if err := s.DeleteLocator(ctx, loc); err != nil {
		t.Fatalf("DeleteLocator: %v", err)
	}
	waitFor(t, "End SID removed", func() bool {
		_, ok := rf.getSID(loc.Masked().Addr())
		return !ok
	})
	waitFor(t, "locator withdrawn", func() bool { return !hasLocatorTLV(t, s, loc) })

	// Deleting an unknown locator is rejected.
	if err := s.DeleteLocator(ctx, loc); err == nil {
		t.Error("expected error deleting an unadvertised locator")
	}
}

func TestAddDeleteFlexAlgo(t *testing.T) {
	s, _, cancel := mutateServer(t)
	defer cancel()
	ctx := context.Background()

	if err := s.AddFlexAlgo(ctx, FlexAlgoConfig{Algo: 128, Priority: 100, AdvertiseDefinition: true}); err != nil {
		t.Fatalf("AddFlexAlgo: %v", err)
	}
	waitFor(t, "algo 128 advertised", func() bool { return hasSRAlgo(t, s, 128) })

	// Reserved and duplicate algorithms are rejected.
	if err := s.AddFlexAlgo(ctx, FlexAlgoConfig{Algo: 5}); err == nil {
		t.Error("expected error for reserved Flex-Algo (<128)")
	}
	if err := s.AddFlexAlgo(ctx, FlexAlgoConfig{Algo: 128}); err == nil {
		t.Error("expected error for duplicate Flex-Algo")
	}

	// Binding a locator to the algo, then attempting to delete the algo, is
	// rejected until the locator is removed.
	loc := netip.MustParsePrefix("fc00:0:128::/48")
	if err := s.AddLocator(ctx, SRv6LocatorConfig{Prefix: loc, Algo: 128}); err != nil {
		t.Fatalf("AddLocator(algo): %v", err)
	}
	if err := s.DeleteFlexAlgo(ctx, 128); err == nil {
		t.Error("expected error deleting Flex-Algo with a bound locator")
	}
	if err := s.DeleteLocator(ctx, loc); err != nil {
		t.Fatalf("DeleteLocator: %v", err)
	}
	if err := s.DeleteFlexAlgo(ctx, 128); err != nil {
		t.Fatalf("DeleteFlexAlgo: %v", err)
	}
	waitFor(t, "algo 128 withdrawn", func() bool { return !hasSRAlgo(t, s, 128) })

	// Deleting an unknown algo is rejected.
	if err := s.DeleteFlexAlgo(ctx, 200); err == nil {
		t.Error("expected error deleting an unconfigured Flex-Algo")
	}
}

// TestAddLocatorRequiresAlgoParticipation checks a flex-algo-bound locator is
// rejected until the node participates in that algorithm.
func TestAddLocatorRequiresAlgoParticipation(t *testing.T) {
	s, _, cancel := mutateServer(t)
	defer cancel()
	ctx := context.Background()
	loc := netip.MustParsePrefix("fc00:0:128::/48")

	if err := s.AddLocator(ctx, SRv6LocatorConfig{Prefix: loc, Algo: 128}); err == nil {
		t.Error("expected error binding a locator to an unparticipated algo")
	}
	if err := s.AddFlexAlgo(ctx, FlexAlgoConfig{Algo: 128}); err != nil {
		t.Fatalf("AddFlexAlgo: %v", err)
	}
	if err := s.AddLocator(ctx, SRv6LocatorConfig{Prefix: loc, Algo: 128}); err != nil {
		t.Errorf("AddLocator after participation: %v", err)
	}
}

// hasPrefixTLV reports whether this node's own LSP advertises the given prefix
// in its IP reachability TLVs (135 for IPv4, 236 for IPv6).
func hasPrefixTLV(t *testing.T, s *IsisServer, p netip.Prefix) bool {
	t.Helper()
	for _, tlv := range ownLSPTLVs(t, s) {
		switch r := tlv.(type) {
		case *packet.ExtendedIPReachabilityTLV:
			for _, e := range r.Prefixes {
				if e.Prefix.Masked() == p.Masked() {
					return true
				}
			}
		case *packet.IPv6ReachabilityTLV:
			for _, e := range r.Prefixes {
				if e.Prefix.Masked() == p.Masked() {
					return true
				}
			}
		}
	}
	return false
}

// ownLSPSeq returns the sequence number of this node's own fragment-0 LSP.
func ownLSPSeq(t *testing.T, s *IsisServer) uint32 {
	t.Helper()
	var seq uint32
	if err := s.mgmtOperation(context.Background(), func() error {
		if e := s.dbs[packet.Level2].get(lspID(s.systemID, 0)); e != nil {
			seq = e.lsp.SequenceNumber
		}
		return nil
	}); err != nil {
		t.Fatalf("mgmtOperation: %v", err)
	}
	return seq
}

// mutatePair returns two servers converged at Level 2 over one link — a LAN, or
// point-to-point when p2p — A with an IPv4 interface address so its prefixes
// resolve to a next hop on B.
func mutatePair(t *testing.T, p2p bool) (*IsisServer, *IsisServer, context.CancelFunc) {
	t.Helper()
	ta := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xa1}, 1500)
	tb := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xb2}, 1500)
	datalink.Link(ta, tb)

	area := packet.AreaAddress{0x49, 0x00, 0x01}
	cfgA := CircuitConfig{Name: "a", Transport: ta, P2P: p2p, Level2: true, Padding: ptrFalse(), IPv4Addrs: []netip.Addr{netip.MustParseAddr("10.0.0.1")}}
	cfgB := CircuitConfig{Name: "b", Transport: tb, P2P: p2p, Level2: true, Padding: ptrFalse(), IPv4Addrs: []netip.Addr{netip.MustParseAddr("10.0.0.2")}}
	fastHello(&cfgA)
	fastHello(&cfgB)

	a := mustServer(t, WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}), WithAreaAddresses(area), WithCircuit(cfgA))
	b := mustServer(t, WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 2}), WithAreaAddresses(area), WithCircuit(cfgB))

	ctx, cancel := context.WithCancel(context.Background())
	go a.Serve(ctx) //nolint:errcheck // ctx shutdown
	go b.Serve(ctx) //nolint:errcheck // ctx shutdown
	waitFor(t, "a sees b Up", func() bool { st, ok := adjState(t, a, packet.Level2); return ok && st == AdjUp })
	waitFor(t, "b sees a Up", func() bool { st, ok := adjState(t, b, packet.Level2); return ok && st == AdjUp })
	return a, b, cancel
}

func TestAddDeletePrefix(t *testing.T) {
	s, _, cancel := mutateServer(t)
	defer cancel()
	ctx := context.Background()
	v4 := netip.MustParsePrefix("10.9.9.0/24")
	v6 := netip.MustParsePrefix("fc00:9::/64")

	if err := s.AddPrefix(ctx, AdvertisedPrefix{Prefix: v4, Metric: 10}); err != nil {
		t.Fatalf("AddPrefix(v4): %v", err)
	}
	if err := s.AddPrefix(ctx, AdvertisedPrefix{Prefix: v6, Metric: 20}); err != nil {
		t.Fatalf("AddPrefix(v6): %v", err)
	}
	waitFor(t, "prefixes advertised", func() bool { return hasPrefixTLV(t, s, v4) && hasPrefixTLV(t, s, v6) })

	// A prefix already advertised is rejected, matched on its masked form.
	if err := s.AddPrefix(ctx, AdvertisedPrefix{Prefix: netip.MustParsePrefix("10.9.9.7/24")}); err == nil {
		t.Error("expected error re-adding an advertised prefix")
	}
	// An invalid prefix is rejected.
	if err := s.AddPrefix(ctx, AdvertisedPrefix{}); err == nil {
		t.Error("expected error for an invalid prefix")
	}

	seq := ownLSPSeq(t, s)
	if err := s.DeletePrefix(ctx, v4); err != nil {
		t.Fatalf("DeletePrefix: %v", err)
	}
	waitFor(t, "prefix withdrawn", func() bool { return !hasPrefixTLV(t, s, v4) })
	if got := ownLSPSeq(t, s); got <= seq {
		t.Errorf("own LSP sequence = %d, want > %d (the withdrawal must re-originate)", got, seq)
	}

	// Deleting an unadvertised prefix is rejected.
	if err := s.DeletePrefix(ctx, v4); err == nil {
		t.Error("expected error deleting an unadvertised prefix")
	}
}

// TestAddPrefixRejectsUnroutablePrefixesAndUnusableMetrics pins the validation
// the runtime API owes the LSDB: a prefix nobody can route to is never
// originated, and neither is a metric SPF would treat as unreachable. The
// default route is not unroutable — default-information origination is
// legitimate, and suppressing it is policy.advertise's job.
//
// The configuration path owes the LSDB exactly the same, and is asserted on
// the same table: a prefix only the mutator refused made a file the daemon
// starts on a file it cannot reload (config.Diff).
func TestAddPrefixRejectsUnroutablePrefixesAndUnusableMetrics(t *testing.T) {
	s, _, cancel := mutateServer(t)
	defer cancel()
	ctx := context.Background()

	for _, tc := range []struct {
		prefix string
		metric uint32
		ok     bool
	}{
		{"224.0.0.0/4", 10, false},               // IPv4 multicast
		{"ff00::/8", 10, false},                  // IPv6 multicast
		{"169.254.0.0/16", 10, false},            // IPv4 link-local
		{"fe80::/10", 10, false},                 // IPv6 link-local
		{"::ffff:10.0.0.0/120", 10, false},       // IPv4-mapped IPv6
		{"0.0.0.0/8", 10, false},                 // unspecified, not the default route
		{"::/8", 10, false},                      // unspecified, not the default route
		{"10.1.0.0/16", maxPathMetric, false},    // at the reachability ceiling
		{"10.2.0.0/16", maxPathMetric - 1, true}, // just below it
		{"0.0.0.0/0", 10, true},                  // default-information origination
		{"::/0", 10, true},                       // default-information origination
		{"fc00:1::/64", 0, true},                 // an ordinary ULA prefix
	} {
		p := AdvertisedPrefix{Prefix: netip.MustParsePrefix(tc.prefix), Metric: tc.metric}
		if err := s.AddPrefix(ctx, p); (err == nil) != tc.ok {
			t.Errorf("AddPrefix(%s, metric %d) err = %v, want ok=%v", tc.prefix, tc.metric, err, tc.ok)
		}
		if err := ValidateOptions(WithAdvertisedPrefix(p.Prefix, p.Metric)); (err == nil) != tc.ok {
			t.Errorf("configured prefix %s, metric %d: err = %v, want ok=%v", tc.prefix, tc.metric, err, tc.ok)
		}
	}
}

// TestAddPrefixReachesPeerRIB checks a runtime prefix floods and is installed
// by the peer, and that deleting it withdraws the peer's route.
func TestAddPrefixReachesPeerRIB(t *testing.T) {
	a, b, cancel := mutatePair(t, false)
	defer cancel()
	ctx := context.Background()
	dst := netip.MustParsePrefix("10.9.9.0/24")

	hasRoute := func() bool {
		routes, err := b.ListRoutes(ctx)
		if err != nil {
			return false
		}
		for _, r := range routes {
			if r.Prefix == dst {
				return true
			}
		}
		return false
	}

	if err := a.AddPrefix(ctx, AdvertisedPrefix{Prefix: dst, Metric: 10}); err != nil {
		t.Fatalf("AddPrefix: %v", err)
	}
	waitFor(t, "b installs a's new prefix", hasRoute)

	if err := a.DeletePrefix(ctx, dst); err != nil {
		t.Fatalf("DeletePrefix: %v", err)
	}
	waitFor(t, "b withdraws the deleted prefix", func() bool { return !hasRoute() })
}

func TestSetOverload(t *testing.T) {
	s, _, cancel := mutateServer(t)
	defer cancel()
	ctx := context.Background()

	if err := s.SetOverload(ctx, true); err != nil {
		t.Fatalf("SetOverload(true): %v", err)
	}
	waitFor(t, "own LSP has the overload bit set", func() bool { set, ok := ownOverload(t, s); return ok && set })
	g, err := s.GetGlobal(ctx)
	if err != nil {
		t.Fatalf("GetGlobal: %v", err)
	}
	if !g.Overload {
		t.Error("GetGlobal().Overload = false, want true while overloaded")
	}

	if err := s.SetOverload(ctx, false); err != nil {
		t.Fatalf("SetOverload(false): %v", err)
	}
	waitFor(t, "own LSP clears the overload bit", func() bool { set, ok := ownOverload(t, s); return ok && !set })
	if g, err = s.GetGlobal(ctx); err != nil {
		t.Fatalf("GetGlobal: %v", err)
	} else if g.Overload {
		t.Error("GetGlobal().Overload = true, want false once cleared")
	}
}

func TestClearAdjacency(t *testing.T) {
	a, _, cancel := mutatePair(t, false)
	defer cancel()
	ctx := context.Background()

	sub, err := a.Subscribe(ctx)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer sub.Unsubscribe()

	if err := a.ClearAdjacency(ctx, "a", nil); err != nil {
		t.Fatalf("ClearAdjacency: %v", err)
	}
	deadline := time.After(3 * time.Second)
	for down := false; !down; {
		select {
		case ev, ok := <-sub.Events:
			if !ok {
				t.Fatal("watch channel closed unexpectedly")
			}
			down = ev.Adjacency != nil && ev.Adjacency.State == AdjDown
		case <-deadline:
			t.Fatal("timed out waiting for the adjacency Down event")
		}
	}
	// Hellos re-form the adjacency without any further action.
	waitFor(t, "adjacency re-forms", func() bool { st, ok := adjState(t, a, packet.Level2); return ok && st == AdjUp })

	// Clearing an adjacency that does not exist is a no-op, not an error.
	absent := packet.SystemID{0, 0, 0, 0, 0, 9}
	if err := a.ClearAdjacency(ctx, "a", &absent); err != nil {
		t.Errorf("ClearAdjacency for an absent neighbor: %v", err)
	}
	// An unknown circuit is an error.
	if err := a.ClearAdjacency(ctx, "nope", nil); err == nil {
		t.Error("expected error clearing adjacencies on an unknown circuit")
	}
}

// TestClearAdjacencyOnP2PClearsFloodingFlagsAndReforms: clearing a
// point-to-point adjacency is the same teardown the hold timer performs — the
// neighbor is detached, the flooding flags aimed at it are dropped (ISO 10589
// 7.3.17 re-arms the whole database when it comes back), and hellos re-form it
// with no further action.
func TestClearAdjacencyOnP2PClearsFloodingFlagsAndReforms(t *testing.T) {
	a, _, cancel := mutatePair(t, true)
	defer cancel()
	ctx := context.Background()

	// Arm a flag so "cleared" is distinguishable from "never set".
	if err := a.mgmtOperation(ctx, func() error {
		a.circuits[0].setSRM(packet.Level2, lspID(packet.SystemID{0, 0, 0, 0, 0, 9}, 0), time.Now())
		return nil
	}); err != nil {
		t.Fatalf("mgmtOperation: %v", err)
	}

	if err := a.ClearAdjacency(ctx, "a", nil); err != nil {
		t.Fatalf("ClearAdjacency: %v", err)
	}
	if err := a.mgmtOperation(ctx, func() error {
		c := a.circuits[0]
		if c.p2pAdj != nil {
			t.Errorf("p2p adjacency to %v still attached after the clear", c.p2pAdj.systemID)
		}
		if n := len(c.srm[packet.Level2]); n != 0 {
			t.Errorf("%d SRM flags survived the clear, want 0", n)
		}
		return nil
	}); err != nil {
		t.Fatalf("mgmtOperation: %v", err)
	}

	waitFor(t, "p2p adjacency re-forms", func() bool { st, ok := adjState(t, a, packet.Level2); return ok && st == AdjUp })
}

// v4ReachMetrics returns the metric of every TLV 135 entry for p — one element
// per entry, so a prefix advertised twice is visible as two.
func v4ReachMetrics(tlvs []packet.TLV, p netip.Prefix) []uint32 {
	var out []uint32
	for _, tlv := range tlvs {
		r, ok := tlv.(*packet.ExtendedIPReachabilityTLV)
		if !ok {
			continue
		}
		for _, e := range r.Prefixes {
			if e.Prefix.Masked() == p.Masked() {
				out = append(out, e.Metric)
			}
		}
	}
	return out
}

// TestRuntimePrefixSurvivesConnectedSubnetWithdrawal: a prefix added through
// the management API is the operator's, and stays advertised at the metric the
// operator gave it even while a circuit has the same subnet connected — once,
// not twice — and after that circuit withdraws its address.
func TestRuntimePrefixSurvivesConnectedSubnetWithdrawal(t *testing.T) {
	s, _, cancel := mutateServer(t)
	defer cancel()
	ctx := context.Background()
	p := netip.MustParsePrefix("10.9.9.0/24")

	// 77, not the circuit's DefaultMetric, so "the operator's metric wins" is
	// visible in the assertions below.
	if err := s.AddPrefix(ctx, AdvertisedPrefix{Prefix: p, Metric: 77}); err != nil {
		t.Fatalf("AddPrefix: %v", err)
	}
	waitFor(t, "prefix advertised", func() bool { return len(v4ReachMetrics(ownLSPTLVs(t, s), p)) == 1 })

	if err := s.SetCircuitAddresses(ctx, "c", []netip.Addr{netip.MustParseAddr("10.9.9.1")}, nil, []netip.Prefix{p}); err != nil {
		t.Fatalf("SetCircuitAddresses(connected): %v", err)
	}
	if got := v4ReachMetrics(ownLSPTLVs(t, s), p); len(got) != 1 || got[0] != 77 {
		t.Errorf("with %s also connected: TLV 135 metrics = %v, want exactly [77]", p, got)
	}

	if err := s.SetCircuitAddresses(ctx, "c", nil, nil, nil); err != nil {
		t.Fatalf("SetCircuitAddresses(withdraw): %v", err)
	}
	if got := v4ReachMetrics(ownLSPTLVs(t, s), p); len(got) != 1 || got[0] != 77 {
		t.Errorf("after the circuit withdrew its address: TLV 135 metrics = %v, want exactly [77]", got)
	}
}

// TestDeletePrefixOfConnectedOnlyPrefixIsRejected: a subnet that only a circuit
// contributes is not the management API's to withdraw — the next address event
// would bring it straight back — so DeletePrefix refuses it and says what to do
// instead, and the prefix stays advertised.
func TestDeletePrefixOfConnectedOnlyPrefixIsRejected(t *testing.T) {
	s, _, cancel := mutateServer(t)
	defer cancel()
	ctx := context.Background()
	p := netip.MustParsePrefix("10.9.9.0/24")

	if err := s.SetCircuitAddresses(ctx, "c", []netip.Addr{netip.MustParseAddr("10.9.9.1")}, nil, []netip.Prefix{p}); err != nil {
		t.Fatalf("SetCircuitAddresses: %v", err)
	}
	err := s.DeletePrefix(ctx, p)
	if err == nil {
		t.Fatalf("DeletePrefix accepted the connected subnet %s", p)
	}
	if !strings.Contains(err.Error(), "connected on c") {
		t.Errorf("DeletePrefix error = %q, want it to name the circuit the subnet is connected on", err)
	}
	if got := v4ReachMetrics(ownLSPTLVs(t, s), p); len(got) != 1 {
		t.Errorf("after the refused delete: TLV 135 metrics = %v, want the circuit's single entry", got)
	}
}

// TestConfigPrefixDeletedThenConnectedIsAdvertisedOnce: deleting a configured
// prefix really forgets it, so a circuit that later has the same subnet
// connected advertises it once, at the circuit's metric.
func TestConfigPrefixDeletedThenConnectedIsAdvertisedOnce(t *testing.T) {
	p := netip.MustParsePrefix("10.9.9.0/24")
	cfg := CircuitConfig{Name: "c", Transport: datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 1}, 1500), Level2: true, Padding: ptrFalse(), Metric: 33}
	fastHello(&cfg)
	s := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(cfg), WithAdvertisedPrefix(p, 77),
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Serve(ctx) //nolint:errcheck // ctx shutdown

	if err := s.DeletePrefix(ctx, p); err != nil {
		t.Fatalf("DeletePrefix: %v", err)
	}
	waitFor(t, "configured prefix withdrawn", func() bool { return len(v4ReachMetrics(ownLSPTLVs(t, s), p)) == 0 })

	if err := s.SetCircuitAddresses(ctx, "c", []netip.Addr{netip.MustParseAddr("10.9.9.1")}, nil, []netip.Prefix{p}); err != nil {
		t.Fatalf("SetCircuitAddresses: %v", err)
	}
	// The push asks for a re-origination rather than making one, so the LSP
	// follows within minLSPGenInterval instead of before the RPC returns.
	waitFor(t, "the connected subnet is advertised", func() bool {
		return len(v4ReachMetrics(ownLSPTLVs(t, s), p)) > 0
	})
	if got := v4ReachMetrics(ownLSPTLVs(t, s), p); len(got) != 1 || got[0] != 33 {
		t.Errorf("once %s is connected: TLV 135 metrics = %v, want exactly [33] (the circuit's metric)", p, got)
	}
}
