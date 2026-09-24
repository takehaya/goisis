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

// ownReach is one IP reachability entry this node originated: its metric and
// its up/down bit.
type ownReach struct {
	metric uint32
	down   bool
}

// ownIPReach collects the IP reachability this node originates in its own LSP
// at a level, as prefix -> every entry advertised for it (a slice, so a prefix
// advertised twice is visible).
func ownIPReach(t *testing.T, s *IsisServer, level packet.Level) map[netip.Prefix][]ownReach {
	t.Helper()
	db := s.dbs[level]
	if db == nil {
		t.Fatalf("no Level-%d LSDB", level)
	}
	out := map[netip.Prefix][]ownReach{}
	for id, e := range db.entries {
		if id.NodeID() != nodeID(s.systemID, 0) || !e.purgedAt.IsZero() {
			continue
		}
		for _, tlv := range e.lsp.TLVs {
			switch tl := tlv.(type) {
			case *packet.ExtendedIPReachabilityTLV:
				for _, p := range tl.Prefixes {
					out[p.Prefix] = append(out[p.Prefix], ownReach{metric: p.Metric, down: p.Down})
				}
			case *packet.IPv6ReachabilityTLV:
				for _, p := range tl.Prefixes {
					out[p.Prefix] = append(out[p.Prefix], ownReach{metric: p.Metric, down: p.Down})
				}
			}
		}
	}
	return out
}

// ownIPReachTLVs returns the Level-1 IP reachability TLVs this node originates,
// so another node's database can be fed exactly what we put on the wire.
func ownIPReachTLVs(t *testing.T, s *IsisServer) []packet.TLV {
	t.Helper()
	db := s.dbs[packet.Level1]
	if db == nil {
		t.Fatal("no Level-1 LSDB")
	}
	var out []packet.TLV
	for id, e := range db.entries {
		if id.NodeID() != nodeID(s.systemID, 0) || !e.purgedAt.IsZero() {
			continue
		}
		for _, tlv := range e.lsp.TLVs {
			switch tlv.(type) {
			case *packet.ExtendedIPReachabilityTLV, *packet.IPv6ReachabilityTLV:
				out = append(out, tlv)
			}
		}
	}
	return out
}

// l2OwnReach is ownIPReach at Level 2, reduced to the metrics.
func l2OwnReach(t *testing.T, s *IsisServer) map[netip.Prefix][]uint32 {
	t.Helper()
	out := map[netip.Prefix][]uint32{}
	for p, entries := range ownIPReach(t, s, packet.Level2) {
		for _, e := range entries {
			out[p] = append(out[p], e.metric)
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

// injectBL2 installs B's Level-2 LSP: reachable back to us, plus the given
// reachability TLVs.
func injectBL2(s *IsisServer, now time.Time, tlvs ...packet.TLV) {
	injectLSPAt(s, packet.Level2, l1l2PeerB, append([]packet.TLV{isReach(l1l2Self)}, tlvs...), now)
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
	s.drainLSPGen(now) // the export change is re-originated at the next drain

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
	// Past the minimum generation interval, so the throttle is not what keeps
	// the LSP still.
	s.drainLSPGen(now.Add(minLSPGenInterval))
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
	s.drainLSPGen(now)
	if _, ok := l2OwnReach(t, s)[p]; !ok {
		t.Fatalf("%s was not exported to Level 2 in the first place", p)
	}
	seq := l2OwnSeq(t, s)

	delete(s.dbs[packet.Level1].entries, lspID(l1l2PeerB, 0))
	s.updateRIB(now)
	s.drainLSPGen(now.Add(minLSPGenInterval))

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

// A connected subnet is this node's own advertisement, at the metric of the
// circuit that has it. The Level-1 neighbour on that link advertises the subnet
// too -- the ordinary case for any shared link -- and that copy must not become
// a second entry for the same prefix in our Level-2 LSP, at a second metric,
// for a Level-2 receiver to resolve however it happens to.
func TestAConnectedSubnetIsNotDuplicatedIntoL2Export(t *testing.T) {
	conn := netip.MustParsePrefix("10.0.0.0/24")
	s := l1l2Server(t, true)
	now := time.Now()
	s.setCircuitPrefixes("c", []netip.Prefix{conn})
	area := netip.MustParsePrefix("10.1.0.0/24")
	injectB(s, now, &packet.ExtendedIPReachabilityTLV{
		Prefixes: []packet.ExtendedIPReachEntry{{Prefix: conn, Metric: 5}, {Prefix: area, Metric: 5}},
	})
	s.regenerateLSPs(false, now)
	s.updateRIB(now)
	s.drainLSPGen(now)

	// 10 is the circuit's metric, which is what we originate the subnet at; an
	// export of B's copy would land beside it at 10 + 5 -- which is what B's
	// other prefix, the one that is not ours, comes out at.
	got := l2OwnReach(t, s)
	if want := []uint32{15}; !slices.Equal(got[area], want) {
		t.Fatalf("L2 LSP metrics for %s = %v, want %v; the topology under test exports nothing", area, got[area], want)
	}
	if want := []uint32{10}; !slices.Equal(got[conn], want) {
		t.Errorf("L2 LSP metrics for the connected %s = %v, want %v (ours, once)", conn, got[conn], want)
	}
}

// An SRv6 locator is originated at every level this node runs, mirrored into
// IPv6 reachability at metric 0 (RFC 9352 SHOULD). A Level-1 neighbour
// advertising the same locator -- what an anycast locator means -- must not add
// a second entry for it to our Level-2 LSP.
func TestOurOwnLocatorIsNotDuplicatedIntoL2Export(t *testing.T) {
	loc := netip.MustParsePrefix("fc00:1::/48")
	s := l1l2Server(t, true, WithSRv6Locator(loc))
	now := time.Now()
	area := netip.MustParsePrefix("2001:db8:1::/64")
	injectB(s, now, &packet.IPv6ReachabilityTLV{
		Prefixes: []packet.IPv6ReachEntry{{Prefix: loc, Metric: 5}, {Prefix: area, Metric: 5}},
	})
	s.regenerateLSPs(false, now)
	s.updateRIB(now)
	s.drainLSPGen(now)

	got := l2OwnReach(t, s)
	if want := []uint32{15}; !slices.Equal(got[area], want) {
		t.Fatalf("L2 LSP metrics for %s = %v, want %v; the topology under test exports nothing", area, got[area], want)
	}
	if want := []uint32{0}; !slices.Equal(got[loc], want) {
		t.Errorf("L2 LSP metrics for our own locator %s = %v, want %v (ours, once)", loc, got[loc], want)
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
	s.drainLSPGen(now)

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

// The export policy (WithAdvertiseFilter / policy.advertise) governs everything
// this node originates into its LSP, the Level-1 prefixes it propagates upward
// included: with the documented deny-by-default and an allowlist, only the
// permitted Level-1 prefixes reach the Level-2 LSP.
func TestAdvertiseFilterAppliesToTheL1ExportIntoTheL2LSP(t *testing.T) {
	permitted := netip.MustParsePrefix("10.1.0.0/24")
	denied := netip.MustParsePrefix("10.2.0.0/24")
	deniedV6 := netip.MustParsePrefix("2001:db8:1::/64")
	converge := func(s *IsisServer, now time.Time) {
		injectB(s, now,
			&packet.ExtendedIPReachabilityTLV{Prefixes: []packet.ExtendedIPReachEntry{
				{Prefix: permitted, Metric: 5},
				{Prefix: denied, Metric: 5},
			}},
			&packet.IPv6ReachabilityTLV{Prefixes: []packet.IPv6ReachEntry{
				{Prefix: deniedV6, Metric: 5},
			}},
		)
		s.regenerateLSPs(false, now)
		s.updateRIB(now)
		s.drainLSPGen(now)
	}
	now := time.Now()

	unfiltered := l1l2Server(t, true)
	converge(unfiltered, now)
	for _, p := range []netip.Prefix{permitted, denied, deniedV6} {
		if _, ok := l2OwnReach(t, unfiltered)[p]; !ok {
			t.Fatalf("a node without an export policy did not export %s; the topology under test is wrong", p)
		}
	}

	filtered := l1l2Server(t, true, WithAdvertiseFilter(func(ap AdvertisedPrefix) bool {
		return ap.Prefix == permitted // deny by default, one allowlist entry
	}))
	converge(filtered, now)
	got := l2OwnReach(t, filtered)
	// 10 (the circuit metric to B) + 5 (B's metric for the prefix).
	if want := []uint32{15}; !slices.Equal(got[permitted], want) {
		t.Errorf("L2 LSP metrics for the permitted %s = %v, want %v", permitted, got[permitted], want)
	}
	for _, p := range []netip.Prefix{denied, deniedV6} {
		if m, ok := got[p]; ok {
			t.Errorf("%s exported into the L2 LSP at metric %v despite the deny-by-default export policy", p, m)
		}
	}
}

// Fixture for the downward direction: prefixes reachable only through Level 2.
var (
	leakV4       = netip.MustParsePrefix("10.9.0.0/24")
	leakV6       = netip.MustParsePrefix("2001:db8:9::/64")
	leakDeniedV4 = netip.MustParsePrefix("10.8.0.0/24")
)

// leakFixture converges a node whose Level-2 neighbour B advertises leakV4,
// leakV6 and leakDeniedV4, none of which is reachable inside the Level-1 area.
func leakFixture(t *testing.T, s *IsisServer, now time.Time) {
	t.Helper()
	injectB(s, now) // B is a Level-1 neighbour too, with no reachability of its own
	injectBL2(s, now,
		&packet.ExtendedIPReachabilityTLV{Prefixes: []packet.ExtendedIPReachEntry{
			{Prefix: leakV4, Metric: 5},
			{Prefix: leakDeniedV4, Metric: 5},
		}},
		&packet.IPv6ReachabilityTLV{Prefixes: []packet.IPv6ReachEntry{
			{Prefix: leakV6, Metric: 5},
		}},
	)
	s.regenerateLSPs(false, now)
	s.updateRIB(now)
	s.drainLSPGen(now)
}

func permitEverything() AdvertiseFilter { return func(AdvertisedPrefix) bool { return true } }

// An L1L2 IS with a leak policy originates the Level-2 prefixes it permits into
// its Level-1 LSP, at the total Level-2 path metric and with the up/down bit set
// (ISO 10589 7.2.9 / RFC 5305 §4.1 / RFC 5308 §2).
func TestL1L2NodeLeaksPermittedL2PrefixesIntoItsL1LSPWithTheDownBitSet(t *testing.T) {
	s := l1l2Server(t, true, WithL2LeakFilter(permitEverything()))
	now := time.Now()
	leakFixture(t, s, now)

	got := ownIPReach(t, s, packet.Level1)
	for _, p := range []netip.Prefix{leakV4, leakV6} {
		// 10 (the circuit metric to B) + 5 (B's metric for the prefix).
		want := []ownReach{{metric: 15, down: true}}
		if !slices.Equal(got[p], want) {
			t.Errorf("L1 LSP entries for %s = %v, want %v", p, got[p], want)
		}
	}

	// The leak goes into the Level-1 LSP and nowhere else: re-advertising into
	// Level 2, down bit and all, what we learned from Level 2 is the loop the
	// bit exists to prevent (RFC 5305 §4.1).
	for _, p := range []netip.Prefix{leakV4, leakV6} {
		if m, ok := l2OwnReach(t, s)[p]; ok {
			t.Errorf("the leaker put %s back into its own Level-2 LSP at metric %v", p, m)
		}
	}

	// Leaking into our own Level-1 LSP must not feed itself: the next pass sees
	// the same leak set (our own prefixes are not part of our own SPF result)
	// and leaves the LSP alone.
	e := s.dbs[packet.Level1].entries[lspID(s.systemID, 0)]
	if e == nil {
		t.Fatal("no own Level-1 LSP")
	}
	seq := e.lsp.SequenceNumber
	s.updateRIB(now)
	s.drainLSPGen(now.Add(minLSPGenInterval))
	if got := s.dbs[packet.Level1].entries[lspID(s.systemID, 0)].lsp.SequenceNumber; got != seq {
		t.Errorf("own L1 LSP re-originated on an unchanged leak set (seq %d -> %d)", seq, got)
	}
}

// Leaking is off unless an operator asks for it: without a leak policy an L1L2
// node's Level-1 LSP carries nothing from Level 2.
func TestNothingIsLeakedIntoLevel1WithoutALeakPolicy(t *testing.T) {
	s := l1l2Server(t, true)
	now := time.Now()
	leakFixture(t, s, now)

	if len(s.l2Leak) != 0 {
		t.Errorf("l2Leak = %v, want empty with no leak policy configured", s.l2Leak)
	}
	got := ownIPReach(t, s, packet.Level1)
	for _, p := range []netip.Prefix{leakV4, leakV6, leakDeniedV4} {
		if e, ok := got[p]; ok {
			t.Errorf("%s leaked into the L1 LSP as %v with no leak policy configured", p, e)
		}
	}
	// The same Level-2 reachability is in the RIB, so the fixture really does
	// offer something to leak.
	if _, ok := s.rib[leakV4]; !ok {
		t.Errorf("%s is not even a Level-2 route; the topology under test is wrong", leakV4)
	}
}

// The leak policy decides which Level-2 prefixes reach the area: with the
// documented deny-by-default and an allowlist, only the permitted ones do.
func TestLeakPolicyFiltersWhatReachesTheL1LSP(t *testing.T) {
	permitted := PrefixList{Rules: []PrefixRule{{Action: Permit, Prefix: leakV4}}}
	s := l1l2Server(t, true, WithL2LeakFilter(permitted.AdvertiseFilter()))
	now := time.Now()
	leakFixture(t, s, now)

	got := ownIPReach(t, s, packet.Level1)
	if want := []ownReach{{metric: 15, down: true}}; !slices.Equal(got[leakV4], want) {
		t.Errorf("L1 LSP entries for the permitted %s = %v, want %v", leakV4, got[leakV4], want)
	}
	for _, p := range []netip.Prefix{leakDeniedV4, leakV6} {
		if e, ok := got[p]; ok {
			t.Errorf("%s leaked into the L1 LSP as %v despite the deny-by-default leak policy", p, e)
		}
	}
}

// What the leaker put on the wire is what a Level-1-only IS routes on: replaying
// its Level-1 reachability TLVs from a neighbour installs the leaked prefixes.
func TestAnL1OnlyNodeInstallsALeakedPrefix(t *testing.T) {
	now := time.Now()
	leaker := l1l2Server(t, true, WithL2LeakFilter(permitEverything()))
	leakFixture(t, leaker, now)

	receiver := l1l2Server(t, false)
	injectB(receiver, now, ownIPReachTLVs(t, leaker)...)
	receiver.regenerateLSPs(false, now)
	receiver.updateRIB(now)

	for _, p := range []netip.Prefix{leakV4, leakV6} {
		r, ok := receiver.rib[p]
		if !ok {
			t.Errorf("a Level-1-only IS did not install the leaked %s", p)
			continue
		}
		// 10 (the receiver's circuit metric to the leaker) + 15 (the metric the
		// leaker advertised), so the leaked metric composes with the Level-1 one.
		if r.Metric != 25 {
			t.Errorf("leaked route %s metric = %d, want 25", p, r.Metric)
		}
	}
}

// The protection that makes leaking safe: a prefix that arrives in Level 1 with
// the up/down bit set is never propagated back into Level 2 (RFC 5305 §4.1), so
// two L1L2 nodes in the same area cannot bounce it between the levels.
func TestALeakedPrefixIsNotPropagatedBackIntoLevel2(t *testing.T) {
	now := time.Now()
	leaker := l1l2Server(t, true, WithL2LeakFilter(permitEverything()))
	leakFixture(t, leaker, now)

	// A sibling L1L2 IS in the same area hears the leak from its Level-1
	// neighbour, and leaks nothing of its own.
	sibling := l1l2Server(t, true)
	injectB(sibling, now, ownIPReachTLVs(t, leaker)...)
	sibling.regenerateLSPs(false, now)
	sibling.updateRIB(now)
	sibling.drainLSPGen(now)

	if _, ok := sibling.rib[leakV4]; !ok {
		t.Fatalf("the sibling did not even install %s; the topology under test is wrong", leakV4)
	}
	for _, p := range []netip.Prefix{leakV4, leakV6} {
		if m, ok := l2OwnReach(t, sibling)[p]; ok {
			t.Errorf("the down-marked %s was propagated back into Level 2 at metric %v", p, m)
		}
	}
}

// Another L1L2 IS leaking the same prefix must not make this one stand down:
// suppression on a down-marked Level-1 route would make every border router in
// the area drop and re-add the leak together.
func TestAnotherISLeakingTheSamePrefixDoesNotSuppressOurs(t *testing.T) {
	now := time.Now()
	other := l1l2Server(t, true, WithL2LeakFilter(permitEverything()))
	leakFixture(t, other, now)

	s := l1l2Server(t, true, WithL2LeakFilter(permitEverything()))
	leakFixture(t, s, now)
	// B now also carries the other IS's leak at Level 1, so s knows leakV4 at
	// both levels — at Level 1 only because someone else leaked it.
	injectB(s, now, ownIPReachTLVs(t, other)...)
	s.updateRIB(now)
	s.drainLSPGen(now.Add(minLSPGenInterval))

	if want := []ownReach{{metric: 15, down: true}}; !slices.Equal(ownIPReach(t, s, packet.Level1)[leakV4], want) {
		t.Errorf("L1 LSP entries for %s = %v, want %v (a peer's leak must not suppress ours)",
			leakV4, ownIPReach(t, s, packet.Level1)[leakV4], want)
	}
}

// The other half of the same rule, in the forwarding plane: RFC 5302 §3.2 ranks
// a sibling's leak (preference class 3) below our own Level-2 route (class 2),
// so not standing down for it must not mean routing through it. Both borders
// leak, and if each preferred the other's copy they would point at each other.
func TestOurOwnLevel2RouteOutranksASiblingsLeakedCopy(t *testing.T) {
	now := time.Now()
	other := l1l2Server(t, true, WithL2LeakFilter(permitEverything()))
	leakFixture(t, other, now)

	s := l1l2Server(t, true, WithL2LeakFilter(permitEverything()))
	leakFixture(t, s, now)
	for _, p := range []netip.Prefix{leakV4, leakV6} {
		// 10 (the circuit metric to B) + 5 (B's Level-2 metric for the prefix).
		if r := s.rib[p]; r.Level != packet.Level2 || r.Metric != 15 {
			t.Fatalf("%s = level %v metric %d before the sibling's leak, want Level 2 metric 15; the topology under test is wrong",
				p, r.Level, r.Metric)
		}
	}

	// B now also carries the other IS's leak at Level 1, so s knows the prefixes
	// at both levels — at Level 1 only because someone else leaked them.
	injectB(s, now, ownIPReachTLVs(t, other)...)
	s.updateRIB(now)

	for _, p := range []netip.Prefix{leakV4, leakV6} {
		if r := s.rib[p]; r.Level != packet.Level2 || r.Metric != 15 {
			t.Errorf("%s = level %v metric %d, want Level 2 metric 15 (a down-marked Level-1 route must not win)",
				p, r.Level, r.Metric)
		}
	}
}

// Genuine intra-area reachability is not leaked: the area already has a better
// path to it than through Level 2.
func TestIntraAreaReachabilityIsNotLeakedBackIntoTheArea(t *testing.T) {
	s := l1l2Server(t, true, WithL2LeakFilter(permitEverything()))
	now := time.Now()
	// B advertises leakV4 at both levels — Level 1 wins (betterRoute) — and
	// leakDeniedV4 at Level 2 only, so the leak is demonstrably working.
	injectB(s, now, &packet.ExtendedIPReachabilityTLV{
		Prefixes: []packet.ExtendedIPReachEntry{{Prefix: leakV4, Metric: 5}},
	})
	injectBL2(s, now, &packet.ExtendedIPReachabilityTLV{Prefixes: []packet.ExtendedIPReachEntry{
		{Prefix: leakV4, Metric: 5},
		{Prefix: leakDeniedV4, Metric: 5},
	}})
	s.regenerateLSPs(false, now)
	s.updateRIB(now)
	s.drainLSPGen(now)

	got := ownIPReach(t, s, packet.Level1)
	if _, ok := got[leakDeniedV4]; !ok {
		t.Fatalf("the Level-2-only %s was not leaked; the topology under test is wrong", leakDeniedV4)
	}
	if e, ok := got[leakV4]; ok {
		t.Errorf("the intra-area %s was leaked into Level 1 as %v", leakV4, e)
	}
}

// intraV4 is reachable inside the Level-1 area, and visible at Level 2 as well
// because a border router has already exported it upward.
var intraV4 = netip.MustParsePrefix("10.7.0.0/24")

// A border must keep exporting a prefix its area genuinely owns even when a
// sibling border leaks a copy of it down (RFC 5302 §3.2: the route's preference
// class is the winning advertisement's, not the worst one seen). Otherwise the
// two borders latch: X stops exporting because Y leaked, Y keeps leaking
// because nobody exports, and the prefix is black-holed for the whole domain.
func TestBothBordersKeepExportingAnIntraAreaPrefixASiblingLeaks(t *testing.T) {
	now := time.Now()
	// The sibling has intraV4 at Level 2 only — its Level-1 LSDB has not caught
	// up, or it is a foreign IS that leaks unconditionally — so it leaks it.
	other := l1l2Server(t, true, WithL2LeakFilter(permitEverything()))
	injectB(other, now)
	injectBL2(other, now, &packet.ExtendedIPReachabilityTLV{
		Prefixes: []packet.ExtendedIPReachEntry{{Prefix: intraV4, Metric: 5}},
	})
	other.regenerateLSPs(false, now)
	other.updateRIB(now)
	other.drainLSPGen(now)
	if want := []ownReach{{metric: 15, down: true}}; !slices.Equal(ownIPReach(t, other, packet.Level1)[intraV4], want) {
		t.Fatalf("the sibling did not leak %s; the topology under test is wrong", intraV4)
	}

	// This border's area genuinely owns intraV4 (metric 5, bit clear) and its
	// Level-1 LSDB also carries the sibling's leaked copy of it.
	s := l1l2Server(t, true, WithL2LeakFilter(permitEverything()))
	injectB(s, now, append([]packet.TLV{&packet.ExtendedIPReachabilityTLV{
		Prefixes: []packet.ExtendedIPReachEntry{{Prefix: intraV4, Metric: 5}},
	}}, ownIPReachTLVs(t, other)...)...)
	injectBL2(s, now, &packet.ExtendedIPReachabilityTLV{
		Prefixes: []packet.ExtendedIPReachEntry{{Prefix: intraV4, Metric: 5}},
	})
	s.regenerateLSPs(false, now)
	s.updateRIB(now)
	s.drainLSPGen(now)

	// 10 (the circuit metric to B) + 5 (B's metric for the prefix): the
	// intra-area path, not the sibling's leaked copy at 25.
	if want := []uint32{15}; !slices.Equal(l2OwnReach(t, s)[intraV4], want) {
		t.Errorf("L2 LSP metrics for the intra-area %s = %v, want %v (a sibling's leak must not stop the upward export)",
			intraV4, l2OwnReach(t, s)[intraV4], want)
	}
	if r := s.rib[intraV4]; r.Level != packet.Level1 || r.Metric != 15 {
		t.Errorf("%s = level %v metric %d, want Level 1 metric 15 (the area's own path)", intraV4, r.Level, r.Metric)
	}
	// The other end of the latch: having an intra-area route, this border has
	// nothing to leak, so it does not start leaking back at the sibling.
	if e, ok := ownIPReach(t, s, packet.Level1)[intraV4]; ok {
		t.Errorf("the intra-area %s was leaked back into its own area as %v", intraV4, e)
	}
}

// TestInterLevelPrefixCountsAreReportedOnEveryRecompute covers what this node
// injects across the level boundary in both directions. The RIB gauge counts
// what the node learned; these count what it originates because of the level
// boundary, which is the number a leak policy edit moves. They are reported on
// every recompute, not only when the set changes, so a node that stops leaking
// reports 0 instead of leaving its last count behind.
func TestInterLevelPrefixCountsAreReportedOnEveryRecompute(t *testing.T) {
	areaV4 := netip.MustParsePrefix("10.1.0.0/24")
	permitted := PrefixList{Rules: []PrefixRule{{Action: Permit, Prefix: leakV4}}}
	m := newCountingMetrics()
	s := l1l2Server(t, true, WithL2LeakFilter(permitted.AdvertiseFilter()), WithMetrics(m))
	now := time.Now()
	injectB(s, now, &packet.ExtendedIPReachabilityTLV{
		Prefixes: []packet.ExtendedIPReachEntry{{Prefix: areaV4, Metric: 5}},
	})
	injectBL2(s, now, &packet.ExtendedIPReachabilityTLV{
		Prefixes: []packet.ExtendedIPReachEntry{
			{Prefix: leakV4, Metric: 5},
			{Prefix: leakDeniedV4, Metric: 5},
		},
	})
	s.regenerateLSPs(false, now)
	s.updateRIB(now)

	if n, ok := m.gauge("inter_level_prefixes", "l2_to_l1"); !ok || n != 1 {
		t.Errorf("leaked into Level 1 = %d (reported %v), want 1: only %s is permitted", n, ok, leakV4)
	}
	if n, ok := m.gauge("inter_level_prefixes", "l1_to_l2"); !ok || n != 1 {
		t.Errorf("exported into Level 2 = %d (reported %v), want 1: %s is the area's own", n, ok, areaV4)
	}

	// The Level-2 topology goes away: the leak set empties, and the gauge has
	// to follow it down rather than stay at its last value.
	delete(s.dbs[packet.Level2].entries, lspID(l1l2PeerB, 0))
	s.updateRIB(now)
	if n, _ := m.gauge("inter_level_prefixes", "l2_to_l1"); n != 0 {
		t.Errorf("leaked into Level 1 = %d after the Level-2 route went away, want 0", n)
	}

	// The same for the export direction, which the name of this test promises
	// too: a node that stops exporting reports 0 rather than leaving its last
	// count on the gauge for an operator to read as reachability it still has.
	delete(s.dbs[packet.Level1].entries, lspID(l1l2PeerB, 0))
	s.updateRIB(now)
	if n, _ := m.gauge("inter_level_prefixes", "l1_to_l2"); n != 0 {
		t.Errorf("exported into Level 2 = %d after the Level-1 route went away, want 0", n)
	}
}

// l1OwnSeq returns the sequence number of this node's own Level-1 LSP.
func l1OwnSeq(t *testing.T, s *IsisServer) uint32 {
	t.Helper()
	e := s.dbs[packet.Level1].entries[lspID(s.systemID, 0)]
	if e == nil {
		t.Fatal("no own Level-1 LSP")
	}
	return e.lsp.SequenceNumber
}

// A default route is not reachability to leak, whoever advertised it at Level
// 2: what tells a Level-1-only IS to send everything else to a border router is
// the ATT bit (RFC 1195 §3.2), and a leaked default would compete with it.
func TestADefaultRouteIsNotLeakedIntoLevel1(t *testing.T) {
	s := l1l2Server(t, true, WithL2LeakFilter(permitEverything()))
	now := time.Now()
	injectB(s, now) // a Level-1 neighbour with no reachability of its own
	injectBL2(s, now,
		&packet.ExtendedIPReachabilityTLV{Prefixes: []packet.ExtendedIPReachEntry{
			{Prefix: defaultV4, Metric: 5},
			{Prefix: leakV4, Metric: 5},
		}},
		&packet.IPv6ReachabilityTLV{Prefixes: []packet.IPv6ReachEntry{
			{Prefix: defaultV6, Metric: 5},
			{Prefix: leakV6, Metric: 5},
		}},
	)
	s.regenerateLSPs(false, now)
	s.updateRIB(now)
	s.drainLSPGen(now)

	got := ownIPReach(t, s, packet.Level1)
	for _, p := range []netip.Prefix{leakV4, leakV6} {
		if _, ok := got[p]; !ok {
			t.Fatalf("the ordinary %s was not leaked; the topology under test is wrong", p)
		}
	}
	for _, p := range []netip.Prefix{defaultV4, defaultV6} {
		if e, ok := got[p]; ok {
			t.Errorf("the Level-2 default %s was leaked into the area as %v", p, e)
		}
	}
}

// A prefix this node originates itself is advertised once, as its own: leaking
// the Level-2 copy back would put the same prefix in the same Level-1 LSP
// twice, at two metrics and with two different up/down bits, for a Level-1-only
// receiver to resolve however it happens to.
func TestOurOwnPrefixIsNotLeakedBackIntoOurLevel1LSP(t *testing.T) {
	own := netip.MustParsePrefix("10.6.0.0/24")
	s := l1l2Server(t, true, WithL2LeakFilter(permitEverything()), WithAdvertisedPrefix(own, 20))
	now := time.Now()
	injectB(s, now)
	injectBL2(s, now, &packet.ExtendedIPReachabilityTLV{Prefixes: []packet.ExtendedIPReachEntry{
		{Prefix: own, Metric: 5},
		{Prefix: leakV4, Metric: 5},
	}})
	s.regenerateLSPs(false, now)
	s.updateRIB(now)
	s.drainLSPGen(now)

	got := ownIPReach(t, s, packet.Level1)
	if _, ok := got[leakV4]; !ok {
		t.Fatalf("%s was not leaked; the topology under test is wrong", leakV4)
	}
	if want := []ownReach{{metric: 20}}; !slices.Equal(got[own], want) {
		t.Errorf("L1 LSP entries for our own %s = %v, want %v (ours, once, not down-marked)", own, got[own], want)
	}
}

// A connected subnet is ours whoever else advertises it: a Level-2 peer with a
// route to the same subnet must not have it leaked back into the Level-1 LSP
// that already carries it, where the area would see the one prefix twice, at
// two metrics and with two different up/down bits.
func TestOurOwnConnectedSubnetIsNotLeakedBackIntoOurLevel1LSP(t *testing.T) {
	conn := netip.MustParsePrefix("10.0.0.0/24")
	s := l1l2Server(t, true, WithL2LeakFilter(permitEverything()))
	now := time.Now()
	s.setCircuitPrefixes("c", []netip.Prefix{conn})
	injectB(s, now) // a Level-1 neighbour with no reachability of its own
	injectBL2(s, now, &packet.ExtendedIPReachabilityTLV{Prefixes: []packet.ExtendedIPReachEntry{
		{Prefix: conn, Metric: 5},
		{Prefix: leakV4, Metric: 5},
	}})
	s.regenerateLSPs(false, now)
	s.updateRIB(now)
	s.drainLSPGen(now)

	got := ownIPReach(t, s, packet.Level1)
	if _, ok := got[leakV4]; !ok {
		t.Fatalf("%s was not leaked; the topology under test is wrong", leakV4)
	}
	if want := []ownReach{{metric: 10}}; !slices.Equal(got[conn], want) {
		t.Errorf("L1 LSP entries for the connected %s = %v, want %v (ours, once, not down-marked)",
			conn, got[conn], want)
	}
}

// The same, for the other set this node originates without an operator naming
// it in a prefix list: an SRv6 locator a Level-2 peer also advertises is not
// leaked back into the Level-1 LSP that already mirrors it at metric 0.
func TestOurOwnLocatorIsNotLeakedBackIntoOurLevel1LSP(t *testing.T) {
	loc := netip.MustParsePrefix("fc00:1::/48")
	s := l1l2Server(t, true, WithSRv6Locator(loc), WithL2LeakFilter(permitEverything()))
	now := time.Now()
	injectB(s, now)
	injectBL2(s, now, &packet.IPv6ReachabilityTLV{Prefixes: []packet.IPv6ReachEntry{
		{Prefix: loc, Metric: 5},
		{Prefix: leakV6, Metric: 5},
	}})
	s.regenerateLSPs(false, now)
	s.updateRIB(now)
	s.drainLSPGen(now)

	got := ownIPReach(t, s, packet.Level1)
	if _, ok := got[leakV6]; !ok {
		t.Fatalf("%s was not leaked; the topology under test is wrong", leakV6)
	}
	if want := []ownReach{{metric: 0}}; !slices.Equal(got[loc], want) {
		t.Errorf("L1 LSP entries for our own locator %s = %v, want %v (ours, once, not down-marked)",
			loc, got[loc], want)
	}
}

// RFC 5302 §3.3 RECOMMENDS that the up/down bit be ignored in a Level-2 LSP and
// the prefix accepted either way, because the bit is defined for a Level-1
// advertisement (RFC 5305 §4.1) and says nothing at Level 2 until IS-IS grows a
// third level. So a down-marked Level-2 prefix is leaked like any other, and our
// own copy of it carries the bit because every leak does.
func TestTheUpDownBitIsIgnoredInALevel2Advertisement(t *testing.T) {
	s := l1l2Server(t, true, WithL2LeakFilter(permitEverything()))
	now := time.Now()
	injectB(s, now)
	injectBL2(s, now, &packet.ExtendedIPReachabilityTLV{Prefixes: []packet.ExtendedIPReachEntry{
		{Prefix: leakV4, Metric: 5, Down: true},
		{Prefix: leakDeniedV4, Metric: 5},
	}})
	s.regenerateLSPs(false, now)
	s.updateRIB(now)
	s.drainLSPGen(now)

	got := ownIPReach(t, s, packet.Level1)
	if _, ok := got[leakDeniedV4]; !ok {
		t.Fatalf("the ordinary %s was not leaked; the topology under test is wrong", leakDeniedV4)
	}
	// 10 (the circuit metric to B) + 5 (B's metric for the prefix).
	if want := []ownReach{{metric: 15, down: true}}; !slices.Equal(got[leakV4], want) {
		t.Errorf("L1 LSP entries for the down-marked Level-2 %s = %v, want %v", leakV4, got[leakV4], want)
	}
}

// The bit removed above was not what stopped a leak from being leaked again;
// two other things do, and this is the near one. A leak lands in a Level-1 LSP,
// so a prefix the area has only as another border's leak is neither in the
// Level-2 route table the candidates come from nor outside "reachability the
// area already has" -- it fails both tests, not the up/down one. The far one,
// and the loop that actually matters, is that the leaked copy never travels
// back up to Level 2 where it would become a candidate again:
// TestALeakedPrefixIsNotPropagatedBackIntoLevel2 pins that.
func TestAnotherBordersLeakIsNotLeakedAgain(t *testing.T) {
	s := l1l2Server(t, true, WithL2LeakFilter(permitEverything()))
	now := time.Now()
	// B carries a sibling's leak of leakV4 at Level 1 -- down-marked, and with
	// no Level-2 route behind it here -- plus an ordinary Level-2 prefix, so the
	// leak is demonstrably working.
	injectB(s, now, &packet.ExtendedIPReachabilityTLV{Prefixes: []packet.ExtendedIPReachEntry{
		{Prefix: leakV4, Metric: 5, Down: true},
	}})
	injectBL2(s, now, &packet.ExtendedIPReachabilityTLV{Prefixes: []packet.ExtendedIPReachEntry{
		{Prefix: leakDeniedV4, Metric: 5},
	}})
	s.regenerateLSPs(false, now)
	s.updateRIB(now)
	s.drainLSPGen(now)

	if r := s.rib[leakV4]; r.Level != packet.Level1 {
		t.Fatalf("%s = level %v, want Level 1; the topology under test is wrong", leakV4, r.Level)
	}
	got := ownIPReach(t, s, packet.Level1)
	if _, ok := got[leakDeniedV4]; !ok {
		t.Fatalf("the Level-2 %s was not leaked; the topology under test is wrong", leakDeniedV4)
	}
	if e, ok := got[leakV4]; ok {
		t.Errorf("the Level-1-only %s was leaked into the area as %v", leakV4, e)
	}
}

// flexLoc is advertised inside the area as an algorithm-128 SRv6 locator only.
var flexLoc = netip.MustParsePrefix("2001:db8:128::/64")

// Reachability the area already has means algorithm-0 reachability. A
// Flex-Algo prefix is reachable only for the nodes participating in that
// algorithm and only over its constrained path (RFC 9350 §14.2), and an area
// can be partitioned for a Flex-Algorithm while the base algorithm still has
// continuity (RFC 9350 §13.1) -- so a locator the area reaches only under
// algorithm 128 gives it no plain path, and the Level-2 prefix is still leaked.
func TestAFlexAlgoOnlyIntraAreaPrefixDoesNotSuppressTheLeak(t *testing.T) {
	s := l1l2Server(t, true, WithL2LeakFilter(permitEverything()), WithFlexAlgo(FlexAlgoConfig{Algo: 128}))
	now := time.Now()
	// B advertises flexLoc inside the area for algorithm 128 only, and leakV6
	// as ordinary algorithm-0 Level-1 reachability.
	injectB(s, now, fadCap(128),
		&packet.SRv6LocatorTLV{Locators: []packet.SRv6Locator{{Algorithm: 128, Locator: flexLoc}}},
		&packet.IPv6ReachabilityTLV{Prefixes: []packet.IPv6ReachEntry{{Prefix: leakV6, Metric: 5}}})
	// At Level 2 all three are plain reachability: flexLoc and leakV6 shared
	// with the area, leakDeniedV4 reachable through Level 2 alone.
	injectBL2(s, now,
		&packet.IPv6ReachabilityTLV{Prefixes: []packet.IPv6ReachEntry{
			{Prefix: flexLoc, Metric: 5},
			{Prefix: leakV6, Metric: 5},
		}},
		&packet.ExtendedIPReachabilityTLV{Prefixes: []packet.ExtendedIPReachEntry{
			{Prefix: leakDeniedV4, Metric: 5},
		}},
	)
	s.regenerateLSPs(false, now)
	s.updateRIB(now)
	s.drainLSPGen(now)

	if r, ok := s.computeSPF(packet.Level1, 128, now)[flexLoc]; !ok || r.algo != 128 {
		t.Fatalf("%s is not an algorithm-128 Level-1 route; the topology under test is wrong", flexLoc)
	}
	got := ownIPReach(t, s, packet.Level1)
	if _, ok := got[leakDeniedV4]; !ok {
		t.Fatalf("the Level-2-only %s was not leaked; the topology under test is wrong", leakDeniedV4)
	}
	// 10 (the circuit metric to B) + 5 (B's Level-2 metric for the prefix).
	if want := []ownReach{{metric: 15, down: true}}; !slices.Equal(got[flexLoc], want) {
		t.Errorf("L1 LSP entries for the Flex-Algo-only %s = %v, want %v", flexLoc, got[flexLoc], want)
	}
	// The control: algorithm-0 reachability inside the area does suppress it.
	if e, ok := got[leakV6]; ok {
		t.Errorf("the intra-area %s was leaked into Level 1 as %v", leakV6, e)
	}
}

// A leak is withdrawn when the Level-2 route behind it goes away. A stale leak
// is worse than a stale export: a Level-1-only IS has no other view of the
// prefix, so it keeps forwarding to us until the LSP ages out.
func TestALeakIsWithdrawnWhenItsLevel2RouteDisappears(t *testing.T) {
	s := l1l2Server(t, true, WithL2LeakFilter(permitEverything()))
	now := time.Now()
	leakFixture(t, s, now)
	if _, ok := ownIPReach(t, s, packet.Level1)[leakV4]; !ok {
		t.Fatalf("%s was not leaked in the first place", leakV4)
	}
	seq := l1OwnSeq(t, s)

	// B still exists and is still reachable; it just no longer advertises any
	// reachability of its own.
	injectBL2(s, now)
	s.updateRIB(now)
	s.drainLSPGen(now.Add(minLSPGenInterval))

	if len(s.l2Leak) != 0 {
		t.Errorf("l2Leak = %v, want empty once the Level-2 routes are gone", s.l2Leak)
	}
	got := ownIPReach(t, s, packet.Level1)
	for _, p := range []netip.Prefix{leakV4, leakV6, leakDeniedV4} {
		if e, ok := got[p]; ok {
			t.Errorf("%s still leaked as %v after its Level-2 route went away", p, e)
		}
	}
	if got := l1OwnSeq(t, s); got <= seq {
		t.Errorf("own L1 LSP sequence number = %d, want > %d (the withdrawal must be flooded)", got, seq)
	}
}

// A leaked metric reaches the wire below the reachability ceiling, which RFC
// 5305 §4 reserves for "unreachable". No topology can drive this: computeSPF
// drops a path that reaches the ceiling, so l2LeakSet never holds one and the
// clamp in regenerateNodeLSP is the belt to that pair of braces. Setting the
// leak set directly is the only way to ask what origination does with one --
// and without the clamp the leak would tell the whole area the prefix is
// unreachable rather than distant.
func TestALeakedMetricIsClampedBelowTheReachabilityCeilingOnTheWire(t *testing.T) {
	s := l1l2Server(t, true, WithL2LeakFilter(permitEverything()))
	s.l2Leak = map[netip.Prefix]uint32{leakV4: maxPathMetric}
	s.regenerateLSPs(false, time.Now())

	want := []ownReach{{metric: maxPathMetric - 1, down: true}}
	if got := ownIPReach(t, s, packet.Level1)[leakV4]; !slices.Equal(got, want) {
		t.Errorf("L1 LSP entries for %s = %v, want %v", leakV4, got, want)
	}
}
