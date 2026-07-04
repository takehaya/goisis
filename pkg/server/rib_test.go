package server

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/takehaya/goisis/pkg/datalink"
	"github.com/takehaya/goisis/pkg/fib"
	"github.com/takehaya/goisis/pkg/packet"
)

// recordFIB records the routes and local SIDs currently programmed.
type recordFIB struct {
	mu     sync.Mutex
	routes map[netip.Prefix][]fib.Nexthop
	sids   map[netip.Addr]fib.LocalSID
}

func newRecordFIB() *recordFIB {
	return &recordFIB{routes: map[netip.Prefix][]fib.Nexthop{}, sids: map[netip.Addr]fib.LocalSID{}}
}

func (f *recordFIB) Update(p netip.Prefix, nh []fib.Nexthop) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.routes[p] = nh
	return nil
}

func (f *recordFIB) Withdraw(p netip.Prefix) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.routes, p)
	return nil
}

func (f *recordFIB) Sweep(func(netip.Prefix) bool) error { return nil }

func (f *recordFIB) AddLocalSID(s fib.LocalSID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sids[s.SID] = s
	return nil
}

func (f *recordFIB) RemoveLocalSID(sid netip.Addr) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.sids, sid)
	return nil
}

func (f *recordFIB) get(p netip.Prefix) ([]fib.Nexthop, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	nh, ok := f.routes[p]
	return nh, ok
}

func (f *recordFIB) getSID(sid netip.Addr) (fib.LocalSID, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.sids[sid]
	return s, ok
}

// failFIB is a single-threaded FIB stub for white-box programFIB/updateRIB
// tests: it records installed routes and per-prefix call counts, and can be
// armed to fail every Update (failNext) or Update/Withdraw of specific
// prefixes (failUpdate/failWithdraw).
type failFIB struct {
	installed    map[netip.Prefix]bool
	withdrawn    map[netip.Prefix]bool
	failUpdate   map[netip.Prefix]bool
	failWithdraw map[netip.Prefix]bool
	updates      map[netip.Prefix]int
	withdraws    map[netip.Prefix]int
	failNext     bool
}

func newFailFIB() *failFIB {
	return &failFIB{
		installed:    map[netip.Prefix]bool{},
		withdrawn:    map[netip.Prefix]bool{},
		failUpdate:   map[netip.Prefix]bool{},
		failWithdraw: map[netip.Prefix]bool{},
		updates:      map[netip.Prefix]int{},
		withdraws:    map[netip.Prefix]int{},
	}
}

func (f *failFIB) Update(p netip.Prefix, _ []fib.Nexthop) error {
	f.updates[p]++
	if f.failNext || f.failUpdate[p] {
		return errFIB
	}
	f.installed[p] = true
	return nil
}

func (f *failFIB) Withdraw(p netip.Prefix) error {
	f.withdraws[p]++
	if f.failWithdraw[p] {
		return errFIB
	}
	delete(f.installed, p)
	f.withdrawn[p] = true
	return nil
}

func (f *failFIB) Sweep(func(netip.Prefix) bool) error { return nil }

func (f *failFIB) AddLocalSID(fib.LocalSID) error  { return nil }
func (f *failFIB) RemoveLocalSID(netip.Addr) error { return nil }

var errFIB = fibError("fib unavailable")

type fibError string

func (e fibError) Error() string { return string(e) }

// TestProgramFIBFailureThenWithdraw drives programFIB through the failed-update
// then become-undesired sequence and asserts the stale route is still
// withdrawn (regression for the M4 "delete from rib" bug).
func TestProgramFIBFailureThenWithdraw(t *testing.T) {
	ff := newFailFIB()
	s := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(CircuitConfig{Name: "c", Transport: datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 1}, 1500), Level2: true, Padding: ptrFalse()}),
		WithFIB(ff),
	)
	p := netip.MustParsePrefix("10.9.9.0/24")
	r1 := RouteInfo{Prefix: p, Metric: 10, NextHops: []NextHopInfo{{Interface: "c", Gateway: netip.MustParseAddr("10.0.0.2")}}}
	r2 := RouteInfo{Prefix: p, Metric: 20, NextHops: []NextHopInfo{{Interface: "c", Gateway: netip.MustParseAddr("10.0.0.3")}}}

	commit := func(next map[netip.Prefix]RouteInfo) {
		s.programFIB(next)
		s.rib = next
	}

	commit(map[netip.Prefix]RouteInfo{p: r1}) // cycle 0: install
	if !ff.installed[p] {
		t.Fatal("route not installed on cycle 0")
	}
	ff.failNext = true
	commit(map[netip.Prefix]RouteInfo{p: r2}) // cycle 1: change, Update fails
	if !s.fibPending[p] {
		t.Fatal("failed prefix not marked pending for retry")
	}
	ff.failNext = false
	commit(map[netip.Prefix]RouteInfo{}) // cycle 2: prefix becomes undesired
	if !ff.withdrawn[p] {
		t.Fatal("stale route was not withdrawn after a failed update (leak)")
	}
	if s.fibPending[p] {
		t.Error("withdrawn prefix should be cleared from the pending set")
	}
}

// TestProgramFIBRetryNoDuplicateEmit asserts a failed update is retried
// without re-emitting a watch event for the unchanged route.
func TestProgramFIBRetryNoDuplicateEmit(t *testing.T) {
	ff := newFailFIB()
	s := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(CircuitConfig{Name: "c", Transport: datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 1}, 1500), Level2: true, Padding: ptrFalse()}),
		WithFIB(ff),
	)
	// Add a watcher directly (no Serve loop in this white-box test).
	w := &watcher{ch: make(chan Event, 64)}
	s.watchers[w] = struct{}{}

	p := netip.MustParsePrefix("10.9.9.0/24")
	r := RouteInfo{Prefix: p, Metric: 10, NextHops: []NextHopInfo{{Interface: "c", Gateway: netip.MustParseAddr("10.0.0.2")}}}
	commit := func(next map[netip.Prefix]RouteInfo) { s.programFIB(next); s.rib = next }

	ff.failNext = true
	commit(map[netip.Prefix]RouteInfo{p: r}) // add (emit) + Update fails -> pending
	ff.failNext = false
	commit(map[netip.Prefix]RouteInfo{p: r}) // unchanged: retry Update, must NOT re-emit

	adds := 0
	for {
		select {
		case ev := <-w.ch:
			if ev.Route != nil && !ev.Withdrawn {
				adds++
			}
			continue
		default:
		}
		break
	}
	if adds != 1 {
		t.Errorf("got %d add events for an unchanged route, want 1", adds)
	}
	if !ff.installed[p] {
		t.Error("route not installed after retry")
	}
}

// TestBetterRoute pins the route-preference comparator: level first (L1 over
// L2, and it dominates the algorithm), then the lower algorithm; the incumbent
// stays on a full tie.
func TestBetterRoute(t *testing.T) {
	r := func(l packet.Level, algo uint8) route { return route{level: l, algo: algo} }
	for _, tc := range []struct {
		name                 string
		candidate, incumbent route
		want                 bool
	}{
		{"L1-algo0 beats L2-algo0", r(packet.Level1, 0), r(packet.Level2, 0), true},
		{"L2-algo0 loses to L1-algo0", r(packet.Level2, 0), r(packet.Level1, 0), false},
		{"same level: algo0 beats flex-algo", r(packet.Level2, 0), r(packet.Level2, 128), true},
		{"same level: flex-algo loses to algo0", r(packet.Level2, 128), r(packet.Level2, 0), false},
		// Level dominates the algorithm: an L1 Flex-Algo route displaces an
		// L2 algorithm-0 route (and not vice versa).
		{"L1-flexalgo beats L2-algo0", r(packet.Level1, 128), r(packet.Level2, 0), true},
		{"L2-algo0 loses to L1-flexalgo", r(packet.Level2, 0), r(packet.Level1, 128), false},
		{"full tie keeps incumbent", r(packet.Level2, 0), r(packet.Level2, 0), false},
	} {
		if got := betterRoute(tc.candidate, tc.incumbent); got != tc.want {
			t.Errorf("%s: betterRoute = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// ribServer returns a server with one broadcast circuit and a fabricated Up
// adjacency to peer ..02 on every enabled level, so white-box updateRIB tests
// can resolve next hops without a Serve loop or hello exchange.
func ribServer(t *testing.T, level1 bool, extra ...ServerOption) *IsisServer {
	t.Helper()
	opts := append([]ServerOption{
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(CircuitConfig{Name: "c", Transport: datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 1}, 1500), Level1: level1, Level2: true, Padding: ptrFalse()}),
	}, extra...)
	s := mustServer(t, opts...)
	c := s.circuits[0]
	peer := packet.SystemID{0, 0, 0, 0, 0, 2}
	for _, l := range c.cfg.levels() {
		c.adjs[l][peer] = &adjacency{
			systemID:     peer,
			state:        AdjUp,
			neighborIPv4: []netip.Addr{netip.MustParseAddr("10.0.0.2")},
			neighborIPv6: []netip.Addr{netip.MustParseAddr("fe80::2")},
		}
	}
	return s
}

// injectLSPAt is injectLSP for an arbitrary level.
func injectLSPAt(s *IsisServer, level packet.Level, id packet.SystemID, tlvs []packet.TLV, now time.Time) {
	lid := lspID(id, 0)
	s.dbs[level].entries[lid] = &lspEntry{
		lsp:      &packet.LSP{Level: level, RemainingTime: maxAgeSeconds, LSPID: lid, SequenceNumber: 1, ISType: 2, TLVs: tlvs},
		inserted: now,
		lifetime: maxAgeSeconds,
	}
}

// TestUpdateRIBPrefersLevel1OverLevel2: the same prefix computed at both levels
// resolves to the L1 route even when the L2 path is cheaper (level dominates;
// ISO 10589 / RFC 1195 intra-area precedence).
func TestUpdateRIBPrefersLevel1OverLevel2(t *testing.T) {
	s := ribServer(t, true)
	now := time.Now()
	self := packet.SystemID{0, 0, 0, 0, 0, 1}
	peer := packet.SystemID{0, 0, 0, 0, 0, 2}
	p := netip.MustParsePrefix("10.55.0.0/24")

	for _, l := range []packet.Level{packet.Level1, packet.Level2} {
		injectLSPAt(s, l, self, []packet.TLV{isReach(peer)}, now)
	}
	injectLSPAt(s, packet.Level1, peer, []packet.TLV{isReach(self),
		&packet.ExtendedIPReachabilityTLV{Prefixes: []packet.ExtendedIPReachEntry{v4("10.55.0.0/24", 50)}}}, now)
	injectLSPAt(s, packet.Level2, peer, []packet.TLV{isReach(self),
		&packet.ExtendedIPReachabilityTLV{Prefixes: []packet.ExtendedIPReachEntry{v4("10.55.0.0/24", 5)}}}, now)

	s.updateRIB(now)
	r, ok := s.rib[p]
	if !ok {
		t.Fatalf("no RIB route for %s", p)
	}
	if r.Level != packet.Level1 {
		t.Errorf("route level = %v, want Level1 (preferred over the cheaper L2 route)", r.Level)
	}
	if r.Metric != 60 {
		t.Errorf("metric = %d, want 60 (the L1 path)", r.Metric)
	}
}

// TestUpdateRIBAlgoCollisionPrefersAlgo0: a shared prefix claimed by algorithm
// 0 (plain IPv6 reachability) and by a Flex-Algo SRv6 locator at the same level
// resolves to algorithm 0 (plain reachability wins deterministically).
func TestUpdateRIBAlgoCollisionPrefersAlgo0(t *testing.T) {
	s := ribServer(t, false,
		WithFlexAlgo(FlexAlgoConfig{Algo: 128, MetricType: packet.FlexAlgoMetricIGP, Priority: 100}))
	now := time.Now()
	self := packet.SystemID{0, 0, 0, 0, 0, 1}
	peer := packet.SystemID{0, 0, 0, 0, 0, 2}
	shared := netip.MustParsePrefix("fc00:0:7::/48")

	injectLSP(s, self, []packet.TLV{partCap(), isReach(peer)}, now)
	injectLSP(s, peer, []packet.TLV{fadCap(100), isReach(self),
		&packet.IPv6ReachabilityTLV{Prefixes: []packet.IPv6ReachEntry{{Metric: 5, Prefix: shared}}},
		algoLocTLV(128, shared),
	}, now)

	s.updateRIB(now)
	r, ok := s.rib[shared]
	if !ok {
		t.Fatalf("no RIB route for %s", shared)
	}
	if r.Algorithm != 0 {
		t.Errorf("route algorithm = %d, want 0 (plain reachability over Flex-Algo)", r.Algorithm)
	}
	if r.Metric != 15 { // 10 (edge) + 5 (TLV 236), not the locator's 10 + 0
		t.Errorf("metric = %d, want 15 (the algorithm-0 route)", r.Metric)
	}
}

func TestRIBRouteWithResolvedNextHop(t *testing.T) {
	ta := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xa1}, 1500)
	tb := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xb2}, 1500)
	datalink.Link(ta, tb)

	area := packet.AreaAddress{0x49, 0x00, 0x01}
	dst := netip.MustParsePrefix("10.9.9.0/24")
	aIP := netip.MustParseAddr("10.0.0.1")

	cfgA := CircuitConfig{Name: "a", Transport: ta, Level2: true, Padding: ptrFalse(), IPv4Addrs: []netip.Addr{aIP}}
	cfgB := CircuitConfig{Name: "b", Transport: tb, Level2: true, Padding: ptrFalse(), IPv4Addrs: []netip.Addr{netip.MustParseAddr("10.0.0.2")}}
	fastHello(&cfgA)
	fastHello(&cfgB)

	a := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}), WithAreaAddresses(area),
		WithCircuit(cfgA), WithAdvertisedPrefix(dst, 10),
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

	// B should compute a route to A's advertised prefix, with the next hop
	// resolved to A's interface address.
	waitFor(t, "b RIB has 10.9.9.0/24", func() bool {
		routes, err := b.ListRoutes(context.Background())
		if err != nil {
			return false
		}
		for _, r := range routes {
			if r.Prefix == dst {
				return len(r.NextHops) == 1 && r.NextHops[0].Gateway == aIP && r.NextHops[0].Interface == "b"
			}
		}
		return false
	})

	// And B must have programmed it into the FIB.
	waitFor(t, "b FIB programmed 10.9.9.0/24", func() bool {
		nh, ok := bfib.get(dst)
		return ok && len(nh) == 1 && nh[0].Gateway == aIP
	})
}

func TestRIBWithdrawsOnPeerLoss(t *testing.T) {
	ta := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xa1}, 1500)
	tb := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xb2}, 1500)
	datalink.Link(ta, tb)

	area := packet.AreaAddress{0x49, 0x00, 0x01}
	dst := netip.MustParsePrefix("10.9.9.0/24")
	cfgA := CircuitConfig{Name: "a", Transport: ta, Level2: true, Padding: ptrFalse(), IPv4Addrs: []netip.Addr{netip.MustParseAddr("10.0.0.1")}, HelloInterval: 50 * time.Millisecond, HoldingMultiplier: 3}
	cfgB := CircuitConfig{Name: "b", Transport: tb, Level2: true, Padding: ptrFalse(), IPv4Addrs: []netip.Addr{netip.MustParseAddr("10.0.0.2")}, HelloInterval: 50 * time.Millisecond, HoldingMultiplier: 3}

	a := mustServer(t, WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}), WithAreaAddresses(area), WithCircuit(cfgA), WithAdvertisedPrefix(dst, 10))
	bfib := newRecordFIB()
	b := mustServer(t, WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 2}), WithAreaAddresses(area), WithCircuit(cfgB), WithFIB(bfib))

	actx, acancel := context.WithCancel(context.Background())
	go a.Serve(actx) //nolint:errcheck // ctx shutdown
	bctx, bcancel := context.WithCancel(context.Background())
	go b.Serve(bctx) //nolint:errcheck // ctx shutdown
	defer bcancel()

	waitFor(t, "b FIB has route", func() bool { _, ok := bfib.get(dst); return ok })

	// Stop A; once its LSP ages/adjacency drops, B must withdraw the route.
	acancel()
	_ = ta.Close()
	waitFor(t, "b FIB withdraws route after peer loss", func() bool { _, ok := bfib.get(dst); return !ok })
}

// TestUpdateRIBFIBFailureRetries drives a real route computation against a FIB
// whose Update fails for one prefix: the failure lands in fibPending while the
// RIB keeps the desired route, the next recompute retries (and clears) the
// write, and a failed Withdraw is logged but never retried — its bookkeeping
// (fibInstalled/fibPending) is cleared regardless, per programFIB's contract.
func TestUpdateRIBFIBFailureRetries(t *testing.T) {
	sf := newFailFIB()
	s := ribServer(t, false, WithFIB(sf))
	now := time.Now()
	self := packet.SystemID{0, 0, 0, 0, 0, 1}
	peer := packet.SystemID{0, 0, 0, 0, 0, 2}
	good := netip.MustParsePrefix("10.1.0.0/24")
	bad := netip.MustParsePrefix("10.2.0.0/24")

	injectLSP(s, self, []packet.TLV{isReach(peer)}, now)
	injectLSP(s, peer, []packet.TLV{isReach(self),
		&packet.ExtendedIPReachabilityTLV{Prefixes: []packet.ExtendedIPReachEntry{v4("10.1.0.0/24", 5), v4("10.2.0.0/24", 5)}},
	}, now)

	sf.failUpdate[bad] = true
	s.updateRIB(now)
	if !s.fibPending[bad] {
		t.Fatal("failed prefix not marked pending for retry")
	}
	if s.fibPending[good] {
		t.Error("healthy prefix wrongly marked pending")
	}
	if _, ok := s.rib[bad]; !ok {
		t.Error("RIB dropped the desired route after a FIB write failure")
	}
	if sf.installed[bad] || !sf.installed[good] {
		t.Errorf("installed = %v, want only %s", sf.installed, good)
	}

	// Recompute with the FIB healthy again: the pending write is retried.
	sf.failUpdate[bad] = false
	s.updateRIB(now)
	if sf.updates[bad] != 2 {
		t.Errorf("updates[%s] = %d, want 2 (initial + retry)", bad, sf.updates[bad])
	}
	if s.fibPending[bad] {
		t.Error("pending flag not cleared after a successful retry")
	}
	if !sf.installed[bad] {
		t.Error("route not installed by the retry")
	}

	// Peer stops advertising `bad` while Withdraw fails: the withdraw is
	// attempted once and the bookkeeping is cleared despite the error.
	injectLSP(s, peer, []packet.TLV{isReach(self),
		&packet.ExtendedIPReachabilityTLV{Prefixes: []packet.ExtendedIPReachEntry{v4("10.1.0.0/24", 5)}},
	}, now)
	sf.failWithdraw[bad] = true
	s.updateRIB(now)
	if sf.withdraws[bad] != 1 {
		t.Fatalf("withdraws[%s] = %d, want 1", bad, sf.withdraws[bad])
	}
	if s.fibPending[bad] || s.fibInstalled[bad] {
		t.Error("withdraw bookkeeping not cleared after a failed Withdraw")
	}
	s.updateRIB(now)
	if sf.withdraws[bad] != 1 {
		t.Errorf("failed Withdraw was retried (%d calls); the contract is log-and-forget", sf.withdraws[bad])
	}
}
