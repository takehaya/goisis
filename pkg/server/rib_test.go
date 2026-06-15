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

// failFIB is a single-threaded FIB stub that can be armed to fail Update and
// records installed routes and withdraw calls (for white-box programFIB tests).
type failFIB struct {
	installed map[netip.Prefix]bool
	withdrawn map[netip.Prefix]bool
	failNext  bool
}

func newFailFIB() *failFIB {
	return &failFIB{installed: map[netip.Prefix]bool{}, withdrawn: map[netip.Prefix]bool{}}
}

func (f *failFIB) Update(p netip.Prefix, _ []fib.Nexthop) error {
	if f.failNext {
		return errFIB
	}
	f.installed[p] = true
	return nil
}

func (f *failFIB) Withdraw(p netip.Prefix) error {
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
