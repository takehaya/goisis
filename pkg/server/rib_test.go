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

// recordFIB records the routes currently programmed.
type recordFIB struct {
	mu     sync.Mutex
	routes map[netip.Prefix][]fib.Nexthop
}

func newRecordFIB() *recordFIB { return &recordFIB{routes: map[netip.Prefix][]fib.Nexthop{}} }

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

func (f *recordFIB) get(p netip.Prefix) ([]fib.Nexthop, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	nh, ok := f.routes[p]
	return nh, ok
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
