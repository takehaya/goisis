package server

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/takehaya/goisis/pkg/datalink"
	"github.com/takehaya/goisis/pkg/packet"
)

func TestWatchEmitsAdjacencyAndRoute(t *testing.T) {
	ta := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xa1}, 1500)
	tb := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xb2}, 1500)
	datalink.Link(ta, tb)

	area := packet.AreaAddress{0x49, 0x00, 0x01}
	dst := netip.MustParsePrefix("10.9.9.0/24")
	cfgA := CircuitConfig{Name: "a", Transport: ta, Level2: true, Padding: ptrFalse(), IPv4Addrs: []netip.Addr{netip.MustParseAddr("10.0.0.1")}}
	cfgB := CircuitConfig{Name: "b", Transport: tb, Level2: true, Padding: ptrFalse(), IPv4Addrs: []netip.Addr{netip.MustParseAddr("10.0.0.2")}}
	// A stepped clock, so the adjacency the events come from cannot expire
	// because a loaded machine stalled a housekeeping tick; steadyHello for
	// the reason steadyHello gives.
	steadyHello(&cfgA)
	steadyHello(&cfgB)

	clk := newFakeClock()
	a := mustServer(t, WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}), WithAreaAddresses(area), WithCircuit(cfgA), WithAdvertisedPrefix(dst, 10), WithClock(clk))
	b := mustServer(t, WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 2}), WithAreaAddresses(area), WithCircuit(cfgB), WithClock(clk))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Start B and subscribe before A exists, so the adjacency cannot reach Up
	// (and emit its event) before the subscriber is registered — otherwise the
	// Up event races the Subscribe call and is occasionally missed under load.
	go b.Serve(ctx) //nolint:errcheck // ctx shutdown
	sub, err := b.Subscribe(ctx)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer sub.Unsubscribe()
	go a.Serve(ctx) //nolint:errcheck // ctx shutdown

	// Take what the subscriber has, and when it has nothing, step the clock so
	// the instances get another housekeeping tick to produce something. The
	// bound is in ticks rather than wall time, so a loaded runner makes this
	// slower and not flakier.
	var gotAdjUp, gotRoute bool
	for ticks := 0; !gotAdjUp || !gotRoute; {
		select {
		case ev, ok := <-sub.Events:
			if !ok {
				t.Fatal("watch channel closed unexpectedly")
			}
			if ev.Adjacency != nil && ev.Adjacency.State == AdjUp {
				gotAdjUp = true
			}
			if ev.Route != nil && ev.Route.Prefix == dst && !ev.Withdrawn {
				gotRoute = true
			}
		default:
			if ticks++; ticks > 120 {
				t.Fatalf("timed out; gotAdjUp=%v gotRoute=%v", gotAdjUp, gotRoute)
			}
			clk.Advance(housekeepInterval)
			time.Sleep(stepDelay)
		}
	}
}

// TestSubscribeInitialSnapshotIsGapFree pins what makes the snapshot worth
// having: it is taken as the watcher is registered, so a converged state is
// reported in Initial and every later change still arrives on Events.
func TestSubscribeInitialSnapshotIsGapFree(t *testing.T) {
	ta := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xa1}, 1500)
	tb := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xb2}, 1500)
	datalink.Link(ta, tb)

	area := packet.AreaAddress{0x49, 0x00, 0x01}
	dst := netip.MustParsePrefix("10.9.9.0/24")
	sysA := packet.SystemID{0, 0, 0, 0, 0, 1}
	cfgA := CircuitConfig{Name: "a", Transport: ta, Level2: true, Padding: ptrFalse(), IPv4Addrs: []netip.Addr{netip.MustParseAddr("10.0.0.1")}}
	cfgB := CircuitConfig{Name: "b", Transport: tb, Level2: true, Padding: ptrFalse(), IPv4Addrs: []netip.Addr{netip.MustParseAddr("10.0.0.2")}}
	fastHello(&cfgA)
	fastHello(&cfgB)

	a := mustServer(t, WithSystemID(sysA), WithAreaAddresses(area), WithCircuit(cfgA), WithAdvertisedPrefix(dst, 10))
	b := mustServer(t, WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 2}), WithAreaAddresses(area), WithCircuit(cfgB))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctxA, cancelA := context.WithCancel(ctx)
	defer cancelA()
	go a.Serve(ctxA) //nolint:errcheck // ctx shutdown
	go b.Serve(ctx)  //nolint:errcheck // ctx shutdown

	// Converge before subscribing: this is the state a consumer that starts
	// late would otherwise have to fetch separately, and race against.
	waitFor(t, "b to learn a's prefix", func() bool {
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
	})

	sub, err := b.Subscribe(ctx)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer sub.Unsubscribe()

	var gotAdjUp, gotRoute bool
	for _, ev := range sub.Initial {
		if ev.Adjacency != nil && ev.Adjacency.SystemID == sysA && ev.Adjacency.State == AdjUp {
			gotAdjUp = true
		}
		if ev.Route != nil && ev.Route.Prefix == dst {
			gotRoute = true
		}
	}
	if !gotAdjUp || !gotRoute {
		t.Fatalf("Initial = %+v; want a's Up adjacency and route %s", sub.Initial, dst)
	}

	// Losing the peer after the snapshot must still reach the subscriber.
	cancelA()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case ev, ok := <-sub.Events:
			if !ok {
				t.Fatal("watch channel closed unexpectedly")
			}
			if ev.Adjacency != nil && ev.Adjacency.State != AdjUp {
				return
			}
			if ev.Route != nil && ev.Route.Prefix == dst && ev.Withdrawn {
				return
			}
		case <-deadline:
			t.Fatal("timed out waiting for a change after the snapshot")
		}
	}
}

// TestSubscribeInitialIsEmptyOnFreshServer: a node with no adjacencies and no
// routes reports nothing, rather than a placeholder event.
func TestSubscribeInitialIsEmptyOnFreshServer(t *testing.T) {
	tr := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 1}, 1500)
	s := mustServer(t, WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(CircuitConfig{Name: "c", Transport: tr, Level2: true, Padding: ptrFalse()}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Serve(ctx) //nolint:errcheck // ctx shutdown

	sub, err := s.Subscribe(ctx)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer sub.Unsubscribe()
	if len(sub.Initial) != 0 {
		t.Errorf("Initial = %+v, want empty", sub.Initial)
	}
}

// TestWatchDropsLaggingSubscriber covers the live stream only: Subscribe's
// Initial snapshot is a slice rather than events queued through the channel,
// so no snapshot, however large, can push a subscriber over the buffer.
func TestWatchDropsLaggingSubscriber(t *testing.T) {
	tr := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 1}, 1500)
	s := mustServer(t, WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(CircuitConfig{Name: "c", Transport: tr, Level2: true, Padding: ptrFalse()}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Serve(ctx) //nolint:errcheck // ctx shutdown

	sub, err := s.Subscribe(ctx)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer sub.Unsubscribe()

	// Flood far more events than the buffer holds, all on the loop, without
	// draining the channel. The loop must not block and must drop us.
	for i := 0; i < watcherBuffer*4; i++ {
		_ = s.mgmtOperation(ctx, func() error {
			s.emit(Event{Route: &RouteInfo{Prefix: netip.MustParsePrefix("10.0.0.0/8")}})
			return nil
		})
	}
	// The lagging subscriber's channel must end up closed.
	waitFor(t, "lagging subscriber dropped", func() bool {
		for {
			select {
			case _, ok := <-sub.Events:
				if !ok {
					return true
				}
			default:
				return false
			}
		}
	})
	// And it must be reported as lagging (not a clean unsubscribe/shutdown).
	if !sub.Lagged() {
		t.Error("dropped subscriber should report Lagged()=true")
	}
}

// TestSubscribeInitialCarriesTheHostnamesListAdjacenciesResolves: Initial
// documents itself as "the same content as ListAdjacencies", and a consumer
// that keys on the hostname must not get a different answer depending on which
// call it made.
func TestSubscribeInitialCarriesTheHostnamesListAdjacenciesResolves(t *testing.T) {
	ta := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xa1}, 1500)
	tb := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xb2}, 1500)
	datalink.Link(ta, tb)

	area := packet.AreaAddress{0x49, 0x00, 0x01}
	cfgA := CircuitConfig{Name: "a", Transport: ta, Level2: true, Padding: ptrFalse()}
	cfgB := CircuitConfig{Name: "b", Transport: tb, Level2: true, Padding: ptrFalse()}
	fastHello(&cfgA)
	fastHello(&cfgB)

	a := mustServer(t, WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}), WithAreaAddresses(area), WithCircuit(cfgA), WithHostname("node-a"))
	b := mustServer(t, WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 2}), WithAreaAddresses(area), WithCircuit(cfgB), WithHostname("node-b"))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx) //nolint:errcheck // ctx shutdown
	go b.Serve(ctx) //nolint:errcheck // ctx shutdown

	// The hostname comes from the peer's LSP, so wait until ListAdjacencies
	// resolves it: before that both answers are legitimately empty.
	waitFor(t, "a to learn b's hostname", func() bool {
		adjs, err := a.ListAdjacencies(ctx)
		return err == nil && len(adjs) == 1 && adjs[0].Hostname == "node-b"
	})

	sub, err := a.Subscribe(ctx)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer sub.Unsubscribe()

	var got []string
	for _, ev := range sub.Initial {
		if ev.Adjacency != nil {
			got = append(got, ev.Adjacency.Hostname)
		}
	}
	if len(got) != 1 || got[0] != "node-b" {
		t.Errorf("Initial adjacency hostnames = %q, want [\"node-b\"] to match ListAdjacencies", got)
	}
}
