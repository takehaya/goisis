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
	fastHello(&cfgA)
	fastHello(&cfgB)

	a := mustServer(t, WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}), WithAreaAddresses(area), WithCircuit(cfgA), WithAdvertisedPrefix(dst, 10))
	b := mustServer(t, WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 2}), WithAreaAddresses(area), WithCircuit(cfgB))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx) //nolint:errcheck // ctx shutdown
	go b.Serve(ctx) //nolint:errcheck // ctx shutdown

	sub, err := b.Subscribe(ctx)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer sub.Unsubscribe()

	var gotAdjUp, gotRoute bool
	deadline := time.After(3 * time.Second)
	for !gotAdjUp || !gotRoute {
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
		case <-deadline:
			t.Fatalf("timed out; gotAdjUp=%v gotRoute=%v", gotAdjUp, gotRoute)
		}
	}
}

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
