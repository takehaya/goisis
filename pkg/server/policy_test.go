package server

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/takehaya/goisis/pkg/datalink"
	"github.com/takehaya/goisis/pkg/packet"
)

// TestAdvertiseFilterSuppressesPrefix checks the export policy keeps a rejected
// prefix out of the originated LSP while still advertising the permitted one.
// White-box: regenerate the node LSP and read it straight from the LSDB.
func TestAdvertiseFilterSuppressesPrefix(t *testing.T) {
	keep := netip.MustParsePrefix("10.1.1.1/32")
	drop := netip.MustParsePrefix("10.9.9.9/32")
	s := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(CircuitConfig{Name: "c", Transport: datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 1}, 1500), Level2: true, Padding: ptrFalse()}),
		WithAdvertisedPrefix(keep, 10),
		WithAdvertisedPrefix(drop, 10),
		WithAdvertiseFilter(func(p AdvertisedPrefix) bool { return p.Prefix != drop }),
	)
	s.regenerateNodeLSP(packet.Level2, false, time.Now())

	e := s.dbs[packet.Level2].get(lspID(s.systemID, 0))
	if e == nil {
		t.Fatal("no own LSP originated")
	}
	got := map[netip.Prefix]bool{}
	for _, tlv := range e.lsp.TLVs {
		if r, ok := tlv.(*packet.ExtendedIPReachabilityTLV); ok {
			for _, ent := range r.Prefixes {
				got[ent.Prefix] = true
			}
		}
	}
	if !got[keep] {
		t.Errorf("permitted prefix %s not advertised", keep)
	}
	if got[drop] {
		t.Errorf("filtered prefix %s leaked into the LSP", drop)
	}
}

// TestFIBFilterKeepsRouteInRIB drives two linked nodes: A advertises two
// prefixes, B installs a FIB policy that rejects one. Both routes must reach
// B's RIB (the filter must not drop them from the RIB), but only the permitted
// one is programmed into B's FIB — the "in the RIB, not the FIB" split.
func TestFIBFilterKeepsRouteInRIB(t *testing.T) {
	ta := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xa1}, 1500)
	tb := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xb2}, 1500)
	datalink.Link(ta, tb)

	area := packet.AreaAddress{0x49, 0x00, 0x01}
	allowed := netip.MustParsePrefix("10.1.1.0/24")
	denied := netip.MustParsePrefix("10.9.9.0/24")
	aIP := netip.MustParseAddr("10.0.0.1")

	cfgA := CircuitConfig{Name: "a", Transport: ta, Level2: true, Padding: ptrFalse(), IPv4Addrs: []netip.Addr{aIP}}
	cfgB := CircuitConfig{Name: "b", Transport: tb, Level2: true, Padding: ptrFalse(), IPv4Addrs: []netip.Addr{netip.MustParseAddr("10.0.0.2")}}
	fastHello(&cfgA)
	fastHello(&cfgB)

	a := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}), WithAreaAddresses(area),
		WithCircuit(cfgA), WithAdvertisedPrefix(allowed, 10), WithAdvertisedPrefix(denied, 10),
	)
	bfib := newRecordFIB()
	b := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 2}), WithAreaAddresses(area),
		WithCircuit(cfgB), WithFIB(bfib),
		WithFIBFilter(func(r RouteInfo) bool { return r.Prefix != denied }),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx) //nolint:errcheck // ctx shutdown
	go b.Serve(ctx) //nolint:errcheck // ctx shutdown

	// Both routes land in B's RIB (the FIB filter must not affect the RIB).
	waitFor(t, "b RIB has both routes", func() bool {
		routes, err := b.ListRoutes(context.Background())
		if err != nil {
			return false
		}
		var a, d bool
		for _, r := range routes {
			switch r.Prefix {
			case allowed:
				a = true
			case denied:
				d = true
			}
		}
		return a && d
	})

	// Only the permitted route is programmed into the FIB; the denied one never
	// is (give the loop a moment to have processed both).
	waitFor(t, "b FIB has the allowed route", func() bool {
		_, ok := bfib.get(allowed)
		return ok
	})
	if _, ok := bfib.get(denied); ok {
		t.Errorf("filtered route %s was programmed into the FIB", denied)
	}
}
