package server

import (
	"context"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/takehaya/goisis/pkg/datalink"
	"github.com/takehaya/goisis/pkg/packet"
)

// v4Reach returns the IPv4 prefixes and metrics carried in TLV 135.
func v4Reach(tlvs []packet.TLV) map[netip.Prefix]uint32 {
	got := map[netip.Prefix]uint32{}
	for _, tlv := range tlvs {
		if r, ok := tlv.(*packet.ExtendedIPReachabilityTLV); ok {
			for _, e := range r.Prefixes {
				got[e.Prefix] = e.Metric
			}
		}
	}
	return got
}

// neighborAddrs returns the IPv4 addresses this server learned from its
// neighbor's hellos on the given circuit (TLV 132).
func neighborAddrs(t *testing.T, s *IsisServer, circuitName string) []netip.Addr {
	t.Helper()
	var out []netip.Addr
	if err := s.mgmtOperation(context.Background(), func() error {
		c := s.circuitNamed(circuitName)
		if c == nil {
			return nil
		}
		for _, adj := range c.adjs[packet.Level2] {
			out = append(out, adj.neighborIPv4...)
		}
		return nil
	}); err != nil {
		t.Fatalf("mgmtOperation: %v", err)
	}
	return out
}

// lanPair starts two servers on one mock LAN segment, each with the given
// circuit customization applied, and waits for the Level-2 adjacency. Both run
// on the fake clock it returns, so the seconds these tests are about pass when
// they say so; steadyHello rather than fastHello because a stepped clock's
// hellos are a whole tick apart (see steadyHello).
func lanPair(t *testing.T, ctx context.Context, tune func(a, b *CircuitConfig), optsA ...ServerOption) (*IsisServer, *IsisServer, *fakeClock) {
	t.Helper()
	ta := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xa1}, 1500)
	tb := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xb2}, 1500)
	datalink.Link(ta, tb)

	area := packet.AreaAddress{0x49, 0x00, 0x01}
	cfgA := CircuitConfig{Name: "a", Transport: ta, Level2: true, Padding: ptrFalse()}
	cfgB := CircuitConfig{Name: "b", Transport: tb, Level2: true, Padding: ptrFalse(),
		IPv4Addrs: []netip.Addr{netip.MustParseAddr("10.0.0.2")}}
	steadyHello(&cfgA)
	steadyHello(&cfgB)
	if tune != nil {
		tune(&cfgA, &cfgB)
	}

	clk := newFakeClock()
	a := mustServer(t, append([]ServerOption{
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}), WithAreaAddresses(area), WithCircuit(cfgA), WithClock(clk),
	}, optsA...)...)
	b := mustServer(t, WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 2}), WithAreaAddresses(area), WithCircuit(cfgB), WithClock(clk))
	go a.Serve(ctx) //nolint:errcheck // ctx shutdown
	go b.Serve(ctx) //nolint:errcheck // ctx shutdown

	waitClock(t, clk, "a sees b Up", func() bool { st, ok := adjState(t, a, packet.Level2); return ok && st == AdjUp })
	waitClock(t, clk, "b sees a Up", func() bool { st, ok := adjState(t, b, packet.Level2); return ok && st == AdjUp })
	return a, b, clk
}

// TestSetCircuitAddressesReachesHellosAndLSP renumbers a live circuit: the
// neighbor must learn the new hello source address, our LSP must advertise the
// new connected subnet and drop the old one, and a prefix that came from the
// configuration must survive untouched.
func TestSetCircuitAddressesReachesHellosAndLSP(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	old := netip.MustParsePrefix("10.0.0.0/24")
	renumbered := netip.MustParsePrefix("10.9.0.0/24")
	static := netip.MustParsePrefix("192.0.2.0/24")
	oldAddr := netip.MustParseAddr("10.0.0.1")
	newAddr := netip.MustParseAddr("10.9.0.1")

	a, b, clk := lanPair(t, ctx, func(cfgA, _ *CircuitConfig) {
		cfgA.Metric = 42
		cfgA.IPv4Addrs = []netip.Addr{oldAddr}
		cfgA.ConnectedPrefixes = []netip.Prefix{old}
	}, WithAdvertisedPrefix(static, 10))

	waitClock(t, clk, "b learns a's original address", func() bool {
		return slices.Contains(neighborAddrs(t, b, "b"), oldAddr)
	})

	if err := a.SetCircuitAddresses(ctx, "a", []netip.Addr{newAddr}, nil, []netip.Prefix{renumbered}); err != nil {
		t.Fatalf("SetCircuitAddresses: %v", err)
	}

	waitClock(t, clk, "b learns a's new address", func() bool {
		return slices.Contains(neighborAddrs(t, b, "b"), newAddr)
	})
	if addrs := neighborAddrs(t, b, "b"); slices.Contains(addrs, oldAddr) {
		t.Errorf("b still advertises the withdrawn address %s: %v", oldAddr, addrs)
	}

	// The push asks for a re-origination rather than making one, so the LSP
	// follows within minLSPGenInterval instead of before the RPC returns.
	waitClock(t, clk, "own LSP advertises the renumbered subnet", func() bool {
		_, ok := v4Reach(ownLSPTLVs(t, a))[renumbered]
		return ok
	})
	got := v4Reach(ownLSPTLVs(t, a))
	if m, ok := got[renumbered]; !ok || m != 42 {
		t.Errorf("own LSP: %s metric = %d (present %v), want 42", renumbered, m, ok)
	}
	if _, ok := got[old]; ok {
		t.Errorf("own LSP still advertises the withdrawn subnet %s", old)
	}
	if _, ok := got[static]; !ok {
		t.Errorf("own LSP dropped the configured prefix %s", static)
	}

	if err := a.mgmtOperation(ctx, func() error {
		if !a.connected[renumbered] {
			t.Errorf("%s is not marked connected", renumbered)
		}
		if a.connected[old] {
			t.Errorf("%s is still marked connected", old)
		}
		return nil
	}); err != nil {
		t.Fatalf("mgmtOperation: %v", err)
	}
}

// TestSetCircuitLinkStateTearsDownAndSilences checks that a link reported down
// takes the adjacency with it at once (rather than after the holding time) and
// stops the hellos, and that reporting it up again re-forms the adjacency.
func TestSetCircuitLinkStateTearsDownAndSilences(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	a, b, clk := lanPair(t, ctx, nil)

	sub, err := a.Subscribe(ctx)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer sub.Unsubscribe()

	if err := a.SetCircuitLinkState(ctx, "a", false); err != nil {
		t.Fatalf("SetCircuitLinkState(false): %v", err)
	}
	// SetCircuitLinkState runs on the Serve loop, so by the time it returns the
	// teardown has happened — no polling needed.
	adjs, err := a.ListAdjacencies(ctx)
	if err != nil {
		t.Fatalf("ListAdjacencies: %v", err)
	}
	if len(adjs) != 0 {
		t.Errorf("adjacencies survived the link going down: %+v", adjs)
	}
	down := false
	for deadline := time.After(2 * time.Second); !down; {
		select {
		case ev := <-sub.Events:
			down = ev.Adjacency != nil && ev.Adjacency.State == AdjDown
		case <-deadline:
			t.Fatal("no adjacency Down event was emitted")
		}
	}

	// Nothing may leave the circuit while the link is down: a sink joined to
	// the segment must stay empty across several housekeeping ticks, which is
	// when hellos actually leave. On a stepped clock those ticks are three
	// advances rather than three seconds of waiting, so the window the sink is
	// watched over is the whole of the one a hello could have left in.
	sink := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xff}, 1500)
	if err := a.mgmtOperation(ctx, func() error { // circuits are the loop's to read
		datalink.Link(a.circuits[0].cfg.Transport.(*datalink.MockTransport), sink)
		return nil
	}); err != nil {
		t.Fatalf("mgmtOperation: %v", err)
	}
	for range 3 {
		clk.Advance(housekeepInterval)
	}
	loopSync(t, a)
	time.Sleep(stepDelay) // the frames a tick sends cross the segment in real time
	_ = sink.Close()      // buffered frames still drain; Recv then reports ErrClosed
	for {
		f, err := sink.Recv()
		if err != nil {
			break
		}
		pdu, err := packet.DecodePDU(packet.TrimToPDULength(f.PDU))
		if err != nil {
			t.Fatalf("decode emitted PDU: %v", err)
		}
		t.Errorf("a transmitted %T while its link was down", pdu)
	}

	if err := a.SetCircuitLinkState(ctx, "a", true); err != nil {
		t.Fatalf("SetCircuitLinkState(true): %v", err)
	}
	waitClock(t, clk, "a sees b Up again", func() bool { st, ok := adjState(t, a, packet.Level2); return ok && st == AdjUp })
	waitClock(t, clk, "b sees a Up again", func() bool { st, ok := adjState(t, b, packet.Level2); return ok && st == AdjUp })
}

// TestCircuitEventsUnknownCircuit checks both setters reject a circuit name the
// server does not have, rather than silently doing nothing.
func TestCircuitEventsUnknownCircuit(t *testing.T) {
	s := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(CircuitConfig{Name: "c", Transport: datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 1}, 1500), Level2: true, Padding: ptrFalse()}),
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Serve(ctx) //nolint:errcheck // ctx shutdown

	if err := s.SetCircuitAddresses(ctx, "nope", nil, nil, nil); err == nil {
		t.Error("SetCircuitAddresses accepted an unknown circuit")
	}
	if err := s.SetCircuitLinkState(ctx, "nope", false); err == nil {
		t.Error("SetCircuitLinkState accepted an unknown circuit")
	}
}

// TestCircuitConnectedPrefixes checks that a circuit's ConnectedPrefixes are
// originated at the circuit's metric and marked connected, exactly as
// WithAdvertisedPrefix + WithConnectedPrefix would.
func TestCircuitConnectedPrefixes(t *testing.T) {
	subnet := netip.MustParsePrefix("10.0.0.0/24")
	s := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(CircuitConfig{
			Name: "c", Transport: datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 1}, 1500),
			Level2: true, Padding: ptrFalse(), Metric: 25,
			ConnectedPrefixes: []netip.Prefix{subnet},
		}),
	)
	s.regenerateNodeLSP(packet.Level2, false, time.Now())

	e := s.dbs[packet.Level2].get(lspID(s.systemID, 0))
	if e == nil {
		t.Fatal("no own LSP originated")
	}
	if m, ok := v4Reach(e.lsp.TLVs)[subnet]; !ok || m != 25 {
		t.Errorf("own LSP: %s metric = %d (present %v), want 25", subnet, m, ok)
	}
	if !s.connected[subnet] {
		t.Errorf("%s is not marked connected", subnet)
	}
}

// TestSetCircuitAddressesIsIdempotentWithTwoAddressesInOneSubnet: the daemon's
// watcher deliberately does not debounce — it re-reads the interface and pushes
// on every netlink message, relying on this call to be a no-op when nothing
// changed. Two addresses in one subnet (a SLAAC and a privacy address in one
// /64 is the everyday case) yield the same connected prefix twice, and the
// kernel may hand the addresses back in another order; neither is a change, so
// neither may cost hellos, a re-origination and an SPF run.
//
// One server, no peer: a converging adjacency recomputes on its own schedule,
// which would drown the runs under test.
func TestSetCircuitAddressesIsIdempotentWithTwoAddressesInOneSubnet(t *testing.T) {
	subnet := netip.MustParsePrefix("2001:db8::/64")
	stable := netip.MustParseAddr("2001:db8::1")
	privacy := netip.MustParseAddr("2001:db8::dead")

	spf := &spfCounter{}
	clk := newFakeClock()
	s := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(CircuitConfig{
			Name: "c", Transport: datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 1}, 1500),
			Level2: true, Padding: ptrFalse(),
			IPv6Addrs:         []netip.Addr{stable, privacy},
			ConnectedPrefixes: []netip.Prefix{subnet, subnet},
		}),
		WithMetrics(spf),
		WithClock(clk),
	)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go s.Serve(ctx) //nolint:errcheck // shut down via ctx
	// The loop arms its timers before it serves anything, so this barrier is
	// also what gives the clock something to fire.
	loopSync(t, s)
	clk.Advance(2 * spfHold) // let startup origination's own recompute drain
	loopSync(t, s)
	before := spf.count()

	for _, addrs := range [][]netip.Addr{
		{stable, privacy}, // the same read again
		{privacy, stable}, // the same addresses, the other order
	} {
		if err := s.SetCircuitAddresses(ctx, "c", nil, addrs, []netip.Prefix{subnet, subnet}); err != nil {
			t.Fatalf("SetCircuitAddresses: %v", err)
		}
	}
	if got := circuitIPv6Addrs(t, s, "c"); !slices.Equal(got, []netip.Addr{stable, privacy}) {
		t.Errorf("stored addresses = %v, want them canonical so a reordered read compares equal", got)
	}
	// A change would mark SPF dirty, which the back-off runs within one hold.
	clk.Advance(2 * spfHold)
	loopSync(t, s)
	if got := spf.count() - before; got != 0 {
		t.Errorf("re-pushing the same addresses ran %d SPF computations, want 0", got)
	}

	// Control: a real change still does the work, so the check above cannot
	// pass by making the call inert.
	if err := s.SetCircuitAddresses(ctx, "c", nil, []netip.Addr{stable}, []netip.Prefix{subnet}); err != nil {
		t.Fatalf("SetCircuitAddresses: %v", err)
	}
	clk.Advance(2 * spfHold)
	loopSync(t, s)
	if got := spf.count() - before; got == 0 {
		t.Error("dropping an address ran no SPF computation: the no-op check is swallowing real changes")
	}
}

// circuitIPv6Addrs reads a circuit's stored IPv6 addresses on the Serve
// goroutine, which owns them.
func circuitIPv6Addrs(t *testing.T, s *IsisServer, name string) []netip.Addr {
	t.Helper()
	var out []netip.Addr
	if err := s.mgmtOperation(context.Background(), func() error {
		if c := s.circuitNamed(name); c != nil {
			out = slices.Clone(c.cfg.IPv6Addrs)
		}
		return nil
	}); err != nil {
		t.Fatalf("read circuit addresses: %v", err)
	}
	return out
}
