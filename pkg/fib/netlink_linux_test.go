//go:build linux

package fib

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// withNetns runs fn inside a fresh network namespace with a dummy interface
// "dum0" carrying 10.0.0.1/24 and 2001:db8::1/64, restoring the caller's
// namespace afterwards. It skips unless run as root.
func withNetns(t *testing.T, fn func(t *testing.T)) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("netlink FIB test needs root; run: go test -exec sudo ./pkg/fib")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	orig, err := netns.Get()
	if err != nil {
		t.Fatalf("get netns: %v", err)
	}
	defer func() { _ = netns.Set(orig); _ = orig.Close() }()

	ns, err := netns.New() // creates and enters a new namespace
	if err != nil {
		t.Fatalf("new netns: %v", err)
	}
	defer func() { _ = ns.Close() }()

	la := netlink.NewLinkAttrs()
	la.Name = "dum0"
	if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: la}); err != nil {
		t.Fatalf("add dummy: %v", err)
	}
	link, err := netlink.LinkByName("dum0")
	if err != nil {
		t.Fatalf("link by name: %v", err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		t.Fatalf("link up: %v", err)
	}
	// seg6local End SIDs hang off the loopback, which a fresh namespace leaves
	// down; the kernel refuses a route through a down device.
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatalf("lo by name: %v", err)
	}
	if err := netlink.LinkSetUp(lo); err != nil {
		t.Fatalf("lo up: %v", err)
	}
	for _, cidr := range []string{"10.0.0.1/24", "2001:db8::1/64"} {
		addr, _ := netlink.ParseAddr(cidr)
		if err := netlink.AddrAdd(link, addr); err != nil {
			t.Fatalf("addr add %s: %v", cidr, err)
		}
	}
	fn(t)
}

func protoISISRoutes(t *testing.T, family int) []netlink.Route {
	t.Helper()
	routes, err := netlink.RouteListFiltered(family,
		&netlink.Route{Protocol: rtprotoISIS}, netlink.RT_FILTER_PROTOCOL)
	if err != nil {
		t.Fatalf("list proto-isis routes: %v", err)
	}
	return routes
}

func TestNetlinkInstallAndWithdraw(t *testing.T) {
	withNetns(t, func(t *testing.T) {
		f := NewNetlink(unix.RT_TABLE_MAIN)
		dst := netip.MustParsePrefix("10.9.9.0/24")
		gw := netip.MustParseAddr("10.0.0.2")

		if err := f.Update(dst, []Nexthop{{Interface: "dum0", Gateway: gw}}); err != nil {
			t.Fatalf("update: %v", err)
		}
		routes := protoISISRoutes(t, netlink.FAMILY_V4)
		if len(routes) != 1 || routes[0].Dst.String() != "10.9.9.0/24" || !routes[0].Gw.Equal(net.ParseIP("10.0.0.2")) {
			t.Fatalf("installed route mismatch: %+v", routes)
		}

		if err := f.Withdraw(dst); err != nil {
			t.Fatalf("withdraw: %v", err)
		}
		if routes := protoISISRoutes(t, netlink.FAMILY_V4); len(routes) != 0 {
			t.Fatalf("route still present after withdraw: %+v", routes)
		}
	})
}

func TestNetlinkIPv6AndSweep(t *testing.T) {
	withNetns(t, func(t *testing.T) {
		f := NewNetlink(unix.RT_TABLE_MAIN)
		v6 := netip.MustParsePrefix("2001:db8:9::/64")
		// IPv6 next hop is a link-local on dum0; use dum0's own link-local
		// is not on the same subnet, so route via the configured global peer.
		gw := netip.MustParseAddr("2001:db8::2")
		if err := f.Update(v6, []Nexthop{{Interface: "dum0", Gateway: gw}}); err != nil {
			t.Fatalf("update v6: %v", err)
		}
		if routes := protoISISRoutes(t, netlink.FAMILY_V6); len(routes) == 0 {
			t.Fatal("no IPv6 proto-isis route installed")
		}

		// Also install an IPv4 route, then sweep keeping nothing.
		_ = f.Update(netip.MustParsePrefix("10.9.9.0/24"), []Nexthop{{Interface: "dum0", Gateway: netip.MustParseAddr("10.0.0.2")}})
		if err := f.Sweep(func(netip.Prefix) bool { return false }); err != nil {
			t.Fatalf("sweep: %v", err)
		}
		if r4 := protoISISRoutes(t, netlink.FAMILY_V4); len(r4) != 0 {
			t.Errorf("v4 routes survived sweep: %+v", r4)
		}
		if r6 := protoISISRoutes(t, netlink.FAMILY_V6); len(r6) != 0 {
			t.Errorf("v6 routes survived sweep: %+v", r6)
		}
	})
}

func TestNetlinkSweepKeepsListed(t *testing.T) {
	withNetns(t, func(t *testing.T) {
		f := NewNetlink(unix.RT_TABLE_MAIN)
		keep := netip.MustParsePrefix("10.1.0.0/24")
		drop := netip.MustParsePrefix("10.2.0.0/24")
		gw := []Nexthop{{Interface: "dum0", Gateway: netip.MustParseAddr("10.0.0.2")}}
		_ = f.Update(keep, gw)
		_ = f.Update(drop, gw)

		if err := f.Sweep(func(p netip.Prefix) bool { return p == keep }); err != nil {
			t.Fatalf("sweep: %v", err)
		}
		routes := protoISISRoutes(t, netlink.FAMILY_V4)
		if len(routes) != 1 || routes[0].Dst.String() != "10.1.0.0/24" {
			t.Fatalf("sweep should keep only 10.1.0.0/24, got %+v", routes)
		}
	})
}

// TestNetlinkRouteCarriesPriorityOnEveryNexthopShape guarantees that both the
// single-gateway and the ECMP form key on a non-zero metric, which is what
// keeps an IS-IS route from aliasing the kernel's connected route.
func TestNetlinkRouteCarriesPriorityOnEveryNexthopShape(t *testing.T) {
	if _, err := netlink.LinkByName("lo"); err != nil {
		t.Skipf("no loopback interface to resolve next hops against: %v", err)
	}
	f := NewNetlink(unix.RT_TABLE_MAIN)
	nh := func(gw string) Nexthop { return Nexthop{Interface: "lo", Gateway: netip.MustParseAddr(gw)} }
	for _, tc := range []struct {
		name     string
		nexthops []Nexthop
	}{
		{"single gateway", []Nexthop{nh("10.0.0.2")}},
		{"ecmp", []Nexthop{nh("10.0.0.2"), nh("10.0.0.3")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := f.route(netip.MustParsePrefix("10.9.9.0/24"), tc.nexthops)
			if err != nil {
				t.Fatalf("route: %v", err)
			}
			if r.Priority != routePriority {
				t.Errorf("Priority = %d, want %d", r.Priority, routePriority)
			}
		})
	}
}

// TestNetlinkKeepsConnectedRouteForTheSamePrefix guarantees that installing an
// IS-IS route for a locally connected subnet leaves the kernel's connected
// route alone — both while the IS-IS route is installed and after it is
// withdrawn, since the two no longer share the [prefix, tos, priority] key
// NLM_F_REPLACE matches on.
func TestNetlinkKeepsConnectedRouteForTheSamePrefix(t *testing.T) {
	withNetns(t, func(t *testing.T) {
		f := NewNetlink(unix.RT_TABLE_MAIN)
		// dum0 carries 10.0.0.1/24, so 10.0.0.0/24 is connected.
		dst := netip.MustParsePrefix("10.0.0.0/24")
		gw := netip.MustParseAddr("10.0.0.2")

		if err := f.Update(dst, []Nexthop{{Interface: "dum0", Gateway: gw}}); err != nil {
			t.Fatalf("update: %v", err)
		}
		routes := protoISISRoutes(t, netlink.FAMILY_V4)
		if len(routes) != 1 || routes[0].Priority != routePriority {
			t.Fatalf("want one proto-isis route at metric %d, got %+v", routePriority, routes)
		}
		if !hasConnectedRoute(t, dst) {
			t.Fatalf("Update replaced the connected route for %s", dst)
		}

		if err := f.Withdraw(dst); err != nil {
			t.Fatalf("withdraw: %v", err)
		}
		if routes := protoISISRoutes(t, netlink.FAMILY_V4); len(routes) != 0 {
			t.Fatalf("withdraw left the isis route behind: %+v", routes)
		}
		if !hasConnectedRoute(t, dst) {
			t.Fatalf("Withdraw removed the connected route for %s", dst)
		}
	})
}

// hasConnectedRoute reports whether the kernel's own (proto kernel scope link)
// route for prefix is present.
func hasConnectedRoute(t *testing.T, prefix netip.Prefix) bool {
	t.Helper()
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4,
		&netlink.Route{Protocol: unix.RTPROT_KERNEL}, netlink.RT_FILTER_PROTOCOL)
	if err != nil {
		t.Fatalf("list connected routes: %v", err)
	}
	for _, r := range routes {
		if r.Dst != nil && r.Dst.String() == prefix.String() {
			return true
		}
	}
	return false
}

// requireSeg6Local skips unless the kernel honors seg6local encapsulation
// (CONFIG_IPV6_SEG6_LWTUNNEL); without it every route below is rejected.
func requireSeg6Local(t *testing.T, f *Netlink) {
	t.Helper()
	probe := netip.MustParseAddr("fc00:6109:ca1::")
	if err := f.AddLocalSID(LocalSID{SID: probe, Behavior: BehaviorEnd}); err != nil {
		t.Skipf("kernel lacks seg6local encapsulation: %v", err)
	}
	if err := f.RemoveLocalSID(probe); err != nil {
		t.Fatalf("remove probe SID: %v", err)
	}
}

// TestNetlinkLocalSIDEndAndEndX: an End SID becomes a seg6local route on the
// SRv6 dummy device the FIB creates for it and an End.X SID a seg6local End.X
// route carrying the next hop as NH6 and the circuit as its device. Both read
// back with their encapsulation — the loopback would lose it (see
// srv6DummyDev) — and removing them leaves neither a route nor the device.
func TestNetlinkLocalSIDEndAndEndX(t *testing.T) {
	withNetns(t, func(t *testing.T) {
		f := NewNetlink(unix.RT_TABLE_MAIN)
		requireSeg6Local(t, f)

		end := netip.MustParseAddr("fc00:0:1::")
		endX := netip.MustParseAddr("fc00:0:1:1::")
		nexthop := netip.MustParseAddr("2001:db8::2")
		if err := f.AddLocalSID(LocalSID{SID: end, Behavior: BehaviorEnd}); err != nil {
			t.Fatalf("add End SID: %v", err)
		}
		if err := f.AddLocalSID(LocalSID{SID: endX, Behavior: BehaviorEndX, Nexthop: nexthop, Interface: "dum0"}); err != nil {
			t.Fatalf("add End.X SID: %v", err)
		}

		srv6, err := netlink.LinkByName(srv6DummyDev)
		if err != nil {
			t.Fatalf("%s by name: %v", srv6DummyDev, err)
		}
		dum, err := netlink.LinkByName("dum0")
		if err != nil {
			t.Fatalf("dum0 by name: %v", err)
		}
		routes := map[string]netlink.Route{}
		for _, r := range protoISISRoutes(t, netlink.FAMILY_V6) {
			routes[r.Dst.String()] = r
		}
		if len(routes) != 2 {
			t.Fatalf("installed %d proto-isis routes, want 2: %+v", len(routes), routes)
		}
		r, ok := routes[end.String()+"/128"]
		if !ok {
			t.Fatalf("no route for End SID %s", end)
		}
		if r.LinkIndex != srv6.Attrs().Index {
			t.Errorf("End SID route device index = %d, want %d (%s)", r.LinkIndex, srv6.Attrs().Index, srv6DummyDev)
		}
		endEnc, ok := r.Encap.(*netlink.SEG6LocalEncap)
		if !ok {
			t.Fatalf("End SID route encap = %T, want a seg6local encap", r.Encap)
		}
		if endEnc.Action != nl.SEG6_LOCAL_ACTION_END {
			t.Errorf("End SID route action = %d, want %d", endEnc.Action, nl.SEG6_LOCAL_ACTION_END)
		}
		r, ok = routes[endX.String()+"/128"]
		if !ok {
			t.Fatalf("no route for End.X SID %s", endX)
		}
		if r.LinkIndex != dum.Attrs().Index {
			t.Errorf("End.X route device index = %d, want %d (dum0)", r.LinkIndex, dum.Attrs().Index)
		}
		enc, ok := r.Encap.(*netlink.SEG6LocalEncap)
		if !ok {
			t.Fatalf("End.X route encap = %T, want a seg6local encap", r.Encap)
		}
		if enc.Action != nl.SEG6_LOCAL_ACTION_END_X {
			t.Errorf("End.X route action = %d, want %d", enc.Action, nl.SEG6_LOCAL_ACTION_END_X)
		}
		if want := net.ParseIP("2001:db8::2"); !enc.In6Addr.Equal(want) {
			t.Errorf("End.X route NH6 = %v, want %v", enc.In6Addr, want)
		}

		for _, sid := range []netip.Addr{end, endX} {
			if err := f.RemoveLocalSID(sid); err != nil {
				t.Fatalf("remove SID %s: %v", sid, err)
			}
		}
		if routes := protoISISRoutes(t, netlink.FAMILY_V6); len(routes) != 0 {
			t.Errorf("local SID routes survived removal: %+v", routes)
		}
		if _, err := netlink.LinkByName(srv6DummyDev); err == nil {
			t.Errorf("%s survived the removal of the last local SID", srv6DummyDev)
		}
	})
}

// TestNetlinkSweepTakesTheSRv6DeviceWithTheLastSweptSID: the startup sweep
// decides what a previous run left behind. A restart that still advertises the
// locator keeps the SID route and the device it sits on; one that no longer
// advertises it must be left with neither, or the device outlives every SID on
// it.
func TestNetlinkSweepTakesTheSRv6DeviceWithTheLastSweptSID(t *testing.T) {
	withNetns(t, func(t *testing.T) {
		f := NewNetlink(unix.RT_TABLE_MAIN)
		requireSeg6Local(t, f)
		sid := netip.MustParseAddr("fc00:0:1::")
		if err := f.AddLocalSID(LocalSID{SID: sid, Behavior: BehaviorEnd}); err != nil {
			t.Fatalf("add End SID: %v", err)
		}

		if err := f.Sweep(func(p netip.Prefix) bool { return p == netip.PrefixFrom(sid, 128) }); err != nil {
			t.Fatalf("sweep keeping the SID: %v", err)
		}
		if routes := protoISISRoutes(t, netlink.FAMILY_V6); len(routes) != 1 {
			t.Fatalf("sweep dropped the SID it was told to keep: %+v", routes)
		}
		if _, err := netlink.LinkByName(srv6DummyDev); err != nil {
			t.Fatalf("sweep removed %s while a SID still sits on it: %v", srv6DummyDev, err)
		}

		if err := f.Sweep(func(netip.Prefix) bool { return false }); err != nil {
			t.Fatalf("sweep keeping nothing: %v", err)
		}
		if routes := protoISISRoutes(t, netlink.FAMILY_V6); len(routes) != 0 {
			t.Errorf("SID route survived the sweep: %+v", routes)
		}
		if _, err := netlink.LinkByName(srv6DummyDev); err == nil {
			t.Errorf("%s survived the sweep of the last SID on it", srv6DummyDev)
		}
	})
}

// The three-namespace topology both SRv6 forwarding tests run on:
//
//	U --(uA|aU)-- A --(aN|nA)-- N
//
// A is the SRv6 endpoint. Traffic reaches it on aU and has to leave on aN —
// the transit case, as opposed to the hairpin a link-local next hop happens to
// survive — steered at a SID of A's by an SRH that U pushes.
const (
	srv6ProbePort = 9909
	srv6ProbeSID  = "fc00:a:1::"
)

var srv6ProbePayload = []byte("goisis-srv6-transit-probe")

func mustNetns(t *testing.T) netns.NsHandle {
	t.Helper()
	h, err := netns.New() // creates and enters
	if err != nil {
		t.Fatalf("new netns: %v", err)
	}
	t.Cleanup(func() { _ = h.Close() })
	return h
}

func enterNetns(t *testing.T, h netns.NsHandle) {
	t.Helper()
	if err := netns.Set(h); err != nil {
		t.Fatalf("enter netns: %v", err)
	}
}

// upAddr brings an interface up and gives it the addresses, skipping duplicate
// address detection so the test does not wait a second per address.
func upAddr(t *testing.T, dev string, cidrs ...string) {
	t.Helper()
	link, err := netlink.LinkByName(dev)
	if err != nil {
		t.Fatalf("link %s: %v", dev, err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		t.Fatalf("link %s up: %v", dev, err)
	}
	for _, cidr := range cidrs {
		addr, err := netlink.ParseAddr(cidr)
		if err != nil {
			t.Fatalf("parse %s: %v", cidr, err)
		}
		addr.Flags |= unix.IFA_F_NODAD
		if err := netlink.AddrAdd(link, addr); err != nil {
			t.Fatalf("addr %s on %s: %v", cidr, dev, err)
		}
	}
}

// sysctlOn sets net sysctls of the namespace the calling thread is in.
func sysctlOn(t *testing.T, keys ...string) {
	t.Helper()
	for _, k := range keys {
		if err := os.WriteFile("/proc/sys/"+k, []byte("1"), 0o644); err != nil {
			t.Fatalf("sysctl %s: %v", k, err)
		}
	}
}

func addRoute6(t *testing.T, dev, dst, gw string, encap netlink.Encap) {
	t.Helper()
	link, err := netlink.LinkByName(dev)
	if err != nil {
		t.Fatalf("link %s: %v", dev, err)
	}
	_, ipnet, err := net.ParseCIDR(dst)
	if err != nil {
		t.Fatalf("parse %s: %v", dst, err)
	}
	r := &netlink.Route{LinkIndex: link.Attrs().Index, Dst: ipnet, Encap: encap}
	if gw != "" {
		r.Gw = net.ParseIP(gw)
	}
	if err := netlink.RouteReplace(r); err != nil {
		t.Fatalf("route %s via %s dev %s: %v", dst, gw, dev, err)
	}
}

// waitResolved pokes the far end until the neighbor entry for addr on dev
// leaves INCOMPLETE, so later measurements are not distorted by queued packets.
func waitResolved(t *testing.T, dev, addr string, poke func()) {
	t.Helper()
	link, err := netlink.LinkByName(dev)
	if err != nil {
		t.Fatalf("link %s: %v", dev, err)
	}
	const resolved = netlink.NUD_REACHABLE | netlink.NUD_STALE | netlink.NUD_DELAY | netlink.NUD_PROBE | netlink.NUD_PERMANENT
	want := net.ParseIP(addr)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		poke()
		neighs, err := netlink.NeighList(link.Attrs().Index, netlink.FAMILY_V6)
		if err != nil {
			t.Fatalf("neighbors on %s: %v", dev, err)
		}
		for _, n := range neighs {
			if n.IP.Equal(want) && n.State&resolved != 0 {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("neighbor %s on %s never resolved", addr, dev)
}

// lockNetns pins the test to one OS thread — a network namespace is a thread
// attribute, so a subtest or goroutine would run somewhere else — and returns
// the teardown that puts the thread back in the caller's namespace. It has to
// be deferred rather than registered with t.Cleanup: cleanups run after the
// test's own defers, by which point the thread would already be unlocked.
func lockNetns(t *testing.T) func() {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("netlink FIB test needs root; run: go test -exec sudo ./pkg/fib")
	}
	runtime.LockOSThread()
	orig, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		t.Fatalf("get netns: %v", err)
	}
	return func() {
		_ = netns.Set(orig)
		_ = orig.Close()
		runtime.UnlockOSThread()
	}
}

// srv6Transit is the built topology: a receiver in N, a sender in U whose
// packets carry an SRH ending at srv6ProbeSID, and the namespaces themselves.
type srv6Transit struct {
	nsU, nsN, nsA netns.NsHandle
	far           net.PacketConn // bound in N to the global address probes end at
	conn          net.Conn       // bound in U, every write steered through the SID
}

// newSRv6Transit builds the topology above and leaves the calling thread in A,
// with the neighbor towards N already resolved so that a later measurement is
// not credited packets the kernel queued during discovery. It installs no SID:
// that is what each test puts in place.
func newSRv6Transit(t *testing.T) *srv6Transit {
	t.Helper()
	tr := &srv6Transit{}
	tr.nsU, tr.nsN, tr.nsA = mustNetns(t), mustNetns(t), mustNetns(t)

	// Both veth pairs are made in A, which then hands one end of each away.
	for _, v := range []struct {
		local, peer string
		ns          netns.NsHandle
	}{
		{"aU", "uA", tr.nsU},
		{"aN", "nA", tr.nsN},
	} {
		la := netlink.NewLinkAttrs()
		la.Name = v.local
		if err := netlink.LinkAdd(&netlink.Veth{LinkAttrs: la, PeerName: v.peer}); err != nil {
			t.Fatalf("add veth %s: %v", v.local, err)
		}
		peer, err := netlink.LinkByName(v.peer)
		if err != nil {
			t.Fatalf("peer %s: %v", v.peer, err)
		}
		if err := netlink.LinkSetNsFd(peer, int(v.ns)); err != nil {
			t.Fatalf("move %s: %v", v.peer, err)
		}
	}
	upAddr(t, "lo")
	upAddr(t, "aU", "2001:db8:1::2/64")
	upAddr(t, "aN", "2001:db8:2::1/64")
	sysctlOn(t, "net/ipv6/conf/all/forwarding", "net/ipv6/conf/all/seg6_enabled",
		"net/ipv6/conf/aU/seg6_enabled", "net/ipv6/conf/aN/seg6_enabled")

	// N answers on both a global address and the link-local an IS-IS hello
	// would carry, so an End.X next hop can be either of the two.
	enterNetns(t, tr.nsN)
	upAddr(t, "lo")
	upAddr(t, "nA", "2001:db8:2::2/64", "fe80::2/64")
	sysctlOn(t, "net/ipv6/conf/all/seg6_enabled", "net/ipv6/conf/nA/seg6_enabled")
	far, err := net.ListenPacket("udp6", fmt.Sprintf("[2001:db8:2::2]:%d", srv6ProbePort))
	if err != nil {
		t.Fatalf("listen at the far end: %v", err)
	}
	t.Cleanup(func() { _ = far.Close() })
	tr.far = far

	// Resolve A's neighbor towards N before measuring anything: while NDP is
	// pending the kernel queues the packets it cannot send yet and releases
	// them once it completes, which would credit them to whichever case is
	// running by then.
	enterNetns(t, tr.nsA)
	warm, err := net.Dial("udp6", fmt.Sprintf("[2001:db8:2::2]:%d", srv6ProbePort))
	if err != nil {
		t.Fatalf("dial the far end from the transit node: %v", err)
	}
	t.Cleanup(func() { _ = warm.Close() })
	waitResolved(t, "aN", "2001:db8:2::2", func() { _, _ = warm.Write(srv6ProbePayload) })

	enterNetns(t, tr.nsU)
	upAddr(t, "lo")
	upAddr(t, "uA", "2001:db8:1::1/64")
	addRoute6(t, "uA", srv6ProbeSID+"/128", "2001:db8:1::2", nil)
	addRoute6(t, "uA", "2001:db8:2::/64", "2001:db8:1::2", nil)
	// Steer traffic for N through A's SID. The SRH segment list is stored last
	// hop first, so srv6ProbeSID is the destination A sees.
	addRoute6(t, "uA", "2001:db8:2::2/128", "2001:db8:1::2", &netlink.SEG6Encap{
		Mode:     nl.SEG6_IPTUN_MODE_ENCAP,
		Segments: []net.IP{net.ParseIP("2001:db8:2::2"), net.ParseIP(srv6ProbeSID)},
	})
	conn, err := net.Dial("udp6", fmt.Sprintf("[2001:db8:2::2]:%d", srv6ProbePort))
	if err != nil {
		t.Fatalf("dial the far end: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	tr.conn = conn

	enterNetns(t, tr.nsA)
	return tr
}

// probe sends n packets from U and returns how many reached N. The calling
// thread is left in A.
func (tr *srv6Transit) probe(t *testing.T, n int) int {
	t.Helper()
	enterNetns(t, tr.nsU)
	tr.drain(t, 200*time.Millisecond) // whatever the previous case left
	for range n {
		// Loss is what the count measures, so a write error is not itself a
		// failure; the first packet or two pay for neighbor discovery on the
		// egress link.
		_, _ = tr.conn.Write(srv6ProbePayload)
		time.Sleep(50 * time.Millisecond)
	}
	got := tr.drain(t, time.Second)
	enterNetns(t, tr.nsA)
	return got
}

// drain reads the far end for d and returns how many probes arrived.
func (tr *srv6Transit) drain(t *testing.T, d time.Duration) int {
	t.Helper()
	buf := make([]byte, 128)
	n := 0
	if err := tr.far.SetReadDeadline(time.Now().Add(d)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	for {
		c, _, err := tr.far.ReadFrom(buf)
		if err != nil {
			return n // deadline
		}
		if bytes.Equal(buf[:c], srv6ProbePayload) {
			n++
		}
	}
}

const srv6Probes = 10

// TestNetlinkEndSIDForwardsTransitTraffic: an End SID installed by the FIB
// forwards a packet steered at it, and reads back carrying its seg6local
// encapsulation. Both fail if the SID is installed on the loopback — Linux
// 6.12 drops the lwtunnel state of such a route, leaving a plain route to the
// SID that swallows every packet (see srv6DummyDev) — which is why this is a
// traffic test and not another attribute comparison.
func TestNetlinkEndSIDForwardsTransitTraffic(t *testing.T) {
	defer lockNetns(t)()
	tr := newSRv6Transit(t)
	f := NewNetlink(unix.RT_TABLE_MAIN)
	requireSeg6Local(t, f)

	sid := netip.MustParseAddr(srv6ProbeSID)
	if err := f.AddLocalSID(LocalSID{SID: sid, Behavior: BehaviorEnd}); err != nil {
		t.Fatalf("install End SID: %v", err)
	}
	routes := protoISISRoutes(t, netlink.FAMILY_V6)
	if len(routes) != 1 {
		t.Fatalf("installed %d proto-isis routes, want 1: %+v", len(routes), routes)
	}
	// Not fatal: the traffic below is the other half of the guarantee, and a
	// route that lost its encapsulation should be reported as both.
	switch enc, ok := routes[0].Encap.(*netlink.SEG6LocalEncap); {
	case !ok:
		t.Errorf("End SID route encap = %T, want a seg6local encap", routes[0].Encap)
	case enc.Action != nl.SEG6_LOCAL_ACTION_END:
		t.Errorf("End SID route action = %d, want %d", enc.Action, nl.SEG6_LOCAL_ACTION_END)
	}
	if got := tr.probe(t, srv6Probes); got == 0 {
		t.Errorf("End SID forwarded none of %d packets", srv6Probes)
	}

	if err := f.RemoveLocalSID(sid); err != nil {
		t.Fatalf("remove End SID: %v", err)
	}
	if routes := protoISISRoutes(t, netlink.FAMILY_V6); len(routes) != 0 {
		t.Errorf("End SID route survived removal: %+v", routes)
	}
	if _, err := netlink.LinkByName(srv6DummyDev); err == nil {
		t.Errorf("%s survived the removal of the last local SID", srv6DummyDev)
	}
	if got := tr.probe(t, srv6Probes); got != 0 {
		t.Errorf("removed End SID still forwarded %d packets", got)
	}
}

// TestNetlinkEndXForwardsFromAnotherIngressInterface: an End.X SID has to
// forward a packet that arrived on some other interface out of its own link.
// Linux resolves the SID's next hop with seg6_lookup_any_nexthop, which pins a
// link-local next hop to the ingress interface, so only a global next hop on
// the adjacency's subnet forwards anything — the control case here, and the
// reason server.endXNexthop never advertises a link-local one.
func TestNetlinkEndXForwardsFromAnotherIngressInterface(t *testing.T) {
	defer lockNetns(t)()
	tr := newSRv6Transit(t)
	f := NewNetlink(unix.RT_TABLE_MAIN)
	requireSeg6Local(t, f)

	sid := LocalSID{SID: netip.MustParseAddr(srv6ProbeSID), Behavior: BehaviorEndX, Interface: "aN"}
	for _, tc := range []struct {
		what    string
		nexthop string
		forward bool
	}{
		{what: "a global next hop on the adjacency's subnet", nexthop: "2001:db8:2::2", forward: true},
		{what: "the neighbor's link-local next hop", nexthop: "fe80::2"},
	} {
		sid.Nexthop = netip.MustParseAddr(tc.nexthop)
		if err := f.AddLocalSID(sid); err != nil {
			t.Fatalf("install End.X SID with %s: %v", tc.what, err)
		}
		switch got := tr.probe(t, srv6Probes); {
		case tc.forward && got == 0:
			t.Errorf("End.X with %s forwarded none of %d packets", tc.what, srv6Probes)
		case !tc.forward && got != 0:
			t.Errorf("End.X with %s forwarded %d packets, want none", tc.what, got)
		}
	}
}

// TestLocalSIDRouteAsksTheKernelForTheRightDecapTable guarantees that each
// decapsulating behavior names its table the way the kernel wants it named.
//
// The three are not interchangeable. End.DT6 takes a plain IPv6 table and the
// kernel looks the packet up in it directly. End.DT4 and End.DT46 name a VRF:
// SEG6_LOCAL_TABLE is refused with EINVAL for both, and the kernel resolves
// SEG6_LOCAL_VRFTABLE through the l3mdev instead. Nothing in goisis originates
// these, so a test that programs the kernel would also have to satisfy two
// prerequisites that are the operator's (a VRF device on that table, and
// net.vrf.strict_mode); this pins the attribute a consumer's SID turns into
// without needing either.
func TestLocalSIDRouteAsksTheKernelForTheRightDecapTable(t *testing.T) {
	// The route is built, not installed: localSIDRoute creates the dummy
	// device the SID lives on, which is the only reason this needs a
	// namespace. No VRF and no sysctl, which is the point.
	withNetns(t, func(t *testing.T) { checkDecapTables(t) })
}

func checkDecapTables(t *testing.T) {
	t.Helper()
	n := &Netlink{}
	for _, tc := range []struct {
		name     string
		behavior SIDBehavior
		action   int
		vrf      bool
	}{
		{"End.DT6 takes a plain table", BehaviorEndDT6, nl.SEG6_LOCAL_ACTION_END_DT6, false},
		{"End.DT4 takes a VRF", BehaviorEndDT4, nl.SEG6_LOCAL_ACTION_END_DT4, true},
		{"End.DT46 takes a VRF", BehaviorEndDT46, seg6LocalActionEndDT46, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := n.localSIDRoute(LocalSID{
				SID: netip.MustParseAddr("fc00:d7::1"), Behavior: tc.behavior, Table: 100,
			})
			if err != nil {
				t.Fatalf("localSIDRoute: %v", err)
			}
			enc, ok := r.Encap.(*netlink.SEG6LocalEncap)
			if !ok {
				t.Fatalf("Encap = %T, want *netlink.SEG6LocalEncap", r.Encap)
			}
			if enc.Action != tc.action {
				t.Errorf("action = %d, want %d", enc.Action, tc.action)
			}
			if got := enc.Flags[nl.SEG6_LOCAL_VRFTABLE]; got != tc.vrf {
				t.Errorf("SEG6_LOCAL_VRFTABLE = %v, want %v", got, tc.vrf)
			}
			if got := enc.Flags[nl.SEG6_LOCAL_TABLE]; got != !tc.vrf {
				t.Errorf("SEG6_LOCAL_TABLE = %v, want %v", got, !tc.vrf)
			}
			if tc.vrf && enc.VrfTable != 100 {
				t.Errorf("VrfTable = %d, want 100", enc.VrfTable)
			}
			if !tc.vrf && enc.Table != 100 {
				t.Errorf("Table = %d, want 100", enc.Table)
			}
		})
	}
}
