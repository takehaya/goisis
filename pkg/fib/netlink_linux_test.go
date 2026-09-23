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
// loopback and an End.X SID a seg6local End.X route carrying the next hop as
// NH6 and the circuit as its device; removing them leaves nothing behind.
//
// Only the End.X route's encapsulation is checked attribute by attribute: a
// route whose device is the loopback loses its lwtunnel state on this kernel
// (6.12 reports no RTA_ENCAP for it, and a packet steered at such a SID is
// dropped), which is a defect in localSIDRoute's device choice for End rather
// than an expectation worth freezing here.
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

		lo, err := netlink.LinkByName("lo")
		if err != nil {
			t.Fatalf("lo by name: %v", err)
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
		if r, ok := routes[end.String()+"/128"]; !ok || r.LinkIndex != lo.Attrs().Index {
			t.Errorf("End SID route = %+v (present %v), want one on lo (index %d)", r, ok, lo.Attrs().Index)
		}
		r, ok := routes[endX.String()+"/128"]
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
	})
}

// The three-namespace topology of the End.X forwarding test:
//
//	U --(uA|aU)-- A --(aN|nA)-- N
//
// A holds an End.X SID whose link is aN, and the traffic reaches A on aU: the
// transit case, as opposed to the hairpin a link-local next hop happens to
// survive.
const endXProbePort = 9909

var endXProbePayload = []byte("goisis-r09-end-x-probe")

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

// TestNetlinkEndXForwardsFromAnotherIngressInterface: an End.X SID has to
// forward a packet that arrived on some other interface out of its own link.
// Linux resolves the SID's next hop with seg6_lookup_any_nexthop, which pins a
// link-local next hop to the ingress interface, so only a global next hop on
// the adjacency's subnet forwards anything — the control case here, and the
// reason server.endXNexthop never advertises a link-local one.
//
// Everything runs on one locked thread: the namespace is a thread attribute,
// and a subtest or goroutine would run somewhere else.
func TestNetlinkEndXForwardsFromAnotherIngressInterface(t *testing.T) {
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

	nsU, nsN, nsA := mustNetns(t), mustNetns(t), mustNetns(t)

	// Both veth pairs are made in A, which then hands one end of each away.
	for _, v := range []struct {
		local, peer string
		ns          netns.NsHandle
	}{
		{"aU", "uA", nsU},
		{"aN", "nA", nsN},
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
	f := NewNetlink(unix.RT_TABLE_MAIN)
	requireSeg6Local(t, f)

	// N answers on both a global address and the link-local an IS-IS hello
	// would carry, so the two next hops differ only in which one is used.
	enterNetns(t, nsN)
	upAddr(t, "lo")
	upAddr(t, "nA", "2001:db8:2::2/64", "fe80::2/64")
	sysctlOn(t, "net/ipv6/conf/all/seg6_enabled", "net/ipv6/conf/nA/seg6_enabled")
	far, err := net.ListenPacket("udp6", fmt.Sprintf("[2001:db8:2::2]:%d", endXProbePort))
	if err != nil {
		t.Fatalf("listen at the far end: %v", err)
	}
	defer far.Close() //nolint:errcheck // test teardown

	// Resolve A's neighbor towards N before measuring anything: while NDP is
	// pending the kernel queues the packets it cannot send yet and releases
	// them once it completes, which would credit them to whichever case is
	// running by then.
	enterNetns(t, nsA)
	warm, err := net.Dial("udp6", fmt.Sprintf("[2001:db8:2::2]:%d", endXProbePort))
	if err != nil {
		t.Fatalf("dial the far end from the transit node: %v", err)
	}
	defer warm.Close() //nolint:errcheck // test teardown
	waitResolved(t, "aN", "2001:db8:2::2", func() { _, _ = warm.Write(endXProbePayload) })

	enterNetns(t, nsU)
	upAddr(t, "lo")
	upAddr(t, "uA", "2001:db8:1::1/64")
	addRoute6(t, "uA", "fc00:a:1::/128", "2001:db8:1::2", nil)
	addRoute6(t, "uA", "2001:db8:2::/64", "2001:db8:1::2", nil)
	// Steer traffic for N through A's End.X SID. The SRH segment list is
	// stored last hop first, so fc00:a:1:: is the destination A sees.
	addRoute6(t, "uA", "2001:db8:2::2/128", "2001:db8:1::2", &netlink.SEG6Encap{
		Mode:     nl.SEG6_IPTUN_MODE_ENCAP,
		Segments: []net.IP{net.ParseIP("2001:db8:2::2"), net.ParseIP("fc00:a:1::")},
	})
	conn, err := net.Dial("udp6", fmt.Sprintf("[2001:db8:2::2]:%d", endXProbePort))
	if err != nil {
		t.Fatalf("dial the far end: %v", err)
	}
	defer conn.Close() //nolint:errcheck // test teardown

	// received drains the far end for d and returns how many probes arrived.
	received := func(d time.Duration) int {
		buf := make([]byte, 128)
		n := 0
		if err := far.SetReadDeadline(time.Now().Add(d)); err != nil {
			t.Fatalf("set read deadline: %v", err)
		}
		for {
			c, _, err := far.ReadFrom(buf)
			if err != nil {
				return n // deadline
			}
			if bytes.Equal(buf[:c], endXProbePayload) {
				n++
			}
		}
	}

	const probes = 10
	sid := LocalSID{SID: netip.MustParseAddr("fc00:a:1::"), Behavior: BehaviorEndX, Interface: "aN"}
	for _, tc := range []struct {
		what    string
		nexthop string
		forward bool
	}{
		{what: "a global next hop on the adjacency's subnet", nexthop: "2001:db8:2::2", forward: true},
		{what: "the neighbor's link-local next hop", nexthop: "fe80::2"},
	} {
		enterNetns(t, nsA)
		sid.Nexthop = netip.MustParseAddr(tc.nexthop)
		if err := f.AddLocalSID(sid); err != nil {
			t.Fatalf("install End.X SID with %s: %v", tc.what, err)
		}
		enterNetns(t, nsU)
		received(200 * time.Millisecond) // whatever the previous case left
		for range probes {
			// Loss is what the counts below measure, so a write error is not
			// itself a failure; the first packet or two pay for neighbor
			// discovery on the egress link.
			_, _ = conn.Write(endXProbePayload)
			time.Sleep(50 * time.Millisecond)
		}
		switch got := received(time.Second); {
		case tc.forward && got == 0:
			t.Errorf("End.X with %s forwarded none of %d packets", tc.what, probes)
		case !tc.forward && got != 0:
			t.Errorf("End.X with %s forwarded %d packets, want none", tc.what, got)
		}
	}
}
