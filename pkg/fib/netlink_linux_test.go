//go:build linux

package fib

import (
	"net"
	"net/netip"
	"os"
	"runtime"
	"testing"

	"github.com/vishvananda/netlink"
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
