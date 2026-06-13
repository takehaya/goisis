//go:build linux

package fib

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// rtprotoISIS is the kernel route protocol id for IS-IS (RTPROT_ISIS); routes
// goisis installs are tagged with it so they are distinguishable and
// sweepable (`ip route show proto isis`).
const rtprotoISIS = unix.RTPROT_ISIS

// Netlink is a Linux FIB that programs routes via rtnetlink. Routes are
// installed in the given table tagged with the IS-IS route protocol. It
// requires CAP_NET_ADMIN.
type Netlink struct {
	table int
}

// NewNetlink returns a netlink FIB writing to the given routing table (use
// unix.RT_TABLE_MAIN, 254, for the main table).
func NewNetlink(table int) *Netlink {
	if table == 0 {
		table = unix.RT_TABLE_MAIN
	}
	return &Netlink{table: table}
}

// Update implements FIB: it installs or atomically replaces the route to
// prefix with the given next-hop set.
func (n *Netlink) Update(prefix netip.Prefix, nexthops []Nexthop) error {
	if len(nexthops) == 0 {
		return n.Withdraw(prefix)
	}
	r, err := n.route(prefix, nexthops)
	if err != nil {
		return err
	}
	if err := netlink.RouteReplace(r); err != nil {
		return fmt.Errorf("fib: replace %s: %w", prefix, err)
	}
	return nil
}

// Withdraw implements FIB.
func (n *Netlink) Withdraw(prefix netip.Prefix) error {
	r := &netlink.Route{Dst: prefixToIPNet(prefix), Protocol: rtprotoISIS, Table: n.table}
	if err := netlink.RouteDel(r); err != nil && !isNotExist(err) {
		return fmt.Errorf("fib: delete %s: %w", prefix, err)
	}
	return nil
}

// Sweep implements FIB: it removes every proto-isis route in the table for
// which keep returns false.
func (n *Netlink) Sweep(keep func(netip.Prefix) bool) error {
	filter := &netlink.Route{Protocol: rtprotoISIS, Table: n.table}
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		routes, err := netlink.RouteListFiltered(family, filter, netlink.RT_FILTER_PROTOCOL|netlink.RT_FILTER_TABLE)
		if err != nil {
			return fmt.Errorf("fib: list proto-isis routes: %w", err)
		}
		for i := range routes {
			r := &routes[i]
			if r.Dst == nil {
				continue
			}
			p, ok := ipNetToPrefix(r.Dst)
			if ok && keep(p) {
				continue
			}
			if err := netlink.RouteDel(r); err != nil && !isNotExist(err) {
				return fmt.Errorf("fib: sweep %s: %w", r.Dst, err)
			}
		}
	}
	return nil
}

// route builds the netlink route for a prefix and its next-hop set, using a
// single gateway for one next hop and an ECMP multipath for several.
func (n *Netlink) route(prefix netip.Prefix, nexthops []Nexthop) (*netlink.Route, error) {
	r := &netlink.Route{Dst: prefixToIPNet(prefix), Protocol: rtprotoISIS, Table: n.table}
	if len(nexthops) == 1 {
		link, err := netlink.LinkByName(nexthops[0].Interface)
		if err != nil {
			return nil, fmt.Errorf("fib: interface %q: %w", nexthops[0].Interface, err)
		}
		r.LinkIndex = link.Attrs().Index
		r.Gw = nexthops[0].Gateway.AsSlice()
		return r, nil
	}
	for _, nh := range nexthops {
		link, err := netlink.LinkByName(nh.Interface)
		if err != nil {
			return nil, fmt.Errorf("fib: interface %q: %w", nh.Interface, err)
		}
		r.MultiPath = append(r.MultiPath, &netlink.NexthopInfo{
			LinkIndex: link.Attrs().Index,
			Gw:        nh.Gateway.AsSlice(),
		})
	}
	return r, nil
}

func prefixToIPNet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{
		IP:   p.Masked().Addr().AsSlice(),
		Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen()),
	}
}

func ipNetToPrefix(n *net.IPNet) (netip.Prefix, bool) {
	addr, ok := netip.AddrFromSlice(n.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	ones, _ := n.Mask.Size()
	return netip.PrefixFrom(addr.Unmap(), ones), true
}

func isNotExist(err error) bool {
	return err == unix.ESRCH || err == unix.ENOENT
}
