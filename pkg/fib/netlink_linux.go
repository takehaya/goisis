//go:build linux

package fib

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// rtprotoISIS is the kernel route protocol id for IS-IS (RTPROT_ISIS); routes
// goisis installs are tagged with it so they are distinguishable and
// sweepable (`ip route show proto isis`).
const rtprotoISIS = unix.RTPROT_ISIS

// routePriority is the metric (RTA_PRIORITY) on every IS-IS route. It must be
// non-zero: a route's kernel key is [prefix, tos, priority], so at metric 0 an
// IS-IS route for a locally connected subnet shares the key with the kernel's
// `proto kernel scope link` route and NLM_F_REPLACE overwrites it — Withdraw
// then leaves the subnet unrouted. 115 is the conventional IS-IS
// administrative distance; an IPv4 connected route (metric 0) still wins.
// Not applied to seg6local local-SID routes: those are ours alone, nothing
// else installs the SID address, and RemoveLocalSID must keep matching them.
const routePriority = 115

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

// Table returns the routing table this FIB writes to.
func (n *Netlink) Table() int { return n.table }

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
	if err := netlink.RouteDel(n.baseRoute(prefix)); err != nil && !isNotExist(err) {
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

// baseRoute is the key shared by every IS-IS route: Update, Withdraw and the
// startup sweep must agree on it, or a delete misses the route it installed.
func (n *Netlink) baseRoute(prefix netip.Prefix) *netlink.Route {
	return &netlink.Route{
		Dst:      prefixToIPNet(prefix),
		Protocol: rtprotoISIS,
		Table:    n.table,
		Priority: routePriority,
	}
}

// route builds the netlink route for a prefix and its next-hop set, using a
// single gateway for one next hop and an ECMP multipath for several.
func (n *Netlink) route(prefix netip.Prefix, nexthops []Nexthop) (*netlink.Route, error) {
	r := n.baseRoute(prefix)
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

// AddLocalSID installs a local SRv6 SID as a seg6local route.
func (n *Netlink) AddLocalSID(sid LocalSID) error {
	r, err := n.localSIDRoute(sid)
	if err != nil {
		return err
	}
	if err := netlink.RouteReplace(r); err != nil {
		return fmt.Errorf("fib: install local SID %s: %w", sid.SID, err)
	}
	return nil
}

// RemoveLocalSID removes a local SRv6 SID.
func (n *Netlink) RemoveLocalSID(sid netip.Addr) error {
	r := &netlink.Route{
		Dst:      &net.IPNet{IP: sid.AsSlice(), Mask: net.CIDRMask(128, 128)},
		Protocol: rtprotoISIS,
		Table:    n.table,
	}
	if err := netlink.RouteDel(r); err != nil && !isNotExist(err) {
		return fmt.Errorf("fib: remove local SID %s: %w", sid, err)
	}
	return nil
}

func (n *Netlink) localSIDRoute(sid LocalSID) (*netlink.Route, error) {
	enc := &netlink.SEG6LocalEncap{Flags: [nl.SEG6_LOCAL_MAX]bool{}}
	enc.Flags[nl.SEG6_LOCAL_ACTION] = true
	// seg6local routes attach to the loopback device, except End.X, which
	// points at the neighbor's link on the circuit the adjacency is on.
	dev := "lo"
	switch sid.Behavior {
	case BehaviorEnd:
		enc.Action = nl.SEG6_LOCAL_ACTION_END
	case BehaviorEndX:
		if !sid.Nexthop.Is6() {
			return nil, fmt.Errorf("fib: End.X SID %s needs an IPv6 next hop", sid.SID)
		}
		enc.Action = nl.SEG6_LOCAL_ACTION_END_X
		enc.Flags[nl.SEG6_LOCAL_NH6] = true
		enc.In6Addr = sid.Nexthop.AsSlice()
		// Not SEG6_LOCAL_OIF: the kernel's End.X action accepts only NH6, and
		// rejects the route outright if any other attribute is set. The egress
		// link is expressed as the route's device instead, which is also what
		// gives a link-local next hop its scope.
		if sid.Interface != "" {
			dev = sid.Interface
		}
	case BehaviorEndDT4:
		enc.Action = nl.SEG6_LOCAL_ACTION_END_DT4
		enc.Flags[nl.SEG6_LOCAL_TABLE] = true
		enc.Table = sid.Table
	case BehaviorEndDT6:
		enc.Action = nl.SEG6_LOCAL_ACTION_END_DT6
		enc.Flags[nl.SEG6_LOCAL_TABLE] = true
		enc.Table = sid.Table
	case BehaviorEndDT46:
		// The vendored netlink library predates SEG6_LOCAL_ACTION_END_DT46.
		return nil, fmt.Errorf("fib: End.DT46 is not yet programmable by the netlink FIB")
	default:
		return nil, fmt.Errorf("fib: unsupported SID behavior %d", sid.Behavior)
	}
	link, err := netlink.LinkByName(dev)
	if err != nil {
		return nil, fmt.Errorf("fib: interface %q for local SID: %w", dev, err)
	}
	return &netlink.Route{
		Dst:       &net.IPNet{IP: sid.SID.AsSlice(), Mask: net.CIDRMask(128, 128)},
		Protocol:  rtprotoISIS,
		Table:     n.table,
		LinkIndex: link.Attrs().Index,
		Encap:     enc,
	}, nil
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
	return errors.Is(err, unix.ESRCH) || errors.Is(err, unix.ENOENT)
}
