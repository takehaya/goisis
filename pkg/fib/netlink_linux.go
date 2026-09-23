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

// srv6DummyDev is the dummy interface every non-End.X local SID is installed
// on. It cannot be the loopback: Linux 6.12 drops the lwtunnel state of a
// seg6local route whose output device is `lo` (the route reads back with no
// RTA_ENCAP and every packet steered at the SID is dropped), while the same
// route on a dummy device forwards. One shared device rather than one per
// locator — the device is only somewhere to hang the route, so N of them would
// be N link-locals and N lifecycles for no gain — and a fixed name so a
// restart finds and reuses the device it made last time.
const srv6DummyDev = "isis-srv6"

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
	// A previous run may have left the SRv6 dummy device behind with every SID
	// on it now swept; the sweep is what keeps it from outliving them.
	return n.pruneSRv6Dummy()
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
	return n.pruneSRv6Dummy()
}

func (n *Netlink) localSIDRoute(sid LocalSID) (*netlink.Route, error) {
	enc := &netlink.SEG6LocalEncap{Flags: [nl.SEG6_LOCAL_MAX]bool{}}
	enc.Flags[nl.SEG6_LOCAL_ACTION] = true
	// seg6local routes attach to our dummy device (see srv6DummyDev), except
	// End.X, which points at the neighbor's link on the circuit the adjacency
	// is on.
	dev := ""
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
		// Not SEG6_LOCAL_OIF: the kernel accepts it next to NH6 and then
		// ignores it. End.X resolves NH6 with seg6_lookup_any_nexthop, which
		// consults neither that attribute nor the route's own device; it sets
		// flowi6_iif and, for a link-local next hop, RT6_LOOKUP_F_IFACE, so a
		// link-local one resolves only on the ingress interface and drops every
		// transit packet. The next hop must therefore be a global address on
		// the circuit's subnet (server.endXNexthop picks it); the device below
		// is what makes `ip -6 route` name the link the SID belongs to.
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
	index, err := n.localSIDDevice(dev)
	if err != nil {
		return nil, err
	}
	return &netlink.Route{
		Dst:       &net.IPNet{IP: sid.SID.AsSlice(), Mask: net.CIDRMask(128, 128)},
		Protocol:  rtprotoISIS,
		Table:     n.table,
		LinkIndex: index,
		Encap:     enc,
	}, nil
}

// localSIDDevice resolves the output device of a local SID route, creating the
// SRv6 dummy device when dev is empty (everything but End.X). The device is
// ours: AddLocalSID is re-run periodically from housekeeping, so one deleted
// or brought down out-of-band is repaired on the next pass.
func (n *Netlink) localSIDDevice(dev string) (int, error) {
	if dev != "" {
		link, err := netlink.LinkByName(dev)
		if err != nil {
			return 0, fmt.Errorf("fib: interface %q for local SID: %w", dev, err)
		}
		return link.Attrs().Index, nil
	}
	link, err := netlink.LinkByName(srv6DummyDev)
	if err != nil {
		if !isLinkNotFound(err) {
			return 0, fmt.Errorf("fib: interface %q for local SID: %w", srv6DummyDev, err)
		}
		attrs := netlink.NewLinkAttrs()
		attrs.Name = srv6DummyDev
		if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: attrs}); err != nil && !errors.Is(err, unix.EEXIST) {
			return 0, fmt.Errorf("fib: create %q for local SIDs: %w", srv6DummyDev, err)
		}
		if link, err = netlink.LinkByName(srv6DummyDev); err != nil {
			return 0, fmt.Errorf("fib: interface %q for local SID: %w", srv6DummyDev, err)
		}
	}
	if link.Attrs().Flags&net.FlagUp == 0 {
		if err := netlink.LinkSetUp(link); err != nil {
			return 0, fmt.Errorf("fib: bring %q up for local SIDs: %w", srv6DummyDev, err)
		}
	}
	return link.Attrs().Index, nil
}

// pruneSRv6Dummy removes the SRv6 dummy device once no local SID is left on
// it, so neither a clean shutdown nor a startup sweep leaves it orphaned. Any
// proto-isis route on the device holds it, in any table: a second instance
// writing to another table shares the device.
func (n *Netlink) pruneSRv6Dummy() error {
	link, err := netlink.LinkByName(srv6DummyDev)
	if err != nil {
		if isLinkNotFound(err) {
			return nil
		}
		return fmt.Errorf("fib: interface %q: %w", srv6DummyDev, err)
	}
	filter := &netlink.Route{Protocol: rtprotoISIS, LinkIndex: link.Attrs().Index}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V6, filter, netlink.RT_FILTER_PROTOCOL|netlink.RT_FILTER_OIF)
	if err != nil {
		return fmt.Errorf("fib: list local SIDs on %q: %w", srv6DummyDev, err)
	}
	if len(routes) > 0 {
		return nil
	}
	if err := netlink.LinkDel(link); err != nil && !isLinkNotFound(err) {
		return fmt.Errorf("fib: remove %q: %w", srv6DummyDev, err)
	}
	return nil
}

func isLinkNotFound(err error) bool {
	var nf netlink.LinkNotFoundError
	return errors.As(err, &nf) || errors.Is(err, unix.ENODEV) || isNotExist(err)
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
