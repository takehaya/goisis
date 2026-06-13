// Package fib abstracts the forwarding-information-base sink that SPF results
// are programmed into. The daemon ships a Linux netlink implementation;
// library consumers can supply their own (e.g. to program an eBPF dataplane)
// or use the no-op default.
package fib

import "net/netip"

// Nexthop is one path to a destination prefix.
type Nexthop struct {
	// Interface is the egress interface name.
	Interface string
	// Gateway is the next-hop address (IPv6 next hops are link-local and
	// require Interface to be set).
	Gateway netip.Addr
}

// FIB programs and withdraws routes. Implementations must be safe to call
// from a single goroutine (the IS-IS management loop drives them).
type FIB interface {
	// Update installs or replaces the route to prefix with the given
	// next-hop set (an empty set is equivalent to Withdraw).
	Update(prefix netip.Prefix, nexthops []Nexthop) error
	// Withdraw removes the route to prefix.
	Withdraw(prefix netip.Prefix) error
	// Sweep removes every route this FIB owns for which keep returns false.
	// It is used at startup to drop stale routes from a previous run.
	Sweep(keep func(netip.Prefix) bool) error
}

// Noop is a FIB that discards all updates. It is the default when no FIB is
// configured (e.g. library consumers that only watch routes).
type Noop struct{}

// Update implements FIB.
func (Noop) Update(netip.Prefix, []Nexthop) error { return nil }

// Withdraw implements FIB.
func (Noop) Withdraw(netip.Prefix) error { return nil }

// Sweep implements FIB.
func (Noop) Sweep(func(netip.Prefix) bool) error { return nil }
