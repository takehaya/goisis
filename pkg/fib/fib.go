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

// SIDBehavior is the local SRv6 endpoint behavior to install for a SID.
type SIDBehavior int

// Local SID behaviors (RFC 8986), mapped to Linux seg6local actions.
const (
	BehaviorEnd SIDBehavior = iota
	BehaviorEndDT4
	BehaviorEndDT6
	BehaviorEndDT46
)

// LocalSID is a SID instantiated locally (a seg6local route on Linux).
type LocalSID struct {
	// SID is the /128 segment identifier.
	SID netip.Addr
	// Behavior is the endpoint behavior to apply.
	Behavior SIDBehavior
	// Table is the VRF/lookup table for End.DT4/DT6/DT46.
	Table int
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

	// AddLocalSID installs (or replaces) a local SRv6 SID (a seg6local route).
	AddLocalSID(sid LocalSID) error
	// RemoveLocalSID removes a local SRv6 SID.
	RemoveLocalSID(sid netip.Addr) error
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

// AddLocalSID implements FIB.
func (Noop) AddLocalSID(LocalSID) error { return nil }

// RemoveLocalSID implements FIB.
func (Noop) RemoveLocalSID(netip.Addr) error { return nil }
