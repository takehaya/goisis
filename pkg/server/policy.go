package server

import "net/netip"

// PrefixAction is the disposition of a prefix-list rule.
type PrefixAction string

const (
	// Permit lets a matching prefix through the filter.
	Permit PrefixAction = "permit"
	// Deny blocks a matching prefix.
	Deny PrefixAction = "deny"
)

// PrefixRule is one entry of a PrefixList. A prefix matches when it falls
// within Prefix (same family, and Prefix contains it) and its length is within
// [MinLen, MaxLen]. When both MinLen and MaxLen are zero the rule matches only
// the exact length of Prefix; otherwise an unset bound defaults to Prefix's
// length (MinLen) or the address width — 32 or 128 (MaxLen).
type PrefixRule struct {
	Action PrefixAction
	Prefix netip.Prefix
	MinLen int
	MaxLen int
}

func (r PrefixRule) matches(p netip.Prefix) bool {
	rp := r.Prefix.Masked()
	if rp.Addr().Is4() != p.Addr().Is4() {
		return false
	}
	if p.Bits() < rp.Bits() || !rp.Contains(p.Addr()) {
		return false
	}
	if r.MinLen == 0 && r.MaxLen == 0 {
		return p.Bits() == rp.Bits()
	}
	lo, hi := r.MinLen, r.MaxLen
	if lo == 0 {
		lo = rp.Bits()
	}
	if hi == 0 {
		hi = p.Addr().BitLen()
	}
	return p.Bits() >= lo && p.Bits() <= hi
}

// PrefixList is an ordered list of rules with a default action. Allows applies
// the first matching rule; if none match, Default decides (an unset Default is
// Deny, the prefix-list convention — so a list of permit rules is an allowlist).
type PrefixList struct {
	Rules   []PrefixRule
	Default PrefixAction
}

// Allows reports whether p passes the list.
func (pl PrefixList) Allows(p netip.Prefix) bool {
	p = p.Masked()
	for _, r := range pl.Rules {
		if r.matches(p) {
			return r.Action == Permit
		}
	}
	return pl.Default == Permit
}

// AdvertiseFilter adapts the list to an export policy over originated prefixes.
func (pl PrefixList) AdvertiseFilter() AdvertiseFilter {
	return func(a AdvertisedPrefix) bool { return pl.Allows(a.Prefix) }
}

// FIBFilter adapts the list to a FIB policy over computed routes.
func (pl PrefixList) FIBFilter() FIBFilter {
	return func(r RouteInfo) bool { return pl.Allows(r.Prefix) }
}
