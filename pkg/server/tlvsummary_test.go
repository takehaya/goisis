package server

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/takehaya/goisis/pkg/packet"
)

// TestTLVSummary pins the operator-facing rendering of one TLV per shape: a
// scalar, a list (one line per entry), a capability with sub-TLVs, and a TLV
// the renderer does not name.
func TestTLVSummary(t *testing.T) {
	for _, tc := range []struct {
		name string
		tlv  packet.TLV
		want []string
	}{
		{
			name: "area addresses",
			tlv:  &packet.AreaAddressesTLV{Addresses: []packet.AreaAddress{{0x49, 0x00, 0x01}}},
			want: []string{"Area Addresses: 49.0001"},
		},
		{
			name: "protocols supported",
			tlv:  &packet.ProtocolsSupportedTLV{NLPIDs: []byte{packet.NLPIDIPv4, packet.NLPIDIPv6}},
			want: []string{"Protocols Supported: IPv4 IPv6"},
		},
		{
			name: "dynamic hostname",
			tlv:  &packet.DynamicHostnameTLV{Hostname: "r1"},
			want: []string{"Dynamic Hostname: r1"},
		},
		{
			// A hostname is whatever octets the peer put on the wire: control
			// characters are neutered, so the escape sequence never reaches
			// the terminal and the newline cannot forge a second line.
			name: "a hostname carrying an escape sequence stays one harmless line",
			tlv:  &packet.DynamicHostnameTLV{Hostname: "r1\x1b[2J\nIPv4 Reachability: 0.0.0.0/0 metric 0"},
			want: []string{"Dynamic Hostname: r1?[2J?IPv4 Reachability: 0.0.0.0/0 metric 0"},
		},
		{
			// proto3 string fields must be valid UTF-8; invalid bytes would
			// fail the Marshal of the whole GetLsdb response.
			name: "a hostname with invalid UTF-8 renders as valid UTF-8",
			tlv:  &packet.DynamicHostnameTLV{Hostname: "\xff\xfe"},
			want: []string{"Dynamic Hostname: \uFFFD"},
		},
		{
			name: "IS reachability, one line per neighbor",
			tlv: &packet.ExtendedISReachabilityTLV{Neighbors: []packet.ExtendedISReachEntry{
				{NeighborID: packet.NodeID{0, 0, 0, 0, 0, 2, 0}, Metric: 10},
				{NeighborID: packet.NodeID{0, 0, 0, 0, 0, 3, 0}, Metric: 20, SubTLVs: []packet.SubTLV{
					&packet.UnknownSubTLV{SubTLVType: 4, Value: []byte{1}},
					&packet.UnknownSubTLV{SubTLVType: 6, Value: []byte{2}},
				}},
			}},
			want: []string{
				"IS Reachability: 0000.0000.0002.00 metric 10",
				"IS Reachability: 0000.0000.0003.00 metric 20 (2 sub-TLVs)",
			},
		},
		{
			name: "IPv4 reachability marks the up/down bit",
			tlv: &packet.ExtendedIPReachabilityTLV{Prefixes: []packet.ExtendedIPReachEntry{
				{Prefix: netip.MustParsePrefix("10.0.0.0/24"), Metric: 10},
				{Prefix: netip.MustParsePrefix("10.1.0.0/24"), Metric: 20, Down: true},
			}},
			want: []string{
				"IPv4 Reachability: 10.0.0.0/24 metric 10",
				"IPv4 Reachability: 10.1.0.0/24 metric 20 down",
			},
		},
		{
			name: "IPv6 reachability",
			tlv: &packet.IPv6ReachabilityTLV{Prefixes: []packet.IPv6ReachEntry{
				{Prefix: netip.MustParsePrefix("2001:db8::/64"), Metric: 10},
			}},
			want: []string{"IPv6 Reachability: 2001:db8::/64 metric 10"},
		},
		{
			name: "SRv6 locator with its End SID",
			tlv: &packet.SRv6LocatorTLV{Locators: []packet.SRv6Locator{{
				Locator: netip.MustParsePrefix("fc00:0:1::/48"),
				EndSIDs: []*packet.SRv6EndSID{{SID: netip.MustParseAddr("fc00:0:1::")}},
			}}},
			want: []string{"SRv6 Locator: fc00:0:1::/48 algo 0 metric 0 End fc00:0:1::"},
		},
		{
			name: "router capability with SR-Algorithm and a FAD",
			tlv: &packet.RouterCapabilityTLV{
				RouterID: netip.MustParseAddr("10.0.0.1"),
				SubTLVs: []packet.SubTLV{
					&packet.SRAlgorithmSubTLV{Algorithms: []uint8{0, 128}},
					&packet.FlexAlgoDefinitionSubTLV{FlexAlgo: 128, MetricType: packet.FlexAlgoMetricIGP, Priority: 100},
					&packet.SRv6CapabilitiesSubTLV{},
				},
			},
			want: []string{"Router Capability: router-id 10.0.0.1 SR-Algorithm 0,128 FAD 128 (metric igp, prio 100) SRv6"},
		},
		{
			name: "authentication names the scheme, never the digest",
			tlv:  &packet.AuthenticationTLV{AuthType: packet.AuthTypeHMACMD5, Value: make([]byte, 16)},
			want: []string{"Authentication: HMAC-MD5"},
		},
		{
			name: "generic authentication carries a key ID",
			tlv:  &packet.AuthenticationTLV{AuthType: packet.AuthTypeGeneric, Value: append([]byte{0x00, 0x01}, make([]byte, 20)...)},
			want: []string{"Authentication: HMAC-SHA (key 1)"},
		},
		{
			name: "purge originator",
			tlv: &packet.UnknownTLV{
				TLVType: packet.TLVTypePurgeOriginatorID,
				Value:   []byte{1, 0, 0, 0, 0, 0, 1},
			},
			want: []string{"Purge Originator: 0000.0000.0001"},
		},
		{
			name: "unknown TLV falls back to type and length",
			tlv:  &packet.UnknownTLV{TLVType: 229, Value: []byte{1, 2, 3, 4, 5, 6}},
			want: []string{"TLV 229: 6 octets"},
		},
		{
			name: "a malformed purge originator falls back too",
			tlv:  &packet.UnknownTLV{TLVType: packet.TLVTypePurgeOriginatorID, Value: []byte{2, 0, 0, 0, 0, 0, 1}},
			want: []string{"TLV 13: 7 octets"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tlvSummary(tc.tlv); !slices.Equal(got, tc.want) {
				t.Errorf("tlvSummary = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestFlexAlgoConstraintSummary pins the operator-facing rendering of every
// FAD constraint sub-sub-TLV RFC 9350 section 6 defines, plus the two shapes
// that must not be rendered as something they are not: a sub-sub-TLV this
// renderer does not name, and one whose length the RFC rules out.
func TestFlexAlgoConstraintSummary(t *testing.T) {
	for _, tc := range []struct {
		name string
		ss   packet.FlexAlgoSubSubTLV
		want string
	}{
		{
			name: "exclude admin group",
			ss:   packet.FlexAlgoSubSubTLV{SubSubTLVType: packet.FlexAlgoSubSubExcludeAdminGroup, Value: []byte{0, 0, 0, 5}},
			want: "exclude-admin-group 0x00000005",
		},
		{
			name: "include-any admin group, one unit per 32 colors",
			ss: packet.FlexAlgoSubSubTLV{
				SubSubTLVType: packet.FlexAlgoSubSubIncludeAnyAdminGroup,
				Value:         []byte{0, 0, 0, 1, 0x80, 0, 0, 0},
			},
			want: "include-any-admin-group 0x00000001,0x80000000",
		},
		{
			name: "include-all admin group",
			ss:   packet.FlexAlgoSubSubTLV{SubSubTLVType: packet.FlexAlgoSubSubIncludeAllAdminGroup, Value: []byte{0, 0, 0x10, 0}},
			want: "include-all-admin-group 0x00001000",
		},
		{
			name: "definition flags name the M-flag",
			ss:   packet.FlexAlgoSubSubTLV{SubSubTLVType: packet.FlexAlgoSubSubDefinitionFlags, Value: []byte{packet.FlexAlgoFlagM}},
			want: "flags M",
		},
		{
			// RFC 9350 section 6.4 makes an unsupported flag bit a reason to
			// stop participating, so a bit goisis does not know must still be
			// visible.
			name: "an unassigned flag bit is named by position",
			ss:   packet.FlexAlgoSubSubTLV{SubSubTLVType: packet.FlexAlgoSubSubDefinitionFlags, Value: []byte{0x80, 0x20}},
			want: "flags M,bit 10",
		},
		{
			name: "flags with nothing set",
			ss:   packet.FlexAlgoSubSubTLV{SubSubTLVType: packet.FlexAlgoSubSubDefinitionFlags, Value: []byte{0x00}},
			want: "flags none",
		},
		{
			name: "exclude SRLG",
			ss: packet.FlexAlgoSubSubTLV{
				SubSubTLVType: packet.FlexAlgoSubSubExcludeSRLG,
				Value:         []byte{0, 0, 0, 100, 0, 0, 0x03, 0xe8},
			},
			want: "exclude-srlg 100,1000",
		},
		{
			name: "an unrecognised sub-sub-TLV falls back to type and length",
			ss:   packet.FlexAlgoSubSubTLV{SubSubTLVType: 99, Value: []byte{1, 2, 3}},
			want: "sub-sub-TLV 99: 3 octets",
		},
		{
			name: "an admin group that is not a whole number of 4-octet units falls back too",
			ss:   packet.FlexAlgoSubSubTLV{SubSubTLVType: packet.FlexAlgoSubSubExcludeAdminGroup, Value: []byte{0, 0, 5}},
			want: "sub-sub-TLV 1: 3 octets",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := flexAlgoConstraintSummary(tc.ss); got != tc.want {
				t.Errorf("flexAlgoConstraintSummary = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestTLVSummariesSplitsEntries: a list TLV contributes one line per entry, so
// the rendered slice is longer than the TLV count; an empty list contributes
// nothing rather than a blank line.
func TestTLVSummariesSplitsEntries(t *testing.T) {
	got := tlvSummaries([]packet.TLV{
		&packet.DynamicHostnameTLV{Hostname: "r1"},
		&packet.ExtendedIPReachabilityTLV{Prefixes: []packet.ExtendedIPReachEntry{
			{Prefix: netip.MustParsePrefix("10.0.0.0/24"), Metric: 10},
			{Prefix: netip.MustParsePrefix("10.1.0.0/24"), Metric: 10},
		}},
		&packet.IPv6ReachabilityTLV{},
	})
	want := []string{
		"Dynamic Hostname: r1",
		"IPv4 Reachability: 10.0.0.0/24 metric 10",
		"IPv4 Reachability: 10.1.0.0/24 metric 10",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("tlvSummaries = %q, want %q", got, want)
	}
}
