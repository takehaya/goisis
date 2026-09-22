package server

import (
	"net/netip"
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
		want string
	}{
		{
			name: "area addresses",
			tlv:  &packet.AreaAddressesTLV{Addresses: []packet.AreaAddress{{0x49, 0x00, 0x01}}},
			want: "Area Addresses: 49.0001",
		},
		{
			name: "protocols supported",
			tlv:  &packet.ProtocolsSupportedTLV{NLPIDs: []byte{packet.NLPIDIPv4, packet.NLPIDIPv6}},
			want: "Protocols Supported: IPv4 IPv6",
		},
		{
			name: "dynamic hostname",
			tlv:  &packet.DynamicHostnameTLV{Hostname: "r1"},
			want: "Dynamic Hostname: r1",
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
			want: "IS Reachability: 0000.0000.0002.00 metric 10\n" +
				"IS Reachability: 0000.0000.0003.00 metric 20 (2 sub-TLVs)",
		},
		{
			name: "IPv4 reachability marks the up/down bit",
			tlv: &packet.ExtendedIPReachabilityTLV{Prefixes: []packet.ExtendedIPReachEntry{
				{Prefix: netip.MustParsePrefix("10.0.0.0/24"), Metric: 10},
				{Prefix: netip.MustParsePrefix("10.1.0.0/24"), Metric: 20, Down: true},
			}},
			want: "IPv4 Reachability: 10.0.0.0/24 metric 10\n" +
				"IPv4 Reachability: 10.1.0.0/24 metric 20 down",
		},
		{
			name: "IPv6 reachability",
			tlv: &packet.IPv6ReachabilityTLV{Prefixes: []packet.IPv6ReachEntry{
				{Prefix: netip.MustParsePrefix("2001:db8::/64"), Metric: 10},
			}},
			want: "IPv6 Reachability: 2001:db8::/64 metric 10",
		},
		{
			name: "SRv6 locator with its End SID",
			tlv: &packet.SRv6LocatorTLV{Locators: []packet.SRv6Locator{{
				Locator: netip.MustParsePrefix("fc00:0:1::/48"),
				EndSIDs: []*packet.SRv6EndSID{{SID: netip.MustParseAddr("fc00:0:1::")}},
			}}},
			want: "SRv6 Locator: fc00:0:1::/48 algo 0 metric 0 End fc00:0:1::",
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
			want: "Router Capability: router-id 10.0.0.1 SR-Algorithm 0,128 FAD 128 (metric igp, prio 100) SRv6",
		},
		{
			name: "authentication names the scheme, never the digest",
			tlv:  &packet.AuthenticationTLV{AuthType: packet.AuthTypeHMACMD5, Value: make([]byte, 16)},
			want: "Authentication: HMAC-MD5",
		},
		{
			name: "generic authentication carries a key ID",
			tlv:  &packet.AuthenticationTLV{AuthType: packet.AuthTypeGeneric, Value: append([]byte{0x00, 0x01}, make([]byte, 20)...)},
			want: "Authentication: HMAC-SHA (key 1)",
		},
		{
			name: "purge originator",
			tlv: &packet.UnknownTLV{
				TLVType: packet.TLVTypePurgeOriginatorID,
				Value:   []byte{1, 0, 0, 0, 0, 0, 1},
			},
			want: "Purge Originator: 0000.0000.0001",
		},
		{
			name: "unknown TLV falls back to type and length",
			tlv:  &packet.UnknownTLV{TLVType: 229, Value: []byte{1, 2, 3, 4, 5, 6}},
			want: "TLV 229: 6 octets",
		},
		{
			name: "a malformed purge originator falls back too",
			tlv:  &packet.UnknownTLV{TLVType: packet.TLVTypePurgeOriginatorID, Value: []byte{2, 0, 0, 0, 0, 0, 1}},
			want: "TLV 13: 7 octets",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tlvSummary(tc.tlv); got != tc.want {
				t.Errorf("tlvSummary =\n%s\nwant\n%s", got, tc.want)
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
