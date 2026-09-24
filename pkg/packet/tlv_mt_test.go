package packet

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"
)

// TestMTIPv6ReachabilityRoundtrip pins the wire form of TLV 237: the 2-octet MT
// membership field in front of a TLV 236 entry list (RFC 5120 section 7.4).
func TestMTIPv6ReachabilityRoundtrip(t *testing.T) {
	// 237 len | MT 2 | metric 10 | flags 0 | /64 | 2001:db8::
	wire := mustHex(t, "ed 10 0002 0000000a 00 40 20010db800000000")
	tlv := checkTLVRoundtrip(t, wire)[0].(*MTIPv6ReachabilityTLV)
	if tlv.MTID != MTIDIPv6Unicast {
		t.Errorf("MT ID = %d, want %d", tlv.MTID, MTIDIPv6Unicast)
	}
	if len(tlv.Prefixes) != 1 {
		t.Fatalf("decoded %d prefixes, want 1", len(tlv.Prefixes))
	}
	if got, want := tlv.Prefixes[0].Prefix, netip.MustParsePrefix("2001:db8::/64"); got != want {
		t.Errorf("prefix = %s, want %s", got, want)
	}
	if tlv.Prefixes[0].Metric != 10 {
		t.Errorf("metric = %d, want 10", tlv.Prefixes[0].Metric)
	}
}

// TestMTIPReachabilityRoundtrip pins the wire form of TLV 235 (RFC 5120
// section 7.3): a TLV 135 entry list behind an MT ID.
func TestMTIPReachabilityRoundtrip(t *testing.T) {
	// 235 len | MT 3 | metric 10 | ctrl /8 | 10
	wire := mustHex(t, "eb 08 0003 0000000a 08 0a")
	tlv := checkTLVRoundtrip(t, wire)[0].(*MTIPReachabilityTLV)
	if tlv.MTID != 3 {
		t.Errorf("MT ID = %d, want 3", tlv.MTID)
	}
	if got, want := tlv.Prefixes[0].Prefix, netip.MustParsePrefix("10.0.0.0/8"); got != want {
		t.Errorf("prefix = %s, want %s", got, want)
	}
}

// TestMTISReachabilityRoundtrip pins the wire form of TLV 222 (RFC 5120
// section 7.2): a TLV 22 neighbor list behind an MT ID.
func TestMTISReachabilityRoundtrip(t *testing.T) {
	// 222 len | MT 2 | neighbor 0000.0000.0002.00 | metric 10 | 0 sub-TLVs
	wire := mustHex(t, "de 0d 0002 00000000000200 00000a 00")
	tlv := checkTLVRoundtrip(t, wire)[0].(*MTISReachabilityTLV)
	if tlv.MTID != MTIDIPv6Unicast {
		t.Errorf("MT ID = %d, want %d", tlv.MTID, MTIDIPv6Unicast)
	}
	if len(tlv.Neighbors) != 1 {
		t.Fatalf("decoded %d neighbors, want 1", len(tlv.Neighbors))
	}
	if got := tlv.Neighbors[0].NeighborID.SystemID(); got != (SystemID{0, 0, 0, 0, 0, 2}) {
		t.Errorf("neighbor = %s, want 0000.0000.0002", got)
	}
	if tlv.Neighbors[0].Metric != 10 {
		t.Errorf("metric = %d, want 10", tlv.Neighbors[0].Metric)
	}
}

// TestMTopologiesRoundtrip pins TLV 229 (RFC 5120 section 7.1), including the
// O and A bits that share the MT ID's high octet.
func TestMTopologiesRoundtrip(t *testing.T) {
	// 229 len | MT 0 | MT 2 with O set | MT 4 with A set
	wire := mustHex(t, "e5 06 0000 8002 4004")
	tlv := checkTLVRoundtrip(t, wire)[0].(*MTopologiesTLV)
	want := []MTopologyEntry{
		{MTID: 0},
		{MTID: 2, Overload: true},
		{MTID: 4, Attached: true},
	}
	if len(tlv.Topologies) != len(want) {
		t.Fatalf("decoded %d topologies, want %d", len(tlv.Topologies), len(want))
	}
	for i, w := range want {
		if tlv.Topologies[i] != w {
			t.Errorf("topology %d = %+v, want %+v", i, tlv.Topologies[i], w)
		}
	}
}

// TestMTIDReservedBitsNormalized covers the one field of the MT TLVs that is
// not byte-exact: RFC 5120 reserves the top four bits of the MT membership
// field and says to ignore them on receipt, so a decode masks them off and the
// re-encode clears them (the fuzz targets require that re-encoding then be a
// fixed point, which is what the second round-trip checks).
func TestMTIDReservedBitsNormalized(t *testing.T) {
	dirty := mustHex(t, "ed 10 f002 0000000a 00 40 20010db800000000")
	clean := mustHex(t, "ed 10 0002 0000000a 00 40 20010db800000000")
	tlvs, err := decodeTLVs(dirty)
	if err != nil {
		t.Fatalf("decodeTLVs: %v", err)
	}
	if got := tlvs[0].(*MTIPv6ReachabilityTLV).MTID; got != MTIDIPv6Unicast {
		t.Errorf("MT ID = %d, want %d (reserved bits leaked in)", got, MTIDIPv6Unicast)
	}
	out, err := serializeTLVs(tlvs)
	if err != nil {
		t.Fatalf("serializeTLVs: %v", err)
	}
	if !bytes.Equal(out, clean) {
		t.Fatalf("re-encode = %x, want %x", out, clean)
	}
	checkTLVRoundtrip(t, clean)
}

// TestMTDecodeErrors checks the malformed shapes that must be rejected rather
// than guessed at. An MT ID of zero is deliberately absent from this list: RFC
// 5120 says such a TLV is ignored, which is the decision process's job — see
// TestMTIPv6ReachabilityIgnoresOtherTopologies in pkg/server.
func TestMTDecodeErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		wire string
		want error
	}{
		{"237 MT ID truncated", "ed 01 00", ErrTruncated},
		{"235 MT ID truncated", "eb 00", ErrTruncated},
		{"222 MT ID truncated", "de 01 00", ErrTruncated},
		{"237 entry truncated", "ed 03 0002 00", ErrTruncated},
		{"222 entry truncated", "de 05 0002 000000", ErrTruncated},
		{"229 odd length", "e5 03 0000 80", errBadTLV},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := decodeTLVs(mustHex(t, tc.wire))
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}
