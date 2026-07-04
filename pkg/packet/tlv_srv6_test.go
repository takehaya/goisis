package packet

import (
	"bytes"
	"net/netip"
	"reflect"
	"testing"
)

func TestSRv6LocatorRoundtrip(t *testing.T) {
	tlv := &SRv6LocatorTLV{
		MTID: 0,
		Locators: []SRv6Locator{
			{
				Metric:    10,
				Algorithm: 0,
				Locator:   netip.MustParsePrefix("fc00:0:1::/48"),
				EndSIDs: []*SRv6EndSID{
					{
						Behavior:  SRv6BehaviorEnd,
						SID:       netip.MustParseAddr("fc00:0:1::"),
						Structure: &SIDStructure{LocatorBlock: 32, LocatorNode: 16, Function: 16, Argument: 0},
					},
				},
			},
		},
	}
	wire, err := tlv.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	decoded := checkTLVRoundtrip(t, wire)[0].(*SRv6LocatorTLV)
	if len(decoded.Locators) != 1 {
		t.Fatalf("got %d locators", len(decoded.Locators))
	}
	l := decoded.Locators[0]
	if l.Locator != netip.MustParsePrefix("fc00:0:1::/48") || l.Metric != 10 {
		t.Errorf("locator mismatch: %+v", l)
	}
	if len(l.EndSIDs) != 1 || l.EndSIDs[0].Behavior != SRv6BehaviorEnd ||
		l.EndSIDs[0].SID != netip.MustParseAddr("fc00:0:1::") || l.EndSIDs[0].Structure == nil {
		t.Errorf("end SID mismatch: %+v", l.EndSIDs)
	}
	if s := l.EndSIDs[0].Structure; s.LocatorBlock != 32 || s.LocatorNode != 16 || s.Function != 16 {
		t.Errorf("SID structure mismatch: %+v", s)
	}
}

func TestSRv6LocatorNoEndSID(t *testing.T) {
	// A locator-only advertisement (no End SID) is valid.
	tlv := &SRv6LocatorTLV{Locators: []SRv6Locator{{Metric: 5, Locator: netip.MustParsePrefix("fc00:0:2::/48")}}}
	wire, err := tlv.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	decoded := checkTLVRoundtrip(t, wire)[0].(*SRv6LocatorTLV)
	if len(decoded.Locators[0].EndSIDs) != 0 {
		t.Error("expected no End SIDs")
	}
}

func TestRouterCapabilitySRv6Caps(t *testing.T) {
	tlv := &RouterCapabilityTLV{
		RouterID: netip.MustParseAddr("10.0.0.1"),
		Flags:    0,
		SubTLVs:  []SubTLV{&SRv6CapabilitiesSubTLV{Flags: 0}},
	}
	wire, err := tlv.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	decoded := checkTLVRoundtrip(t, wire)[0].(*RouterCapabilityTLV)
	if decoded.RouterID != netip.MustParseAddr("10.0.0.1") {
		t.Errorf("router id = %v", decoded.RouterID)
	}
	if len(decoded.SubTLVs) != 1 {
		t.Fatalf("got %d sub-TLVs", len(decoded.SubTLVs))
	}
	if _, ok := decoded.SubTLVs[0].(*SRv6CapabilitiesSubTLV); !ok {
		t.Errorf("sub-TLV not SRv6 capabilities: %T", decoded.SubTLVs[0])
	}
}

func TestSRv6CapabilitiesPreservesSubSubTLVs(t *testing.T) {
	// Octets after the 2-byte flags (RFC 9352 optional sub-sub-TLVs) must
	// round-trip byte-exact rather than being silently dropped.
	tlv := &RouterCapabilityTLV{
		SubTLVs: []SubTLV{&SRv6CapabilitiesSubTLV{Flags: 0x4000, SubSubTLVs: []byte{0xaa, 0xbb}}},
	}
	wire, err := tlv.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	decoded := checkTLVRoundtrip(t, wire)[0].(*RouterCapabilityTLV)
	caps, ok := decoded.SubTLVs[0].(*SRv6CapabilitiesSubTLV)
	if !ok {
		t.Fatalf("sub-TLV not SRv6 capabilities: %T", decoded.SubTLVs[0])
	}
	if caps.Flags != 0x4000 || len(caps.SubSubTLVs) != 2 || caps.SubSubTLVs[0] != 0xaa || caps.SubSubTLVs[1] != 0xbb {
		t.Errorf("trailing sub-sub-TLV octets not preserved: %+v", caps)
	}
}

func TestSRv6LocatorPreservesUnknownSubTLV(t *testing.T) {
	// A locator sub-TLV this package does not implement (type 99) advertised
	// alongside an End SID must survive decode -> encode byte-exactly rather
	// than being silently dropped.
	tlv := &SRv6LocatorTLV{Locators: []SRv6Locator{{
		Metric:  10,
		Locator: netip.MustParsePrefix("fc00:0:1::/48"),
		EndSIDs: []*SRv6EndSID{{Behavior: SRv6BehaviorEnd, SID: netip.MustParseAddr("fc00:0:1::")}},
		Unknown: []UnknownSubTLV{{SubTLVType: 99, Value: []byte{0xaa, 0xbb, 0xcc}}},
	}}}
	wire, err := tlv.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	decoded := checkTLVRoundtrip(t, wire)[0].(*SRv6LocatorTLV)
	l := decoded.Locators[0]
	if len(l.EndSIDs) != 1 || l.EndSIDs[0].SID != netip.MustParseAddr("fc00:0:1::") {
		t.Errorf("end SID mismatch: %+v", l.EndSIDs)
	}
	if len(l.Unknown) != 1 || l.Unknown[0].SubTLVType != 99 || !bytes.Equal(l.Unknown[0].Value, []byte{0xaa, 0xbb, 0xcc}) {
		t.Errorf("unknown sub-TLV not preserved: %+v", l.Unknown)
	}
}

func TestSRv6EndSIDPreservesUnknownSubSubTLV(t *testing.T) {
	// A sub-sub-TLV this package does not implement (type 7) advertised
	// alongside the SID Structure must survive decode -> encode byte-exactly
	// rather than being silently dropped.
	tlv := &SRv6LocatorTLV{Locators: []SRv6Locator{{
		Locator: netip.MustParsePrefix("fc00:0:1::/48"),
		EndSIDs: []*SRv6EndSID{{
			Behavior:  SRv6BehaviorEnd,
			SID:       netip.MustParseAddr("fc00:0:1::"),
			Structure: &SIDStructure{LocatorBlock: 32, LocatorNode: 16, Function: 16},
			Unknown:   []UnknownSubTLV{{SubTLVType: 7, Value: []byte{0x01, 0x02}}},
		}},
	}}}
	wire, err := tlv.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	decoded := checkTLVRoundtrip(t, wire)[0].(*SRv6LocatorTLV)
	e := decoded.Locators[0].EndSIDs[0]
	if e.Structure == nil || e.Structure.LocatorBlock != 32 {
		t.Errorf("SID structure mismatch: %+v", e.Structure)
	}
	if len(e.Unknown) != 1 || e.Unknown[0].SubTLVType != 7 || !bytes.Equal(e.Unknown[0].Value, []byte{0x01, 0x02}) {
		t.Errorf("unknown sub-sub-TLV not preserved: %+v", e.Unknown)
	}
}

func TestSRv6LocatorUnknownBeforeEndSIDNoDataLoss(t *testing.T) {
	// Hand-crafted wire whose unknown sub-TLV (type 99) precedes the End SID:
	// re-encoding regroups (End SIDs first, then unknowns), so byte-exactness
	// is not guaranteed for this ordering — but decoding the re-encoded form
	// must yield the same TLV as the original (no data loss) and re-encoding
	// must be a fixed point.
	wire := mustHex(t, `
		1b 2b
		00 00
		00 00 00 0a 00 00 30 fc 00 00 00 00 01
		1b
		63 03 aa bb cc
		05 14 00 0001 fc00 0000 0001 0000 0000 0000 0000 0000 00`)
	tlvs, err := decodeTLVs(wire)
	if err != nil {
		t.Fatalf("decodeTLVs: %v", err)
	}
	enc, err := serializeTLVs(tlvs)
	if err != nil {
		t.Fatalf("serializeTLVs: %v", err)
	}
	tlvs2, err := decodeTLVs(enc)
	if err != nil {
		t.Fatalf("decodeTLVs (re-encoded): %v", err)
	}
	if !reflect.DeepEqual(tlvs, tlvs2) {
		t.Errorf("data lost across re-encode:\n first %+v\nsecond %+v", tlvs, tlvs2)
	}
	enc2, err := serializeTLVs(tlvs2)
	if err != nil {
		t.Fatalf("serializeTLVs (second): %v", err)
	}
	if !bytes.Equal(enc, enc2) {
		t.Errorf("encode not idempotent:\n first %x\nsecond %x", enc, enc2)
	}
}

func TestSRv6EndpointBehaviorOpaque(t *testing.T) {
	// An unknown endpoint behavior (e.g. a uSID flavor) must round-trip.
	tlv := &SRv6LocatorTLV{Locators: []SRv6Locator{{
		Locator: netip.MustParsePrefix("fc00:0:3::/48"),
		EndSIDs: []*SRv6EndSID{{Behavior: 0x002b /* uN, NEXT-CSID */, SID: netip.MustParseAddr("fc00:0:3::")}},
	}}}
	wire, err := tlv.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	decoded := checkTLVRoundtrip(t, wire)[0].(*SRv6LocatorTLV)
	if decoded.Locators[0].EndSIDs[0].Behavior != 0x002b {
		t.Errorf("opaque behavior lost: %d", decoded.Locators[0].EndSIDs[0].Behavior)
	}
}
