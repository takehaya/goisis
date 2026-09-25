package packet

import (
	"bytes"
	"errors"
	"slices"
	"testing"
)

// TestASLARoundtrip: an ASLA naming the Flex-Algorithm application, carrying
// both admin-group encodings, survives a decode/encode cycle byte for byte and
// comes back as the typed sub-TLVs a consumer switches on.
func TestASLARoundtrip(t *testing.T) {
	tlv := &ExtendedISReachabilityTLV{Neighbors: []ExtendedISReachEntry{{
		NeighborID: NodeID{0, 0, 0, 0, 0, 2, 0},
		Metric:     10,
		SubTLVs: []SubTLV{&ASLASubTLV{
			SABM: []byte{ASLAAppFlexAlgo},
			SubSubTLVs: []SubTLV{
				&AdminGroupSubTLV{Groups: []uint32{0x0000_0005}},
				&AdminGroupSubTLV{Extended: true, Groups: []uint32{0x0000_0005, 0x8000_0000}},
			},
		}},
	}}}
	wire, err := tlv.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	decoded := checkTLVRoundtrip(t, wire)[0].(*ExtendedISReachabilityTLV)
	asla, ok := decoded.Neighbors[0].SubTLVs[0].(*ASLASubTLV)
	if !ok {
		t.Fatalf("sub-TLV decoded as %T, want *ASLASubTLV", decoded.Neighbors[0].SubTLVs[0])
	}
	if asla.Type() != 16 || asla.Legacy || !asla.Apps(ASLAAppFlexAlgo) || asla.Apps(ASLAAppRSVPTE) || asla.AnyApp() {
		t.Errorf("application bit mask mismatch: %+v", asla)
	}
	if len(asla.SubSubTLVs) != 2 {
		t.Fatalf("got %d link attributes, want 2", len(asla.SubSubTLVs))
	}
	ag, ok := asla.SubSubTLVs[0].(*AdminGroupSubTLV)
	if !ok || ag.Extended || !slices.Equal(ag.Groups, []uint32{5}) || ag.Type() != 3 {
		t.Errorf("administrative group decoded as %+v (%T)", asla.SubSubTLVs[0], asla.SubSubTLVs[0])
	}
	eag, ok := asla.SubSubTLVs[1].(*AdminGroupSubTLV)
	if !ok || !eag.Extended || !slices.Equal(eag.Groups, []uint32{5, 0x8000_0000}) || eag.Type() != 14 {
		t.Errorf("extended administrative group decoded as %+v (%T)", asla.SubSubTLVs[1], asla.SubSubTLVs[1])
	}
}

// TestASLALegacyFlagAndLegacySubTLVs: the L-flag survives the cycle, and the
// admin-group code points decode the same one level up, directly under TLV 22,
// which is where an L-flag advertisement sends a reader (RFC 8919 §4.2).
func TestASLALegacyFlagAndLegacySubTLVs(t *testing.T) {
	tlv := &ExtendedISReachabilityTLV{Neighbors: []ExtendedISReachEntry{{
		NeighborID: NodeID{0, 0, 0, 0, 0, 2, 0},
		Metric:     10,
		SubTLVs: []SubTLV{
			&ASLASubTLV{Legacy: true, SABM: []byte{ASLAAppFlexAlgo}},
			&AdminGroupSubTLV{Groups: []uint32{0x0000_0002}},
		},
	}}}
	wire, err := tlv.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	decoded := checkTLVRoundtrip(t, wire)[0].(*ExtendedISReachabilityTLV)
	asla, ok := decoded.Neighbors[0].SubTLVs[0].(*ASLASubTLV)
	if !ok || !asla.Legacy || len(asla.SubSubTLVs) != 0 {
		t.Errorf("ASLA decoded as %+v (%T), want the L-flag set and no attributes", decoded.Neighbors[0].SubTLVs[0], decoded.Neighbors[0].SubTLVs[0])
	}
	ag, ok := decoded.Neighbors[0].SubTLVs[1].(*AdminGroupSubTLV)
	if !ok || !slices.Equal(ag.Groups, []uint32{2}) {
		t.Errorf("legacy administrative group decoded as %+v (%T)", decoded.Neighbors[0].SubTLVs[1], decoded.Neighbors[0].SubTLVs[1])
	}
}

// TestASLAUnparseableStaysOpaque: RFC 8919 §4.2 says an ASLA whose bit-mask
// length exceeds 8 MUST be ignored. Ignoring it is not rejecting the LSP that
// carries it, so it decodes to an opaque sub-TLV: invisible to a consumer's
// type switch, and byte-exact on the way back out.
func TestASLAUnparseableStaysOpaque(t *testing.T) {
	for name, value := range map[string]string{
		"SABM length 9":          "09 00 00 00 00 00 00 00 00 00",
		"UDABM length 9":         "00 09 00 00 00 00 00 00 00 00 00",
		"mask longer than value": "04 00 00 00",
		"shorter than a header":  "01",
		"malformed attribute":    "01 00 10 03 05 00 00 00", // admin group of 5 octets
	} {
		t.Run(name, func(t *testing.T) {
			wire := append([]byte{16, 0}, mustHex(t, value)...)
			wire[1] = byte(len(wire) - 2)
			subs, err := decodeSubTLVs(SubTLVContextISReachability, wire)
			if err != nil {
				t.Fatalf("decodeSubTLVs: %v", err)
			}
			if _, ok := subs[0].(*UnknownSubTLV); !ok {
				t.Fatalf("decoded as %T, want it left opaque", subs[0])
			}
			out, err := serializeSubTLVs(subs)
			if err != nil {
				t.Fatalf("serializeSubTLVs: %v", err)
			}
			if !bytes.Equal(out, wire) {
				t.Errorf("roundtrip mismatch:\n got %x\nwant %x", out, wire)
			}
		})
	}
}

// TestAdminGroupLengthRules: RFC 5305 §3.1 fixes the administrative group at
// one 32-bit word and RFC 7308 makes the extended group a multiple of four
// octets; neither is guessed at from a value of another length.
func TestAdminGroupLengthRules(t *testing.T) {
	if _, err := decodeAdminGroup(mustHex(t, "00 00 00 05 00 00 00 06")); !errors.Is(err, errBadTLV) {
		t.Errorf("8-octet administrative group: err = %v, want errBadTLV", err)
	}
	if _, err := decodeExtendedAdminGroup(mustHex(t, "00 00 00 05 00")); !errors.Is(err, errBadTLV) {
		t.Errorf("5-octet extended administrative group: err = %v, want errBadTLV", err)
	}
	if _, err := (&AdminGroupSubTLV{Groups: []uint32{1, 2}}).Serialize(); !errors.Is(err, errBadTLV) {
		t.Errorf("two-word administrative group: err = %v, want errBadTLV", err)
	}
	if _, err := (&ASLASubTLV{SABM: make([]byte, 9)}).Serialize(); !errors.Is(err, ErrTooLong) {
		t.Errorf("9-octet SABM: err = %v, want ErrTooLong", err)
	}
}

// TestMalformedAdminGroupStaysOpaque: a link attribute whose length does not
// match its code point is ignored, not fatal. RFC 5305 §2 has a reader skip a
// sub-TLV it cannot use, and RFC 8919 §4.2 gives these same octets the same
// meaning one level down inside an ASLA, so both positions must agree. LSPs
// flood: failing the PDU over one attribute would take its originator off
// every goisis in the area, not just off its neighbour.
func TestMalformedAdminGroupStaysOpaque(t *testing.T) {
	// The attribute beside the malformed one is the control: containment must
	// not degrade into never parsing anything.
	const goodEAG = "0e 08 00000005 80000000"
	positions := map[string]struct {
		wrap  func(attrs []byte) []byte
		attrs func(t *testing.T, subs []SubTLV) []SubTLV
	}{
		"directly under TLV 22": {
			wrap:  func(attrs []byte) []byte { return attrs },
			attrs: func(_ *testing.T, subs []SubTLV) []SubTLV { return subs },
		},
		"nested in an ASLA": {
			wrap: func(attrs []byte) []byte {
				asla := []byte{subTLVASLA, byte(3 + len(attrs)), 0x01, 0x00, ASLAAppFlexAlgo}
				return append(asla, attrs...)
			},
			attrs: func(t *testing.T, subs []SubTLV) []SubTLV {
				t.Helper()
				asla, ok := subs[0].(*ASLASubTLV)
				if !ok {
					t.Fatalf("ASLA decoded as %T, want it still typed", subs[0])
				}
				return asla.SubSubTLVs
			},
		},
	}
	for what, bad := range map[string]string{
		"administrative group of 5 octets":          "03 05 0000000500",
		"extended administrative group of 5 octets": "0e 05 0000000500",
	} {
		for where, pos := range positions {
			t.Run(what+", "+where, func(t *testing.T) {
				subs := pos.wrap(append(mustHex(t, bad), mustHex(t, goodEAG)...))
				entry := []byte{0, 0, 0, 0, 0, 2, 0, 0, 0, 10, byte(len(subs))}
				wire := append([]byte{byte(TLVTypeExtendedISReachability), byte(len(entry) + len(subs))}, entry...)
				wire = append(wire, subs...)

				tlv, ok := checkTLVRoundtrip(t, wire)[0].(*ExtendedISReachabilityTLV)
				if !ok {
					t.Fatalf("TLV 22 did not decode as an extended IS reachability TLV")
				}
				if len(tlv.Neighbors) != 1 || tlv.Neighbors[0].Metric != 10 {
					t.Fatalf("entry decoded as %+v, want the rest of it intact", tlv.Neighbors)
				}
				attrs := pos.attrs(t, tlv.Neighbors[0].SubTLVs)
				if len(attrs) != 2 {
					t.Fatalf("got %d attributes, want 2", len(attrs))
				}
				if _, ok := attrs[0].(*UnknownSubTLV); !ok {
					t.Errorf("malformed attribute decoded as %T, want it left opaque", attrs[0])
				}
				eag, ok := attrs[1].(*AdminGroupSubTLV)
				if !ok || !eag.Extended || !slices.Equal(eag.Groups, []uint32{5, 0x8000_0000}) {
					t.Errorf("the attribute beside it decoded as %+v (%T), want it typed", attrs[1], attrs[1])
				}
			})
		}
	}
}
