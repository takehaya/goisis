package packet

import (
	"bytes"
	"errors"
	"slices"
	"testing"
)

// TestSubTLVDecoderErrorStaysOpaque pins the containment where it is decided —
// decodeSubTLVs, not any one decoder. RFC 5305 §2 has a reader skip a sub-TLV
// it cannot use, and skipping is not rejecting the PDU that carries it; a
// value a registered decoder refuses is therefore preserved opaquely, exactly
// as an unregistered code point is. Walking the registry rather than a list of
// code points means a decoder added later inherits the rule.
func TestSubTLVDecoderErrorStaysOpaque(t *testing.T) {
	// One octet is a value every decoder that validates a length refuses; one
	// that accepts it says nothing about containment, so it is skipped.
	wire := []byte{0, 1, 0xff}
	pinned := 0
	for ctx, decoders := range subTLVDecoders {
		for typ, dec := range decoders {
			if _, err := dec(wire[2:]); err == nil {
				continue
			}
			pinned++
			wire[0] = typ
			subs, err := decodeSubTLVs(ctx, wire)
			if err != nil {
				t.Errorf("context %d sub-TLV %d: decodeSubTLVs = %v, want no error", ctx, typ, err)
				continue
			}
			if len(subs) != 1 {
				t.Errorf("context %d sub-TLV %d: got %d sub-TLVs, want 1", ctx, typ, len(subs))
				continue
			}
			if _, ok := subs[0].(*UnknownSubTLV); !ok {
				t.Errorf("context %d sub-TLV %d: decoded as %T, want it left opaque", ctx, typ, subs[0])
				continue
			}
			out, err := serializeSubTLVs(subs)
			if err != nil || !bytes.Equal(out, wire) {
				t.Errorf("context %d sub-TLV %d: re-encode = %x, %v; want %x", ctx, typ, out, err, wire)
			}
		}
	}
	if pinned == 0 {
		t.Fatal("no registered decoder refused the value, so nothing was pinned")
	}
}

// TestSubTLVAreaFramingStillFails guarantees the other end of the line
// decodeSubTLVs draws. A decoder that refuses its value leaves the sub-TLV
// opaque; length octets that cannot be split into sub-TLVs at all fail, because
// there are no boundaries left to preserve anything against. Dropping a
// trailing odd octet instead would lose the byte-exact round trip this package
// is built on -- quietly, which is the one way it must not go.
func TestSubTLVAreaFramingStillFails(t *testing.T) {
	for _, tc := range []struct {
		name string
		wire []byte
	}{
		{"a type octet with no length", []byte{3}},
		{"a length that overruns the area", []byte{3, 4, 0, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := decodeSubTLVs(SubTLVContextISReachability, tc.wire); !errors.Is(err, ErrTruncated) {
				t.Errorf("decodeSubTLVs(%x) = %v, want ErrTruncated", tc.wire, err)
			}
		})
	}
}

// TestRefusedAttributeIsToldApartFromAnUnknownOne: containment makes a value a
// registered decoder refused look exactly like a code point no decoder is
// registered for — the same opaque form, and for an admin group the same empty
// colour set, which an exclude rule leaves alone. UnknownSubTLV.Refused is the
// one bit that tells the two apart, and RefusedSubTLV is how a caller finds it
// without walking the container shapes itself. The byte-exact round trip is
// asserted with it: the flag is decode-side only and must not reach the wire.
func TestRefusedAttributeIsToldApartFromAnUnknownOne(t *testing.T) {
	// A well-formed extended administrative group sits beside every case as
	// the control: marking a refusal must not disturb the attribute next to it.
	sibling := mustHex(t, "0e 04 00000005")
	asla := func(attrs []byte) []byte {
		return append([]byte{subTLVASLA, byte(3 + len(attrs)), 0x01, 0x00, ASLAAppFlexAlgo}, attrs...)
	}
	for _, tc := range []struct {
		name  string
		attrs []byte
		// want is the code point RefusedSubTLV must report, or -1 for
		// "nothing here was refused".
		want int
	}{
		{"an administrative group of 3 octets", mustHex(t, "03 03 000005"), subTLVAdminGroup},
		{"the same one nested in an ASLA", asla(mustHex(t, "03 03 000005")), subTLVAdminGroup},
		{"an extended administrative group of 6 octets", mustHex(t, "0e 06 000000050000"), subTLVExtendedAdminGroup},
		{"an ASLA with SABM length 9", mustHex(t, "10 02 0900"), subTLVASLA},
		{"an unregistered code point", mustHex(t, "63 02 dead"), -1},
		{"a well-formed administrative group", mustHex(t, "03 04 00000005"), -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attrs := append(slices.Clone(tc.attrs), sibling...)
			entry := []byte{0, 0, 0, 0, 0, 2, 0, 0, 0, 10, byte(len(attrs))}
			wire := append([]byte{byte(TLVTypeExtendedISReachability), byte(len(entry) + len(attrs))}, entry...)
			wire = append(wire, attrs...)

			tlvs := checkTLVRoundtrip(t, wire)
			refused := RefusedSubTLV(tlvs)
			switch {
			case tc.want < 0 && refused != nil:
				t.Errorf("RefusedSubTLV reported sub-TLV %d, want nothing refused", refused.SubTLVType)
			case tc.want >= 0 && refused == nil:
				t.Errorf("RefusedSubTLV reported nothing, want sub-TLV %d", tc.want)
			case tc.want >= 0 && int(refused.SubTLVType) != tc.want:
				t.Errorf("RefusedSubTLV reported sub-TLV %d, want %d", refused.SubTLVType, tc.want)
			}

			decoded := tlvs[0].(*ExtendedISReachabilityTLV).Neighbors[0].SubTLVs
			last, ok := decoded[len(decoded)-1].(*AdminGroupSubTLV)
			if !ok || !last.Extended || !slices.Equal(last.Groups, []uint32{5}) {
				t.Errorf("the attribute beside it decoded as %+v (%T), want it typed", decoded[len(decoded)-1], decoded[len(decoded)-1])
			}
		})
	}
}

// TestEveryContextWithDecodersIsWalked guards the shortcut in RefusedSubTLV: it
// walks the neighbor TLVs and the Router Capability TLV because those are the
// contexts decoders are registered in, and registering one in a fourth context
// would make refusals there silent again — which is the whole defect.
func TestEveryContextWithDecodersIsWalked(t *testing.T) {
	walked := map[SubTLVContext]bool{
		SubTLVContextISReachability:   true,
		SubTLVContextASLA:             true,
		SubTLVContextRouterCapability: true,
	}
	for ctx := range subTLVDecoders {
		if !walked[ctx] {
			t.Errorf("context %d has a registered decoder, but RefusedSubTLV does not walk a TLV that carries it", ctx)
		}
	}
}

// TestRefusedSubTLVWalksEveryCarrierItClaims guarantees each arm of the walk
// RefusedSubTLV performs, which TestEveryContextWithDecodersIsWalked does not:
// that canary guards the *context* axis — a decoder registered where nothing
// looks — while the switch keys on the *carrier* axis, the TLVs that hold a
// sub-TLV area at all. A carrier dropped from the switch is invisible to it.
//
// The second neighbour entry is here for the same reason: the walk returns the
// first refusal it finds, so an arm that stops after entry one reports nothing
// for a peer whose colours sit on its second link.
func TestRefusedSubTLVWalksEveryCarrierItClaims(t *testing.T) {
	bad := mustHex(t, "03 03 000005") // an administrative group three octets long
	entry := func(last byte, attrs []byte) []byte {
		e := []byte{0, 0, 0, 0, 0, last, 0, 0, 0, 10, byte(len(attrs))}
		return append(e, attrs...)
	}
	// The router capability area has its own registry, so the refusal there
	// has to be a code point registered in it: an administrative group is
	// simply unknown at that level and would prove nothing.
	badCap := mustHex(t, "19 01 00") // SRv6 capabilities, one octet
	for _, tc := range []struct {
		name string
		wire []byte
		want uint8
	}{
		{"TLV 22, the first entry",
			append([]byte{byte(TLVTypeExtendedISReachability), 11 + byte(len(bad))}, entry(2, bad)...),
			subTLVAdminGroup},
		{"TLV 22, an entry after the first",
			append(append([]byte{byte(TLVTypeExtendedISReachability), 11 + 11 + byte(len(bad))}, entry(2, nil)...), entry(3, bad)...),
			subTLVAdminGroup},
		{"TLV 222, which shares the entry list",
			append([]byte{byte(TLVTypeMTISReachability), 2 + 11 + byte(len(bad)), 0x00, 0x02}, entry(2, bad)...),
			subTLVAdminGroup},
		{"TLV 242, the router capability area",
			append([]byte{byte(TLVTypeRouterCapability), 5 + byte(len(badCap)), 10, 0, 0, 1, 0}, badCap...),
			badCap[0]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tlvs := checkTLVRoundtrip(t, tc.wire)
			if refused := RefusedSubTLV(tlvs); refused == nil {
				t.Error("RefusedSubTLV reported nothing: this carrier is not walked")
			} else if refused.SubTLVType != tc.want {
				t.Errorf("RefusedSubTLV reported sub-TLV %d, want %d", refused.SubTLVType, tc.want)
			}
		})
	}
}
