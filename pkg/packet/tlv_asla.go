package packet

import (
	"encoding/binary"
	"fmt"
	"slices"
)

// Link-attribute code points. RFC 8919 §4.2 gives an attribute the same number
// as a sub-sub-TLV of ASLA that it has as a legacy sub-TLV of the neighbor
// TLVs, so these are registered in both contexts.
const (
	subTLVASLA               = 16 // Application-Specific Link Attributes (RFC 8919 §4.2)
	subTLVAdminGroup         = 3  // Administrative Group (RFC 5305 §3.1), one 32-bit mask
	subTLVExtendedAdminGroup = 14 // Extended Administrative Group (RFC 7308), 4-octet units
)

// Standard Application Identifier Bits of the SABM (RFC 8919 §4.1), sent from
// bit 0 = the most significant bit of the first octet.
const (
	ASLAAppRSVPTE   uint8 = 0x80 // R-bit
	ASLAAppSRPolicy uint8 = 0x40 // S-bit
	ASLAAppLFA      uint8 = 0x20 // F-bit
	ASLAAppFlexAlgo uint8 = 0x10 // X-bit (RFC 9350 §12)
)

const (
	// aslaMaxMaskLen is the SABM/UDABM ceiling of RFC 8919 §4.1.
	aslaMaxMaskLen = 8
	// aslaLegacyFlag is the L-flag, bit 0 of the SABM length octet.
	aslaLegacyFlag = 0x80
	// aslaMaskLenMask keeps the length out of the flag bit in either length
	// octet (bit 0 is the L-flag in the first, Reserved in the second).
	aslaMaskLenMask = 0x7f
)

// ASLASubTLV is the Application-Specific Link Attributes sub-TLV (type 16, RFC
// 8919 §4.2): a set of link attributes scoped to the applications named by the
// two bit masks. RFC 9350 §12 makes it the only place a Flexible Algorithm may
// read a link's colors from, the L-flag being the one exception.
type ASLASubTLV struct {
	// Legacy is the L-flag: the named applications take their attributes from
	// the legacy sub-TLVs of the neighbor TLV instead of from this one.
	Legacy bool
	// SABM and UDABM are the standard and user-defined application bit masks,
	// each at most 8 octets. A zero-length pair means any application (RFC
	// 8919 §6.2).
	SABM  []byte
	UDABM []byte
	// SubSubTLVs are the link attributes, decoded in SubTLVContextASLA.
	SubSubTLVs []SubTLV
}

// Type implements SubTLV.
func (a *ASLASubTLV) Type() uint8 { return subTLVASLA }

// Serialize implements SubTLV. The Reserved bit of the UDABM length octet is
// normalized to 0 (RFC 8919 §4.1 transmits it as 0), so a re-encode of a peer
// that set it is not byte-exact — it is a fixed point, which is the contract
// FuzzDecodeTLVs holds the codec to.
func (a *ASLASubTLV) Serialize() ([]byte, error) {
	if len(a.SABM) > aslaMaxMaskLen || len(a.UDABM) > aslaMaxMaskLen {
		return nil, fmt.Errorf("ASLA: %w: SABM %d, UDABM %d octets", ErrTooLong, len(a.SABM), len(a.UDABM))
	}
	attrs, err := serializeSubTLVs(a.SubSubTLVs)
	if err != nil {
		return nil, err
	}
	first := byte(len(a.SABM))
	if a.Legacy {
		first |= aslaLegacyFlag
	}
	value := make([]byte, 0, 2+len(a.SABM)+len(a.UDABM)+len(attrs))
	value = append(value, first, byte(len(a.UDABM)))
	value = append(value, a.SABM...)
	value = append(value, a.UDABM...)
	value = append(value, attrs...)
	return encodeSubTLV(subTLVASLA, value)
}

// Apps reports whether the SABM names the application whose bit is set in app
// (one of the ASLAApp* constants, all of which live in the first octet).
func (a *ASLASubTLV) Apps(app uint8) bool {
	return len(a.SABM) > 0 && a.SABM[0]&app != 0
}

// AnyApp reports whether both bit masks are zero-length, which RFC 8919 §4.2
// offers to every application that has no advertisement of its own.
func (a *ASLASubTLV) AnyApp() bool { return len(a.SABM) == 0 && len(a.UDABM) == 0 }

// decodeASLA decodes an Application-Specific Link Attributes sub-TLV. RFC 8919
// §4.2 says a mask length above 8 means the entire sub-TLV MUST be ignored,
// and ignoring is not failing: an error here would take the whole LSP down
// with it. Anything this cannot parse therefore stays opaque, which
// round-trips byte-exactly and is invisible to every consumer's type switch —
// the same outcome the RFC asks for.
func decodeASLA(value []byte) (SubTLV, error) {
	a, ok := parseASLA(value)
	if !ok {
		return &UnknownSubTLV{SubTLVType: subTLVASLA, Value: slices.Clone(value)}, nil
	}
	return a, nil
}

func parseASLA(value []byte) (*ASLASubTLV, bool) {
	if len(value) < 2 {
		return nil, false
	}
	sabmLen, udabmLen := int(value[0]&aslaMaskLenMask), int(value[1]&aslaMaskLenMask)
	if sabmLen > aslaMaxMaskLen || udabmLen > aslaMaxMaskLen || len(value) < 2+sabmLen+udabmLen {
		return nil, false
	}
	a := &ASLASubTLV{
		Legacy: value[0]&aslaLegacyFlag != 0,
		SABM:   slices.Clone(value[2 : 2+sabmLen]),
		UDABM:  slices.Clone(value[2+sabmLen : 2+sabmLen+udabmLen]),
	}
	attrs, err := decodeSubTLVs(SubTLVContextASLA, value[2+sabmLen+udabmLen:])
	if err != nil {
		return nil, false
	}
	a.SubSubTLVs = attrs
	return a, true
}

// AdminGroupSubTLV carries a link's colors in either of the two encodings RFC
// 9350 §12 requires a Flex-Algorithm receiver to accept: the Administrative
// Group of RFC 5305 §3.1 (code 3, exactly one 32-bit mask) and the Extended
// Administrative Group of RFC 7308 (code 14, any number of them). One type for
// both, because they are the same bitmask at two lengths.
type AdminGroupSubTLV struct {
	// Extended selects the RFC 7308 encoding (code 14).
	Extended bool
	// Groups is the mask in the 4-octet units it is defined in, most
	// significant word first. RFC 7308 numbers the bits within a unit; nothing
	// here depends on that numbering.
	Groups []uint32
}

// Type implements SubTLV.
func (g *AdminGroupSubTLV) Type() uint8 {
	if g.Extended {
		return subTLVExtendedAdminGroup
	}
	return subTLVAdminGroup
}

// Serialize implements SubTLV.
func (g *AdminGroupSubTLV) Serialize() ([]byte, error) {
	if !g.Extended && len(g.Groups) != 1 {
		return nil, fmt.Errorf("%w: administrative group is one 32-bit word, got %d", errBadTLV, len(g.Groups))
	}
	value := make([]byte, 4*len(g.Groups))
	for i, w := range g.Groups {
		binary.BigEndian.PutUint32(value[4*i:], w)
	}
	return encodeSubTLV(g.Type(), value)
}

func decodeAdminGroup(value []byte) (SubTLV, error) {
	if len(value) != 4 {
		return nil, fmt.Errorf("%w: administrative group is 4 octets, got %d", errBadTLV, len(value))
	}
	return &AdminGroupSubTLV{Groups: []uint32{binary.BigEndian.Uint32(value)}}, nil
}

func decodeExtendedAdminGroup(value []byte) (SubTLV, error) {
	if len(value)%4 != 0 {
		return nil, fmt.Errorf("%w: extended administrative group is a multiple of 4 octets, got %d", errBadTLV, len(value))
	}
	g := &AdminGroupSubTLV{Extended: true}
	for i := 0; i < len(value); i += 4 {
		g.Groups = append(g.Groups, binary.BigEndian.Uint32(value[i:i+4]))
	}
	return g, nil
}

func init() {
	registerSubTLVDecoder(SubTLVContextISReachability, subTLVASLA, decodeASLA)
	// The legacy encodings, which RFC 9350 §12 reads only behind an ASLA that
	// sets the L-flag, but which the codec decodes wherever they appear.
	registerSubTLVDecoder(SubTLVContextISReachability, subTLVAdminGroup, decodeAdminGroup)
	registerSubTLVDecoder(SubTLVContextISReachability, subTLVExtendedAdminGroup, decodeExtendedAdminGroup)
	registerSubTLVDecoder(SubTLVContextASLA, subTLVAdminGroup, decodeAdminGroup)
	registerSubTLVDecoder(SubTLVContextASLA, subTLVExtendedAdminGroup, decodeExtendedAdminGroup)
}
