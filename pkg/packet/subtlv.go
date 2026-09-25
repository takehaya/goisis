package packet

import (
	"fmt"
	"slices"
)

// SubTLVContext selects the sub-TLV registry to decode against. IS-IS
// sub-TLV code points are only meaningful relative to their parent TLV
// (IANA keeps one registry per parent family), so the same numeric code
// decodes differently per context.
type SubTLVContext uint8

// Sub-TLV registries (grouped the way IANA groups parent TLVs).
const (
	// SubTLVContextISReachability covers neighbor TLVs 22, 23, 25, 141,
	// 222 and 223.
	SubTLVContextISReachability SubTLVContext = iota
	// SubTLVContextIPReachability covers prefix TLVs 27, 135, 235, 236
	// and 237.
	SubTLVContextIPReachability
	// SubTLVContextRouterCapability covers TLV 242.
	SubTLVContextRouterCapability
	// SubTLVContextASLA covers the link attributes nested inside an
	// Application-Specific Link Attributes sub-TLV (RFC 8919 §4.2). Its code
	// points are the neighbor TLVs' own, but one level further down, so they
	// cannot share that registry.
	SubTLVContextASLA
)

// SubTLV is a decoded sub-TLV.
type SubTLV interface {
	// Type returns the sub-TLV type code (meaning depends on context).
	Type() uint8
	// Serialize renders the sub-TLV including its type and length octets.
	Serialize() ([]byte, error)
}

// UnknownSubTLV preserves a sub-TLV this package does not implement.
type UnknownSubTLV struct {
	SubTLVType uint8
	Value      []byte
	// Refused distinguishes the two ways this form is reached on decode: a
	// code point with no decoder (false) and one whose decoder rejected the
	// value (true). Both are opaque to every consumer's type switch, which is
	// what decodeSubTLVs is for; the flag exists so the server can count the
	// second, which is a peer advertising an attribute this node then ignores
	// — for the admin-group family, one that an exclude rule stops pruning on.
	//
	// Decode-side only: Serialize does not read it, and nothing sets it on a
	// sub-TLV this node originates, so the byte-exact round trip is unchanged.
	Refused bool
}

// Type implements SubTLV.
func (s *UnknownSubTLV) Type() uint8 { return s.SubTLVType }

// Serialize implements SubTLV.
func (s *UnknownSubTLV) Serialize() ([]byte, error) {
	return encodeSubTLV(s.SubTLVType, s.Value)
}

// encodeSubTLV wraps value in a sub-TLV type+length header (the sub-TLV
// counterpart of encodeTLV).
func encodeSubTLV(t uint8, value []byte) ([]byte, error) {
	if len(value) > 255 {
		return nil, fmt.Errorf("sub-TLV %d: %w: %d octets", t, ErrTooLong, len(value))
	}
	out := make([]byte, 0, 2+len(value))
	out = append(out, t, byte(len(value)))
	return append(out, value...), nil
}

type subTLVDecoder func(value []byte) (SubTLV, error)

var subTLVDecoders = map[SubTLVContext]map[uint8]subTLVDecoder{}

// registerSubTLVDecoder registers a sub-TLV decoder within a context. It is
// meant to be called from init functions and panics on duplicate
// registration.
func registerSubTLVDecoder(ctx SubTLVContext, t uint8, dec subTLVDecoder) {
	m, ok := subTLVDecoders[ctx]
	if !ok {
		m = map[uint8]subTLVDecoder{}
		subTLVDecoders[ctx] = m
	}
	if _, dup := m[t]; dup {
		panic(fmt.Sprintf("duplicate sub-TLV decoder for context %d type %d", ctx, t))
	}
	m[t] = dec
}

// decodeSubTLVs decodes a sub-TLV area against the registry for ctx. A
// decoder that rejects its value does not fail the area, and so does not fail
// the PDU: RFC 5305 §2 has a reader skip a sub-TLV it cannot use, and RFC 8919
// §4.2 says the same of a whole ASLA whose bit-mask lengths are out of range.
// Skipping is not rejecting, and LSPs flood, so failing here over one
// attribute would take its originator off every node in the area. What a
// decoder refuses is preserved opaquely instead, exactly as an unregistered
// code point is: byte-exact on the way back out and invisible to every
// consumer's type switch, which is the outcome those clauses ask for.
//
// The length octets themselves still fail: an area that cannot be split into
// sub-TLVs at all has no boundaries to preserve anything against.
func decodeSubTLVs(ctx SubTLVContext, b []byte) ([]SubTLV, error) {
	var out []SubTLV
	for len(b) > 0 {
		if len(b) < 2 {
			return nil, fmt.Errorf("sub-TLV header: %w", ErrTruncated)
		}
		typ := b[0]
		length := int(b[1])
		if len(b) < 2+length {
			return nil, fmt.Errorf("sub-TLV %d value (%d octets): %w", typ, length, ErrTruncated)
		}
		out = append(out, decodeSubTLV(ctx, typ, b[2:2+length]))
		b = b[2+length:]
	}
	return out, nil
}

// decodeSubTLV decodes one sub-TLV, falling back to the opaque form both when
// the code point is unregistered and when its decoder refuses the value.
func decodeSubTLV(ctx SubTLVContext, typ uint8, value []byte) SubTLV {
	if dec, ok := subTLVDecoders[ctx][typ]; ok {
		if sub, err := dec(value); err == nil {
			return sub
		}
		return &UnknownSubTLV{SubTLVType: typ, Value: slices.Clone(value), Refused: true}
	}
	return &UnknownSubTLV{SubTLVType: typ, Value: slices.Clone(value)}
}

// RefusedSubTLV returns the first sub-TLV of a decoded TLV area whose
// registered decoder refused its value, or nil if none did. It is what lets a
// caller report a contained refusal (see UnknownSubTLV.Refused) without
// reaching into every container shape itself.
//
// It walks only the TLVs that can hold one: a refusal needs a registered
// decoder, and decoders are registered in three of the four contexts —
// SubTLVContextIPReachability has none, so the prefix TLVs carry unknown
// sub-TLVs and nothing else. TestEveryContextWithDecodersIsWalked fails if a
// decoder is registered in a context this walk does not reach.
func RefusedSubTLV(tlvs []TLV) *UnknownSubTLV {
	for _, tlv := range tlvs {
		var found *UnknownSubTLV
		switch t := tlv.(type) {
		case *ExtendedISReachabilityTLV:
			found = refusedInISReach(t.Neighbors)
		case *MTISReachabilityTLV:
			found = refusedInISReach(t.Neighbors)
		case *RouterCapabilityTLV:
			found = refusedInSubTLVs(t.SubTLVs)
		}
		if found != nil {
			return found
		}
	}
	return nil
}

// refusedInISReach scans the sub-TLV area of every neighbor entry, the list
// TLV 22 and TLV 222 share.
func refusedInISReach(neighbors []ExtendedISReachEntry) *UnknownSubTLV {
	for _, n := range neighbors {
		if found := refusedInSubTLVs(n.SubTLVs); found != nil {
			return found
		}
	}
	return nil
}

// refusedInSubTLVs scans one sub-TLV area, descending into an ASLA: its
// attributes are decoded against their own registry (SubTLVContextASLA), so a
// refusal one level down is the same event one level up.
func refusedInSubTLVs(subs []SubTLV) *UnknownSubTLV {
	for _, sub := range subs {
		switch s := sub.(type) {
		case *UnknownSubTLV:
			if s.Refused {
				return s
			}
		case *ASLASubTLV:
			if found := refusedInSubTLVs(s.SubSubTLVs); found != nil {
				return found
			}
		}
	}
	return nil
}

// serializeSubTLVs renders a sub-TLV area in order.
func serializeSubTLVs(subs []SubTLV) ([]byte, error) {
	var out []byte
	for _, sub := range subs {
		b, err := sub.Serialize()
		if err != nil {
			return nil, err
		}
		out = append(out, b...)
	}
	return out, nil
}
