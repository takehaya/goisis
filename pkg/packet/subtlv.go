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
}

// Type implements SubTLV.
func (s *UnknownSubTLV) Type() uint8 { return s.SubTLVType }

// Serialize implements SubTLV.
func (s *UnknownSubTLV) Serialize() ([]byte, error) {
	if len(s.Value) > 255 {
		return nil, fmt.Errorf("sub-TLV %d: %w: %d octets", s.SubTLVType, ErrTooLong, len(s.Value))
	}
	out := make([]byte, 0, 2+len(s.Value))
	out = append(out, s.SubTLVType, byte(len(s.Value)))
	return append(out, s.Value...), nil
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

// decodeSubTLVs decodes a sub-TLV area against the registry for ctx.
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
		value := b[2 : 2+length]
		if dec, ok := subTLVDecoders[ctx][typ]; ok {
			sub, err := dec(value)
			if err != nil {
				return nil, fmt.Errorf("sub-TLV %d: %w", typ, err)
			}
			out = append(out, sub)
		} else {
			out = append(out, &UnknownSubTLV{SubTLVType: typ, Value: slices.Clone(value)})
		}
		b = b[2+length:]
	}
	return out, nil
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
