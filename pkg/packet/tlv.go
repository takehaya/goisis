package packet

import (
	"fmt"
	"slices"
)

// TLVType identifies a top-level IS-IS TLV (IANA isis-tlv-codepoints).
type TLVType uint8

// TLV type codes implemented or referenced by goisis.
const (
	TLVTypeAreaAddresses          TLVType = 1
	TLVTypeISNeighbors            TLVType = 6
	TLVTypePadding                TLVType = 8
	TLVTypeLSPEntries             TLVType = 9
	TLVTypeAuthentication         TLVType = 10
	TLVTypeExtendedISReachability TLVType = 22
	TLVTypeSRv6Locator            TLVType = 27
	TLVTypeProtocolsSupported     TLVType = 129
	TLVTypeIPInterfaceAddresses   TLVType = 132
	TLVTypeExtendedIPReachability TLVType = 135
	TLVTypeDynamicHostname        TLVType = 137
	TLVTypeIPv6InterfaceAddresses TLVType = 232
	TLVTypeIPv6Reachability       TLVType = 236
	TLVTypeP2PThreeWayAdjacency   TLVType = 240
	TLVTypeRouterCapability       TLVType = 242
)

// TLV is a decoded IS-IS TLV.
type TLV interface {
	// Type returns the TLV type code.
	Type() TLVType
	// Serialize renders the TLV including its type and length octets. It
	// fails with ErrTooLong if the value exceeds 255 octets; producers
	// that may exceed that (e.g. many prefixes) must split their content
	// across multiple TLV instances.
	Serialize() ([]byte, error)
}

// UnknownTLV preserves a TLV this package does not implement. It survives
// re-serialization byte for byte.
type UnknownTLV struct {
	TLVType TLVType
	Value   []byte
}

// Type implements TLV.
func (t *UnknownTLV) Type() TLVType { return t.TLVType }

// Serialize implements TLV.
func (t *UnknownTLV) Serialize() ([]byte, error) {
	return encodeTLV(t.TLVType, t.Value)
}

type tlvDecoder func(value []byte) (TLV, error)

var tlvDecoders = map[TLVType]tlvDecoder{}

// registerTLVDecoder registers the decoder for a TLV type. It is meant to
// be called from init functions and panics on duplicate registration.
func registerTLVDecoder(t TLVType, dec tlvDecoder) {
	if _, dup := tlvDecoders[t]; dup {
		panic(fmt.Sprintf("duplicate TLV decoder for type %d", t))
	}
	tlvDecoders[t] = dec
}

// decodeTLVs decodes a whole TLV area. Unknown TLV types are preserved as
// UnknownTLV; a structurally invalid known TLV fails the whole area (and
// with it the PDU).
func decodeTLVs(b []byte) ([]TLV, error) {
	var out []TLV
	for len(b) > 0 {
		if len(b) < 2 {
			return nil, fmt.Errorf("TLV header: %w", ErrTruncated)
		}
		typ := TLVType(b[0])
		length := int(b[1])
		if len(b) < 2+length {
			return nil, fmt.Errorf("TLV %d value (%d octets): %w", typ, length, ErrTruncated)
		}
		value := b[2 : 2+length]
		if dec, ok := tlvDecoders[typ]; ok {
			tlv, err := dec(value)
			if err != nil {
				return nil, fmt.Errorf("TLV %d: %w", typ, err)
			}
			out = append(out, tlv)
		} else {
			out = append(out, &UnknownTLV{TLVType: typ, Value: slices.Clone(value)})
		}
		b = b[2+length:]
	}
	return out, nil
}

// serializeTLVs renders a TLV area in order.
func serializeTLVs(tlvs []TLV) ([]byte, error) {
	var out []byte
	for _, tlv := range tlvs {
		b, err := tlv.Serialize()
		if err != nil {
			return nil, fmt.Errorf("TLV %d: %w", tlv.Type(), err)
		}
		out = append(out, b...)
	}
	return out, nil
}

// encodeTLV wraps value in a type+length header.
func encodeTLV(t TLVType, value []byte) ([]byte, error) {
	if len(value) > 255 {
		return nil, fmt.Errorf("%w: %d octets", ErrTooLong, len(value))
	}
	out := make([]byte, 0, 2+len(value))
	out = append(out, byte(t), byte(len(value)))
	return append(out, value...), nil
}
