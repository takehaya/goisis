package packet

import (
	"fmt"
	"slices"
	"strings"
)

// AreaAddress is an IS-IS area address: 1-13 octets, AFI first.
type AreaAddress []byte

const maxAreaAddressLen = 13

func (a AreaAddress) String() string {
	// Dotted hex, AFI octet first: 49.0001.
	var sb strings.Builder
	for i, b := range a {
		switch {
		case i == 0:
			fmt.Fprintf(&sb, "%02x", b)
		case i%2 == 1:
			fmt.Fprintf(&sb, ".%02x", b)
		default:
			fmt.Fprintf(&sb, "%02x", b)
		}
	}
	return sb.String()
}

// AreaAddressesTLV is the Area Addresses TLV (type 1, ISO 10589), carried
// in hello PDUs and LSP fragment zero.
type AreaAddressesTLV struct {
	Addresses []AreaAddress
}

// Type implements TLV.
func (t *AreaAddressesTLV) Type() TLVType { return TLVTypeAreaAddresses }

// Serialize implements TLV.
func (t *AreaAddressesTLV) Serialize() ([]byte, error) {
	var value []byte
	for _, a := range t.Addresses {
		if len(a) == 0 || len(a) > maxAreaAddressLen {
			return nil, fmt.Errorf("%w: area address of %d octets", errBadTLV, len(a))
		}
		value = append(value, byte(len(a)))
		value = append(value, a...)
	}
	return encodeTLV(TLVTypeAreaAddresses, value)
}

func decodeAreaAddressesTLV(value []byte) (TLV, error) {
	tlv := &AreaAddressesTLV{}
	for len(value) > 0 {
		addrLen := int(value[0])
		if addrLen == 0 || addrLen > maxAreaAddressLen {
			return nil, fmt.Errorf("%w: area address of %d octets", errBadTLV, addrLen)
		}
		if len(value) < 1+addrLen {
			return nil, fmt.Errorf("area address: %w", ErrTruncated)
		}
		tlv.Addresses = append(tlv.Addresses, AreaAddress(slices.Clone(value[1:1+addrLen])))
		value = value[1+addrLen:]
	}
	return tlv, nil
}

func init() {
	registerTLVDecoder(TLVTypeAreaAddresses, decodeAreaAddressesTLV)
}
