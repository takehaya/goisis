package packet

import (
	"fmt"
	"slices"
)

// SNPA is a subnetwork point of attachment: a 6-octet MAC address on a LAN.
type SNPA [6]byte

func (s SNPA) String() string {
	return fmt.Sprintf("%02x%02x.%02x%02x.%02x%02x", s[0], s[1], s[2], s[3], s[4], s[5])
}

// ISNeighborsTLV is the IS Neighbors TLV (type 6): the SNPAs (MAC
// addresses) of neighbors seen on a LAN, echoed in LAN hellos to drive the
// three-way handshake. LAN hello only.
type ISNeighborsTLV struct {
	Neighbors []SNPA
}

// Type implements TLV.
func (t *ISNeighborsTLV) Type() TLVType { return TLVTypeISNeighbors }

// Serialize implements TLV.
func (t *ISNeighborsTLV) Serialize() ([]byte, error) {
	value := make([]byte, 0, len(t.Neighbors)*6)
	for _, n := range t.Neighbors {
		value = append(value, n[:]...)
	}
	return encodeTLV(TLVTypeISNeighbors, value)
}

func decodeISNeighborsTLV(value []byte) (TLV, error) {
	if len(value)%6 != 0 {
		return nil, fmt.Errorf("%w: IS neighbors length %d not a multiple of 6", errBadTLV, len(value))
	}
	tlv := &ISNeighborsTLV{}
	for len(value) > 0 {
		tlv.Neighbors = append(tlv.Neighbors, SNPA(value[:6]))
		value = value[6:]
	}
	return tlv, nil
}

// PaddingTLV is the Padding TLV (type 8): zero octets used to pad hellos
// toward the interface MTU so MTU mismatches break adjacency early. Its
// content is ignored on receive; goisis originates all-zero padding.
type PaddingTLV struct {
	Length int
}

// Type implements TLV.
func (t *PaddingTLV) Type() TLVType { return TLVTypePadding }

// Serialize implements TLV.
func (t *PaddingTLV) Serialize() ([]byte, error) {
	if t.Length < 0 || t.Length > 255 {
		return nil, fmt.Errorf("%w: padding length %d", ErrTooLong, t.Length)
	}
	return encodeTLV(TLVTypePadding, make([]byte, t.Length))
}

func decodePaddingTLV(value []byte) (TLV, error) {
	// Content is ignored per ISO 10589; goisis emits zeros, so byte-exact
	// round-tripping holds for conformant (all-zero) padding.
	return &PaddingTLV{Length: len(value)}, nil
}

// AuthType identifies the authentication scheme in TLV 10.
type AuthType uint8

// Authentication types (IANA, TLV 10).
const (
	AuthTypeCleartext AuthType = 1  // RFC 1195
	AuthTypeHMACMD5   AuthType = 54 // RFC 5304
	AuthTypeGeneric   AuthType = 3  // RFC 5310
)

// AuthenticationTLV is the Authentication TLV (type 10).
type AuthenticationTLV struct {
	AuthType AuthType
	Value    []byte
}

// Type implements TLV.
func (t *AuthenticationTLV) Type() TLVType { return TLVTypeAuthentication }

// Serialize implements TLV.
func (t *AuthenticationTLV) Serialize() ([]byte, error) {
	value := make([]byte, 0, 1+len(t.Value))
	value = append(value, byte(t.AuthType))
	value = append(value, t.Value...)
	return encodeTLV(TLVTypeAuthentication, value)
}

func decodeAuthenticationTLV(value []byte) (TLV, error) {
	if len(value) < 1 {
		return nil, fmt.Errorf("authentication: %w", ErrTruncated)
	}
	return &AuthenticationTLV{
		AuthType: AuthType(value[0]),
		Value:    slices.Clone(value[1:]),
	}, nil
}

// NLPID values carried in the Protocols Supported TLV.
const (
	NLPIDIPv4 = 0xcc // 204
	NLPIDIPv6 = 0x8e // 142
)

// ProtocolsSupportedTLV is the Protocols Supported TLV (type 129, RFC
// 1195): the NLPIDs the originator routes (IPv4 0xcc, IPv6 0x8e).
type ProtocolsSupportedTLV struct {
	NLPIDs []byte
}

// Type implements TLV.
func (t *ProtocolsSupportedTLV) Type() TLVType { return TLVTypeProtocolsSupported }

// Serialize implements TLV.
func (t *ProtocolsSupportedTLV) Serialize() ([]byte, error) {
	return encodeTLV(TLVTypeProtocolsSupported, t.NLPIDs)
}

func decodeProtocolsSupportedTLV(value []byte) (TLV, error) {
	return &ProtocolsSupportedTLV{NLPIDs: slices.Clone(value)}, nil
}

// DynamicHostnameTLV is the Dynamic Hostname TLV (type 137, RFC 5301): an
// ASCII name mapped to the originating system ID for diagnostics.
type DynamicHostnameTLV struct {
	Hostname string
}

// Type implements TLV.
func (t *DynamicHostnameTLV) Type() TLVType { return TLVTypeDynamicHostname }

// Serialize implements TLV.
func (t *DynamicHostnameTLV) Serialize() ([]byte, error) {
	if len(t.Hostname) < 1 {
		return nil, fmt.Errorf("%w: empty dynamic hostname", errBadTLV)
	}
	return encodeTLV(TLVTypeDynamicHostname, []byte(t.Hostname))
}

func decodeDynamicHostnameTLV(value []byte) (TLV, error) {
	if len(value) < 1 {
		return nil, fmt.Errorf("dynamic hostname: %w", ErrTruncated)
	}
	return &DynamicHostnameTLV{Hostname: string(value)}, nil
}

func init() {
	registerTLVDecoder(TLVTypeISNeighbors, decodeISNeighborsTLV)
	registerTLVDecoder(TLVTypePadding, decodePaddingTLV)
	registerTLVDecoder(TLVTypeAuthentication, decodeAuthenticationTLV)
	registerTLVDecoder(TLVTypeProtocolsSupported, decodeProtocolsSupportedTLV)
	registerTLVDecoder(TLVTypeDynamicHostname, decodeDynamicHostnameTLV)
}
