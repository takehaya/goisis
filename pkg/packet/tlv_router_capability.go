package packet

import (
	"fmt"
	"net/netip"
	"slices"
)

// Router Capability TLV flags (RFC 7981) and sub-TLV code points.
const (
	routerCapFlagSBit = 0x01 // flooding scope is the whole routing domain
	routerCapFlagDBit = 0x02 // the TLV has leaked down a level

	subTLVSRv6Capabilities = 25 // sub-TLV of the Router Capability TLV (242)
)

// RouterCapabilityTLV is the IS-IS Router Capability TLV (type 242, RFC 7981):
// a router ID, flags, and capability sub-TLVs (SR/SRv6/Flex-Algo).
type RouterCapabilityTLV struct {
	RouterID netip.Addr // IPv4 router ID (zero if unset)
	Flags    byte
	SubTLVs  []SubTLV
}

// Type implements TLV.
func (t *RouterCapabilityTLV) Type() TLVType { return TLVTypeRouterCapability }

// DomainWide reports the S-bit (the capability floods domain-wide).
func (t *RouterCapabilityTLV) DomainWide() bool { return t.Flags&routerCapFlagSBit != 0 }

// Serialize implements TLV.
func (t *RouterCapabilityTLV) Serialize() ([]byte, error) {
	var rid [4]byte
	if t.RouterID.Is4() {
		rid = t.RouterID.As4()
	}
	value := make([]byte, 0, 5)
	value = append(value, rid[:]...)
	value = append(value, t.Flags)
	sub, err := serializeSubTLVs(t.SubTLVs)
	if err != nil {
		return nil, err
	}
	value = append(value, sub...)
	return encodeTLV(TLVTypeRouterCapability, value)
}

func decodeRouterCapabilityTLV(value []byte) (TLV, error) {
	if len(value) < 5 {
		return nil, fmt.Errorf("router capability: %w", ErrTruncated)
	}
	tlv := &RouterCapabilityTLV{
		RouterID: netip.AddrFrom4([4]byte(value[0:4])),
		Flags:    value[4],
	}
	subs, err := decodeSubTLVs(SubTLVContextRouterCapability, value[5:])
	if err != nil {
		return nil, err
	}
	tlv.SubTLVs = subs
	return tlv, nil
}

// SRv6CapabilitiesSubTLV is the SRv6 Capabilities sub-TLV (type 25 of TLV
// 242, RFC 9352): a 16-bit flags field (bit 0x4000 = O-flag, SRH OAM). Its
// presence signals SRv6 support.
type SRv6CapabilitiesSubTLV struct {
	Flags uint16
	// SubSubTLVs preserves any octets after the 2-byte flags (RFC 9352 reserves
	// room for optional sub-sub-TLVs) so the sub-TLV round-trips byte-exact even
	// when a peer advertises content goisis does not interpret.
	SubSubTLVs []byte
}

// Type implements SubTLV.
func (s *SRv6CapabilitiesSubTLV) Type() uint8 { return subTLVSRv6Capabilities }

// Serialize implements SubTLV.
func (s *SRv6CapabilitiesSubTLV) Serialize() ([]byte, error) {
	value := make([]byte, 0, 2+len(s.SubSubTLVs))
	value = append(value, byte(s.Flags>>8), byte(s.Flags))
	value = append(value, s.SubSubTLVs...)
	return encodeSubTLV(subTLVSRv6Capabilities, value)
}

func decodeSRv6Capabilities(value []byte) (SubTLV, error) {
	if len(value) < 2 {
		return nil, fmt.Errorf("SRv6 capabilities: %w", ErrTruncated)
	}
	s := &SRv6CapabilitiesSubTLV{Flags: uint16(value[0])<<8 | uint16(value[1])}
	if len(value) > 2 {
		s.SubSubTLVs = slices.Clone(value[2:])
	}
	return s, nil
}

func init() {
	registerTLVDecoder(TLVTypeRouterCapability, decodeRouterCapabilityTLV)
	registerSubTLVDecoder(SubTLVContextRouterCapability, subTLVSRv6Capabilities, decodeSRv6Capabilities)
}
