package packet

import (
	"fmt"
	"net/netip"
)

// SRv6 End.X sub-TLV code points, registered in the IS-reachability sub-TLV
// context (RFC 9352 §8).
const (
	subTLVSRv6EndXSID    = 43 // RFC 9352 §8.1, p2p neighbor
	subTLVSRv6LANEndXSID = 44 // RFC 9352 §8.2, LAN neighbor behind a pseudonode
	// Flags, Algorithm, Weight, Endpoint Behavior, SID, sub-sub-TLV length.
	srv6EndXSIDFixedLen = 1 + 1 + 1 + 2 + 16 + 1
)

// SRv6 End.X SID flags (RFC 9352 §8.1).
const (
	SRv6EndXFlagBackup     = 0x80 // B: eligible for protection (TI-LFA)
	SRv6EndXFlagSet        = 0x40 // S: the SID is assigned to a set of adjacencies
	SRv6EndXFlagPersistent = 0x20 // P: persistent across control-plane restarts
)

// SRv6EndXSIDSubTLV is the SRv6 End.X SID sub-TLV (type 43, RFC 9352 §8.1):
// an adjacency-scoped SID advertised in an IS reachability TLV (22/23/222/223)
// whose entry names the point-to-point neighbor directly.
type SRv6EndXSIDSubTLV struct {
	Flags     byte
	Algorithm uint8
	Weight    uint8
	Behavior  SRv6EndpointBehavior
	SID       netip.Addr // 16-octet SRv6 SID
	// Structure, if non-nil, is the SID Structure sub-sub-TLV.
	Structure *SIDStructure
	// Unknown preserves sub-sub-TLVs this package does not implement so the
	// SID re-serializes without data loss. On encode they follow the SID
	// Structure, in received order.
	Unknown []UnknownSubTLV
}

// Type implements SubTLV.
func (s *SRv6EndXSIDSubTLV) Type() uint8 { return subTLVSRv6EndXSID }

// Serialize implements SubTLV.
func (s *SRv6EndXSIDSubTLV) Serialize() ([]byte, error) {
	body, err := s.body()
	if err != nil {
		return nil, err
	}
	return encodeSubTLV(subTLVSRv6EndXSID, body)
}

// body renders the part shared with the LAN variant: everything from the flags
// through the sub-sub-TLV area.
func (s *SRv6EndXSIDSubTLV) body() ([]byte, error) {
	sub, err := encodeSIDSubSubTLVs(s.Structure, s.Unknown)
	if err != nil {
		return nil, err
	}
	if len(sub) > 255-srv6EndXSIDFixedLen {
		return nil, fmt.Errorf("%w: %d octets of SRv6 End.X SID sub-sub-TLVs", ErrTooLong, len(sub))
	}
	sid := s.SID.As16()
	out := make([]byte, 0, srv6EndXSIDFixedLen+len(sub))
	out = append(out, s.Flags, s.Algorithm, s.Weight, byte(s.Behavior>>8), byte(s.Behavior))
	out = append(out, sid[:]...)
	out = append(out, byte(len(sub)))
	return append(out, sub...), nil
}

// SRv6LANEndXSIDSubTLV is the SRv6 LAN End.X SID sub-TLV (type 44, RFC 9352
// §8.2). On a broadcast circuit the IS reachability entry points at the
// pseudonode, so the sub-TLV names the neighbor the SID forwards to; the rest
// of the encoding is the point-to-point one.
type SRv6LANEndXSIDSubTLV struct {
	// Neighbor is the System ID of the LAN neighbor, encoded ahead of the
	// flags (RFC 9352 §8.2).
	Neighbor SystemID
	SRv6EndXSIDSubTLV
}

// Type implements SubTLV. It shadows the embedded point-to-point type's.
func (s *SRv6LANEndXSIDSubTLV) Type() uint8 { return subTLVSRv6LANEndXSID }

// Serialize implements SubTLV.
func (s *SRv6LANEndXSIDSubTLV) Serialize() ([]byte, error) {
	body, err := s.body()
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(s.Neighbor)+len(body))
	out = append(out, s.Neighbor[:]...)
	return encodeSubTLV(subTLVSRv6LANEndXSID, append(out, body...))
}

// decodeEndXSIDBody decodes the flags-through-sub-sub-TLVs part shared by both
// variants.
func decodeEndXSIDBody(v []byte, what string) (SRv6EndXSIDSubTLV, error) {
	var s SRv6EndXSIDSubTLV
	if len(v) < srv6EndXSIDFixedLen {
		return s, fmt.Errorf("%s: %w", what, ErrTruncated)
	}
	s.Flags, s.Algorithm, s.Weight = v[0], v[1], v[2]
	s.Behavior = SRv6EndpointBehavior(uint16(v[3])<<8 | uint16(v[4]))
	s.SID = netip.AddrFrom16([16]byte(v[5:21]))
	subLen := int(v[21])
	if len(v) < srv6EndXSIDFixedLen+subLen {
		return s, fmt.Errorf("%s sub-sub-TLVs: %w", what, ErrTruncated)
	}
	st, unknown, err := decodeSIDSubSubTLVs(v[srv6EndXSIDFixedLen : srv6EndXSIDFixedLen+subLen])
	if err != nil {
		return s, err
	}
	s.Structure, s.Unknown = st, unknown
	return s, nil
}

func decodeEndXSID(v []byte) (SubTLV, error) {
	s, err := decodeEndXSIDBody(v, "SRv6 End.X SID")
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func decodeLANEndXSID(v []byte) (SubTLV, error) {
	if len(v) < systemIDLen {
		return nil, fmt.Errorf("SRv6 LAN End.X SID neighbor: %w", ErrTruncated)
	}
	s, err := decodeEndXSIDBody(v[systemIDLen:], "SRv6 LAN End.X SID")
	if err != nil {
		return nil, err
	}
	return &SRv6LANEndXSIDSubTLV{Neighbor: SystemID(v[:systemIDLen]), SRv6EndXSIDSubTLV: s}, nil
}

func init() {
	registerSubTLVDecoder(SubTLVContextISReachability, subTLVSRv6EndXSID, decodeEndXSID)
	registerSubTLVDecoder(SubTLVContextISReachability, subTLVSRv6LANEndXSID, decodeLANEndXSID)
}
