package packet

import (
	"fmt"
	"net/netip"
)

// SRv6 sub-TLV and sub-sub-TLV code points (RFC 9352).
const (
	subTLVSRv6EndSID   = 5 // sub-TLV of the SRv6 Locator TLV (27)
	subSubTLVSIDStruct = 1 // sub-sub-TLV of an SRv6 SID sub-TLV
	srv6EndSIDFixedLen = 1 + 2 + 16 + 1
	sidStructureLen    = 4
)

// SRv6EndpointBehavior is the IANA SRv6 Endpoint Behavior code point (RFC
// 8986). It is treated opaquely so future behaviors (uSID, etc.) need no code
// change. Common values: End=1.
type SRv6EndpointBehavior uint16

// SRv6 endpoint behaviors that goisis names; others are carried opaquely.
const (
	SRv6BehaviorEnd    SRv6EndpointBehavior = 1
	SRv6BehaviorEndDT6 SRv6EndpointBehavior = 18
	SRv6BehaviorEndDT4 SRv6EndpointBehavior = 19
)

// SIDStructure is the SID Structure sub-sub-TLV (type 1): the bit lengths of
// the locator-block, locator-node, function, and argument parts of a SID. It
// is informational and must not exceed 128 bits in total.
type SIDStructure struct {
	LocatorBlock byte
	LocatorNode  byte
	Function     byte
	Argument     byte
}

// SRv6EndSID is the SRv6 End SID sub-TLV (type 5) carried in a Locator TLV.
type SRv6EndSID struct {
	Flags    byte
	Behavior SRv6EndpointBehavior
	SID      netip.Addr // 16-octet SRv6 SID
	// Structure, if non-nil, is the SID Structure sub-sub-TLV.
	Structure *SIDStructure
}

func (e *SRv6EndSID) encode() []byte {
	sid := e.SID.As16()
	out := make([]byte, 0, srv6EndSIDFixedLen+2+sidStructureLen)
	out = append(out, e.Flags, byte(e.Behavior>>8), byte(e.Behavior))
	out = append(out, sid[:]...)
	if e.Structure != nil {
		out = append(out, 2+sidStructureLen) // sub-sub-TLV length
		out = append(out, subSubTLVSIDStruct, sidStructureLen,
			e.Structure.LocatorBlock, e.Structure.LocatorNode, e.Structure.Function, e.Structure.Argument)
	} else {
		out = append(out, 0)
	}
	return out
}

func decodeEndSID(v []byte) (*SRv6EndSID, error) {
	if len(v) < srv6EndSIDFixedLen {
		return nil, fmt.Errorf("SRv6 End SID: %w", ErrTruncated)
	}
	e := &SRv6EndSID{
		Flags:    v[0],
		Behavior: SRv6EndpointBehavior(uint16(v[1])<<8 | uint16(v[2])),
		SID:      netip.AddrFrom16([16]byte(v[3:19])),
	}
	subLen := int(v[19])
	if len(v) < srv6EndSIDFixedLen+subLen {
		return nil, fmt.Errorf("SRv6 End SID sub-sub-TLVs: %w", ErrTruncated)
	}
	sub := v[srv6EndSIDFixedLen : srv6EndSIDFixedLen+subLen]
	for len(sub) > 0 {
		// A trailing octet too short for a sub-sub-TLV header is malformed —
		// reject it rather than silently dropping it (consistency with the
		// sub-TLV registry; preserves byte-exact intent).
		if len(sub) < 2 {
			return nil, fmt.Errorf("SRv6 SID sub-sub-TLV header: %w", ErrTruncated)
		}
		t, l := sub[0], int(sub[1])
		if len(sub) < 2+l {
			return nil, fmt.Errorf("SRv6 SID sub-sub-TLV %d: %w", t, ErrTruncated)
		}
		if t == subSubTLVSIDStruct && l == sidStructureLen {
			e.Structure = &SIDStructure{LocatorBlock: sub[2], LocatorNode: sub[3], Function: sub[4], Argument: sub[5]}
		}
		sub = sub[2+l:]
	}
	return e, nil
}

// SRv6Locator is one locator entry in the SRv6 Locator TLV.
type SRv6Locator struct {
	Metric    uint32
	Flags     byte // bit 0x80 = D-flag (down/leaked)
	Algorithm uint8
	Locator   netip.Prefix // the locator prefix (Loc-Size bits)
	EndSIDs   []*SRv6EndSID
}

// SRv6LocatorTLV is the SRv6 Locator TLV (type 27, RFC 9352).
type SRv6LocatorTLV struct {
	MTID     uint16 // 12-bit, 0 = standard topology
	Locators []SRv6Locator
}

// Type implements TLV.
func (t *SRv6LocatorTLV) Type() TLVType { return TLVTypeSRv6Locator }

// Serialize implements TLV.
func (t *SRv6LocatorTLV) Serialize() ([]byte, error) {
	value := []byte{byte(t.MTID >> 8 & 0x0f), byte(t.MTID)}
	for _, l := range t.Locators {
		if !l.Locator.Addr().Is6() {
			return nil, fmt.Errorf("%w: SRv6 locator %s is not IPv6", errBadTLV, l.Locator)
		}
		bits := l.Locator.Bits()
		if bits < 0 || bits > 128 {
			return nil, fmt.Errorf("%w: SRv6 locator size %d", errBadTLV, bits)
		}
		var sub []byte
		for _, e := range l.EndSIDs {
			enc := e.encode()
			sub = append(sub, subTLVSRv6EndSID, byte(len(enc)))
			sub = append(sub, enc...)
		}
		if len(sub) > 255 {
			return nil, fmt.Errorf("%w: %d octets of SRv6 locator sub-TLVs", ErrTooLong, len(sub))
		}
		value = append(value,
			byte(l.Metric>>24), byte(l.Metric>>16), byte(l.Metric>>8), byte(l.Metric),
			l.Flags, l.Algorithm, byte(bits))
		full := l.Locator.Addr().As16()
		value = append(value, full[:(bits+7)/8]...)
		value = append(value, byte(len(sub)))
		value = append(value, sub...)
	}
	return encodeTLV(TLVTypeSRv6Locator, value)
}

func decodeSRv6LocatorTLV(value []byte) (TLV, error) {
	if len(value) < 2 {
		return nil, fmt.Errorf("SRv6 Locator MTID: %w", ErrTruncated)
	}
	tlv := &SRv6LocatorTLV{MTID: uint16(value[0]&0x0f)<<8 | uint16(value[1])}
	value = value[2:]
	for len(value) > 0 {
		if len(value) < 8 {
			return nil, fmt.Errorf("SRv6 locator entry: %w", ErrTruncated)
		}
		loc := SRv6Locator{
			Metric:    uint32(value[0])<<24 | uint32(value[1])<<16 | uint32(value[2])<<8 | uint32(value[3]),
			Flags:     value[4],
			Algorithm: value[5],
		}
		bits := int(value[6])
		if bits > 128 {
			return nil, fmt.Errorf("%w: SRv6 locator size %d", errBadTLV, bits)
		}
		sigLen := (bits + 7) / 8
		off := 7 + sigLen
		if len(value) < off+1 {
			return nil, fmt.Errorf("SRv6 locator prefix: %w", ErrTruncated)
		}
		var full [16]byte
		copy(full[:], value[7:off])
		// Canonicalize: RFC 9352 says trailing locator bits are zero and must
		// be ignored on receive, so mask any host bits a peer left set.
		loc.Locator = netip.PrefixFrom(netip.AddrFrom16(full), bits).Masked()
		subLen := int(value[off])
		off++
		if len(value) < off+subLen {
			return nil, fmt.Errorf("SRv6 locator sub-TLVs: %w", ErrTruncated)
		}
		sub := value[off : off+subLen]
		for len(sub) > 0 {
			if len(sub) < 2 {
				return nil, fmt.Errorf("SRv6 locator sub-TLV header: %w", ErrTruncated)
			}
			st, sl := sub[0], int(sub[1])
			if len(sub) < 2+sl {
				return nil, fmt.Errorf("SRv6 locator sub-TLV %d: %w", st, ErrTruncated)
			}
			if st == subTLVSRv6EndSID {
				e, err := decodeEndSID(sub[2 : 2+sl])
				if err != nil {
					return nil, err
				}
				loc.EndSIDs = append(loc.EndSIDs, e)
			}
			sub = sub[2+sl:]
		}
		tlv.Locators = append(tlv.Locators, loc)
		value = value[off+subLen:]
	}
	return tlv, nil
}

func init() {
	registerTLVDecoder(TLVTypeSRv6Locator, decodeSRv6LocatorTLV)
}
