package packet

import (
	"fmt"
)

const maxWideMetric = 0xffffff // 24-bit

// ExtendedISReachEntry is one neighbor in an Extended IS Reachability TLV.
type ExtendedISReachEntry struct {
	NeighborID NodeID // system ID + pseudonode octet
	Metric     uint32 // 24-bit wide metric
	SubTLVs    []SubTLV
}

// ExtendedISReachabilityTLV is the Extended IS Reachability TLV (type 22,
// RFC 5305): wide-metric neighbor adjacencies with sub-TLVs (TE, SR, SRv6
// adjacency SIDs).
type ExtendedISReachabilityTLV struct {
	Neighbors []ExtendedISReachEntry
}

// Type implements TLV.
func (t *ExtendedISReachabilityTLV) Type() TLVType { return TLVTypeExtendedISReachability }

// Serialize implements TLV.
func (t *ExtendedISReachabilityTLV) Serialize() ([]byte, error) {
	var value []byte
	for _, n := range t.Neighbors {
		if n.Metric > maxWideMetric {
			return nil, fmt.Errorf("%w: IS metric %d exceeds 24 bits", errBadTLV, n.Metric)
		}
		sub, err := serializeSubTLVs(n.SubTLVs)
		if err != nil {
			return nil, err
		}
		if len(sub) > 255 {
			return nil, fmt.Errorf("%w: %d octets of IS-reach sub-TLVs", ErrTooLong, len(sub))
		}
		value = append(value, n.NeighborID[:]...)
		value = append(value, byte(n.Metric>>16), byte(n.Metric>>8), byte(n.Metric))
		value = append(value, byte(len(sub)))
		value = append(value, sub...)
	}
	return encodeTLV(TLVTypeExtendedISReachability, value)
}

func decodeExtendedISReachabilityTLV(value []byte) (TLV, error) {
	tlv := &ExtendedISReachabilityTLV{}
	for len(value) > 0 {
		if len(value) < 11 {
			return nil, fmt.Errorf("extended IS reach entry: %w", ErrTruncated)
		}
		e := ExtendedISReachEntry{
			NeighborID: NodeID(value[0:7]),
			Metric:     uint32(value[7])<<16 | uint32(value[8])<<8 | uint32(value[9]),
		}
		subLen := int(value[10])
		if len(value) < 11+subLen {
			return nil, fmt.Errorf("extended IS reach sub-TLVs (%d octets): %w", subLen, ErrTruncated)
		}
		if subLen > 0 {
			subs, err := decodeSubTLVs(SubTLVContextISReachability, value[11:11+subLen])
			if err != nil {
				return nil, err
			}
			e.SubTLVs = subs
		}
		tlv.Neighbors = append(tlv.Neighbors, e)
		value = value[11+subLen:]
	}
	return tlv, nil
}

func init() {
	registerTLVDecoder(TLVTypeExtendedISReachability, decodeExtendedISReachabilityTLV)
}
