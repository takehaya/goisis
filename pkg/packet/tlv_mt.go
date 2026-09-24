package packet

import "fmt"

// MT IDs from the reserved range of RFC 5120 §7.5. Only the two goisis acts on
// are named: #0 is the standard topology — the one the TLVs without an MT ID
// describe — and #2 is the IPv6 unicast topology a peer configured for
// multi-topology IPv6 advertises its IPv6 prefixes in.
const (
	MTIDStandard    uint16 = 0
	MTIDIPv6Unicast uint16 = 2
)

// mtIDLen is the 2-octet MT membership field RFC 5120 §§7.2-7.4 put in front of
// the entry list of TLVs 22, 135 and 236 to make TLVs 222, 235 and 237.
const mtIDLen = 2

// M-Topologies TLV (229) flag bits (RFC 5120 §7.1).
const (
	mtFlagOverload = 0x80 // O bit
	mtFlagAttached = 0x40 // A bit
)

// decodeMTID splits the MT membership field off the front of a TLV 222/235/237
// value. The top four bits are reserved and "ignored on receipt", so they are
// masked off and re-encoded as zero — the one field of these TLVs that is
// normalized rather than byte-exact, as the SRv6 Locator TLV already does with
// the same field.
//
// An MT ID of zero is deliberately not an error, though §§7.2-7.4 say such a
// TLV MUST be ignored: ignoring is the decision process's job (see
// buildTopology), not the codec's. Rejecting it here would fail the whole PDU,
// so one peer's stray TLV would blackhole every LSP it sends.
func decodeMTID(name string, value []byte) (uint16, []byte, error) {
	if len(value) < mtIDLen {
		return 0, nil, fmt.Errorf("%s MT ID: %w", name, ErrTruncated)
	}
	return uint16(value[0]&0x0f)<<8 | uint16(value[1]), value[mtIDLen:], nil
}

// encodeMTID renders the MT membership field with the reserved bits clear.
func encodeMTID(mtid uint16) []byte {
	return []byte{byte(mtid >> 8 & 0x0f), byte(mtid)}
}

// MTISReachabilityTLV is the MT Intermediate Systems TLV (type 222, RFC 5120
// §7.2): the neighbor list of TLV 22 for one topology.
type MTISReachabilityTLV struct {
	MTID      uint16
	Neighbors []ExtendedISReachEntry
}

// Type implements TLV.
func (t *MTISReachabilityTLV) Type() TLVType { return TLVTypeMTISReachability }

// Serialize implements TLV.
func (t *MTISReachabilityTLV) Serialize() ([]byte, error) {
	entries, err := serializeISReachEntries(t.Neighbors)
	if err != nil {
		return nil, err
	}
	return encodeTLV(TLVTypeMTISReachability, append(encodeMTID(t.MTID), entries...))
}

func decodeMTISReachabilityTLV(value []byte) (TLV, error) {
	mtid, rest, err := decodeMTID("MT IS reach", value)
	if err != nil {
		return nil, err
	}
	neighbors, err := decodeISReachEntries(rest)
	if err != nil {
		return nil, err
	}
	return &MTISReachabilityTLV{MTID: mtid, Neighbors: neighbors}, nil
}

// MTIPReachabilityTLV is the Multi-Topology Reachable IPv4 Prefixes TLV (type
// 235, RFC 5120 §7.3): the prefix list of TLV 135 for one topology.
type MTIPReachabilityTLV struct {
	MTID     uint16
	Prefixes []ExtendedIPReachEntry
}

// Type implements TLV.
func (t *MTIPReachabilityTLV) Type() TLVType { return TLVTypeMTIPReachability }

// Serialize implements TLV.
func (t *MTIPReachabilityTLV) Serialize() ([]byte, error) {
	entries, err := serializeIPReachEntries(t.Prefixes)
	if err != nil {
		return nil, err
	}
	return encodeTLV(TLVTypeMTIPReachability, append(encodeMTID(t.MTID), entries...))
}

func decodeMTIPReachabilityTLV(value []byte) (TLV, error) {
	mtid, rest, err := decodeMTID("MT IP reach", value)
	if err != nil {
		return nil, err
	}
	prefixes, err := decodeIPReachEntries(rest)
	if err != nil {
		return nil, err
	}
	return &MTIPReachabilityTLV{MTID: mtid, Prefixes: prefixes}, nil
}

// MTIPv6ReachabilityTLV is the Multi-Topology Reachable IPv6 Prefixes TLV (type
// 237, RFC 5120 §7.4): the prefix list of TLV 236 for one topology. A peer
// configured for multi-topology IPv6 puts its IPv6 prefixes here, under MT #2,
// and none in TLV 236.
type MTIPv6ReachabilityTLV struct {
	MTID     uint16
	Prefixes []IPv6ReachEntry
}

// Type implements TLV.
func (t *MTIPv6ReachabilityTLV) Type() TLVType { return TLVTypeMTIPv6Reachability }

// Serialize implements TLV.
func (t *MTIPv6ReachabilityTLV) Serialize() ([]byte, error) {
	entries, err := serializeIPv6ReachEntries(t.Prefixes)
	if err != nil {
		return nil, err
	}
	return encodeTLV(TLVTypeMTIPv6Reachability, append(encodeMTID(t.MTID), entries...))
}

func decodeMTIPv6ReachabilityTLV(value []byte) (TLV, error) {
	mtid, rest, err := decodeMTID("MT IPv6 reach", value)
	if err != nil {
		return nil, err
	}
	prefixes, err := decodeIPv6ReachEntries(rest)
	if err != nil {
		return nil, err
	}
	return &MTIPv6ReachabilityTLV{MTID: mtid, Prefixes: prefixes}, nil
}

// MTopologyEntry is one MT membership advertised in the M-Topologies TLV. The
// two flags are valid only in LSP fragment 0 and only for a non-zero MT ID;
// elsewhere RFC 5120 §7.1 says to send them clear and ignore them on receipt.
type MTopologyEntry struct {
	MTID     uint16
	Overload bool // O bit: this topology is overloaded
	Attached bool // A bit: this topology is attached to another level
}

// MTopologiesTLV is the M-Topologies TLV (type 229, RFC 5120 §7.1): the set of
// topologies the sender participates in, carried in hellos and LSP fragment 0.
// It may occur more than once, in which case the sets union; its absence means
// MT #0 alone, so a router that advertises it must list MT #0 too.
type MTopologiesTLV struct {
	Topologies []MTopologyEntry
}

// Type implements TLV.
func (t *MTopologiesTLV) Type() TLVType { return TLVTypeMTopologies }

// Serialize implements TLV.
func (t *MTopologiesTLV) Serialize() ([]byte, error) {
	value := make([]byte, 0, len(t.Topologies)*mtIDLen)
	for _, e := range t.Topologies {
		hi := byte(e.MTID >> 8 & 0x0f)
		if e.Overload {
			hi |= mtFlagOverload
		}
		if e.Attached {
			hi |= mtFlagAttached
		}
		value = append(value, hi, byte(e.MTID))
	}
	return encodeTLV(TLVTypeMTopologies, value)
}

func decodeMTopologiesTLV(value []byte) (TLV, error) {
	if len(value)%mtIDLen != 0 {
		return nil, fmt.Errorf("%w: M-Topologies length %d not a multiple of %d", errBadTLV, len(value), mtIDLen)
	}
	tlv := &MTopologiesTLV{}
	for len(value) > 0 {
		tlv.Topologies = append(tlv.Topologies, MTopologyEntry{
			MTID:     uint16(value[0]&0x0f)<<8 | uint16(value[1]),
			Overload: value[0]&mtFlagOverload != 0,
			Attached: value[0]&mtFlagAttached != 0,
		})
		value = value[mtIDLen:]
	}
	return tlv, nil
}

func init() {
	registerTLVDecoder(TLVTypeMTISReachability, decodeMTISReachabilityTLV)
	registerTLVDecoder(TLVTypeMTopologies, decodeMTopologiesTLV)
	registerTLVDecoder(TLVTypeMTIPReachability, decodeMTIPReachabilityTLV)
	registerTLVDecoder(TLVTypeMTIPv6Reachability, decodeMTIPv6ReachabilityTLV)
}
