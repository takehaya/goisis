package packet

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// On-wire sizes and flag bits of the IP TLVs in this file. The reachability
// flag octets differ per family: RFC 5305 §4.1 packs the IPv4 prefix length
// into the control octet with the flags, while RFC 5308 §2 gives IPv6 a full
// flags octet followed by a separate prefix-length octet.
const (
	ipv4AddrLen = 4
	ipv6AddrLen = 16

	prefixFlagDown     = 0x80 // up/down bit (RFC 5305 §4.1 / RFC 5308 §2)
	prefixFlagSubTLV   = 0x40 // sub-TLVs present, IPv4 control octet
	prefixFlagExternal = 0x40 // X bit (external origin), IPv6 flags octet
	prefixFlagSubTLV6  = 0x20 // sub-TLVs present, IPv6 flags octet
	prefixLenMask      = 0x3f // prefix-length bits of the IPv4 control octet
)

// IPInterfaceAddressesTLV is the IP Interface Addresses TLV (type 132, RFC
// 1195): the originator's IPv4 interface addresses.
type IPInterfaceAddressesTLV struct {
	Addresses []netip.Addr // IPv4
}

// Type implements TLV.
func (t *IPInterfaceAddressesTLV) Type() TLVType { return TLVTypeIPInterfaceAddresses }

// Serialize implements TLV.
func (t *IPInterfaceAddressesTLV) Serialize() ([]byte, error) {
	value := make([]byte, 0, len(t.Addresses)*ipv4AddrLen)
	for _, a := range t.Addresses {
		if !a.Is4() {
			return nil, fmt.Errorf("%w: %s is not IPv4", errBadTLV, a)
		}
		b := a.As4()
		value = append(value, b[:]...)
	}
	return encodeTLV(TLVTypeIPInterfaceAddresses, value)
}

func decodeIPInterfaceAddressesTLV(value []byte) (TLV, error) {
	if len(value)%ipv4AddrLen != 0 {
		return nil, fmt.Errorf("%w: IPv4 interface addresses length %d not a multiple of %d", errBadTLV, len(value), ipv4AddrLen)
	}
	tlv := &IPInterfaceAddressesTLV{}
	for len(value) > 0 {
		tlv.Addresses = append(tlv.Addresses, netip.AddrFrom4([4]byte(value[:ipv4AddrLen])))
		value = value[ipv4AddrLen:]
	}
	return tlv, nil
}

// IPv6InterfaceAddressesTLV is the IPv6 Interface Addresses TLV (type 232,
// RFC 5308). Link-local addresses appear in hellos, global in LSPs.
type IPv6InterfaceAddressesTLV struct {
	Addresses []netip.Addr // IPv6
}

// Type implements TLV.
func (t *IPv6InterfaceAddressesTLV) Type() TLVType { return TLVTypeIPv6InterfaceAddresses }

// Serialize implements TLV.
func (t *IPv6InterfaceAddressesTLV) Serialize() ([]byte, error) {
	value := make([]byte, 0, len(t.Addresses)*ipv6AddrLen)
	for _, a := range t.Addresses {
		if !a.Is6() {
			return nil, fmt.Errorf("%w: %s is not IPv6", errBadTLV, a)
		}
		b := a.As16()
		value = append(value, b[:]...)
	}
	return encodeTLV(TLVTypeIPv6InterfaceAddresses, value)
}

func decodeIPv6InterfaceAddressesTLV(value []byte) (TLV, error) {
	if len(value)%ipv6AddrLen != 0 {
		return nil, fmt.Errorf("%w: IPv6 interface addresses length %d not a multiple of %d", errBadTLV, len(value), ipv6AddrLen)
	}
	tlv := &IPv6InterfaceAddressesTLV{}
	for len(value) > 0 {
		tlv.Addresses = append(tlv.Addresses, netip.AddrFrom16([16]byte(value[:ipv6AddrLen])))
		value = value[ipv6AddrLen:]
	}
	return tlv, nil
}

// packPrefix returns the significant leading octets of a prefix's address:
// ceil(bits/8) octets, as carried on the wire by TLVs 135 and 236.
func packPrefix(p netip.Prefix, full []byte) []byte {
	n := (p.Bits() + 7) / 8
	return full[:n]
}

// unpackPrefix rebuilds an address from the significant leading octets,
// zero-filling the rest, then forms a prefix of the given bit length.
func unpackPrefix(sig []byte, bits int, v6 bool) netip.Prefix {
	if v6 {
		var full [16]byte
		copy(full[:], sig)
		return netip.PrefixFrom(netip.AddrFrom16(full), bits)
	}
	var full [4]byte
	copy(full[:], sig)
	return netip.PrefixFrom(netip.AddrFrom4(full), bits)
}

// ExtendedIPReachEntry is one prefix in an Extended IP Reachability TLV.
type ExtendedIPReachEntry struct {
	Metric uint32
	// Down is the RFC 5305 up/down bit: true means the prefix was leaked down
	// from a higher level (the on-wire bit is set). The zero value (false) is
	// the common "up" case.
	Down    bool
	Prefix  netip.Prefix
	SubTLVs []SubTLV
}

// ExtendedIPReachabilityTLV is the Extended IP Reachability TLV (type 135,
// RFC 5305): wide-metric IPv4 prefixes with optional sub-TLVs.
type ExtendedIPReachabilityTLV struct {
	Prefixes []ExtendedIPReachEntry
}

// Type implements TLV.
func (t *ExtendedIPReachabilityTLV) Type() TLVType { return TLVTypeExtendedIPReachability }

// Serialize implements TLV.
func (t *ExtendedIPReachabilityTLV) Serialize() ([]byte, error) {
	var value []byte
	for _, e := range t.Prefixes {
		if !e.Prefix.Addr().Is4() || e.Prefix.Bits() < 0 || e.Prefix.Bits() > 32 {
			return nil, fmt.Errorf("%w: %s is not a valid IPv4 prefix", errBadTLV, e.Prefix)
		}
		sub, err := serializeSubTLVs(e.SubTLVs)
		if err != nil {
			return nil, fmt.Errorf("extended IP reach sub-TLVs: %w", err)
		}
		if len(sub) > 255 {
			return nil, fmt.Errorf("%w: %d octets of IP-reach sub-TLVs", ErrTooLong, len(sub))
		}
		var metric [4]byte
		binary.BigEndian.PutUint32(metric[:], e.Metric)
		value = append(value, metric[:]...)

		ctrl := byte(e.Prefix.Bits())
		if e.Down {
			ctrl |= prefixFlagDown
		}
		if len(sub) > 0 {
			ctrl |= prefixFlagSubTLV
		}
		value = append(value, ctrl)
		full := e.Prefix.Addr().As4()
		value = append(value, packPrefix(e.Prefix, full[:])...)
		// RFC 5305 / FRR #14514: only emit the sub-TLV length when the
		// sub-TLV-present bit is set.
		if len(sub) > 0 {
			value = append(value, byte(len(sub)))
			value = append(value, sub...)
		}
	}
	return encodeTLV(TLVTypeExtendedIPReachability, value)
}

func decodeExtendedIPReachabilityTLV(value []byte) (TLV, error) {
	tlv := &ExtendedIPReachabilityTLV{}
	err := decodePrefixReach(value, false, func(e prefixReachEntry) {
		tlv.Prefixes = append(tlv.Prefixes, ExtendedIPReachEntry{
			Metric:  e.metric,
			Down:    e.down,
			Prefix:  e.prefix,
			SubTLVs: e.subTLVs,
		})
	})
	if err != nil {
		return nil, err
	}
	return tlv, nil
}

// IPv6ReachEntry is one prefix in an IPv6 Reachability TLV.
type IPv6ReachEntry struct {
	Metric uint32
	// Down is the RFC 5308 up/down bit: true means leaked down from a higher
	// level (on-wire bit set). The zero value (false) is the common "up" case.
	Down     bool
	External bool // X bit
	Prefix   netip.Prefix
	SubTLVs  []SubTLV
}

// IPv6ReachabilityTLV is the IPv6 Reachability TLV (type 236, RFC 5308).
type IPv6ReachabilityTLV struct {
	Prefixes []IPv6ReachEntry
}

// Type implements TLV.
func (t *IPv6ReachabilityTLV) Type() TLVType { return TLVTypeIPv6Reachability }

// Serialize implements TLV.
func (t *IPv6ReachabilityTLV) Serialize() ([]byte, error) {
	var value []byte
	for _, e := range t.Prefixes {
		if !e.Prefix.Addr().Is6() || e.Prefix.Bits() < 0 || e.Prefix.Bits() > 128 {
			return nil, fmt.Errorf("%w: %s is not a valid IPv6 prefix", errBadTLV, e.Prefix)
		}
		sub, err := serializeSubTLVs(e.SubTLVs)
		if err != nil {
			return nil, fmt.Errorf("IPv6 reach sub-TLVs: %w", err)
		}
		if len(sub) > 255 {
			return nil, fmt.Errorf("%w: %d octets of IPv6-reach sub-TLVs", ErrTooLong, len(sub))
		}
		var metric [4]byte
		binary.BigEndian.PutUint32(metric[:], e.Metric)
		value = append(value, metric[:]...)

		var flags byte
		if e.Down {
			flags |= prefixFlagDown
		}
		if e.External {
			flags |= prefixFlagExternal
		}
		if len(sub) > 0 {
			flags |= prefixFlagSubTLV6
		}
		value = append(value, flags, byte(e.Prefix.Bits()))
		full := e.Prefix.Addr().As16()
		value = append(value, packPrefix(e.Prefix, full[:])...)
		if len(sub) > 0 {
			value = append(value, byte(len(sub)))
			value = append(value, sub...)
		}
	}
	return encodeTLV(TLVTypeIPv6Reachability, value)
}

func decodeIPv6ReachabilityTLV(value []byte) (TLV, error) {
	tlv := &IPv6ReachabilityTLV{}
	err := decodePrefixReach(value, true, func(e prefixReachEntry) {
		tlv.Prefixes = append(tlv.Prefixes, IPv6ReachEntry{
			Metric:   e.metric,
			Down:     e.down,
			External: e.external,
			Prefix:   e.prefix,
			SubTLVs:  e.subTLVs,
		})
	})
	if err != nil {
		return nil, err
	}
	return tlv, nil
}

// prefixReachEntry is the family-neutral form of one decoded reachability
// entry, produced by decodePrefixReach and converted by the per-family
// decoders above.
type prefixReachEntry struct {
	metric   uint32
	down     bool
	external bool // IPv6 only; always false for IPv4
	prefix   netip.Prefix
	subTLVs  []SubTLV
}

// decodePrefixReach decodes the entry list shared by the Extended IP
// Reachability (135, RFC 5305 §4) and IPv6 Reachability (236, RFC 5308 §2)
// TLVs: per entry a 4-octet metric, the flag/prefix-length octet(s), the
// significant prefix octets, and — when the sub-TLV flag is set — a
// length-prefixed sub-TLV block. Each decoded entry is handed to emit so the
// per-family callers append straight into their typed slices (this runs per
// received LSP; no intermediate slice).
func decodePrefixReach(value []byte, v6 bool, emit func(prefixReachEntry)) error {
	name, fam, headLen, maxBits := "extended IP reach", "IPv4", 5, 32
	if v6 {
		name, fam, headLen, maxBits = "IPv6 reach", "IPv6", 6, 128
	}
	for len(value) > 0 {
		if len(value) < headLen {
			return fmt.Errorf("%s entry: %w", name, ErrTruncated)
		}
		e := prefixReachEntry{metric: binary.BigEndian.Uint32(value[0:4])}
		var bits int
		var hasSub bool
		if v6 {
			flags := value[4]
			e.down = flags&prefixFlagDown != 0
			e.external = flags&prefixFlagExternal != 0
			hasSub = flags&prefixFlagSubTLV6 != 0
			bits = int(value[5])
		} else {
			ctrl := value[4]
			e.down = ctrl&prefixFlagDown != 0
			hasSub = ctrl&prefixFlagSubTLV != 0
			bits = int(ctrl & prefixLenMask)
		}
		if bits > maxBits {
			return fmt.Errorf("%w: %s prefix length %d", errBadTLV, fam, bits)
		}
		sigLen := (bits + 7) / 8
		off := headLen + sigLen
		if len(value) < off {
			return fmt.Errorf("%s prefix: %w", name, ErrTruncated)
		}
		e.prefix = unpackPrefix(value[headLen:off], bits, v6)
		if hasSub {
			if len(value) < off+1 {
				return fmt.Errorf("%s sub-TLV length: %w", name, ErrTruncated)
			}
			subLen := int(value[off])
			off++
			if len(value) < off+subLen {
				return fmt.Errorf("%s sub-TLVs (%d octets): %w", name, subLen, ErrTruncated)
			}
			subs, err := decodeSubTLVs(SubTLVContextIPReachability, value[off:off+subLen])
			if err != nil {
				return fmt.Errorf("%s sub-TLVs: %w", name, err)
			}
			e.subTLVs = subs
			off += subLen
		}
		emit(e)
		value = value[off:]
	}
	return nil
}

func init() {
	registerTLVDecoder(TLVTypeIPInterfaceAddresses, decodeIPInterfaceAddressesTLV)
	registerTLVDecoder(TLVTypeIPv6InterfaceAddresses, decodeIPv6InterfaceAddressesTLV)
	registerTLVDecoder(TLVTypeExtendedIPReachability, decodeExtendedIPReachabilityTLV)
	registerTLVDecoder(TLVTypeIPv6Reachability, decodeIPv6ReachabilityTLV)
}
