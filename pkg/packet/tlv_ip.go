package packet

import (
	"encoding/binary"
	"fmt"
	"net/netip"
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
	value := make([]byte, 0, len(t.Addresses)*4)
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
	if len(value)%4 != 0 {
		return nil, fmt.Errorf("%w: IPv4 interface addresses length %d not a multiple of 4", errBadTLV, len(value))
	}
	tlv := &IPInterfaceAddressesTLV{}
	for len(value) > 0 {
		tlv.Addresses = append(tlv.Addresses, netip.AddrFrom4([4]byte(value[:4])))
		value = value[4:]
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
	value := make([]byte, 0, len(t.Addresses)*16)
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
	if len(value)%16 != 0 {
		return nil, fmt.Errorf("%w: IPv6 interface addresses length %d not a multiple of 16", errBadTLV, len(value))
	}
	tlv := &IPv6InterfaceAddressesTLV{}
	for len(value) > 0 {
		tlv.Addresses = append(tlv.Addresses, netip.AddrFrom16([16]byte(value[:16])))
		value = value[16:]
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
	Metric  uint32
	Up      bool // false = up; true = down (leaked between levels, RFC 5305)
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
			return nil, err
		}
		if len(sub) > 255 {
			return nil, fmt.Errorf("%w: %d octets of IP-reach sub-TLVs", ErrTooLong, len(sub))
		}
		var metric [4]byte
		binary.BigEndian.PutUint32(metric[:], e.Metric)
		value = append(value, metric[:]...)

		ctrl := byte(e.Prefix.Bits())
		if e.Up {
			ctrl |= 0x80 // up/down bit
		}
		if len(sub) > 0 {
			ctrl |= 0x40 // sub-TLV present
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
	for len(value) > 0 {
		if len(value) < 5 {
			return nil, fmt.Errorf("extended IP reach entry: %w", ErrTruncated)
		}
		metric := binary.BigEndian.Uint32(value[0:4])
		ctrl := value[4]
		bits := int(ctrl & 0x3f)
		if bits > 32 {
			return nil, fmt.Errorf("%w: IPv4 prefix length %d", errBadTLV, bits)
		}
		sigLen := (bits + 7) / 8
		off := 5 + sigLen
		if len(value) < off {
			return nil, fmt.Errorf("extended IP reach prefix: %w", ErrTruncated)
		}
		prefix := unpackPrefix(value[5:off], bits, false)
		e := ExtendedIPReachEntry{Metric: metric, Up: ctrl&0x80 != 0, Prefix: prefix}
		if ctrl&0x40 != 0 { // sub-TLV present
			if len(value) < off+1 {
				return nil, fmt.Errorf("extended IP reach sub-TLV length: %w", ErrTruncated)
			}
			subLen := int(value[off])
			off++
			if len(value) < off+subLen {
				return nil, fmt.Errorf("extended IP reach sub-TLVs (%d octets): %w", subLen, ErrTruncated)
			}
			subs, err := decodeSubTLVs(SubTLVContextIPReachability, value[off:off+subLen])
			if err != nil {
				return nil, err
			}
			e.SubTLVs = subs
			off += subLen
		}
		tlv.Prefixes = append(tlv.Prefixes, e)
		value = value[off:]
	}
	return tlv, nil
}

// IPv6ReachEntry is one prefix in an IPv6 Reachability TLV.
type IPv6ReachEntry struct {
	Metric   uint32
	Up       bool // false = up; true = down
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
			return nil, err
		}
		if len(sub) > 255 {
			return nil, fmt.Errorf("%w: %d octets of IPv6-reach sub-TLVs", ErrTooLong, len(sub))
		}
		var metric [4]byte
		binary.BigEndian.PutUint32(metric[:], e.Metric)
		value = append(value, metric[:]...)

		var flags byte
		if e.Up {
			flags |= 0x80
		}
		if e.External {
			flags |= 0x40
		}
		if len(sub) > 0 {
			flags |= 0x20 // sub-TLV present
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
	for len(value) > 0 {
		if len(value) < 6 {
			return nil, fmt.Errorf("IPv6 reach entry: %w", ErrTruncated)
		}
		metric := binary.BigEndian.Uint32(value[0:4])
		flags := value[4]
		bits := int(value[5])
		if bits > 128 {
			return nil, fmt.Errorf("%w: IPv6 prefix length %d", errBadTLV, bits)
		}
		sigLen := (bits + 7) / 8
		off := 6 + sigLen
		if len(value) < off {
			return nil, fmt.Errorf("IPv6 reach prefix: %w", ErrTruncated)
		}
		prefix := unpackPrefix(value[6:off], bits, true)
		e := IPv6ReachEntry{
			Metric:   metric,
			Up:       flags&0x80 != 0,
			External: flags&0x40 != 0,
			Prefix:   prefix,
		}
		if flags&0x20 != 0 { // sub-TLV present
			if len(value) < off+1 {
				return nil, fmt.Errorf("IPv6 reach sub-TLV length: %w", ErrTruncated)
			}
			subLen := int(value[off])
			off++
			if len(value) < off+subLen {
				return nil, fmt.Errorf("IPv6 reach sub-TLVs (%d octets): %w", subLen, ErrTruncated)
			}
			subs, err := decodeSubTLVs(SubTLVContextIPReachability, value[off:off+subLen])
			if err != nil {
				return nil, err
			}
			e.SubTLVs = subs
			off += subLen
		}
		tlv.Prefixes = append(tlv.Prefixes, e)
		value = value[off:]
	}
	return tlv, nil
}

func init() {
	registerTLVDecoder(TLVTypeIPInterfaceAddresses, decodeIPInterfaceAddressesTLV)
	registerTLVDecoder(TLVTypeIPv6InterfaceAddresses, decodeIPv6InterfaceAddressesTLV)
	registerTLVDecoder(TLVTypeExtendedIPReachability, decodeExtendedIPReachabilityTLV)
	registerTLVDecoder(TLVTypeIPv6Reachability, decodeIPv6ReachabilityTLV)
}
