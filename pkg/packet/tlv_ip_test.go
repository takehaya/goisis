package packet

import (
	"bytes"
	"net/netip"
	"testing"
)

func TestExtendedIPReachabilityNoSubTLVBit(t *testing.T) {
	// Regression for FRR #14514: with no sub-TLVs the sub-TLV-present bit
	// must be clear and no sub-TLV length octet emitted.
	tlv := &ExtendedIPReachabilityTLV{Prefixes: []ExtendedIPReachEntry{
		{Metric: 10, Prefix: netip.MustParsePrefix("10.0.0.0/8")},
	}}
	wire, err := tlv.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	// type(135) len metric(4) ctrl(1) prefix(1 octet for /8)
	want := []byte{135, 6, 0, 0, 0, 10, 8, 10}
	if !bytes.Equal(wire, want) {
		t.Fatalf("wire = % x, want % x", wire, want)
	}
	if wire[6]&0x40 != 0 {
		t.Error("sub-TLV-present bit set with no sub-TLVs")
	}
}

func TestExtendedIPReachabilityPrefixLengths(t *testing.T) {
	for _, p := range []string{"0.0.0.0/0", "10.0.0.0/8", "192.168.0.0/16", "192.0.2.0/24", "192.0.2.1/32"} {
		prefix := netip.MustParsePrefix(p)
		tlv := &ExtendedIPReachabilityTLV{Prefixes: []ExtendedIPReachEntry{{Metric: 1, Prefix: prefix}}}
		wire, err := tlv.Serialize()
		if err != nil {
			t.Fatalf("%s: Serialize: %v", p, err)
		}
		decoded := checkTLVRoundtrip(t, wire)[0].(*ExtendedIPReachabilityTLV)
		if got := decoded.Prefixes[0].Prefix; got != prefix {
			t.Errorf("%s: decoded prefix = %s", p, got)
		}
	}
}

func TestExtendedIPReachabilityUpDownAndSubTLV(t *testing.T) {
	tlv := &ExtendedIPReachabilityTLV{Prefixes: []ExtendedIPReachEntry{
		{
			Metric:  100,
			Down:    true,
			Prefix:  netip.MustParsePrefix("203.0.113.0/24"),
			SubTLVs: []SubTLV{&UnknownSubTLV{SubTLVType: 1, Value: []byte{0xaa, 0xbb}}},
		},
	}}
	wire, err := tlv.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	decoded := checkTLVRoundtrip(t, wire)[0].(*ExtendedIPReachabilityTLV)
	e := decoded.Prefixes[0]
	if !e.Down {
		t.Error("up/down bit lost")
	}
	if len(e.SubTLVs) != 1 || e.SubTLVs[0].Type() != 1 {
		t.Errorf("sub-TLVs lost: %+v", e.SubTLVs)
	}
}

func TestIPv6ReachabilityRoundtrip(t *testing.T) {
	tlv := &IPv6ReachabilityTLV{Prefixes: []IPv6ReachEntry{
		{Metric: 10, Prefix: netip.MustParsePrefix("2001:db8::/32")},
		{Metric: 20, External: true, Down: true, Prefix: netip.MustParsePrefix("2001:db8:1:2::/64")},
		{Metric: 0, Prefix: netip.MustParsePrefix("::/0")},
	}}
	wire, err := tlv.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	decoded := checkTLVRoundtrip(t, wire)[0].(*IPv6ReachabilityTLV)
	if len(decoded.Prefixes) != 3 {
		t.Fatalf("got %d prefixes, want 3", len(decoded.Prefixes))
	}
	if !decoded.Prefixes[1].External || !decoded.Prefixes[1].Down {
		t.Errorf("X/U flags lost: %+v", decoded.Prefixes[1])
	}
	if decoded.Prefixes[2].Prefix != netip.MustParsePrefix("::/0") {
		t.Errorf("default route mangled: %s", decoded.Prefixes[2].Prefix)
	}
}

func TestIPInterfaceAddressesRoundtrip(t *testing.T) {
	v4 := &IPInterfaceAddressesTLV{Addresses: []netip.Addr{
		netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.1"),
	}}
	wire, err := v4.Serialize()
	if err != nil {
		t.Fatalf("Serialize v4: %v", err)
	}
	checkTLVRoundtrip(t, wire)

	v6 := &IPv6InterfaceAddressesTLV{Addresses: []netip.Addr{
		netip.MustParseAddr("fe80::1"),
	}}
	wire, err = v6.Serialize()
	if err != nil {
		t.Fatalf("Serialize v6: %v", err)
	}
	checkTLVRoundtrip(t, wire)
}

func TestIPReachabilityDecodeErrors(t *testing.T) {
	// IPv4 prefix length > 32.
	if _, err := decodeTLVs(mustHex(t, "87 06 00 00 00 0a 21 0a")); err == nil {
		t.Error("expected error for IPv4 prefix length 33")
	}
	// IPv6 prefix length > 128.
	if _, err := decodeTLVs(mustHex(t, "ec 07 00 00 00 0a 00 81 20")); err == nil {
		t.Error("expected error for IPv6 prefix length 129")
	}
}
