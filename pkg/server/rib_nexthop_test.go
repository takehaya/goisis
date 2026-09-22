package server

import (
	"net/netip"
	"testing"

	"github.com/takehaya/goisis/pkg/datalink"
	"github.com/takehaya/goisis/pkg/packet"
)

// TestPickGatewayPrefersAddressOnAConnectedSubnet: TLV 132 carries every
// address of the neighbor's interface, so the first one may be off-link. The
// gateway must be one this node can actually reach, else the kernel rejects
// the route with ENETUNREACH.
func TestPickGatewayPrefersAddressOnAConnectedSubnet(t *testing.T) {
	addrs := []netip.Addr{netip.MustParseAddr("10.9.9.1"), netip.MustParseAddr("10.0.0.2")}
	connected := map[netip.Prefix]bool{netip.MustParsePrefix("10.0.0.0/24"): true}

	if got, want := pickGateway(addrs, true, connected), netip.MustParseAddr("10.0.0.2"); got != want {
		t.Errorf("gateway = %v, want %v (the address on a connected subnet)", got, want)
	}
	// Nothing corroborates either address: keep the neighbor reachable rather
	// than dropping the route.
	if got, want := pickGateway(addrs, true, nil), netip.MustParseAddr("10.9.9.1"); got != want {
		t.Errorf("gateway with no connected match = %v, want the first address %v", got, want)
	}
	if got := pickGateway(nil, true, connected); got.IsValid() {
		t.Errorf("gateway for a neighbor with no addresses = %v, want invalid", got)
	}
}

// TestPickGatewayPrefersLinkLocalIPv6 pins RFC 5308 2 and 3: hellos carry
// link-local addresses and those are the next hops, even when the peer also
// lists a global address first.
func TestPickGatewayPrefersLinkLocalIPv6(t *testing.T) {
	addrs := []netip.Addr{netip.MustParseAddr("2001:db8::2"), netip.MustParseAddr("fe80::2")}

	if got, want := pickGateway(addrs, false, nil), netip.MustParseAddr("fe80::2"); got != want {
		t.Errorf("gateway = %v, want the link-local %v", got, want)
	}
	globals := []netip.Addr{netip.MustParseAddr("2001:db8::2"), netip.MustParseAddr("2001:db8::3")}
	if got, want := pickGateway(globals, false, nil), netip.MustParseAddr("2001:db8::2"); got != want {
		t.Errorf("gateway with no link-local = %v, want the first address %v", got, want)
	}
}

// TestResolveNextHopsSkipsNeighborWithoutFamily: a neighbor whose TLV 129
// lists only IPv4 must not be used as the next hop for an IPv6 prefix. A
// neighbor that sent no TLV 129 at all stays usable (RFC 1195 3.1 requires
// it, but receive is lenient).
func TestResolveNextHopsSkipsNeighborWithoutFamily(t *testing.T) {
	peer := packet.SystemID{0, 0, 0, 0, 0, 2}
	gw := netip.MustParseAddr("fe80::2")
	p := netip.MustParsePrefix("2001:db8:1::/48")

	for _, tc := range []struct {
		name   string
		nlpids []byte
		want   bool
	}{
		{"IPv4-only neighbor is skipped", []byte{packet.NLPIDIPv4}, false},
		{"no Protocols Supported TLV is permissive", nil, true},
		{"dual-stack neighbor is used", []byte{packet.NLPIDIPv4, packet.NLPIDIPv6}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := mustServer(t,
				WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
				WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
				WithCircuit(CircuitConfig{Name: "c", Transport: datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 1}, 1500), Level2: true, Padding: ptrFalse()}),
			)
			c := s.circuits[0]
			c.adjs[packet.Level2][peer] = &adjacency{
				systemID:     peer,
				state:        AdjUp,
				neighborIPv6: []netip.Addr{gw},
				nlpids:       tc.nlpids,
			}

			nhs := s.resolveNextHops(p, []packet.SystemID{peer})
			if !tc.want {
				if len(nhs) != 0 {
					t.Fatalf("next hops = %v, want none", nhs)
				}
				return
			}
			if len(nhs) != 1 || nhs[0].Gateway != gw || nhs[0].Interface != "c" {
				t.Fatalf("next hops = %v, want one via c/%v", nhs, gw)
			}
		})
	}
}

// TestAdjacencyRecordsHelloNLPIDs: the Protocols Supported TLV of a hello is
// what resolveNextHops later filters on, so it must reach the adjacency.
func TestAdjacencyRecordsHelloNLPIDs(t *testing.T) {
	s, c, local := disServer(t, u8(64))
	nbr := packet.SystemID{0, 0, 0, 0, 0, 0xff}
	h := neighborHello(nbr, 10, nodeID(nbr, 1), local)
	h.TLVs = append(h.TLVs, &packet.ProtocolsSupportedTLV{NLPIDs: []byte{packet.NLPIDIPv4, packet.NLPIDIPv6}})

	s.processLANHello(c, packet.SNPA{0, 0, 0, 0, 0, 0xff}, h)

	adj := c.adjs[packet.Level2][nbr]
	if adj == nil {
		t.Fatal("no adjacency formed")
	}
	if got, want := adj.nlpids, []byte{packet.NLPIDIPv4, packet.NLPIDIPv6}; string(got) != string(want) {
		t.Errorf("adjacency nlpids = %v, want %v", got, want)
	}
}
