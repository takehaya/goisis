package server

import (
	"testing"

	"github.com/takehaya/goisis/pkg/datalink"
	"github.com/takehaya/goisis/pkg/packet"
)

func u8(v uint8) *uint8 { return &v }

// neighborHello builds an L2 LAN hello from a neighbor that echoes echoSNPA
// (so the receiver completes the three-way handshake).
func neighborHello(sysID packet.SystemID, prio uint8, lanID packet.NodeID, echo packet.SNPA) *packet.LANHello {
	return &packet.LANHello{
		Level:       packet.Level2,
		CircuitType: packet.CircuitTypeLevel2,
		SourceID:    sysID,
		HoldingTime: 30,
		Priority:    prio,
		LANID:       lanID,
		TLVs:        []packet.TLV{&packet.ISNeighborsTLV{Neighbors: []packet.SNPA{echo}}},
	}
}

// disServer builds a stopped server with one broadcast L2 circuit. The FSM
// is driven synchronously in tests, so no Serve loop is needed.
func disServer(t *testing.T, prio *uint8) (*IsisServer, *circuit, packet.SNPA) {
	t.Helper()
	local := packet.SNPA{0, 0, 0, 0, 0, 0xa1}
	tr := datalink.NewMockTransport(local, 1500)
	s := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(CircuitConfig{Name: "c", Transport: tr, Level2: true, Priority: prio, Padding: ptrFalse()}),
	)
	return s, s.circuits[0], local
}

func TestDISPreemption(t *testing.T) {
	s, c, local := disServer(t, u8(64))
	nbr := packet.SystemID{0, 0, 0, 0, 0, 0xff}
	nbrSNPA := packet.SNPA{0, 0, 0, 0, 0, 0xff}
	nbrLAN := nodeID(nbr, 0x05)

	// Neighbor at lower priority: we should win and be DIS.
	s.processLANHello(c, nbrSNPA, neighborHello(nbr, 10, nbrLAN, local))
	if got, want := c.dis[packet.Level2], nodeID(s.systemID, c.pseudonodeID); got != want {
		t.Fatalf("after low-prio neighbor, DIS = %v, want self %v", got, want)
	}

	// Neighbor raises its priority above ours while staying Up: it must
	// preempt us as DIS (regression: re-election on field change).
	s.processLANHello(c, nbrSNPA, neighborHello(nbr, 100, nbrLAN, local))
	if got := c.dis[packet.Level2]; got != nbrLAN {
		t.Fatalf("after preemption, DIS = %v, want neighbor %v", got, nbrLAN)
	}
}

func TestDISKeepsLANIDWhenWinnerUnknown(t *testing.T) {
	s, c, local := disServer(t, u8(64))
	selfDIS := nodeID(s.systemID, c.pseudonodeID)

	// A low-priority neighbor: we are DIS with our own LAN ID.
	low := packet.SystemID{0, 0, 0, 0, 0, 0x10}
	s.processLANHello(c, packet.SNPA{0, 0, 0, 0, 0, 0x10}, neighborHello(low, 10, nodeID(low, 1), local))
	if c.dis[packet.Level2] != selfDIS {
		t.Fatalf("expected self DIS %v, got %v", selfDIS, c.dis[packet.Level2])
	}

	// A higher-priority neighbor that has NOT advertised a LAN ID yet
	// (zero). It wins the election, but we must keep the last-known-good
	// DIS LAN ID instead of flapping to zero.
	hi := packet.SystemID{0, 0, 0, 0, 0, 0xfe}
	s.processLANHello(c, packet.SNPA{0, 0, 0, 0, 0, 0xfe}, neighborHello(hi, 100, packet.NodeID{}, local))
	if got := c.dis[packet.Level2]; got == (packet.NodeID{}) {
		t.Fatalf("DIS LAN ID flapped to zero when winner had no LAN ID")
	}
}

func TestProcessLANHelloDropsZeroHolding(t *testing.T) {
	s, c, local := disServer(t, u8(64))
	nbr := packet.SystemID{0, 0, 0, 0, 0, 0xff}
	h := neighborHello(nbr, 10, nodeID(nbr, 1), local)
	h.HoldingTime = 0
	s.processLANHello(c, packet.SNPA{0, 0, 0, 0, 0, 0xff}, h)
	if len(c.adjs[packet.Level2]) != 0 {
		t.Errorf("hello with zero holding time created an adjacency")
	}
}
