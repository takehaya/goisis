package server

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/takehaya/goisis/pkg/datalink"
	"github.com/takehaya/goisis/pkg/packet"
)

// mtuOptions describes a node with one circuit per given MTU, advertising far
// more reachability than fits a single LSP at any of the budgets tested here.
func mtuOptions(mtus ...int) []ServerOption {
	opts := []ServerOption{
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
	}
	for i, mtu := range mtus {
		opts = append(opts, WithCircuit(CircuitConfig{
			Name:      fmt.Sprintf("c%d", i),
			Transport: datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, byte(i + 1)}, mtu),
			Level2:    true,
			Padding:   ptrFalse(),
		}))
	}
	for i := 0; i < 400; i++ { // ~9 octets/entry
		opts = append(opts, WithAdvertisedPrefix(netip.MustParsePrefix(fmt.Sprintf("10.%d.%d.1/32", i/256, i%256)), 10))
	}
	return opts
}

// checkFragments originates the node LSP and asserts the reachability needed
// more than one fragment and that every fragment fits maxSize on the wire.
func checkFragments(t *testing.T, s *IsisServer, maxSize int) {
	t.Helper()
	s.regenerateNodeLSP(packet.Level2, false, time.Now())
	frags := ownFragments(s)
	if len(frags) < 2 {
		t.Fatalf("got %d fragments, want the reachability to span >= 2", len(frags))
	}
	for num, e := range frags {
		if len(e.raw) > maxSize {
			t.Errorf("fragment %d is %d octets, over the %d-octet LSP MTU", num, len(e.raw), maxSize)
		}
	}
}

// TestOriginationFitsSmallestCircuitMTU: a circuit too narrow for a
// 1492-octet LSP caps this node's own fragments at its MTU less the LLC
// header, so every fragment can actually be transmitted on it.
func TestOriginationFitsSmallestCircuitMTU(t *testing.T) {
	checkFragments(t, mustServer(t, mtuOptions(1000)...), 1000-3)
}

// TestOriginationUsesSmallestCircuitMTU: with circuits of differing MTUs the
// smallest one governs — an LSP is flooded on all of them.
func TestOriginationUsesSmallestCircuitMTU(t *testing.T) {
	checkFragments(t, mustServer(t, mtuOptions(1500, 1280)...), 1280-3)
}

// TestOriginationHonorsLSPMTU: WithLSPMTU overrides a larger interface MTU,
// for a path that carries less than the interface claims.
func TestOriginationHonorsLSPMTU(t *testing.T) {
	checkFragments(t, mustServer(t, append(mtuOptions(1500), WithLSPMTU(600))...), 600)
}

// TestLSPMTUBelowMinimumRejected: a configured LSP MTU that leaves no room for
// reachability is a misconfiguration, refused at construction rather than at
// every origination.
func TestLSPMTUBelowMinimumRejected(t *testing.T) {
	if _, err := NewIsisServer(append(mtuOptions(1500), WithLSPMTU(400))...); err == nil {
		t.Fatal("NewIsisServer accepted an LSP MTU below the 512-octet minimum")
	}
}

// TestTransmitSRMDropsLSPOverCircuitMTU: a foreign LSP larger than a circuit's
// MTU cannot be re-fragmented by this transit node, so it is never sent there.
// The SRM flag is cleared rather than rescheduled forever (p2p, where the flag
// would otherwise survive the send), and the drop is warned once per circuit.
func TestTransmitSRMDropsLSPOverCircuitMTU(t *testing.T) {
	var logBuf bytes.Buffer
	local := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 1}, 1000)
	peer := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 2}, 1000)
	datalink.Link(local, peer)
	s := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(CircuitConfig{Name: "c", Transport: local, Level2: true, P2P: true, Padding: ptrFalse()}),
		WithLogger(slog.New(slog.NewTextHandler(&logBuf, nil))),
	)
	now := time.Now()
	c := s.circuits[0]

	// 1400 octets: past this circuit's 997-octet budget, inside the 1492-octet
	// buffer, so a wider circuit would flood it unchanged.
	tlvs := []packet.TLV{&packet.UnknownTLV{TLVType: 200, Value: make([]byte, 111)}}
	for i := 0; i < 5; i++ {
		tlvs = append(tlvs, &packet.UnknownTLV{TLVType: 200, Value: make([]byte, 250)})
	}
	id := lspID(packet.SystemID{0, 0, 0, 0, 0, 9}, 0)
	lsp := &packet.LSP{Level: packet.Level2, RemainingTime: maxAgeSeconds, LSPID: id, SequenceNumber: 1, ISType: 2, TLVs: tlvs}
	raw, err := lsp.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	if len(raw) != 1400 {
		t.Fatalf("test LSP is %d octets, want 1400", len(raw))
	}
	s.dbs[packet.Level2].entries[id] = &lspEntry{lsp: lsp, raw: raw, inserted: now, lifetime: maxAgeSeconds}

	c.setSRM(packet.Level2, id, now)
	s.transmitSRM(c, packet.Level2, now)

	if _, ok := c.srm[packet.Level2][id]; ok {
		t.Error("SRM still set: the oversize LSP would be retried forever")
	}
	// Nothing may have gone out: a sentinel sent afterwards is the first frame
	// the peer sees.
	sentinel := []byte{0xde, 0xad}
	if err := local.Send(c.dest(packet.Level2), sentinel); err != nil {
		t.Fatalf("send sentinel: %v", err)
	}
	f, err := peer.Recv()
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if !bytes.Equal(f.PDU, sentinel) {
		t.Errorf("sent %d octets on a circuit that cannot carry them", len(f.PDU))
	}

	// The warning is per circuit, not per retransmission attempt.
	c.setSRM(packet.Level2, id, now)
	s.transmitSRM(c, packet.Level2, now)
	if n := strings.Count(logBuf.String(), "level=WARN"); n != 1 {
		t.Errorf("logged %d warnings, want exactly one", n)
	}
}
