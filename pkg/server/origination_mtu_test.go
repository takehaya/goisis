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

// oversizeSRMServer is a p2p L2 node on a 1000-octet circuit with an Up
// neighbor, so transmitSRM reaches the circuit-MTU check. It returns the other
// end of the segment, to see what (if anything) was actually sent.
func oversizeSRMServer(t *testing.T, logBuf *bytes.Buffer, m Metrics) (*IsisServer, *circuit, *datalink.MockTransport) {
	t.Helper()
	local := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 1}, 1000)
	peer := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 2}, 1000)
	datalink.Link(local, peer)
	s := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(CircuitConfig{Name: "c", Transport: local, Level2: true, P2P: true, Padding: ptrFalse()}),
		WithLogger(slog.New(slog.NewTextHandler(logBuf, nil))),
		WithMetrics(m),
	)
	c := s.circuits[0]
	upP2PAdj(c, packet.SystemID{0, 0, 0, 0, 0, 9}, time.Now()) // p2p floods only to an Up neighbor
	return s, c, peer
}

// injectOversizeLSP stores a foreign LSP of 1400 octets under sys: past the
// 997-octet budget of a 1000-octet circuit, inside the 1492-octet buffer, so a
// wider circuit would flood it unchanged.
func injectOversizeLSP(t *testing.T, s *IsisServer, sys packet.SystemID, now time.Time) packet.LSPID {
	t.Helper()
	tlvs := []packet.TLV{&packet.UnknownTLV{TLVType: 200, Value: make([]byte, 111)}}
	for i := 0; i < 5; i++ {
		tlvs = append(tlvs, &packet.UnknownTLV{TLVType: 200, Value: make([]byte, 250)})
	}
	id := lspID(sys, 0)
	lsp := &packet.LSP{Level: packet.Level2, RemainingTime: maxAgeSeconds, LSPID: id, SequenceNumber: 1, ISType: 2, TLVs: tlvs}
	raw, err := lsp.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	if len(raw) != 1400 {
		t.Fatalf("test LSP is %d octets, want 1400", len(raw))
	}
	s.dbs[packet.Level2].entries[id] = &lspEntry{lsp: lsp, raw: raw, inserted: now, lifetime: maxAgeSeconds}
	return id
}

// TestTransmitSRMDropsLSPOverCircuitMTU: a foreign LSP larger than a circuit's
// MTU cannot be re-fragmented by this transit node, so it is never sent there.
// The SRM flag is cleared rather than rescheduled forever (p2p, where the flag
// would otherwise survive the send). The neighbor keeps asking for it, so every
// attempt is counted even though only the first one is logged.
func TestTransmitSRMDropsLSPOverCircuitMTU(t *testing.T) {
	var logBuf bytes.Buffer
	m := newCountingMetrics()
	s, c, peer := oversizeSRMServer(t, &logBuf, m)
	now := time.Now()
	id := injectOversizeLSP(t, s, packet.SystemID{0, 0, 0, 0, 0, 9}, now)

	c.setSRM(packet.Level2, id, now)
	s.transmitSRM(c, packet.Level2, now)

	if _, ok := c.srm[packet.Level2][id]; ok {
		t.Error("SRM still set: the oversize LSP would be retried forever")
	}
	// Nothing may have gone out: a sentinel sent afterwards is the first frame
	// the peer sees.
	sentinel := []byte{0xde, 0xad}
	if err := c.cfg.Transport.Send(c.dest(packet.Level2), sentinel); err != nil {
		t.Fatalf("send sentinel: %v", err)
	}
	f, err := peer.Recv()
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if !bytes.Equal(f.PDU, sentinel) {
		t.Errorf("sent %d octets on a circuit that cannot carry them", len(f.PDU))
	}

	// A second PSNP for the same LSP drops it again: the drop is counted per
	// attempt, the warning stays at one.
	c.setSRM(packet.Level2, id, now)
	s.transmitSRM(c, packet.Level2, now)
	if got := m.count("flood_drop", "c", floodDropOversize); got != 2 {
		t.Errorf("counted %d oversize flood drops, want one per attempt (2)", got)
	}
	if n := strings.Count(logBuf.String(), "level=WARN"); n != 1 {
		t.Errorf("logged %d warnings for one LSP, want exactly one", n)
	}
}

// TestTransmitSRMWarnsForEachOversizeLSP: the suppression is keyed per
// (circuit, LSP ID), so a second, different LSP that cannot be flooded is
// reported instead of inheriting the first one's silence.
func TestTransmitSRMWarnsForEachOversizeLSP(t *testing.T) {
	var logBuf bytes.Buffer
	m := newCountingMetrics()
	s, c, _ := oversizeSRMServer(t, &logBuf, m)
	now := time.Now()
	for _, sys := range []packet.SystemID{{0, 0, 0, 0, 0, 9}, {0, 0, 0, 0, 0, 0xa}} {
		id := injectOversizeLSP(t, s, sys, now)
		c.setSRM(packet.Level2, id, now)
		s.transmitSRM(c, packet.Level2, now)
	}
	if n := strings.Count(logBuf.String(), "level=WARN"); n != 2 {
		t.Errorf("logged %d warnings for two oversize LSPs, want one each", n)
	}
	if got := m.count("flood_drop", "c", floodDropOversize); got != 2 {
		t.Errorf("counted %d oversize flood drops, want 2", got)
	}
}
