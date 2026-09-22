package server

import (
	"testing"
	"time"

	"github.com/takehaya/goisis/pkg/datalink"
	"github.com/takehaya/goisis/pkg/packet"
)

// upP2PAdj fabricates the Up point-to-point adjacency at Level 2 that flooding
// requires before it transmits on a p2p circuit, last heard at lastHeard.
func upP2PAdj(c *circuit, peer packet.SystemID, lastHeard time.Time) {
	adj := &adjacency{systemID: peer, state: AdjUp, holding: 30, lastHeard: lastHeard}
	adj.levels.add(packet.Level2)
	c.p2pAdj = adj
}

// captureFrames links a listener onto the circuit's segment and returns a
// function that ends the capture and reports every frame sent since.
func captureFrames(t *testing.T, c *circuit) func() []datalink.Frame {
	t.Helper()
	peer := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xff}, 1500)
	datalink.Link(c.cfg.Transport.(*datalink.MockTransport), peer)
	return func() []datalink.Frame {
		_ = peer.Close()
		var out []datalink.Frame
		for {
			f, err := peer.Recv()
			if err != nil {
				return out
			}
			out = append(out, f)
		}
	}
}

// TestP2PCircuitWithoutAdjacencySendsNoLSPs: a p2p circuit whose neighbor is
// not (or not yet) Up carries no LSP, however many are flagged. The flag
// survives, so the LSP goes out as soon as an adjacency comes Up.
func TestP2PCircuitWithoutAdjacencySendsNoLSPs(t *testing.T) {
	now := time.Now()
	s, c := snpServer(t, true)
	id := lspID(packet.SystemID{0, 0, 0, 0, 0, 2}, 0)
	putEntry(s, id, 1, 1000, now)
	stop := captureFrames(t, c)

	s.floodLSP(packet.Level2, id, nil, now)
	s.transmitSRM(c, packet.Level2, now)

	if frames := stop(); len(frames) != 0 {
		t.Errorf("sent %d PDUs on a p2p circuit with no adjacency, want none", len(frames))
	}
	if !hasSRM(c, id) {
		t.Error("SRM cleared without an adjacency: the LSP would never be sent once one comes Up")
	}
}

// TestP2PAdjacencyExpiryClearsFloodingFlags: when the neighbor's holding time
// elapses, every flooding flag on the circuit goes with it — they describe
// what to send to a router that is gone (ISO 10589 7.3.17 re-arms them when an
// adjacency comes Up).
func TestP2PAdjacencyExpiryClearsFloodingFlags(t *testing.T) {
	now := time.Now()
	s, c := snpServer(t, true)
	peer := packet.SystemID{0, 0, 0, 0, 0, 2}

	// Originate our own LSP up front: the expiry re-originates, and an LSP
	// first built there would flood and set a flag of its own.
	s.regenerateLSPs(false, now)
	c.clearFlags()

	upP2PAdj(c, peer, now.Add(-time.Minute)) // holding is 30 s: already expired
	a, b, unheld := lspID(peer, 0), lspID(peer, 1), lspID(peer, 2)
	putEntry(s, a, 1, 1000, now)
	putEntry(s, b, 1, 1000, now)
	c.setSRM(packet.Level2, a, now)
	c.setSSN(packet.Level2, b)
	c.setSSNAck(packet.Level2, packet.LSPEntry{LSPID: unheld, SequenceNumber: 1})

	s.expireAdjacencies(c, now)

	if c.p2pAdj != nil {
		t.Fatalf("expired p2p adjacency still attached: %+v", c.p2pAdj)
	}
	for _, l := range c.cfg.levels() {
		if n := len(c.srm[l]); n != 0 {
			t.Errorf("level %v: %d SRM flags survived the adjacency", l, n)
		}
		if n := len(c.ssn[l]); n != 0 {
			t.Errorf("level %v: %d SSN flags survived the adjacency", l, n)
		}
		if n := len(c.ssnAck[l]); n != 0 {
			t.Errorf("level %v: %d SSN acks survived the adjacency", l, n)
		}
	}
}

// TestP2PFlagsAreRearmedOnAdjacencyUp: clearing the flags on the way down
// strands nothing, because the adjacency coming back Up re-floods (ISO 10589
// 7.3.17).
func TestP2PFlagsAreRearmedOnAdjacencyUp(t *testing.T) {
	now := time.Now()
	s, c := snpServer(t, true)
	peer := packet.SystemID{0, 0, 0, 0, 0, 2}
	area := packet.AreaAddress{0x49, 0x00, 0x01}

	s.regenerateLSPs(false, now)
	c.clearFlags()
	upP2PAdj(c, peer, now.Add(-time.Minute))
	s.expireAdjacencies(c, now)

	// The neighbor returns and echoes our system ID and circuit ID, so the
	// three-way handshake completes at once (RFC 5303).
	s.processP2PHello(c, packet.SNPA{0, 0, 0, 0, 0, 0xb2}, p2pHelloEchoing(peer, area, s.systemID, c.extCircID))

	if c.p2pAdj == nil || c.p2pAdj.state != AdjUp {
		t.Fatalf("adjacency did not reach Up: %+v", c.p2pAdj)
	}
	if !hasSRM(c, lspID(s.systemID, 0)) {
		t.Error("own LSP not re-flagged for the returned neighbor")
	}
}

// TestLANCircuitWithoutAdjacenciesStillSendsLSPs: the p2p gate leaves
// broadcast circuits alone — their flags are per circuit, not per neighbor,
// and the DIS's CSNPs, not an adjacency check, govern them.
func TestLANCircuitWithoutAdjacenciesStillSendsLSPs(t *testing.T) {
	now := time.Now()
	s, c := snpServer(t, false)
	id := lspID(packet.SystemID{0, 0, 0, 0, 0, 2}, 0)
	putEntry(s, id, 1, 1000, now)
	stop := captureFrames(t, c)

	s.floodLSP(packet.Level2, id, nil, now)
	s.transmitSRM(c, packet.Level2, now)

	if frames := stop(); len(frames) != 1 {
		t.Errorf("sent %d PDUs on a LAN with no adjacencies, want 1", len(frames))
	}
	if hasSRM(c, id) {
		t.Error("LAN SRM survived the send; the DIS CSNP provides the reliability")
	}
}
