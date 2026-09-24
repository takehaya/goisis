package server

import (
	"testing"
	"time"

	"github.com/takehaya/goisis/pkg/datalink"
	"github.com/takehaya/goisis/pkg/packet"
)

// restartServer is disServer with a clock the test drives, for the assertions
// that are about when a hold expires rather than about what a frame said.
func restartServer(t *testing.T, prio *uint8) (*IsisServer, *circuit, packet.SNPA, *fakeClock) {
	t.Helper()
	clk := newFakeClock()
	local := packet.SNPA{0, 0, 0, 0, 0, 0xa1}
	s := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(CircuitConfig{
			Name:      "c",
			Transport: datalink.NewMockTransport(local, 1500),
			Level2:    true,
			Priority:  prio,
			Padding:   ptrFalse(),
		}),
		WithClock(clk),
	)
	return s, s.circuits[0], local, clk
}

// restartP2PServer is snpServer's point-to-point form with a clock the test
// drives, so an assertion can step past syncCircuitLevel's hold-down.
func restartP2PServer(t *testing.T) (*IsisServer, *circuit, *fakeClock) {
	t.Helper()
	clk := newFakeClock()
	s := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(CircuitConfig{
			Name:      "c",
			Transport: datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 1}, 1500),
			Level2:    true,
			P2P:       true,
			Padding:   ptrFalse(),
		}),
		WithClock(clk),
	)
	return s, s.circuits[0], clk
}

// restartingHello is what a restarting router's IIH looks like: the Restart
// TLV, and an Intermediate System Neighbors option that lists nobody — a
// router that has just restarted has no adjacency database to echo anyone
// from, which is the silence RFC 5306 §3.2.1 tells the helper to ignore. The
// priority is the low one every neighbour in these tests carries, so this node
// stays DIS and the adjacency shows up in the pseudonode LSP it originates.
func restartingHello(sysID packet.SystemID, lanID packet.NodeID, rt *packet.RestartTLV) *packet.LANHello {
	h := neighborHello(sysID, 10, lanID, packet.SNPA{})
	h.TLVs = []packet.TLV{rt}
	return h
}

// restartTLVsIn returns the Restart TLV of every hello among the frames.
func restartTLVsIn(t *testing.T, frames []datalink.Frame) []*packet.RestartTLV {
	t.Helper()
	var out []*packet.RestartTLV
	for _, f := range frames {
		pdu, err := packet.DecodePDU(f.PDU)
		if err != nil {
			t.Fatalf("decode emitted PDU: %v", err)
		}
		var tlvs []packet.TLV
		switch h := pdu.(type) {
		case *packet.LANHello:
			tlvs = h.TLVs
		case *packet.P2PHello:
			tlvs = h.TLVs
		default:
			continue
		}
		if rt := restartTLVOf(tlvs); rt != nil {
			out = append(out, rt)
		}
	}
	return out
}

// soleRestartAck returns the one acknowledgement among the frames, failing if
// there is not exactly one.
func soleRestartAck(t *testing.T, frames []datalink.Frame) *packet.RestartTLV {
	t.Helper()
	var acks []*packet.RestartTLV
	for _, rt := range restartTLVsIn(t, frames) {
		if rt.RestartAck {
			acks = append(acks, rt)
		}
	}
	if len(acks) != 1 {
		t.Fatalf("%d acknowledgements among the frames sent, want exactly 1", len(acks))
	}
	return acks[0]
}

// TestEveryHelloAdvertisesRestartCapability guarantees RFC 5306 §3.2's "All
// IIHs transmitted by a router that supports this capability MUST include this
// TLV": with every flag clear the TLV is the advertisement itself, and it is
// what a neighbor needs to see before it will ask us to hold an adjacency.
// The TLV comes out of the padding budget rather than on top of it, so a
// padded hello still fits the circuit MTU.
func TestEveryHelloAdvertisesRestartCapability(t *testing.T) {
	for _, p2p := range []bool{false, true} {
		s, c := snpServer(t, p2p)
		c.cfg.Padding = nil // default: pad toward the MTU

		var hello packet.PDU = s.buildLANHello(c, packet.Level2, nil)
		tlvs := hello.(*packet.LANHello).TLVs
		if p2p {
			h := s.buildP2PHello(c, nil)
			hello, tlvs = h, h.TLVs
		}
		wire, err := hello.Serialize()
		if err != nil {
			t.Fatalf("p2p=%v: Serialize: %v", p2p, err)
		}
		rt := restartTLVOf(tlvs)
		if rt == nil {
			t.Fatalf("p2p=%v: the hello carries no Restart TLV", p2p)
		}
		if rt.RestartRequest || rt.RestartAck || rt.SuppressAdjacency {
			t.Errorf("p2p=%v: an unsolicited hello carries %+v, want every flag clear", p2p, rt)
		}
		if max := c.cfg.Transport.MTU() - 3; len(wire) > max {
			t.Errorf("p2p=%v: the padded hello is %d octets, past the %d the circuit takes: "+
				"the Restart TLV was appended after the padding was computed", p2p, len(wire), max)
		}
	}
}

// TestHelperHoldsAnAdjacencyAcrossANeighborRestart is the point of the whole
// exercise. RFC 5306 §3.2.1: an IIH with RR set from a neighbor already Up on
// this circuit leaves the adjacency state alone, irrespective of what its IS
// Neighbors option holds. Everything downstream reads that state, so holding
// it is what keeps our LSP advertising the neighbor, keeps SPF crossing the
// edge, and — the part the restarter cannot do without — keeps the update
// process accepting the CSNPs and PSNPs it needs to resynchronize.
func TestHelperHoldsAnAdjacencyAcrossANeighborRestart(t *testing.T) {
	s, c, local, _ := restartServer(t, u8(64))
	nbr := packet.SystemID{0, 0, 0, 0, 0, 0xff}
	nbrSNPA := packet.SNPA{0, 0, 0, 0, 0, 0xff}
	nbrLAN := nodeID(nbr, 0x05)

	// A settled adjacency: the neighbor echoes our SNPA, so it reaches Up.
	s.processLANHello(c, nbrSNPA, neighborHello(nbr, 10, nbrLAN, local))
	if got := c.adjs[packet.Level2][nbr].state; got != AdjUp {
		t.Fatalf("adjacency state = %v before the restart, want Up", got)
	}

	s.processLANHello(c, nbrSNPA, restartingHello(nbr, nbrLAN, &packet.RestartTLV{RestartRequest: true}))

	adj := c.adjs[packet.Level2][nbr]
	if adj == nil {
		t.Fatal("the restart request removed the adjacency outright")
	}
	if adj.state != AdjUp {
		t.Errorf("adjacency state = %v across the restart, want Up", adj.state)
	}
	if s.adjacencyGate(c, packet.PDUTypeL2CSNP, packet.Level2, nbrSNPA) == nil {
		t.Error("the update process refused the restarter's CSNP: the resynchronization it asked for cannot happen")
	}
	// This node is DIS at priority 64 against the neighbor's 10, so the
	// adjacency is advertised in the pseudonode LSP it originates.
	s.regenerateLSPs(false, s.clock.Now())
	if !pseudonodeLists(t, s, c, nbr) {
		t.Error("our pseudonode LSP dropped the restarting neighbor: the area reroutes around a link that is still there")
	}

	// The positive control for the three assertions above: a hello that is not
	// a restart request and echoes nobody is a lost handshake, and must still
	// take the adjacency down to Init. Without this, an implementation that
	// simply never demotes anyone would pass.
	s.processLANHello(c, nbrSNPA, restartingHello(nbr, nbrLAN, &packet.RestartTLV{}))
	if got := c.adjs[packet.Level2][nbr].state; got != AdjInit {
		t.Errorf("adjacency state = %v after a hello that echoes nobody and asks for nothing, want Init", got)
	}
}

// pseudonodeLists reports whether the pseudonode LSP this node originates for
// the circuit advertises IS reachability to id.
func pseudonodeLists(t *testing.T, s *IsisServer, c *circuit, id packet.SystemID) bool {
	t.Helper()
	e := s.dbs[packet.Level2].get(lspID(s.systemID, c.pseudonodeID))
	if e == nil {
		t.Fatal("this node is DIS but originated no pseudonode LSP")
	}
	for _, tlv := range e.lsp.TLVs {
		r, ok := tlv.(*packet.ExtendedISReachabilityTLV)
		if !ok {
			continue
		}
		for _, n := range r.Neighbors {
			if n.NeighborID.SystemID() == id {
				return true
			}
		}
	}
	return false
}

// TestHoldIsRefreshedOnlyByTheFirstRestartRequest guarantees RFC 5306
// §3.2.1a: the first IIH with RR set refreshes the adjacency holding time and
// later ones do not, which is the only thing stopping a peer that restarts
// over and over from pinning this adjacency forever. Leaving restart mode —
// one IIH with RR clear — re-arms the refresh for the next restart.
func TestHoldIsRefreshedOnlyByTheFirstRestartRequest(t *testing.T) {
	s, c, local, clk := restartServer(t, u8(64))
	nbr := packet.SystemID{0, 0, 0, 0, 0, 0xff}
	nbrSNPA := packet.SNPA{0, 0, 0, 0, 0, 0xff}
	nbrLAN := nodeID(nbr, 0x05)
	rr := func() *packet.LANHello {
		return restartingHello(nbr, nbrLAN, &packet.RestartTLV{RestartRequest: true})
	}

	// neighborHello advertises a 30-second holding time.
	s.processLANHello(c, nbrSNPA, neighborHello(nbr, 10, nbrLAN, local))
	adj := c.adjs[packet.Level2][nbr]

	clk.Advance(20 * time.Second)
	s.processLANHello(c, nbrSNPA, rr())
	if got := restartRemainingTime(adj, clk.Now()); got != 30 {
		t.Errorf("after the first restart request, %ds left on the adjacency, want the full 30", got)
	}

	clk.Advance(10 * time.Second)
	s.processLANHello(c, nbrSNPA, rr())
	if got := restartRemainingTime(adj, clk.Now()); got != 20 {
		t.Errorf("after a second restart request, %ds left, want 20: the hold was refreshed twice", got)
	}

	// Past what the one refresh bought, the adjacency expires like any other,
	// however many more requests arrive.
	clk.Advance(21 * time.Second)
	s.processLANHello(c, nbrSNPA, rr())
	if !expired(adj, clk.Now()) {
		t.Error("a repeatedly restarting peer held the adjacency past its holding time")
	}

	// §4.1, "RX RR clr": a normal IIH leaves restart mode, and the restart
	// after this one gets a refresh of its own.
	s.processLANHello(c, nbrSNPA, neighborHello(nbr, 10, nbrLAN, local))
	clk.Advance(10 * time.Second)
	s.processLANHello(c, nbrSNPA, rr())
	if got := restartRemainingTime(adj, clk.Now()); got != 30 {
		t.Errorf("after leaving and re-entering restart mode, %ds left, want the full 30", got)
	}
}

// TestRestartAcknowledgementReportsTheTimeLeftOnTheAdjacency guarantees RFC
// 5306 §3.2.1b: the request is answered at once with an IIH carrying RA, named
// for the restarter on a LAN, and a Remaining Time that is "the current time
// before the holding timer on this adjacency is due to expire" — not the
// configured holding time. The restarter sets T3 from it and declares failure
// when T3 runs out, so the second request's smaller number is the whole point.
func TestRestartAcknowledgementReportsTheTimeLeftOnTheAdjacency(t *testing.T) {
	s, c, local, clk := restartServer(t, u8(64))
	nbr := packet.SystemID{0, 0, 0, 0, 0, 0xff}
	nbrSNPA := packet.SNPA{0, 0, 0, 0, 0, 0xff}
	nbrLAN := nodeID(nbr, 0x05)
	rr := func() *packet.LANHello {
		return restartingHello(nbr, nbrLAN, &packet.RestartTLV{RestartRequest: true})
	}

	s.processLANHello(c, nbrSNPA, neighborHello(nbr, 10, nbrLAN, local))

	stop := captureFrames(t, c)
	clk.Advance(20 * time.Second)
	s.processLANHello(c, nbrSNPA, rr())
	ack := soleRestartAck(t, stop())
	if ack.RestartRequest {
		t.Error("the acknowledgement also asks for a restart of our own")
	}
	if !ack.HasNeighbor || ack.NeighborSystemID != nbr {
		t.Errorf("acknowledgement names %v (present=%v), want the restarter %v: two routers restarting at once would each take the other's",
			ack.NeighborSystemID, ack.HasNeighbor, nbr)
	}
	if !ack.HasRemaining || ack.RemainingTime != 30 {
		t.Errorf("first acknowledgement reports %ds (present=%v), want 30", ack.RemainingTime, ack.HasRemaining)
	}

	stop = captureFrames(t, c)
	clk.Advance(10 * time.Second)
	s.processLANHello(c, nbrSNPA, rr())
	if got := soleRestartAck(t, stop()).RemainingTime; got != 20 {
		t.Errorf("second acknowledgement reports %ds, want 20: the configured holding time is being reported instead of the time left", got)
	}
}

// TestRestartRequestSendsTheWholeDatabaseOverTheLAN guarantees RFC 5306
// §3.2.1c: a LAN restart request is answered with a complete set of CSNPs and
// SRM set on every LSP in the local database. syncCircuitLevel had no LAN
// caller at all before this, so a restarting neighbor on a broadcast segment
// got nothing until the DIS's next periodic CSNP.
func TestRestartRequestSendsTheWholeDatabaseOverTheLAN(t *testing.T) {
	s, c, local, clk := restartServer(t, u8(64))
	nbr := packet.SystemID{0, 0, 0, 0, 0, 0xff}
	nbrSNPA := packet.SNPA{0, 0, 0, 0, 0, 0xff}
	nbrLAN := nodeID(nbr, 0x05)
	for i := uint8(1); i <= 3; i++ {
		putEntry(s, lspID(packet.SystemID{0, 0, 0, 0, 0, 0x10 + i}, 0), uint32(i), 1000, clk.Now())
	}

	// The control: an ordinary hello that takes the adjacency Up is not a
	// request for the database, and must not produce one. Without this, an
	// implementation that synchronized on every hello would pass below.
	stop := captureFrames(t, c)
	s.processLANHello(c, nbrSNPA, neighborHello(nbr, 10, nbrLAN, local))
	if n := countCSNPs(t, stop()); n != 0 {
		t.Fatalf("%d CSNPs sent for an ordinary adjacency coming Up, want none", n)
	}

	stop = captureFrames(t, c)
	s.processLANHello(c, nbrSNPA, restartingHello(nbr, nbrLAN, &packet.RestartTLV{RestartRequest: true}))
	if n := countCSNPs(t, stop()); n == 0 {
		t.Error("the restart request described no database: no CSNP was sent")
	}
	for id := range s.dbs[packet.Level2].entries {
		if !hasSRM(c, id) {
			t.Errorf("LSP %v is in the database but was not flagged for transmission to the restarter", id)
		}
	}
}

// TestRestartSyncIsLeftToTheHighestPriorityEligibleNeighbor guarantees the
// candidate set of RFC 5306 §3.2.1c: on a LAN the database is sent by the
// router with the highest priority among those with an Up adjacency whose IIHs
// carry the Restart TLV, excluding any that is itself in restart mode. A
// neighbor that outranks us but cannot do the job — not restart capable, or
// restarting itself — does not get to silence us.
func TestRestartSyncIsLeftToTheHighestPriorityEligibleNeighbor(t *testing.T) {
	other := packet.SystemID{0, 0, 0, 0, 0, 0xee}
	otherSNPA := packet.SNPA{0, 0, 0, 0, 0, 0xee}
	nbr := packet.SystemID{0, 0, 0, 0, 0, 0xff}
	nbrSNPA := packet.SNPA{0, 0, 0, 0, 0, 0xff}

	// otherHello is the higher-priority third router's IIH, carrying rt (nil
	// for a router that does not implement RFC 5306 at all).
	otherHello := func(local packet.SNPA, rt *packet.RestartTLV) *packet.LANHello {
		h := neighborHello(other, 100, nodeID(other, 1), local)
		if rt != nil {
			h.TLVs = append(h.TLVs, rt)
		}
		return h
	}

	for _, tc := range []struct {
		name  string
		other *packet.RestartTLV
		want  bool
	}{
		{"a restart-capable neighbor outranks us", &packet.RestartTLV{}, false},
		{"the higher-priority router does not implement restart", nil, true},
		{"the higher-priority router is restarting too", &packet.RestartTLV{RestartRequest: true}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, c, local, clk := restartServer(t, u8(64))
			putEntry(s, lspID(packet.SystemID{0, 0, 0, 0, 0, 0x11}, 0), 1, 1000, clk.Now())

			s.processLANHello(c, otherSNPA, otherHello(local, tc.other))
			s.processLANHello(c, nbrSNPA, neighborHello(nbr, 10, nodeID(nbr, 5), local))

			stop := captureFrames(t, c)
			s.processLANHello(c, nbrSNPA, restartingHello(nbr, nodeID(nbr, 5), &packet.RestartTLV{RestartRequest: true}))
			sent := countCSNPs(t, stop()) > 0
			if sent != tc.want {
				t.Errorf("sent the database = %v, want %v", sent, tc.want)
			}
		})
	}
}

// TestSuppressedAdjacencyLeavesTheISReachabilityTLVs guarantees RFC 5306
// §3.2.2: an IIH with SA set keeps the adjacency out of this node's LSPs, and
// it stays out until an IIH with SA clear arrives. Without it, a router that
// is starting is reachable through us while its own LSPs from a previous
// incarnation still out-rank the ones it is about to originate — a blackhole
// for as long as that takes.
func TestSuppressedAdjacencyLeavesTheISReachabilityTLVs(t *testing.T) {
	s, c, local, clk := restartServer(t, u8(64))
	nbr := packet.SystemID{0, 0, 0, 0, 0, 0xff}
	nbrSNPA := packet.SNPA{0, 0, 0, 0, 0, 0xff}
	nbrLAN := nodeID(nbr, 0x05)
	suppressing := func() *packet.LANHello {
		h := neighborHello(nbr, 10, nbrLAN, local)
		h.TLVs = append(h.TLVs, &packet.RestartTLV{SuppressAdjacency: true})
		return h
	}

	s.processLANHello(c, nbrSNPA, suppressing())
	adj := c.adjs[packet.Level2][nbr]
	if adj.state != AdjUp {
		t.Fatalf("adjacency state = %v, want Up: §3.2.2 suppresses the advertisement, not the adjacency", adj.state)
	}
	s.regenerateLSPs(false, clk.Now())
	if pseudonodeLists(t, s, c, nbr) {
		t.Error("our pseudonode LSP advertises a neighbor that asked to be suppressed")
	}
	if s.edgeHasAdjacency(packet.Level2, nodeID(nbr, 0)) {
		t.Error("SPF would still cross the suppressed adjacency, which §3.2.2 forbids in as many words")
	}

	// It survives a Down-to-Up transition: a hello that echoes nobody takes the
	// adjacency to Init, and the next suppressing hello brings it back Up —
	// still suppressed, because no IIH with SA clear has arrived.
	s.processLANHello(c, nbrSNPA, restartingHello(nbr, nbrLAN, &packet.RestartTLV{SuppressAdjacency: true}))
	s.processLANHello(c, nbrSNPA, suppressing())
	clk.Advance(minLSPGenInterval)
	s.regenerateLSPs(false, clk.Now())
	if pseudonodeLists(t, s, c, nbr) {
		t.Error("the adjacency was advertised again after going through Init, with no IIH clearing SA")
	}

	// And an IIH with SA clear brings it back.
	s.processLANHello(c, nbrSNPA, neighborHello(nbr, 10, nbrLAN, local))
	clk.Advance(minLSPGenInterval)
	s.regenerateLSPs(false, clk.Now())
	if !pseudonodeLists(t, s, c, nbr) {
		t.Error("the adjacency stayed suppressed after an IIH with SA clear")
	}
}

// TestHelperHoldsAP2PAdjacencyThroughAStaleCircuitID guarantees the
// point-to-point half of RFC 5306 §3.2.1: while the neighbor has RR set, the
// adjacency is held "irrespective of the other contents of the Point-to-Point
// Three-Way Adjacency option". A restarting router may echo an extended local
// circuit ID left over from its previous incarnation, and RFC 5303 3.2 reads
// that as the peer having moved on to another router — which would tear down
// the adjacency the request is asking us to keep. §3.3.1 says that value is to
// be ignored while a restart is in progress. The database goes out at every
// level the adjacency spans (§3.3.3).
func TestHelperHoldsAP2PAdjacencyThroughAStaleCircuitID(t *testing.T) {
	area := packet.AreaAddress{0x49, 0x00, 0x01}
	s, c, clk := restartP2PServer(t)
	peer := packet.SystemID{0, 0, 0, 0, 0, 2}
	peerSNPA := packet.SNPA{0, 0, 0, 0, 0, 0xb2}
	putEntry(s, lspID(packet.SystemID{0, 0, 0, 0, 0, 0x11}, 0), 1, 1000, clk.Now())

	s.processP2PHello(c, peerSNPA, p2pHelloEchoing(peer, area, s.systemID, c.extCircID))
	if c.p2pAdj == nil || c.p2pAdj.state != AdjUp {
		t.Fatal("the p2p adjacency did not reach Up")
	}
	// Past the hold-down the Up transition's own synchronization armed: what
	// is asserted below is the one the restart request asks for.
	clk.Advance(syncHoldDown)

	// The restarter's IIH: RR set, and a three-way option echoing a circuit ID
	// that is no longer ours.
	restart := p2pHelloEchoing(peer, area, s.systemID, c.extCircID+1)
	restart.TLVs = append(restart.TLVs, &packet.RestartTLV{RestartRequest: true})

	stop := captureFrames(t, c)
	s.processP2PHello(c, peerSNPA, restart)
	if c.p2pAdj == nil {
		t.Fatal("the restart request tore the adjacency down over a stale extended local circuit ID")
	}
	if c.p2pAdj.state != AdjUp {
		t.Errorf("adjacency state = %v across the restart, want Up", c.p2pAdj.state)
	}
	frames := stop()
	if got := soleRestartAck(t, frames); !got.HasRemaining || got.HasNeighbor {
		t.Errorf("point-to-point acknowledgement = %+v, want a remaining time and no System ID (there is only one router it could be for)", got)
	}
	if n := countCSNPs(t, frames); n == 0 {
		t.Error("the restart request described no database: no CSNP was sent")
	}

	// The positive control: without RR, the same stale circuit ID is what RFC
	// 5303 3.2 says it is, and the adjacency goes away.
	plain := p2pHelloEchoing(peer, area, s.systemID, c.extCircID+1)
	s.processP2PHello(c, peerSNPA, plain)
	if c.p2pAdj != nil {
		t.Error("a peer echoing another router's circuit ID kept its adjacency even with no restart in progress")
	}
}
