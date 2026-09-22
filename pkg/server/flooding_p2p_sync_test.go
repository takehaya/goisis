package server

import (
	"context"
	"testing"
	"time"

	"github.com/takehaya/goisis/pkg/datalink"
	"github.com/takehaya/goisis/pkg/packet"
)

func p2pCircuit(name string, tr datalink.Transport) CircuitConfig {
	cfg := CircuitConfig{Name: name, Transport: tr, P2P: true, Level2: true, Padding: ptrFalse()}
	fastHello(&cfg)
	return cfg
}

// srmPending reports whether an LSP is still flagged for transmission on a
// circuit at Level 2.
func srmPending(t *testing.T, s *IsisServer, circuitIdx int, id packet.LSPID) bool {
	t.Helper()
	var pending bool
	if err := s.mgmtOperation(context.Background(), func() error {
		_, pending = s.circuits[circuitIdx].srm[packet.Level2][id]
		return nil
	}); err != nil {
		t.Fatalf("mgmtOperation: %v", err)
	}
	return pending
}

// TestP2PAdjacencyUpSendsWholeDatabase guarantees ISO 10589 7.3.17: a p2p
// adjacency reaching Up hands the neighbor the whole database, not just the
// LSP we re-originate. A--B--C converge first, so that B's flooding flags for
// A's LSP on the B--C circuit are acknowledged and cleared; D then replaces C
// on that circuit and must still learn A's LSP, which B holds from a third
// party. Nothing else would send it: a p2p circuit has no periodic CSNP (only
// the DIS of a LAN sends one) and B re-originates only its own LSP.
func TestP2PAdjacencyUpSendsWholeDatabase(t *testing.T) {
	ta := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xa1}, 1500)
	tb := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xb1}, 1500)
	tb2 := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xb2}, 1500)
	tc := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xc1}, 1500)
	datalink.Link(ta, tb)
	datalink.Link(tb2, tc)

	area := packet.AreaAddress{0x49, 0x00, 0x01}
	idA := packet.SystemID{0, 0, 0, 0, 0, 1}
	idB := packet.SystemID{0, 0, 0, 0, 0, 2}
	idC := packet.SystemID{0, 0, 0, 0, 0, 3}
	idD := packet.SystemID{0, 0, 0, 0, 0, 4}

	a := mustServer(t, WithSystemID(idA), WithAreaAddresses(area), WithCircuit(p2pCircuit("a", ta)))
	b := mustServer(t, WithSystemID(idB), WithAreaAddresses(area),
		WithCircuit(p2pCircuit("b1", tb)), WithCircuit(p2pCircuit("b2", tb2)))
	c := mustServer(t, WithSystemID(idC), WithAreaAddresses(area), WithCircuit(p2pCircuit("c", tc)))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx) //nolint:errcheck // ctx shutdown
	go b.Serve(ctx) //nolint:errcheck // ctx shutdown

	cctx, ccancel := context.WithCancel(ctx)
	cstopped := make(chan error, 1)
	go func() { cstopped <- c.Serve(cctx) }()

	waitFor(t, "c has a's LSP", func() bool { return hasLSPFrom(t, c, idA) })
	// C's PSNP acknowledges A's LSP, which clears B's flag for it on the B--C
	// circuit. Until then the flag left over from the initial flood would
	// deliver the LSP to any newcomer on its own.
	waitFor(t, "b's flag for a's LSP on the c circuit is acknowledged", func() bool {
		return !srmPending(t, b, 1, lspID(idA, 0))
	})

	// C goes away and D is cabled up in its place. Serve closes C's transport
	// on the way out, so wait for it before linking D onto the segment.
	ccancel()
	<-cstopped
	td := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xd1}, 1500)
	datalink.Link(tb2, td)
	d := mustServer(t, WithSystemID(idD), WithAreaAddresses(area), WithCircuit(p2pCircuit("d", td)))
	go d.Serve(ctx) //nolint:errcheck // ctx shutdown

	// The flags set on the Up transition are drained by the 1s housekeeping
	// tick, so allow more time than waitFor's deadline.
	deadline := time.Now().Add(5 * time.Second)
	for !hasLSPFrom(t, d, idA) {
		if time.Now().After(deadline) {
			t.Fatal("d never learned a's LSP over the p2p link that came up last")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestP2PAdjacencyUpSendsCSNP guarantees the two halves of the Up
// synchronization on one circuit: every LSP held is flagged for transmission
// (ISO 10589 7.3.17) and described in a CSNP (7.3.15.1), which is what lets
// the neighbor send back what only it holds.
func TestP2PAdjacencyUpSendsCSNP(t *testing.T) {
	now := time.Now()
	area := packet.AreaAddress{0x49, 0x00, 0x01}
	s, c := snpServer(t, true)
	for i := uint8(1); i <= 3; i++ {
		putEntry(s, lspID(packet.SystemID{0, 0, 0, 0, 0, 0x10 + i}, 0), uint32(i), 1000, now)
	}

	sink := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xff}, 1500)
	datalink.Link(c.cfg.Transport.(*datalink.MockTransport), sink)

	// The neighbor echoes our system ID and circuit ID, which completes the
	// three-way handshake and takes the adjacency to Up.
	s.processP2PHello(c, packet.SNPA{0, 0, 0, 0, 0, 0xb2},
		p2pHelloEchoing(packet.SystemID{0, 0, 0, 0, 0, 2}, area, s.systemID, c.extCircID))
	if c.p2pAdj == nil || c.p2pAdj.state != AdjUp {
		t.Fatal("the p2p adjacency did not reach Up")
	}
	// Buffered frames still drain from a closed inbox, so Recv ends the loop.
	_ = sink.Close()

	advertised := map[packet.LSPID]bool{}
	csnps := 0
	for {
		f, err := sink.Recv()
		if err != nil {
			break
		}
		pdu, err := packet.DecodePDU(f.PDU)
		if err != nil {
			t.Fatalf("decode emitted PDU: %v", err)
		}
		csnp, ok := pdu.(*packet.CSNP)
		if !ok {
			continue // the triggered hello goes out on the same segment
		}
		csnps++
		for _, e := range csnpEntries(csnp) {
			advertised[e.LSPID] = true
		}
	}
	if csnps == 0 {
		t.Fatal("no CSNP was sent when the p2p adjacency came Up")
	}
	for id := range s.dbs[packet.Level2].entries {
		if !advertised[id] {
			t.Errorf("LSP %v is in the database but absent from the CSNPs", id)
		}
		if !hasSRM(c, id) {
			t.Errorf("LSP %v is in the database but not flagged SRM on the circuit", id)
		}
	}
}
