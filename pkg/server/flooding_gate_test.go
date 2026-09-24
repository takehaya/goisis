package server

import (
	"context"
	"testing"
	"time"

	"github.com/takehaya/goisis/pkg/datalink"
	"github.com/takehaya/goisis/pkg/packet"
)

// TestLSPAndSNPsFromSourceWithoutAdjacencyAreIgnored drives a station that
// never sent a hello onto the segment and checks that its LSP, CSNP and PSNP
// reach neither the database nor the flooding flags (ISO 10589 7.3.15.1 /
// 7.3.15.2). The mirror case — the same PDUs accepted once the source is an Up
// adjacency — is TestFloodingTwoNodes.
func TestLSPAndSNPsFromSourceWithoutAdjacencyAreIgnored(t *testing.T) {
	for _, tc := range []struct {
		name string
		p2p  bool
		dst  packet.SNPA
	}{
		{name: "broadcast", p2p: false, dst: datalink.AllL2ISs},
		{name: "p2p", p2p: true, dst: datalink.AllISs},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tv := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xa1}, 1500)
			rogue := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0x99}, 1500)
			datalink.Link(tv, rogue)

			idV := packet.SystemID{0, 0, 0, 0, 0, 1}
			idR := packet.SystemID{0, 0, 0, 0, 0, 9}
			cfg := CircuitConfig{Name: "v", Transport: tv, Level2: true, P2P: tc.p2p, Padding: ptrFalse()}
			fastHello(&cfg)
			m := newCountingMetrics()
			v := mustServer(t, WithSystemID(idV), WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}), WithCircuit(cfg), WithMetrics(m))

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go v.Serve(ctx) //nolint:errcheck // ctx shutdown

			waitFor(t, "victim originates its own LSP", func() bool { return hasLSPFrom(t, v, idV) })

			rogueID := lspID(idR, 0)
			lsp := &packet.LSP{Level: packet.Level2, RemainingTime: 1000, LSPID: rogueID, SequenceNumber: 7, ISType: 3}
			raw, err := lsp.Serialize()
			if err != nil {
				t.Fatalf("serialize LSP: %v", err)
			}
			entry := packet.LSPEntry{LSPID: rogueID, SequenceNumber: 7, RemainingTime: 1000, Checksum: lsp.Checksum()}
			csnp, err := fullRangeCSNP(entry).Serialize()
			if err != nil {
				t.Fatalf("serialize CSNP: %v", err)
			}
			psnp, err := (&packet.PSNP{
				Level: packet.Level2, SourceID: nodeID(idR, 0),
				TLVs: []packet.TLV{&packet.LSPEntriesTLV{Entries: []packet.LSPEntry{entry}}},
			}).Serialize()
			if err != nil {
				t.Fatalf("serialize PSNP: %v", err)
			}
			for _, wire := range [][]byte{raw, csnp, psnp} {
				if err := rogue.Send(tc.dst, wire); err != nil {
					t.Fatalf("rogue send: %v", err)
				}
			}

			// What the fixed wait this replaces was really waiting for is the
			// three frames crossing the segment, which no clock governs. The
			// gate counts each one it turns away, so waiting for that count is
			// both exact and over as soon as they have arrived — and a slow
			// loop makes the test later rather than flaky, as before.
			waitFor(t, "the victim turns all three PDUs away", func() bool {
				return m.count("pdu_drop", "v", dropNoAdjacency) >= 3
			})

			if hasLSPFrom(t, v, idR) {
				t.Error("LSP from a source without an adjacency entered the database")
			}
			var srm, ssn bool
			if err := v.mgmtOperation(ctx, func() error {
				srm, ssn = hasSRM(v.circuits[0], rogueID), hasSSN(v.circuits[0], rogueID)
				return nil
			}); err != nil {
				t.Fatalf("mgmtOperation: %v", err)
			}
			if srm {
				t.Error("SNP from a source without an adjacency raised SRM")
			}
			if ssn {
				t.Error("SNP from a source without an adjacency raised SSN")
			}

			// Control: the very same bytes install when handed to the update
			// process directly, so the drop above is the adjacency gate and not
			// a malformed PDU.
			if err := v.mgmtOperation(ctx, func() error {
				v.processLSP(v.circuits[0], raw, lsp, nil, time.Now())
				return nil
			}); err != nil {
				t.Fatalf("mgmtOperation: %v", err)
			}
			if !hasLSPFrom(t, v, idR) {
				t.Error("control: the LSP was rejected for a reason other than the missing adjacency")
			}
		})
	}
}
