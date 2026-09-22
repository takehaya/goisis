package server

import (
	"testing"
	"time"

	"github.com/takehaya/goisis/pkg/packet"
)

// TestNonDISIgnoresLANPSNPRequest pins ISO 10589 7.3.15.2 b): on a broadcast
// circuit a system that is not the DIS ignores a received PSNP, so a request
// that the DIS answers does not also draw a retransmission from us.
func TestNonDISIgnoresLANPSNPRequest(t *testing.T) {
	now := time.Now()
	peer := packet.SystemID{0, 0, 0, 0, 0, 2}
	id := lspID(peer, 0)

	s, c := snpServer(t, false)            // LAN
	c.dis[packet.Level2] = nodeID(peer, 1) // the peer is the DIS, not us
	putEntry(s, id, 5, 1000, now)          // we hold a newer copy

	s.processPSNP(c, &packet.PSNP{
		Level: packet.Level2, SourceID: nodeID(peer, 0),
		TLVs: []packet.TLV{&packet.LSPEntriesTLV{Entries: []packet.LSPEntry{
			{LSPID: id, SequenceNumber: 2, RemainingTime: 1000},
		}}},
	}, now)
	if hasSRM(c, id) {
		t.Error("LAN PSNP request received by a non-DIS: expected no SRM")
	}
}
