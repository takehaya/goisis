package server

import (
	"time"

	"github.com/takehaya/goisis/pkg/packet"
)

// This file is the "Running Router" column of RFC 5306 §4.1: what this node
// owes a neighbor that is restarting. The restarting half — T1/T2/T3, emitting
// RR and SA, holding back the shutdown purge — is deliberately absent. §4.1 is
// a table of four events, and answering all four of them is a conforming
// implementation of that table rather than half of one.

// restartTLVOf returns the Restart TLV (211) a hello carries, or nil when the
// sender does not implement RFC 5306 at all.
func restartTLVOf(tlvs []packet.TLV) *packet.RestartTLV {
	for _, t := range tlvs {
		if r, ok := t.(*packet.RestartTLV); ok {
			return r
		}
	}
	return nil
}

// helloRestartTLV is the Restart TLV every IIH this node sends carries. RFC
// 5306 §3.2 makes it a MUST on all IIHs of a router that implements restart
// signaling, and with every flag clear it is precisely the capability
// advertisement — it is how a neighbor knows it may ask us to hold an
// adjacency, and how §3.2.1c's candidate set is drawn. ack, when non-nil,
// takes its place for this one IIH.
func helloRestartTLV(ack *packet.RestartTLV) packet.TLV {
	if ack != nil {
		return ack
	}
	return &packet.RestartTLV{}
}

// noteRestart records what one received IIH says about a neighbor's restart
// (RFC 5306 §3.2.1a and §3.2.2) and reports whether the adjacency's holding
// time may be refreshed from it.
//
// Only the first IIH with RR set refreshes the hold. That single rule is the
// whole defence against a peer that restarts over and over: every retry eats
// into the same holding time, the Remaining Time handed back in the
// acknowledgement shrinks with it, and the restarter builds its T3 out of
// those values — so the shrinking is information reaching the restarter, not
// something lost.
func noteRestart(adj *adjacency, rt *packet.RestartTLV) bool {
	adj.restartCapable = rt != nil
	// §3.2.2: suppression lasts "until an IIH with the SA bit clear has been
	// received". A neighbor that stops carrying the TLV at all has stopped
	// asking, which is the same thing.
	adj.suppressed = rt != nil && rt.SuppressAdjacency
	if rt == nil || !rt.RestartRequest {
		// §4.1, "RX RR clr": leaving restart mode is what gives the restart
		// after this one a refresh of its own.
		adj.restartMode = false
		return true
	}
	if adj.restartMode {
		return false
	}
	adj.restartMode = true
	return true
}

// restartAck builds the acknowledgement RFC 5306 §3.2.1b owes a neighbor whose
// IIH had RR set. On a LAN it names the restarter, which §3.2.1b asks for so
// that two routers restarting on one segment at the same time do not each take
// the other's acknowledgement for their own; on a point-to-point circuit there
// is only one router it could be for.
func restartAck(c *circuit, adj *adjacency, now time.Time) *packet.RestartTLV {
	ack := &packet.RestartTLV{
		RestartAck:    true,
		HasRemaining:  true,
		RemainingTime: restartRemainingTime(adj, now),
	}
	if !c.cfg.P2P {
		ack.HasNeighbor = true
		ack.NeighborSystemID = adj.systemID
	}
	return ack
}

// restartRemainingTime is the whole seconds left before this adjacency
// expires: what RFC 5306 §3.2.1b calls "the current time (in seconds) before
// the holding timer on this adjacency is due to expire", which is not the
// holding time the neighbor asked for.
//
// It is computed from the two fields expired() reads, so it stays true as
// §3.2.1a withholds the refresh from repeated restart requests. The restarter
// sets T3 to the minimum of what its neighbors report and declares failure
// when T3 runs out, so a configured holding time here would promise it an
// adjacency that is in fact most of the way to expiry. Seconds are truncated
// rather than rounded, which errs toward expiring early.
func restartRemainingTime(adj *adjacency, now time.Time) uint16 {
	hold := time.Duration(adj.holding) * time.Second
	left := hold - now.Sub(adj.lastHeard)
	switch {
	case left <= 0:
		return 0
	case left >= hold:
		// lastHeard ahead of now: a clock that stepped backwards. Cap at the
		// holding time rather than let the conversion below wrap.
		return adj.holding
	}
	return uint16(left / time.Second)
}

// restartSyncEligible reports whether this router is the one RFC 5306 §3.2.1c
// makes responsible for handing a restarting neighbor on a LAN the complete
// set of CSNPs and the SRM flags: the highest LnRouterPriority, highest source
// MAC breaking ties, among the routers it has an adjacency in state Up to on
// this circuit whose IIHs contain the Restart TLV — counting itself, and
// excluding every neighbor considered to be in restart mode.
//
// Why not ask who the DIS is: the DIS may be the restarter itself, or may not
// be restart capable at all, and §3.2.1c says in as many words that the actual
// DIS is not changed by this process. electDIS's comparator is what is reused
// here; its candidate set is not, and nothing here writes c.dis.
//
// A point-to-point circuit never consults this — §3.2.1c makes its one
// neighbor's request the whole election.
func (s *IsisServer) restartSyncEligible(c *circuit, level packet.Level) bool {
	for _, adj := range c.upAdjacencies(level) {
		// The restarter is itself in restart mode by the time this runs
		// (noteRestart has already seen its RR), so this one test excludes it
		// along with any other neighbor mid-restart.
		if adj.restartMode || !adj.restartCapable {
			continue
		}
		if higherCandidate(adj.priority, adj.snpa, c.cfg.priority(), c.cfg.Transport.LocalSNPA()) {
			return false
		}
	}
	return true
}
