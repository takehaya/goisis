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
// (RFC 5306 §3.2.1a and §3.2.2) and refreshes the adjacency's holding timer as
// far as §3.2.1a allows. held is whether §3.2.1's precondition covered this
// IIH — the caller's holdForRestart, an adjacency already Up to this System ID
// from this source, with RR set.
//
// Only the first such IIH refreshes the hold, and all it refreshes is when the
// adjacency was last heard from — never the Holding Time that IIH carries.
// Those two fields are the factors of the instant the adjacency expires, so a
// request that installed its own Holding Time would set its own hold whether
// or not lastHeard moved, and "otherwise, the holding time is not refreshed"
// would bound nothing. What is left is the bound §3.3 assumes when it calls an
// overrunning restart one "taking longer than the minimum holding time of the
// neighbors": the budget is the neighbor's, the restarter is told what is left
// of it in the acknowledgement (§3.2.1b) and sets T3 from that, so every retry
// shrinks a number the restarter is reading rather than one it chose. That is
// the whole defence against a peer that restarts over and over.
//
// Why not bound the Holding Time generally instead: ISO 10589 leaves that
// value to the sender, a ceiling would need a constant no RFC supplies, and it
// would expire an adjacency the peer legitimately still believes in. The bound
// belongs where §3.2.1a puts it, on the request — a restarter that needs
// longer configures a longer hold before it restarts, which is what "the
// minimum holding time of the neighbors" is.
//
// Why nothing here opens RFC 7987 §3.2's window, which §3.2.1c's exchange is
// the whole reason to: the window follows the exchange, and the exchange is
// syncCircuitLevel's — held down to one run per syncHoldDown per circuit and
// level, and deferred outright when that has not lapsed. A window opened on
// the request instead would reopen on hellos that started no exchange, at
// whatever rate a neighbor cares to send them, which is a filter the watched
// party can switch off. See openSyncWindow.
func noteRestart(adj *adjacency, rt *packet.RestartTLV, held bool, holding uint16, now time.Time) {
	adj.restartCapable = rt != nil
	// §3.2.2: suppression lasts "until an IIH with the SA bit clear has been
	// received". A neighbor that stops carrying the TLV at all has stopped
	// asking, which is the same thing.
	adj.suppressed = rt != nil && rt.SuppressAdjacency
	// restartMode follows the RR bit on every IIH, not only on one held
	// covers: §3.2.1c's candidate set excludes "all routers which are
	// considered in Restart mode", and a router whose first hello on this
	// circuit asks for a restart is one of them. §4.1, "RX RR clr": leaving
	// restart mode is what gives the restart after this one a refresh of its
	// own.
	first := !adj.restartMode
	adj.restartMode = rt != nil && rt.RestartRequest
	if !held {
		// §3.2.1's "Otherwise": an IIH its precondition does not cover is
		// "processed as normal", holding time included — a neighbor whose
		// first hello is a restart request would otherwise be left with an
		// adjacency that has no holding time at all.
		adj.holding, adj.lastHeard = holding, now
		return
	}
	if first {
		adj.lastHeard = now
	}
}

// reportRestart records what one received IIH changed about a neighbor's
// restart state: the request counter, and a line on each edge. It runs after
// noteRestart has applied the IIH, on every IIH the two hello handlers process
// — one that carries no Restart TLV at all is how a neighbor leaves restart
// mode and drops suppression, so it has edges of its own.
//
// Edges and not states, because the helper's correct behaviour is the absence
// of the event that used to be the signal: holding an adjacency means
// "adjacency state change" does not fire, and there is nothing else to explain
// why this node advertises a neighbor it has no handshake with, or why it
// holds an adjacency that is Up and carries nothing. A restarter sets RR on
// every IIH for the length of its restart, so the state itself is worth a line
// once, not once per hello. adj.restartMode and adj.suppressed already hold
// the previous value at the call site, which is what makes the edge free —
// there is no separate record to keep, and none to retire when the adjacency
// goes away.
//
// It returns whether either condition moved, which is the same edge the watch
// stream is emitted on — the caller owns that, because an adjacency whose
// state moved on the same IIH has already reported the new values and must not
// report them twice. See the emit in each hello handler.
func (s *IsisServer) reportRestart(c *circuit, adj *adjacency, held, wasRestarting, wasSuppressed bool) bool {
	if adj.restartMode {
		// Every request, not just the first: a neighbor asking over and over
		// is what §3.2.1a bounds, and the rate is the only sign of it.
		s.metrics.RestartRequest(c.cfg.Name, restartOutcome(held))
	}
	switch {
	case adj.restartMode && !wasRestarting:
		s.logger.Info("neighbor restart request", "circuit", c.cfg.Name,
			"neighbor", adj.systemID, "levels", adj.levels, "held", held)
	case !adj.restartMode && wasRestarting:
		s.logger.Info("neighbor left restart mode", "circuit", c.cfg.Name,
			"neighbor", adj.systemID, "levels", adj.levels)
	}
	if adj.suppressed != wasSuppressed {
		s.logger.Info("neighbor adjacency suppression changed", "circuit", c.cfg.Name,
			"neighbor", adj.systemID, "levels", adj.levels, "suppressed", adj.suppressed)
	}
	return adj.restartMode != wasRestarting || adj.suppressed != wasSuppressed
}

// Outcomes reported through Metrics.RestartRequest.
const (
	restartHeld   = "held"   // §3.2.1's precondition covered the request
	restartUnheld = "unheld" // it did not, so the IIH was processed as normal
)

func restartOutcome(held bool) string {
	if held {
		return restartHeld
	}
	return restartUnheld
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
// §3.2.1a withholds the refresh from repeated restart requests. infoFor
// reports the same seconds to an operator for the same reason: during a hold
// the advertised holding time says nothing about when the adjacency dies. The restarter
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
