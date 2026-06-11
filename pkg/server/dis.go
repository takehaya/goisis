package server

import (
	"bytes"

	"github.com/takehaya/goisis/pkg/packet"
)

// electDIS recomputes the Designated Intermediate System for a broadcast
// circuit level and records the DIS LAN ID to advertise. Election is by
// highest priority, then highest SNPA; it is preemptive with no backup
// (ISO 10589 8.4.5).
func (s *IsisServer) electDIS(c *circuit, level packet.Level) {
	if c.cfg.P2P {
		return
	}

	// Start with ourselves as the candidate.
	bestPriority := c.cfg.priority()
	bestSNPA := c.cfg.Transport.LocalSNPA()
	weAreDIS := true

	for _, adj := range c.upAdjacencies(level) {
		if higherCandidate(adj.priority, adj.snpa, bestPriority, bestSNPA) {
			bestPriority, bestSNPA = adj.priority, adj.snpa
			weAreDIS = false
		}
	}

	prev := c.dis[level]
	if weAreDIS {
		// LAN ID = our system ID + our nonzero pseudonode octet.
		c.dis[level] = nodeID(s.systemID, c.pseudonodeID)
	} else if lan := winningLANID(c, level, bestSNPA); lan != (packet.NodeID{}) {
		// Use the winner's advertised LAN ID, learned from its hellos.
		// If the winner has not advertised a LAN ID yet, keep the previous
		// value rather than flapping to zero.
		c.dis[level] = lan
	}
	if c.dis[level] != prev {
		s.logger.Info("DIS change", "circuit", c.cfg.Name, "level", level,
			"dis", c.dis[level], "self", weAreDIS)
	}
}

// higherCandidate reports whether (p1,s1) beats (p2,s2): higher priority
// wins, ties break on higher SNPA.
func higherCandidate(p1 uint8, s1 packet.SNPA, p2 uint8, s2 packet.SNPA) bool {
	if p1 != p2 {
		return p1 > p2
	}
	return bytes.Compare(s1[:], s2[:]) > 0
}

// winningLANID returns the LAN ID advertised by the Up adjacency with the
// given SNPA, or zero if not yet known.
func winningLANID(c *circuit, level packet.Level, snpa packet.SNPA) packet.NodeID {
	for _, adj := range c.adjs[level] {
		if adj.snpa == snpa && adj.state == AdjUp {
			return adj.lanID
		}
	}
	return packet.NodeID{}
}

// nodeID builds a NodeID from a system ID and pseudonode octet.
func nodeID(id packet.SystemID, pseudonode uint8) packet.NodeID {
	var n packet.NodeID
	copy(n[:6], id[:])
	n[6] = pseudonode
	return n
}
