package server

import (
	"time"

	"github.com/takehaya/goisis/pkg/packet"
)

// AdjState is the state of an IS-IS adjacency.
type AdjState int

// Adjacency states (ISO 10589 / RFC 5303 three-way).
const (
	AdjDown AdjState = iota
	AdjInit
	AdjUp
)

func (s AdjState) String() string {
	switch s {
	case AdjDown:
		return "Down"
	case AdjInit:
		return "Init"
	case AdjUp:
		return "Up"
	default:
		return "Unknown"
	}
}

// adjacency tracks one neighbor on a circuit. For broadcast circuits there
// is one adjacency per (level, neighbor); for p2p there is a single
// adjacency spanning the common levels. It is owned by the Serve loop.
type adjacency struct {
	systemID  packet.SystemID
	snpa      packet.SNPA
	state     AdjState
	priority  uint8 // neighbor's DIS priority (broadcast)
	areaAddrs []packet.AreaAddress
	lanID     packet.NodeID // neighbor's advertised LAN ID (broadcast)
	holding   uint16        // neighbor's advertised holding time (seconds)
	lastHeard time.Time

	// p2p three-way (RFC 5303): the neighbor's extended local circuit ID.
	neighborExtCircID uint32
	levels            levelSet
}

// AdjacencyInfo is an exported snapshot of an adjacency.
type AdjacencyInfo struct {
	Interface string
	Level     packet.Level
	SystemID  packet.SystemID
	SNPA      packet.SNPA
	State     AdjState
	Priority  uint8
	Holding   uint16
}

// levelSet is a small set of levels.
type levelSet uint8

func (s *levelSet) add(l packet.Level)     { *s |= 1 << l }
func (s levelSet) has(l packet.Level) bool { return s&(1<<l) != 0 }
func (s levelSet) levels() []packet.Level {
	var out []packet.Level
	if s.has(packet.Level1) {
		out = append(out, packet.Level1)
	}
	if s.has(packet.Level2) {
		out = append(out, packet.Level2)
	}
	return out
}
