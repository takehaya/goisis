package server

import (
	"net/netip"
	"slices"
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

	// Neighbor interface addresses from its hellos (TLV 132 / 232), used to
	// resolve SPF next-hop gateways (IPv6 are link-local) and, when the peer
	// lists a global one, End.X SID next hops.
	neighborIPv4 []netip.Addr
	neighborIPv6 []netip.Addr

	// NLPIDs the neighbor routes (TLV 129, RFC 1195 3.1); nil when the hello
	// carried no such TLV.
	nlpids []byte
}

// setNeighborAddrs records the addresses a hello listed and reports whether
// they differ from the ones held. The set decides both the SPF next hop and
// whether an End.X SID can be advertised at all (see endXNexthop), so a change
// on an established adjacency has to re-run origination, not just sit in the
// table until the next unrelated event.
func (a *adjacency) setNeighborAddrs(v4, v6 []netip.Addr) bool {
	changed := !slices.Equal(a.neighborIPv4, v4) || !slices.Equal(a.neighborIPv6, v6)
	a.neighborIPv4, a.neighborIPv6 = v4, v6
	return changed
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
	// Hostname is the neighbor's dynamic hostname (TLV 137) as advertised in
	// its LSP, empty until that LSP arrives or when it carries no name. It is
	// resolved by ListAdjacencies and by a subscription's Initial snapshot;
	// live watch events leave it empty, since resolving it costs a pass over
	// the database for every adjacency change.
	Hostname string
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
