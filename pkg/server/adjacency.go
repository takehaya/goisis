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
	// syncSince is when the most recent LSP database exchange over this
	// adjacency began, and is read only while it is Up — the update process
	// reaches it through adjacencyGate, which admits nothing else. RFC 7987
	// §3.2 gates its corrupt-lifetime report on it; see corruptLifetime for
	// why that is this field and not the instant the adjacency came Up.
	//
	// It is never cleared. Nothing marks an exchange finished, and
	// corruptLifetime reads the field's age as the proxy for that exchange
	// having finished, so on a settled adjacency it is hours old and no
	// exchange is running. A clear-on-complete would break the filter: at the
	// zero value every arriving LSP would read as an exchange that finished in
	// 1 AD, which is the false positive the field exists to stop.
	//
	// upSince and syncSpent are what bound how much of the report a neighbor
	// can suppress. upSince is the transition into Up — the one instant of the
	// three a neighbor cannot move, which is what makes it the thing a budget
	// can be measured against — and syncSpent is how much suppression the
	// exchanges since then have added, against maxSyncSuppression. See
	// openSyncWindow.
	syncSince time.Time
	upSince   time.Time
	syncSpent time.Duration

	// Graceful restart (RFC 5306), all three fields fed by noteRestart from
	// every IIH that carries a Restart TLV.
	//
	// restartCapable says the neighbor's IIHs carry the TLV at all, which is
	// what puts it in §3.2.1c's candidate set. restartMode is set by the first
	// IIH with RR set and cleared by one with RR clear; it decides whether this
	// IIH may refresh the holding time (§3.2.1a) and keeps a neighbor that is
	// itself restarting out of that candidate set. suppressed is the SA bit
	// (§3.2.2): the adjacency stays out of our LSPs and out of SPF until an IIH
	// with SA clear arrives. It rides on the adjacency and so survives a
	// Down-to-Up transition, as §3.2.2 requires; an adjacency torn all the way
	// down and rebuilt is rebuilt from an IIH that carries the bit again.
	restartCapable bool
	restartMode    bool
	suppressed     bool

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
	// Restarting and Suppressed are what RFC 5306 says about an adjacency that
	// State cannot: an adjacency the helper holds through a neighbor's restart
	// reads Up precisely because nothing happened to it, and a suppressed one
	// is Up while carrying nothing — it is out of this node's LSPs and out of
	// SPF (§3.2.2), so the adjacency count and the topology disagree by
	// exactly these. Without them an operator has no way to tell a neighbor
	// restarting gracefully from one that is broken.
	Restarting bool
	Suppressed bool
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

// String renders the set for a log line. slog takes a []packet.Level for a
// byte slice — the element type's kind is uint8 — and quotes it as raw bytes,
// so the set is logged as itself rather than as what levels() returns.
func (s levelSet) String() string {
	switch {
	case s.has(packet.Level1) && s.has(packet.Level2):
		return "L1L2"
	case s.has(packet.Level1):
		return "L1"
	case s.has(packet.Level2):
		return "L2"
	}
	return "-"
}

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
