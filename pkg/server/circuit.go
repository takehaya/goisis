package server

import (
	"time"

	"github.com/takehaya/goisis/pkg/packet"
)

// circuit is the runtime state of one IS-IS circuit, owned by the Serve
// loop. Broadcast adjacencies live in adjs[level][systemID]; a p2p circuit
// keeps its single neighbor in p2pAdj.
type circuit struct {
	cfg          CircuitConfig
	pseudonodeID uint8  // nonzero, unique per box (broadcast pseudonode octet)
	extCircID    uint32 // our extended local circuit ID (p2p TLV 240)

	adjs   map[packet.Level]map[packet.SystemID]*adjacency
	p2pAdj *adjacency

	// dupSystemIDWarned suppresses repeats of the duplicate-system-ID warning:
	// hellos arrive every few seconds, so warning per PDU would turn one
	// misconfiguration into log amplification on the management loop.
	dupSystemIDWarned bool

	dis       map[packet.Level]packet.NodeID // elected DIS LAN ID per level
	nextHello time.Time

	// linkDown is set while the interface has no carrier (SetCircuitLinkState).
	// Hellos are suppressed and adjacencies are torn down at once, instead of
	// waiting out the neighbor's holding time.
	linkDown bool

	// Flooding flags per level (ISO 10589 7.3): srm[level][lspid] holds the
	// earliest time to (re)send that LSP on this circuit; ssn[level][lspid]
	// marks an LSP to report in the next PSNP. ssnAck holds the header to
	// report for an SSN entry the database has no copy of; it is a subset of
	// ssn. nextCSNP drives periodic CSNP transmission when this circuit is
	// the DIS.
	srm      map[packet.Level]map[packet.LSPID]time.Time
	ssn      map[packet.Level]map[packet.LSPID]bool
	ssnAck   map[packet.Level]map[packet.LSPID]packet.LSPEntry
	nextCSNP map[packet.Level]time.Time

	oversizeWarned bool // an LSP too large for this circuit was already logged
}

func newCircuit(cfg CircuitConfig, pseudonodeID uint8, extCircID uint32) *circuit {
	c := &circuit{
		cfg:          cfg,
		pseudonodeID: pseudonodeID,
		extCircID:    extCircID,
		adjs:         map[packet.Level]map[packet.SystemID]*adjacency{},
		dis:          map[packet.Level]packet.NodeID{},
		srm:          map[packet.Level]map[packet.LSPID]time.Time{},
		ssn:          map[packet.Level]map[packet.LSPID]bool{},
		ssnAck:       map[packet.Level]map[packet.LSPID]packet.LSPEntry{},
		nextCSNP:     map[packet.Level]time.Time{},
	}
	for _, l := range cfg.levels() {
		c.adjs[l] = map[packet.SystemID]*adjacency{}
		c.srm[l] = map[packet.LSPID]time.Time{}
		c.ssn[l] = map[packet.LSPID]bool{}
		c.ssnAck[l] = map[packet.LSPID]packet.LSPEntry{}
	}
	return c
}

// setSRM marks an LSP for transmission on this circuit at the given level.
func (c *circuit) setSRM(level packet.Level, id packet.LSPID, when time.Time) {
	if m := c.srm[level]; m != nil {
		m[id] = when
	}
}

// clearSRM stops retransmitting an LSP on this circuit.
func (c *circuit) clearSRM(level packet.Level, id packet.LSPID) {
	if m := c.srm[level]; m != nil {
		delete(m, id)
	}
}

// setSSN marks an LSP to be reported in the next PSNP on this circuit.
func (c *circuit) setSSN(level packet.Level, id packet.LSPID) {
	if m := c.ssn[level]; m != nil {
		m[id] = true
	}
}

// setSSNAck marks an LSP to be reported in the next PSNP with the given
// header verbatim, for an LSP the database does not hold and so cannot
// describe.
func (c *circuit) setSSNAck(level packet.Level, e packet.LSPEntry) {
	if m := c.ssnAck[level]; m != nil {
		m[e.LSPID] = e
		c.setSSN(level, e.LSPID)
	}
}

func (c *circuit) clearSSN(level packet.Level, id packet.LSPID) {
	if m := c.ssn[level]; m != nil {
		delete(m, id)
	}
	// ssnAck is a subset of ssn, so the two are always cleared together.
	if m := c.ssnAck[level]; m != nil {
		delete(m, id)
	}
}

// clearFlags drops every flooding flag on the circuit. Called when a p2p
// adjacency leaves Up: the flags describe what to send to a neighbor that is
// gone, and ISO 10589 7.3.17 re-arms them for the whole database when an
// adjacency comes Up, so nothing kept across a Down is of any use. LAN flags
// are not cleared on adjacency expiry: they are per circuit, not per neighbor,
// and the DIS's CSNPs govern them.
func (c *circuit) clearFlags() {
	for _, l := range c.cfg.levels() {
		clear(c.srm[l])
		clear(c.ssn[l])
		clear(c.ssnAck[l])
	}
}

// floodReady reports whether flooding may transmit on this circuit at a level.
// A p2p circuit needs an Up adjacency covering the level: an LSP or a PSNP
// sent without one reaches nobody, and retrying it every
// minLSPTransmissionInterval forever is pure waste. A LAN circuit is always
// ready (see clearFlags).
func (c *circuit) floodReady(level packet.Level) bool {
	if !c.cfg.P2P {
		return true
	}
	adj := c.p2pAdj
	return adj != nil && adj.state == AdjUp && adj.levels.has(level)
}

// isDIS reports whether we are the elected DIS at a level on this broadcast
// circuit.
func (c *circuit) isDIS(level packet.Level, self packet.SystemID) bool {
	return !c.cfg.P2P && c.dis[level].SystemID() == self && c.dis[level].PseudonodeID() != 0
}

// CircuitInfo is an exported snapshot of a circuit's configuration.
type CircuitInfo struct {
	Interface string
	P2P       bool
	Level1    bool
	Level2    bool
	Priority  uint8
	Metric    uint32
	LinkUp    bool
}

func (c *circuit) info() CircuitInfo {
	return CircuitInfo{
		Interface: c.cfg.Name,
		P2P:       c.cfg.P2P,
		Level1:    c.cfg.Level1,
		Level2:    c.cfg.Level2,
		Priority:  c.cfg.priority(),
		Metric:    c.cfg.Metric,
		LinkUp:    !c.linkDown,
	}
}

// adjacencyInfos returns snapshots of all adjacencies on the circuit.
func (c *circuit) adjacencyInfos() []AdjacencyInfo {
	var out []AdjacencyInfo
	if c.cfg.P2P {
		if c.p2pAdj != nil {
			for _, l := range c.p2pAdj.levels.levels() {
				out = append(out, c.infoFor(c.p2pAdj, l))
			}
		}
		return out
	}
	for _, l := range c.cfg.levels() {
		for _, adj := range c.adjs[l] {
			out = append(out, c.infoFor(adj, l))
		}
	}
	return out
}

func (c *circuit) infoFor(adj *adjacency, l packet.Level) AdjacencyInfo {
	return AdjacencyInfo{
		Interface: c.cfg.Name,
		Level:     l,
		SystemID:  adj.systemID,
		SNPA:      adj.snpa,
		State:     adj.state,
		Priority:  adj.priority,
		Holding:   adj.holding,
	}
}

// upAdjacencyFrom reports whether src is the SNPA of an adjacency that is Up
// at this level on the circuit. ISO 10589 7.3.15.1/7.3.15.2 accept an LSP or
// an SNP only from such a source: a station that never sent a hello must not
// be able to reach the update process.
func (c *circuit) upAdjacencyFrom(level packet.Level, src packet.SNPA) bool {
	if c.cfg.P2P {
		adj := c.p2pAdj
		return adj != nil && adj.state == AdjUp && adj.levels.has(level) && adj.snpa == src
	}
	for _, adj := range c.adjs[level] {
		if adj.snpa == src && adj.state == AdjUp {
			return true
		}
	}
	return false
}

// upAdjacencies returns the Up adjacencies at a level (broadcast).
func (c *circuit) upAdjacencies(l packet.Level) []*adjacency {
	var out []*adjacency
	for _, adj := range c.adjs[l] {
		if adj.state == AdjUp {
			out = append(out, adj)
		}
	}
	return out
}
