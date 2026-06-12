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

	dis       map[packet.Level]packet.NodeID // elected DIS LAN ID per level
	nextHello time.Time

	// Flooding flags per level (ISO 10589 7.3): srm[level][lspid] holds the
	// earliest time to (re)send that LSP on this circuit; ssn[level][lspid]
	// marks an LSP to report in the next PSNP. nextCSNP drives periodic
	// CSNP transmission when this circuit is the DIS.
	srm      map[packet.Level]map[packet.LSPID]time.Time
	ssn      map[packet.Level]map[packet.LSPID]bool
	nextCSNP map[packet.Level]time.Time
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
		nextCSNP:     map[packet.Level]time.Time{},
	}
	for _, l := range cfg.levels() {
		c.adjs[l] = map[packet.SystemID]*adjacency{}
		c.srm[l] = map[packet.LSPID]time.Time{}
		c.ssn[l] = map[packet.LSPID]bool{}
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

func (c *circuit) clearSSN(level packet.Level, id packet.LSPID) {
	if m := c.ssn[level]; m != nil {
		delete(m, id)
	}
}

// isDIS reports whether we are the elected DIS at a level on this broadcast
// circuit.
func (c *circuit) isDIS(level packet.Level, self packet.SystemID) bool {
	return !c.cfg.P2P && c.dis[level].SystemID() == self && c.dis[level].PseudonodeID() != 0
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
