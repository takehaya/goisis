package server

import (
	"time"

	"github.com/takehaya/goisis/pkg/packet"
)

// Metrics receives observability events from the IS-IS instance. The server
// calls every method from its single management goroutine, so the write side
// needs no synchronization; only concurrent reads (a scraper on another
// goroutine) must be synchronized, which Prometheus collectors already are.
// The default is NoopMetrics; the daemon wires a Prometheus implementation
// (see pkg/metrics) and library consumers can supply their own telemetry sink.
// Implementations can embed NoopMetrics to stay forward-compatible when
// methods are added to this interface.
type Metrics interface {
	// AdjacencyTransition records an adjacency entering a new state ("Up",
	// "Init", "Down") on a circuit at a level ("L1"/"L2").
	AdjacencyTransition(circuit, level, state string)
	// SPFRun records one shortest-path computation for a level and its duration.
	SPFRun(level string, d time.Duration)
	// LSDBSize reports the current number of LSPs held for a level.
	LSDBSize(level string, n int)
	// FloodTx records one LSP transmitted (flooded) on a circuit.
	FloodTx(circuit string)
	// FloodDrop records one LSP that could not be flooded on a circuit, with
	// the reason: "oversize". Unlike a transient send error this is permanent
	// for that LSP on that circuit — the neighbor keeps requesting it and its
	// database stays short of it — so it is counted rather than only logged.
	FloodDrop(circuit, reason string)
	// FIBPending reports the number of routes whose last FIB write failed and
	// are awaiting retry.
	FIBPending(n int)
	// PDURx records one PDU received on a circuit and successfully decoded.
	// pduType is a short label: "lan_hello_l1", "lan_hello_l2", "p2p_hello",
	// "lsp", "csnp" or "psnp".
	PDURx(circuit, pduType string)
	// PDUDrop records one received PDU that was not installed as it arrived,
	// with the reason: "decode", "auth", "no_adjacency", "checksum",
	// "lsdb_limit", "unknown_purge", "own_sysid_purge", "own_fragment_purge",
	// "own_lsp_reclaimed" or "own_seq_wrap".
	//
	// The four "own_*" reasons are handled rather than discarded: the PDU
	// carried this node's own System ID, so it drove a re-origination or a
	// purge instead of being entered as received. They occur in normal
	// operation (a restart with a stale copy of ours still in the area, a DIS
	// handover), so an alert on the drop rate should exclude them and watch
	// them separately — a steady own_lsp_reclaimed, own_fragment_purge or
	// own_seq_wrap means someone else is originating LSPs in our name.
	PDUDrop(circuit, reason string)
	// AdjacencyCount reports the number of Up adjacencies on a circuit at a
	// level. Every configured circuit and level reports on every housekeeping
	// tick, so a circuit that loses its last neighbor reports 0 instead of
	// leaving a stale value behind.
	AdjacencyCount(circuit, level string, n int)
	// RouteCount reports the number of RIB routes for a level and routing
	// algorithm (decimal; "0" is plain reachability).
	RouteCount(level, algo string, n int)
	// FIBError records one failed FIB write, by operation: "update",
	// "withdraw", "add_sid" or "remove_sid".
	FIBError(op string)
	// EventQueueDepth reports the number of received frames waiting to be
	// handled by the management loop.
	EventQueueDepth(n int)
}

// Reasons reported through Metrics.PDUDrop, one per point at which a received
// PDU is discarded.
const (
	dropDecode           = "decode"
	dropAuth             = "auth"
	dropNoAdjacency      = "no_adjacency"
	dropChecksum         = "checksum"
	dropLSDBLimit        = "lsdb_limit"
	dropUnknownPurge     = "unknown_purge"
	dropOwnSysIDPurge    = "own_sysid_purge"
	dropOwnFragmentPurge = "own_fragment_purge" // a fragment of our node LSP we never originated
	dropOwnLSPReclaimed  = "own_lsp_reclaimed"  // a copy of an LSP we originate, superseded by re-origination
	dropOwnSeqWrap       = "own_seq_wrap"       // a copy of one of ours at the maximum sequence number (ISO 10589 7.3.16.1)
)

// Reasons reported through Metrics.FloodDrop.
const (
	floodDropOversize = "oversize" // larger than this circuit's MTU (ISO 10589 7.3.3)
)

// Operations reported through Metrics.FIBError.
const (
	fibOpUpdate    = "update"
	fibOpWithdraw  = "withdraw"
	fibOpAddSID    = "add_sid"
	fibOpRemoveSID = "remove_sid"
)

// NoopMetrics discards every event. It is the default when no Metrics sink is
// configured.
type NoopMetrics struct{}

// AdjacencyTransition implements Metrics.
func (NoopMetrics) AdjacencyTransition(string, string, string) {}

// SPFRun implements Metrics.
func (NoopMetrics) SPFRun(string, time.Duration) {}

// LSDBSize implements Metrics.
func (NoopMetrics) LSDBSize(string, int) {}

// FloodTx implements Metrics.
func (NoopMetrics) FloodTx(string) {}

// FloodDrop implements Metrics.
func (NoopMetrics) FloodDrop(string, string) {}

// FIBPending implements Metrics.
func (NoopMetrics) FIBPending(int) {}

// PDURx implements Metrics.
func (NoopMetrics) PDURx(string, string) {}

// PDUDrop implements Metrics.
func (NoopMetrics) PDUDrop(string, string) {}

// AdjacencyCount implements Metrics.
func (NoopMetrics) AdjacencyCount(string, string, int) {}

// RouteCount implements Metrics.
func (NoopMetrics) RouteCount(string, string, int) {}

// FIBError implements Metrics.
func (NoopMetrics) FIBError(string) {}

// EventQueueDepth implements Metrics.
func (NoopMetrics) EventQueueDepth(int) {}

// levelLabel renders a level as a short metric label.
func levelLabel(l packet.Level) string {
	switch l {
	case packet.Level1:
		return "L1"
	case packet.Level2:
		return "L2"
	default:
		return "?"
	}
}

// pduLabel renders a PDU type as a short metric label. LSPs and SNPs collapse
// their level: the receive counter is already per circuit, and splitting it by
// level as well would double its cardinality without telling an operator
// anything the LSDB gauges do not.
func pduLabel(t packet.PDUType) string {
	switch t {
	case packet.PDUTypeL1LANHello:
		return "lan_hello_l1"
	case packet.PDUTypeL2LANHello:
		return "lan_hello_l2"
	case packet.PDUTypeP2PHello:
		return "p2p_hello"
	case packet.PDUTypeL1LSP, packet.PDUTypeL2LSP:
		return "lsp"
	case packet.PDUTypeL1CSNP, packet.PDUTypeL2CSNP:
		return "csnp"
	case packet.PDUTypeL1PSNP, packet.PDUTypeL2PSNP:
		return "psnp"
	default:
		return "?"
	}
}
