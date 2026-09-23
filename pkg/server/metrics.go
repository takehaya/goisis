package server

import (
	"context"
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
	// with the reason: "decode", "auth", "link_down", "no_adjacency",
	// "checksum", "lsdb_limit", "adjacency_limit", "hello_invalid",
	// "hello_mismatch", "duplicate_system_id", "unknown_purge",
	// "own_sysid_purge", "own_fragment_purge", "own_lsp_reclaimed" or
	// "own_seq_wrap".
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
	// PDUTxError records one PDU that never reached the wire on a circuit,
	// by the step that failed: "serialize", "auth" or "send". Hellos, SNPs
	// and flooded LSPs share this counter — to an operator they are one
	// fault, "this circuit cannot transmit". Unlike FloodDrop, which reports
	// an LSP that can never be sent on that circuit, these are transient and
	// retried on the next tick, so the rate is what matters.
	PDUTxError(circuit, reason string)
	// PDURxError records one failed receive on a circuit. The reader retries
	// rather than returning, so what is lost is frames, not the circuit; the
	// log is edge-triggered per outage, which leaves this the only sign of a
	// socket that keeps failing.
	PDURxError(circuit string)
	// ConfigReload records one configuration reload by how it ended:
	// "applied", "refused" (nothing changed) or "partial". The three are
	// different operational events — only "partial" leaves the node in
	// neither configuration — so an alert on "is this daemon running its
	// configuration file" needs them apart. The reload runs off a signal,
	// outside the management goroutine; see ReportConfigReload.
	ConfigReload(outcome string)
	// LSPLifetimeFloored records one received LSP whose remaining lifetime the
	// RFC 7987 floor raised to MaxAge, on the circuit it arrived on. The floor
	// is what removed the symptom a corrupted lifetime used to produce (a
	// premature purge, and the originator's re-origination behind it), so this
	// is the only remaining sign of the field being rewritten in flight. A
	// single event is normal — a re-flood from a mid-area node carries an aged
	// value — so what diagnoses a link is the rate on one circuit against its
	// neighbors, which is why this is counted rather than logged.
	LSPLifetimeFloored(circuit string)
	// InterLevelPrefixes reports the number of prefixes this node originates
	// because of the level boundary, by direction: "l2_to_l1" is the leak and
	// "l1_to_l2" the upward export. RouteCount is what this node learned;
	// these are what it injects, which is the number a policy edit moves.
	// Every direction reports on every recompute, so a node that stops leaking
	// reports 0 instead of leaving a stale gauge behind.
	InterLevelPrefixes(direction string, n int)
}

// ReloadOutcome is how a configuration reload ended, as reported through
// Metrics.ConfigReload.
type ReloadOutcome string

// The outcomes of a configuration reload. The set is closed, so the label
// stays constant-derived and its cardinality is three.
const (
	ReloadApplied ReloadOutcome = "applied" // the file is what the node runs
	ReloadRefused ReloadOutcome = "refused" // rejected before anything changed
	ReloadPartial ReloadOutcome = "partial" // some calls landed, one was refused
)

// Directions reported through Metrics.InterLevelPrefixes.
const (
	dirL2ToL1 = "l2_to_l1" // leaked down, up/down bit set (RFC 5305 4.1)
	dirL1ToL2 = "l1_to_l2" // exported up (ISO 10589 7.2.9 / RFC 1195 3.1)
)

// ReportConfigReload records the outcome of a configuration reload. A reload
// is driven by a signal, from a goroutine that is not the management loop, and
// Metrics is called only from that loop — so the report is routed onto it the
// same way a reader goroutine's receive failure is, rather than written to the
// sink where it happened.
func (s *IsisServer) ReportConfigReload(ctx context.Context, outcome ReloadOutcome) error {
	return s.mgmtOperation(ctx, func() error {
		s.metrics.ConfigReload(string(outcome))
		return nil
	})
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
	dropAdjacencyLimit   = "adjacency_limit"    // a hello from a new neighbor on a circuit at its adjacency limit
	dropLinkDown         = "link_down"          // a frame that raced the circuit's link going down
	// The adjacency state machine refuses a hello for one of three kinds of
	// reason, and reports the kind rather than the branch: an operator asking
	// "why is this adjacency not coming up" needs to know whether the hello
	// was unusable, whether it described a network we are not part of, or
	// whether it was our own, and a label per branch would only cost
	// cardinality. The branch itself is in the Debug log (see dropHello).
	dropHelloInvalid      = "hello_invalid"       // wrong circuit type, zero holding time, or a level this circuit does not run
	dropHelloMismatch     = "hello_mismatch"      // no common area (ISO 10589 8.4.2) or no common level
	dropDuplicateSystemID = "duplicate_system_id" // a hello carrying our own System ID
)

// Steps reported through Metrics.PDUTxError: where a PDU stopped on its way to
// the wire.
const (
	txErrSerialize = "serialize"
	txErrAuth      = "auth"
	txErrSend      = "send"
)

// txErrReasons is every reason above, for re-arming the transmit-failure log
// once a PDU goes out (see txSucceeded).
var txErrReasons = [...]string{txErrSerialize, txErrAuth, txErrSend}

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

// PDUTxError implements Metrics.
func (NoopMetrics) PDUTxError(string, string) {}

// PDURxError implements Metrics.
func (NoopMetrics) PDURxError(string) {}

// ConfigReload implements Metrics.
func (NoopMetrics) ConfigReload(string) {}

// LSPLifetimeFloored implements Metrics.
func (NoopMetrics) LSPLifetimeFloored(string) {}

// InterLevelPrefixes implements Metrics.
func (NoopMetrics) InterLevelPrefixes(string, int) {}

// txFailKey identifies one kind of transmit failure on one circuit. The key is
// (circuit, step) and not the PDU: what fails is the circuit's socket or its
// authentication configuration, not one hello or one LSP, so keying per PDU
// would put back the log amplification the edge log exists to stop.
type txFailKey struct {
	circuit string
	reason  string
}

// txFailed counts one PDU that never reached the wire and logs the edge of
// that failure. Every send path runs off a timer, so without the edge log one
// dead socket writes a line per PDU per tick for as long as it stays dead.
func (s *IsisServer) txFailed(c *circuit, reason string, err error, args ...any) {
	s.metrics.PDUTxError(c.cfg.Name, reason)
	s.txFailWarned.warn(txFailKey{circuit: c.cfg.Name, reason: reason}, func() {
		s.logger.Error("circuit cannot transmit; suppressing repeats",
			append([]any{"circuit", c.cfg.Name, "step", reason, "error", err}, args...)...)
	})
}

// txSucceeded re-arms the transmit-failure log for a circuit that has just put
// a PDU on the wire: whatever failed before is over, so the next failure is
// news again.
func (s *IsisServer) txSucceeded(c *circuit) {
	for _, reason := range txErrReasons {
		s.txFailWarned.clear(txFailKey{circuit: c.cfg.Name, reason: reason})
	}
}

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
