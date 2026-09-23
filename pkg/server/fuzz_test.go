package server

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/takehaya/goisis/pkg/datalink"
	"github.com/takehaya/goisis/pkg/packet"
)

// Identities the receive fuzzer drives. Frames arrive from fuzzSrcMAC, which
// the pre-built Up adjacency owns, so the adjacency gate (ISO 10589 7.3.15.1)
// admits LSPs and SNPs and the fuzzer reaches the update process instead of
// stopping at the gate.
var (
	fuzzSelfID   = packet.SystemID{0, 0, 0, 0, 0, 1}
	fuzzPeerID   = packet.SystemID{0, 0, 0, 0, 0, 2}
	fuzzLocalMAC = packet.SNPA{0x02, 0, 0, 0, 0, 0x01}
	fuzzSrcMAC   = packet.SNPA{0x02, 0, 0, 0, 0, 0x02}
)

// rxFuzzServer returns a fresh server with one dual-level circuit and an Up
// adjacency from fuzzSrcMAC. Serve is deliberately not started: handleRx then
// runs on the calling goroutine, which stays the single mutator of protocol
// state. A fresh server per iteration keeps iterations independent, so a
// crasher reproduces from its input alone.
func rxFuzzServer(t *testing.T, p2p bool) (*IsisServer, *circuit) {
	t.Helper()
	s := mustServer(t,
		WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
		WithSystemID(fuzzSelfID),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(CircuitConfig{
			Name: "c", Transport: datalink.NewMockTransport(fuzzLocalMAC, 1500),
			P2P: p2p, Level1: true, Level2: true, Padding: ptrFalse(),
		}),
	)
	c := s.circuits[0]
	var both levelSet
	both.add(packet.Level1)
	both.add(packet.Level2)
	if p2p {
		c.p2pAdj = &adjacency{systemID: fuzzPeerID, snpa: fuzzSrcMAC, state: AdjUp, levels: both}
	} else {
		for _, l := range c.cfg.levels() {
			c.adjs[l][fuzzPeerID] = &adjacency{systemID: fuzzPeerID, snpa: fuzzSrcMAC, state: AdjUp, levels: both}
		}
	}
	// Our own LSPs are the SPF root: without them computeSPF returns at its
	// first check and updateRIB below would exercise nothing.
	s.regenerateLSPs(false, time.Now())
	return s, c
}

// FuzzHandleRx drives the receive state machine — decode, authentication, the
// hello FSM, and the update process (processLSP/processCSNP/processPSNP) —
// with arbitrary bytes, then runs the transmit and SPF passes those mutations
// feed. The contract is no panic: the management loop is a single goroutine,
// so one hostile PDU that panics takes the daemon down.
func FuzzHandleRx(f *testing.F) {
	// The FRR golden PDUs are real, well-formed inputs of every type — the
	// best starting point for the mutator.
	matches, _ := filepath.Glob("../packet/testdata/frr_pdu_*.bin")
	for _, path := range matches {
		if b, err := os.ReadFile(path); err == nil {
			f.Add(b)
		}
	}
	for _, seed := range rxFuzzSeeds(f) {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// Broadcast and p2p take different branches in nearly every handler,
		// so each input drives both.
		for _, p2p := range []bool{false, true} {
			s, c := rxFuzzServer(t, p2p)
			s.handleRx(c, datalink.Frame{PDU: data, Src: fuzzSrcMAC})
			now := time.Now()
			s.floodTransmit(now)
			s.updateRIB(now)
			// The management API renders the LSDB into proto3 string fields,
			// which must hold valid UTF-8: a peer-supplied hostname that does
			// not would break GetLsdb for every operator, not just for the
			// PDU that carried it.
			hostnames := s.hostnameIndex(now)
			for _, l := range []packet.Level{packet.Level1, packet.Level2} {
				for _, info := range s.dbs[l].snapshot(now, hostnames) {
					if !utf8.ValidString(info.Hostname) {
						t.Fatalf("LSP %s hostname %q is not valid UTF-8", info.LSPID, info.Hostname)
					}
					for _, line := range info.TLVs {
						if !utf8.ValidString(line) {
							t.Fatalf("LSP %s TLV line %q is not valid UTF-8", info.LSPID, line)
						}
					}
				}
			}
		}
	})
}

// rxFuzzSeeds are hand-built PDUs covering shapes the FRR corpus lacks: they
// reach the corners of the update process that only a hostile peer produces.
func rxFuzzSeeds(f *testing.F) [][]byte {
	f.Helper()
	var maxID packet.LSPID
	for i := range maxID {
		maxID[i] = 0xff
	}
	pdus := []packet.PDU{
		// Our own System ID on a pseudonode we cannot own: the purge path.
		&packet.LSP{Level: packet.Level2, RemainingTime: 1000, ISType: 2,
			LSPID: lspID(fuzzSelfID, 0x7f), SequenceNumber: 4},
		// A purge for an LSP ID we do not hold.
		&packet.LSP{Level: packet.Level2, RemainingTime: 0, ISType: 2,
			LSPID: lspID(fuzzPeerID, 0), SequenceNumber: 9},
		// A hostname (TLV 137) whose octets are not valid UTF-8: it reaches
		// the operator-facing snapshot the body checks above.
		&packet.LSP{Level: packet.Level2, RemainingTime: 1000, ISType: 2,
			LSPID: lspID(fuzzPeerID, 0), SequenceNumber: 5,
			TLVs: []packet.TLV{&packet.DynamicHostnameTLV{Hostname: "\xff\xfe"}}},
		// A CSNP with Start > End: no LSP ID can fall inside the range.
		&packet.CSNP{Level: packet.Level2, SourceID: nodeID(fuzzPeerID, 0),
			StartLSP: maxID, EndLSP: packet.LSPID{}},
		// A hello echoing our SNPA, which drives the adjacency to Up and with
		// it DIS election and LSP re-origination.
		&packet.LANHello{Level: packet.Level2, CircuitType: packet.CircuitTypeLevel12,
			SourceID: fuzzPeerID, HoldingTime: 30, Priority: 64, LANID: nodeID(fuzzPeerID, 1),
			TLVs: []packet.TLV{&packet.ISNeighborsTLV{Neighbors: []packet.SNPA{fuzzLocalMAC}}}},
	}
	out := make([][]byte, 0, len(pdus))
	for _, p := range pdus {
		wire, err := p.Serialize()
		if err != nil {
			f.Fatalf("serialize seed %T: %v", p, err)
		}
		out = append(out, wire)
	}
	return out
}
