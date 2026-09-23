package server

import (
	"fmt"
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

// The key the authenticated flavour of the fuzzer runs with. SHA-256 rather
// than MD5 on purpose: the RFC 5310 Authentication TLV carries a key ID, so
// authDigestRange's length and key-ID arithmetic — the part a hostile TLV
// offset attacks — is only reached by the SHA family (RFC 5304's MD5 value is
// a bare digest).
var fuzzAuthSpec = authSpec{algo: packet.AuthSHA256, keyID: 7, key: []byte("fuzz")}

// rxFuzzServer returns a fresh server with one dual-level circuit and an Up
// adjacency from fuzzSrcMAC. Serve is deliberately not started: handleRx then
// runs on the calling goroutine, which stays the single mutator of protocol
// state. A fresh server per iteration keeps iterations independent, so a
// crasher reproduces from its input alone. keyed configures the same HMAC key
// for hellos and for both levels' LSPs/SNPs, so every receive path runs its
// verification instead of returning at !spec.on().
func rxFuzzServer(t *testing.T, p2p, keyed bool) (*IsisServer, *circuit) {
	t.Helper()
	cfg := CircuitConfig{
		Name: "c", Transport: datalink.NewMockTransport(fuzzLocalMAC, 1500),
		P2P: p2p, Level1: true, Level2: true, Padding: ptrFalse(),
	}
	opts := []ServerOption{
		WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
		WithSystemID(fuzzSelfID),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
	}
	if keyed {
		auth := AuthConfig{Algorithm: fuzzAuthSpec.algo, KeyID: fuzzAuthSpec.keyID, Secret: string(fuzzAuthSpec.key)}
		cfg.HelloPassword = auth.Secret
		cfg.HelloAuthAlgorithm = auth.Algorithm
		cfg.HelloKeyID = auth.KeyID
		opts = append(opts, WithAreaAuth(auth), WithDomainAuth(auth))
	}
	s := mustServer(t, append(opts, WithCircuit(cfg))...)
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
		// and an unauthenticated scope returns from pduAuthOK/helloAuthOK
		// before authSpec.verify runs at all, so each input drives all four
		// combinations.
		for _, p2p := range []bool{false, true} {
			for _, keyed := range []bool{false, true} {
				s, c := rxFuzzServer(t, p2p, keyed)
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
					infos := s.dbs[l].snapshot(now, hostnames)
					renderTLVs(infos)
					for _, info := range infos {
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
		}
	})
}

// rxFuzzSeeds are hand-built PDUs covering shapes the FRR corpus lacks: they
// reach the corners of the update process that only a hostile peer produces.
// Each carries a valid digest for fuzzAuthSpec, so the mutator starts from
// inputs the keyed flavour accepts and reaches the update process through
// authentication rather than being dropped by it; the unauthenticated flavour
// simply ignores the extra TLV.
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
		wire, err := signSeed(p)
		if err != nil {
			f.Fatalf("seed %T: %v", p, err)
		}
		// A seed that does not verify would be dropped by the keyed flavour
		// before reaching anything, and the extra flavour would silently cover
		// nothing but the drop path.
		_, isLSP := p.(*packet.LSP)
		if !fuzzAuthSpec.verify(wire, packet.HeaderLen(p.PDUType()), isLSP) {
			f.Fatalf("seed %T does not carry a valid digest", p)
		}
		out = append(out, wire)
	}
	return out
}

// signSeed appends the Authentication TLV placeholder fuzzAuthSpec expects,
// serializes the PDU and fills the digest. An LSP goes through
// FinalizeLSPAuth, which also repairs the Fletcher checksum the digest is
// covered by.
func signSeed(p packet.PDU) ([]byte, error) {
	switch v := p.(type) {
	case *packet.LSP:
		v.TLVs = append(v.TLVs, authTLVPlaceholder(fuzzAuthSpec))
	case *packet.CSNP:
		v.TLVs = append(v.TLVs, authTLVPlaceholder(fuzzAuthSpec))
	case *packet.LANHello:
		v.TLVs = append(v.TLVs, authTLVPlaceholder(fuzzAuthSpec))
	default:
		return nil, fmt.Errorf("no auth TLV appender for %T", p)
	}
	wire, err := p.Serialize()
	if err != nil {
		return nil, fmt.Errorf("serialize: %w", err)
	}
	if _, isLSP := p.(*packet.LSP); isLSP {
		err = packet.FinalizeLSPAuth(wire, fuzzAuthSpec.algo, fuzzAuthSpec.keyID, fuzzAuthSpec.key)
	} else {
		err = packet.PatchAuth(wire, packet.HeaderLen(p.PDUType()), fuzzAuthSpec.algo, fuzzAuthSpec.keyID, fuzzAuthSpec.key, false)
	}
	if err != nil {
		return nil, fmt.Errorf("patch auth: %w", err)
	}
	return wire, nil
}
