package server

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/takehaya/goisis/pkg/datalink"
	"github.com/takehaya/goisis/pkg/packet"
)

func ownFragments(s *IsisServer) map[uint8]*lspEntry {
	out := map[uint8]*lspEntry{}
	for id, e := range s.dbs[packet.Level2].entries {
		nid := id.NodeID()
		if nid.SystemID() == s.systemID && nid.PseudonodeID() == 0 && e.own && e.purgedAt.IsZero() {
			out[id.FragmentID()] = e
		}
	}
	return out
}

// TestOriginationFragmentsLargeNodeLSP: a node with more reachability than fits
// one LSP splits across fragments 0..N. Every prefix is advertised, each
// fragment fits the architectural buffer, and fragment 0 carries the fixed TLVs.
func TestOriginationFragmentsLargeNodeLSP(t *testing.T) {
	const n = 400 // ~9 octets/entry, far past one 1492-octet LSP
	opts := []ServerOption{
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(CircuitConfig{Name: "c", Transport: datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 1}, 1500), Level2: true, Padding: ptrFalse()}),
	}
	want := map[netip.Prefix]bool{}
	for i := 0; i < n; i++ {
		p := netip.MustParsePrefix(fmt.Sprintf("10.%d.%d.1/32", i/256, i%256))
		want[p] = true
		opts = append(opts, WithAdvertisedPrefix(p, 10))
	}
	s := mustServer(t, opts...)
	s.regenerateNodeLSP(packet.Level2, false, time.Now())

	frags := ownFragments(s)
	if len(frags) < 2 {
		t.Fatalf("expected the node LSP to span >=2 fragments, got %d", len(frags))
	}
	if _, ok := frags[0]; !ok {
		t.Fatal("fragment 0 missing")
	}
	// Fragment 0 carries the fixed area-addresses TLV; higher fragments must not.
	if !hasTLV[*packet.AreaAddressesTLV](frags[0]) {
		t.Error("fragment 0 lacks the AreaAddresses TLV")
	}
	got := map[netip.Prefix]bool{}
	for num, e := range frags {
		raw, err := e.lsp.Serialize()
		if err != nil {
			t.Fatalf("fragment %d serialize: %v", num, err)
		}
		if len(raw) > packet.ReceiveLSPBufferSize {
			t.Errorf("fragment %d is %d octets, over the %d buffer", num, len(raw), packet.ReceiveLSPBufferSize)
		}
		if num != 0 && hasTLV[*packet.AreaAddressesTLV](e) {
			t.Errorf("fragment %d should not carry fixed TLVs", num)
		}
		for _, tlv := range e.lsp.TLVs {
			if r, ok := tlv.(*packet.ExtendedIPReachabilityTLV); ok {
				for _, ent := range r.Prefixes {
					got[ent.Prefix] = true
				}
			}
		}
	}
	if len(got) != n {
		t.Errorf("advertised %d/%d prefixes across fragments", len(got), n)
	}
}

func hasTLV[T packet.TLV](e *lspEntry) bool {
	for _, tlv := range e.lsp.TLVs {
		if _, ok := tlv.(T); ok {
			return true
		}
	}
	return false
}

// TestSPFAggregatesAcrossFragments: a peer that splits its reachability across
// fragment 0 and fragment 1 must have all of it seen by SPF.
func TestSPFAggregatesAcrossFragments(t *testing.T) {
	mock := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 1}, 1500)
	s := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(CircuitConfig{Name: "c", Transport: mock, Level2: true, Padding: ptrFalse()}),
	)
	now := time.Now()
	self := packet.SystemID{0, 0, 0, 0, 0, 1}
	peer := packet.SystemID{0, 0, 0, 0, 0, 2}
	inFrag0 := netip.MustParsePrefix("10.1.0.0/24")
	inFrag1 := netip.MustParsePrefix("10.2.0.0/24")

	put := func(sysID packet.SystemID, frag uint8, tlvs []packet.TLV) {
		id := lspIDFrag(sysID, 0, frag)
		s.dbs[packet.Level2].entries[id] = &lspEntry{
			lsp:      &packet.LSP{Level: packet.Level2, RemainingTime: maxAgeSeconds, LSPID: id, SequenceNumber: 1, ISType: 2, TLVs: tlvs},
			inserted: now, lifetime: maxAgeSeconds,
		}
	}
	put(self, 0, []packet.TLV{
		&packet.ExtendedISReachabilityTLV{Neighbors: []packet.ExtendedISReachEntry{{NeighborID: nodeID(peer, 0), Metric: 10}}},
	})
	put(peer, 0, []packet.TLV{
		&packet.ExtendedISReachabilityTLV{Neighbors: []packet.ExtendedISReachEntry{{NeighborID: nodeID(self, 0), Metric: 10}}},
		&packet.ExtendedIPReachabilityTLV{Prefixes: []packet.ExtendedIPReachEntry{{Metric: 10, Prefix: inFrag0}}},
	})
	put(peer, 1, []packet.TLV{
		&packet.ExtendedIPReachabilityTLV{Prefixes: []packet.ExtendedIPReachEntry{{Metric: 10, Prefix: inFrag1}}},
	})

	routes := s.computeSPF(packet.Level2, 0, now)
	if _, ok := routes[inFrag0]; !ok {
		t.Errorf("prefix in fragment 0 (%s) not reachable", inFrag0)
	}
	if _, ok := routes[inFrag1]; !ok {
		t.Errorf("prefix in fragment 1 (%s) not reachable — SPF did not aggregate fragments", inFrag1)
	}
}

// TestOriginationPurgesStaleFragments: shrinking the advertised set re-collapses
// the LSP to fewer fragments and purges the now-unused higher ones.
func TestOriginationPurgesStaleFragments(t *testing.T) {
	const n = 400
	opts := []ServerOption{
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(CircuitConfig{Name: "c", Transport: datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 1}, 1500), Level2: true, Padding: ptrFalse()}),
	}
	for i := 0; i < n; i++ {
		opts = append(opts, WithAdvertisedPrefix(netip.MustParsePrefix(fmt.Sprintf("10.%d.%d.1/32", i/256, i%256)), 10))
	}
	s := mustServer(t, opts...)
	now := time.Now()
	s.regenerateNodeLSP(packet.Level2, false, now)
	before := len(ownFragments(s))
	if before < 2 {
		t.Fatalf("setup: expected multiple fragments, got %d", before)
	}

	// Drop to a single prefix and re-originate.
	s.prefixes = []AdvertisedPrefix{{Prefix: netip.MustParsePrefix("10.0.0.1/32"), Metric: 10}}
	s.regenerateNodeLSP(packet.Level2, false, now)

	after := ownFragments(s)
	if len(after) != 1 {
		t.Errorf("expected 1 live fragment after shrinking, got %d", len(after))
	}
	// The previously-highest fragment must now be purged (held as a purge).
	hi := uint8(before - 1)
	e := s.dbs[packet.Level2].entries[lspIDFrag(s.systemID, 0, hi)]
	if e == nil || e.purgedAt.IsZero() {
		t.Errorf("stale fragment %d was not purged", hi)
	}
}

// TestPackLSPFragmentsSmallBudget drives the pure packer past 256 fragments
// with a tiny budget: every TLV is placed exactly once, no fragment is empty
// or over budget, and the fixed TLVs land only in fragment 0. (The 0..255
// fragment-ID truncation is originateFragmented's job, not the packer's.)
func TestPackLSPFragmentsSmallBudget(t *testing.T) {
	mk := func() packet.TLV { return &packet.UnknownTLV{TLVType: 200, Value: make([]byte, 8)} }
	fixed := []packet.TLV{mk()} // serializes to 10 octets
	var variable []packet.TLV
	for i := 0; i < 600; i++ {
		variable = append(variable, mk())
	}
	const budget = 24 // two 10-octet TLVs per fragment

	frags := packLSPFragments(fixed, variable, budget)

	// fragment 0: fixed + 1 variable; then 299 fragments of 2 and one of 1.
	if len(frags) != 301 {
		t.Fatalf("got %d fragments, want 301", len(frags))
	}
	total := 0
	for n, f := range frags {
		if len(f) == 0 {
			t.Errorf("fragment %d is empty", n)
		}
		if got := tlvsLen(f); got > budget {
			t.Errorf("fragment %d holds %d octets, over the %d budget", n, got, budget)
		}
		for _, tlv := range f {
			if tlv == fixed[0] && n != 0 {
				t.Errorf("fixed TLV leaked into fragment %d", n)
			}
		}
		total += len(f)
	}
	if want := len(fixed) + len(variable); total != want {
		t.Errorf("packed %d TLVs, want %d", total, want)
	}
}

// TestOriginateFragmentedTruncatesAt256: a TLV set needing more than 256
// fragments is truncated at the 8-bit fragment-ID space — fragments 0..255
// are originated, the overflow is logged as the only error, nothing panics,
// and purgeStaleFragments purges none of the surviving fragments.
func TestOriginateFragmentedTruncatesAt256(t *testing.T) {
	var logBuf bytes.Buffer
	s := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(CircuitConfig{Name: "c", Transport: datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 1}, 1500), Level2: true, Padding: ptrFalse()}),
		WithLogger(slog.New(slog.NewTextHandler(&logBuf, nil))),
	)
	now := time.Now()

	// 1300 TLVs of 252 serialized octets: 5 fit the ~1465-octet budget, so the
	// packer yields 260 fragments — past the 256 fragment IDs.
	var variable []packet.TLV
	for i := 0; i < 1300; i++ {
		variable = append(variable, &packet.UnknownTLV{TLVType: 200, Value: make([]byte, 250)})
	}
	s.originateFragmented(packet.Level2, 0, nil, variable, false, false, now)

	frags := ownFragments(s)
	if len(frags) != 256 {
		t.Fatalf("got %d live fragments, want 256", len(frags))
	}
	for n := 0; n < 256; n++ {
		if _, ok := frags[uint8(n)]; !ok {
			t.Errorf("fragment %d missing", n)
		}
	}
	// No own fragment may be left purged: keep==256 covers the whole ID space.
	for id, e := range s.dbs[packet.Level2].entries {
		if e.own && !e.purgedAt.IsZero() {
			t.Errorf("fragment %v was orphaned as a purge", id)
		}
	}
	// The truncation error is the only anomaly surfaced.
	errs := 0
	for _, line := range strings.Split(logBuf.String(), "\n") {
		if strings.Contains(line, "level=ERROR") {
			errs++
			if !strings.Contains(line, "fragments") {
				t.Errorf("unexpected error logged: %s", line)
			}
		}
	}
	if errs != 1 {
		t.Errorf("logged %d errors, want exactly the truncation error", errs)
	}
}

// TestOriginateSkipsUnserializableTLV: a TLV whose value exceeds the 255-octet
// limit cannot serialize (tlvChunks emits such an entry alone by contract);
// originate must skip the fragment — log, no panic, no stored LSP.
func TestOriginateSkipsUnserializableTLV(t *testing.T) {
	s := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(CircuitConfig{Name: "c", Transport: datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 1}, 1500), Level2: true, Padding: ptrFalse()}),
	)
	now := time.Now()
	id := lspIDFrag(s.systemID, 0, 1)
	big := &packet.UnknownTLV{TLVType: 200, Value: make([]byte, 300)}

	s.originate(packet.Level2, id, []packet.TLV{big}, false, false, now)

	if s.dbs[packet.Level2].get(id) != nil {
		t.Error("fragment with an unserializable TLV was stored")
	}
}

// TestOriginateDropsOversizeFragment: individually valid TLVs whose sum
// overflows ReceiveLSPBufferSize (only reachable when the fixed set alone
// exceeds the fragment budget) must not be stored or flooded — peers would
// discard the LSP and the content would silently black-hole.
func TestOriginateDropsOversizeFragment(t *testing.T) {
	s := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(CircuitConfig{Name: "c", Transport: datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 1}, 1500), Level2: true, Padding: ptrFalse()}),
	)
	now := time.Now()
	id := lspID(s.systemID, 0)
	var tlvs []packet.TLV
	for i := 0; i < 7; i++ { // 7 * 252 = 1764 octets > 1492
		tlvs = append(tlvs, &packet.UnknownTLV{TLVType: 200, Value: make([]byte, 250)})
	}

	s.originate(packet.Level2, id, tlvs, false, false, now)

	if s.dbs[packet.Level2].get(id) != nil {
		t.Error("oversize LSP fragment was stored")
	}
}
