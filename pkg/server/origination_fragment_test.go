package server

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/takehaya/goisis/pkg/datalink"
	"github.com/takehaya/goisis/pkg/packet"
)

func ownFragments(s *IsisServer, pn uint8) map[uint8]*lspEntry {
	out := map[uint8]*lspEntry{}
	for id, e := range s.dbs[packet.Level2].entries {
		nid := id.NodeID()
		if nid.SystemID() == s.systemID && nid.PseudonodeID() == pn && e.own && e.purgedAt.IsZero() {
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

	frags := ownFragments(s, 0)
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
	before := len(ownFragments(s, 0))
	if before < 2 {
		t.Fatalf("setup: expected multiple fragments, got %d", before)
	}

	// Drop to a single prefix and re-originate.
	s.prefixes = []AdvertisedPrefix{{Prefix: netip.MustParsePrefix("10.0.0.1/32"), Metric: 10}}
	s.regenerateNodeLSP(packet.Level2, false, now)

	after := ownFragments(s, 0)
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
