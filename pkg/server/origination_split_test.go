package server

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/takehaya/goisis/pkg/datalink"
	"github.com/takehaya/goisis/pkg/packet"
)

// TestOriginationSplitsOversizeReachability is a regression for the silent
// black hole where all prefixes were packed into one TLV: encodeTLV rejects a
// value >255 octets, so originate advertised nothing. With splitting, a large
// prefix set must produce multiple ExtendedIPReachability TLVs that together
// carry every prefix.
func TestOriginationSplitsOversizeReachability(t *testing.T) {
	const n = 60 // ~9 octets/entry → well past one TLV's 255-octet value limit
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

	e := s.dbs[packet.Level2].get(lspID(s.systemID, 0))
	if e == nil {
		t.Fatal("no own LSP originated (the oversize-TLV black hole)")
	}
	tlvCount := 0
	got := map[netip.Prefix]bool{}
	for _, tlv := range e.lsp.TLVs {
		r, ok := tlv.(*packet.ExtendedIPReachabilityTLV)
		if !ok {
			continue
		}
		tlvCount++
		// Each emitted TLV must itself be within the 255-octet limit.
		if _, err := r.Serialize(); err != nil {
			t.Errorf("emitted TLV does not fit the wire: %v", err)
		}
		for _, ent := range r.Prefixes {
			got[ent.Prefix] = true
		}
	}
	if tlvCount < 2 {
		t.Errorf("expected the prefix set to split across >=2 TLVs, got %d", tlvCount)
	}
	if len(got) != n {
		t.Errorf("advertised %d/%d prefixes; splitting dropped some", len(got), n)
	}
	for p := range want {
		if !got[p] {
			t.Errorf("prefix %s missing from the originated LSP", p)
		}
	}

	// The whole LSP must serialize cleanly (the pre-fix failure mode was
	// MarshalTLVs erroring and originate advertising nothing).
	if _, err := e.lsp.Serialize(); err != nil {
		t.Fatalf("own LSP failed to serialize: %v", err)
	}
}

// TestTLVChunksSingleAndEmpty covers the boundary behaviours of the splitter.
func TestTLVChunksSingleAndEmpty(t *testing.T) {
	mk := func(e []packet.ExtendedIPReachEntry) packet.TLV {
		return &packet.ExtendedIPReachabilityTLV{Prefixes: e}
	}
	if got := tlvChunks(nil, mk); got != nil {
		t.Errorf("empty input should yield nil, got %v", got)
	}
	one := []packet.ExtendedIPReachEntry{{Metric: 10, Prefix: netip.MustParsePrefix("10.0.0.0/24")}}
	if got := tlvChunks(one, mk); len(got) != 1 {
		t.Errorf("single entry should yield 1 TLV, got %d", len(got))
	}
}

// TestLinkAttributesCannotEmptyTheOwnLSP: a circuit's link attributes are
// repeated in front of every IS-reachability entry and are never split, so
// they share one entry's sub-TLV area with the neighbor's own sub-TLVs. Past
// the point where they leave no room, no entry serializes, the node originates
// fragment 0 with no Extended IS Reachability TLV at all, and every peer's
// two-way check drops it — on a configuration file both startup and SIGHUP
// accept. The ceiling is on the serialized attributes rather than on the admin
// group, so the next sub-TLV added beside it is measured by the same line.
func TestLinkAttributesCannotEmptyTheOwnLSP(t *testing.T) {
	colored := func(words int) []ServerOption {
		g := make([]uint32, words)
		for i := range g {
			g[i] = 0x8000_0001
		}
		return []ServerOption{
			WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
			WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
			WithCircuit(CircuitConfig{
				Name: "a", Transport: datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xa1}, 1500),
				P2P: true, Level2: true, Padding: ptrFalse(), AdminGroup: g,
			}),
		}
	}
	// The largest admin group the configuration accepts, found rather than
	// assumed: the assertions below are about that boundary wherever it sits.
	const searchCap = 256
	words := 1
	for ; words < searchCap && ValidateOptions(colored(words+1)...) == nil; words++ {
	}
	if words == searchCap {
		t.Fatalf("nothing bounds a circuit's link attributes: %d admin-group words still validate", searchCap)
	}
	if err := ValidateOptions(colored(words + 1)...); err == nil {
		t.Errorf("%d admin-group words validate", words+1)
	}
	if _, err := NewIsisServer(colored(words + 1)...); err == nil {
		t.Errorf("%d admin-group words start a server", words+1)
	}

	// Everything under the ceiling has to work, with the neighbor's own
	// sub-TLVs beside it: 20 End.X SIDs is what lowers the threshold in the
	// first place, and appendISReach must still split them into entries that
	// each fit a TLV.
	s := mustServer(t, colored(words)...)
	var endX []packet.SubTLV
	for i := range 20 {
		endX = append(endX, &packet.SRv6EndXSIDSubTLV{
			Behavior: packet.SRv6BehaviorEndX,
			SID:      netip.AddrFrom16([16]byte{0xfc, 0, 0, 0, 0, 1, 0, byte(i)}),
		})
	}
	id := nodeID(packet.SystemID{0, 0, 0, 0, 0, 2}, 0)
	for _, e := range appendISReach(nil, id, 10, s.circuits[0].cfg.aslaSubTLVs(), endX) {
		if _, err := (&packet.ExtendedISReachabilityTLV{Neighbors: []packet.ExtendedISReachEntry{e}}).Serialize(); err != nil {
			t.Errorf("an entry at the largest accepted admin group (%d words) does not fit a TLV: %v", words, err)
		}
	}

	// And the node still advertises the neighbor it holds an adjacency to.
	var lv levelSet
	lv.add(packet.Level2)
	s.circuits[0].p2pAdj = &adjacency{systemID: packet.SystemID{0, 0, 0, 0, 0, 2}, state: AdjUp, levels: lv}
	s.regenerateLSPs(false, time.Now())
	e := s.dbs[packet.Level2].get(lspID(s.systemID, 0))
	if e == nil {
		t.Fatal("no own Level-2 LSP")
	}
	reach := 0
	for _, tlv := range e.lsp.TLVs {
		if r, ok := tlv.(*packet.ExtendedISReachabilityTLV); ok {
			reach += len(r.Neighbors)
		}
	}
	if reach == 0 {
		t.Errorf("at the largest accepted admin group (%d words) the node advertises no neighbor at all", words)
	}
}
