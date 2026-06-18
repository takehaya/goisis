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
