package server

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/takehaya/goisis/pkg/datalink"
	"github.com/takehaya/goisis/pkg/packet"
)

// benchLSDB installs n foreign LSPs carrying roughly what a real node
// advertises — a hostname, two IS neighbors and eight prefixes — so the TLV
// line count per LSP is representative. Every entry is in place before Serve
// starts, so the injection is not racing the loop the read goes through.
func benchLSDB(b *testing.B, n int) *IsisServer {
	b.Helper()
	s, err := NewIsisServer(
		WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
		WithSystemID(benchSystemID(0)),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(CircuitConfig{
			Name: "c", Transport: datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 1}, 1500),
			Level2: true, Padding: ptrFalse(),
		}),
	)
	if err != nil {
		b.Fatalf("NewIsisServer: %v", err)
	}

	now := time.Now()
	for i := 1; i <= n; i++ {
		prefixes := make([]packet.ExtendedIPReachEntry, 0, 8)
		for j := range 8 {
			addr := netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), byte(j << 5)})
			prefixes = append(prefixes, packet.ExtendedIPReachEntry{Prefix: netip.PrefixFrom(addr, 27), Metric: 10})
		}
		injectLSPAt(s, packet.Level2, benchSystemID(i), []packet.TLV{
			&packet.DynamicHostnameTLV{Hostname: fmt.Sprintf("r%d", i)},
			&packet.ExtendedISReachabilityTLV{Neighbors: []packet.ExtendedISReachEntry{
				{NeighborID: nodeID(benchSystemID(i-1), 0), Metric: 10},
				{NeighborID: nodeID(benchSystemID(i%n+1), 0), Metric: 10},
			}},
			&packet.ExtendedIPReachabilityTLV{Prefixes: prefixes},
		}, now)
	}
	return s
}

// BenchmarkListLSDB sizes the management read path against a 5000-LSP
// database. detail=false is the number that matters: it is the part that runs
// inside mgmtOperation, on the one goroutine that also sends hellos, floods
// and expires adjacencies, so it has to stay a copy. The gap to detail=true is
// the TLV rendering that used to run there too — tens of thousands of strings
// per read, re-paid every time a dropped monitor resubscribes.
func BenchmarkListLSDB(b *testing.B) {
	s := benchLSDB(b, 5000)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Serve(ctx) //nolint:errcheck // ctx shutdown

	for _, detail := range []bool{false, true} {
		b.Run(fmt.Sprintf("detail=%t", detail), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if _, err := s.listLSDB(ctx, detail); err != nil {
					b.Fatalf("listLSDB: %v", err)
				}
			}
		})
	}
}
