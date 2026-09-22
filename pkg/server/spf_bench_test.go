package server

import (
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/netip"
	"testing"
	"time"

	"github.com/takehaya/goisis/pkg/datalink"
	"github.com/takehaya/goisis/pkg/packet"
)

// benchSystemID maps a node index onto a System ID.
func benchSystemID(i int) packet.SystemID {
	return packet.SystemID{0, 0, 0, byte(i >> 16), byte(i >> 8), byte(i)}
}

// benchTopology installs an n-node single-area L2 topology in the LSDB: a ring
// (connected, and every edge bidirectional so the two-way check passes) plus
// one chord per node from a fixed seed, so the graph is the same on every run.
// Node 0 is this server. Each node advertises one /32.
//
// No adjacencies are created: computeSPF reads the LSDB only — resolving a
// first hop to a gateway happens later, in updateRIB.
func benchTopology(b *testing.B, n int) (*IsisServer, time.Time) {
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

	neighbors := make([][]int, n)
	link := func(a, z int) {
		neighbors[a] = append(neighbors[a], z)
		neighbors[z] = append(neighbors[z], a)
	}
	for i := range n {
		link(i, (i+1)%n)
	}
	rng := rand.New(rand.NewPCG(1, 2))
	for i := range n {
		if j := rng.IntN(n); j != i {
			link(i, j)
		}
	}

	now := time.Now()
	for i := range n {
		reach := make([]packet.ExtendedISReachEntry, 0, len(neighbors[i]))
		for _, j := range neighbors[i] {
			reach = append(reach, packet.ExtendedISReachEntry{NeighborID: nodeID(benchSystemID(j), 0), Metric: 10})
		}
		prefix := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 1}), 32)
		injectLSPAt(s, packet.Level2, benchSystemID(i), []packet.TLV{
			&packet.ExtendedISReachabilityTLV{Neighbors: reach},
			&packet.ExtendedIPReachabilityTLV{Prefixes: []packet.ExtendedIPReachEntry{{Prefix: prefix, Metric: 10}}},
		}, now)
	}
	return s, now
}

// BenchmarkComputeSPF sizes the O(V^2) popMin choice documented in spf.go: one
// full SPF run over 50, 200 and 1000 nodes.
func BenchmarkComputeSPF(b *testing.B) {
	for _, n := range []int{50, 200, 1000} {
		b.Run(fmt.Sprintf("nodes=%d", n), func(b *testing.B) {
			s, now := benchTopology(b, n)
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				s.computeSPF(packet.Level2, 0, now)
			}
		})
	}
}
