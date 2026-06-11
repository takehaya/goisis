package interop

import (
	"context"
	"testing"

	"github.com/takehaya/goisis/pkg/packet"
)

var frrSysID = packet.SystemID{0, 0, 0, 0, 0, 0xff}

func TestFRRBroadcastAdjacency(t *testing.T) {
	requireInterop(t)
	node := startFRR(t, false)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := startGoisis(t, ctx, node.hostVeth, false)

	waitUp(t, "goisis sees FRR Up", func() bool { return goisisSeesUp(t, s, frrSysID) })
	waitUp(t, "FRR sees goisis Up", func() bool { return node.neighborUp(t, "0000.0000.0001") })
}

func TestFRRP2PAdjacency(t *testing.T) {
	requireInterop(t)
	node := startFRR(t, true)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := startGoisis(t, ctx, node.hostVeth, true)

	waitUp(t, "goisis sees FRR Up (p2p)", func() bool { return goisisSeesUp(t, s, frrSysID) })
	waitUp(t, "FRR sees goisis Up (p2p)", func() bool { return node.neighborUp(t, "0000.0000.0001") })
}
