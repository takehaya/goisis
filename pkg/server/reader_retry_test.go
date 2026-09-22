package server

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/takehaya/goisis/pkg/datalink"
	"github.com/takehaya/goisis/pkg/packet"
)

// flakyTransport delegates to a MockTransport but fails the first Recv with a
// transient error, as a socket would under ENOBUFS.
type flakyTransport struct {
	*datalink.MockTransport
	failed atomic.Bool
}

func (f *flakyTransport) Recv() (datalink.Frame, error) {
	if f.failed.CompareAndSwap(false, true) {
		return datalink.Frame{}, errors.New("datalink: recv: no buffer space available")
	}
	return f.MockTransport.Recv()
}

// syncBuf is a log sink written by a reader goroutine and read by the test.
type syncBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestReaderSurvivesTransientRecvError checks that a transient Recv error
// does not kill a circuit's reader: the adjacency still forms after the
// retry, and the outage is warned about once rather than per retry.
func TestReaderSurvivesTransientRecvError(t *testing.T) {
	ta := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xa1}, 1500)
	tb := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xb2}, 1500)
	datalink.Link(ta, tb)

	area := packet.AreaAddress{0x49, 0x00, 0x01}
	cfgA := CircuitConfig{Name: "a", Transport: &flakyTransport{MockTransport: ta}, Level2: true, Padding: ptrFalse()}
	cfgB := CircuitConfig{Name: "b", Transport: tb, Level2: true, Padding: ptrFalse()}
	fastHello(&cfgA)
	fastHello(&cfgB)

	var logs syncBuf
	a := mustServer(t, WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}), WithAreaAddresses(area),
		WithCircuit(cfgA), WithLogger(slog.New(slog.NewTextHandler(&logs, nil))))
	b := mustServer(t, WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 2}), WithAreaAddresses(area), WithCircuit(cfgB))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx) //nolint:errcheck // ctx shutdown
	go b.Serve(ctx) //nolint:errcheck // ctx shutdown

	// waitFor allows 3s, which covers the readerRetryDelay the reader waits
	// out before its first successful Recv.
	waitFor(t, "a sees b Up", func() bool { st, ok := adjState(t, a, packet.Level2); return ok && st == AdjUp })

	if n := strings.Count(logs.String(), "circuit receive error"); n != 1 {
		t.Errorf("warnings for one transient Recv error = %d, want 1", n)
	}
}
