package datalink

import (
	"sync"
	"testing"

	"github.com/takehaya/goisis/pkg/packet"
)

func TestMockLinkDelivers(t *testing.T) {
	a := NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xa}, 1500)
	b := NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xb}, 1500)
	Link(a, b)

	if err := a.Send(AllL1ISs, []byte{0x83, 0x01}); err != nil {
		t.Fatalf("send: %v", err)
	}
	f, err := b.Recv()
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if f.Src != a.LocalSNPA() {
		t.Errorf("src = %v, want %v", f.Src, a.LocalSNPA())
	}
}

// TestMockSendCloseRace stresses concurrent Send and Close. It must never
// panic with "send on closed channel" (regression for the deliver/Close
// race). Run with -race for full coverage.
func TestMockSendCloseRace(t *testing.T) {
	for i := 0; i < 2000; i++ {
		a := NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xa}, 1500)
		b := NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xb}, 1500)
		Link(a, b)

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_ = a.Send(AllL1ISs, []byte{0x83})
			}
		}()
		go func() {
			defer wg.Done()
			_ = b.Close()
		}()
		wg.Wait()
		_ = a.Close()
	}
}
