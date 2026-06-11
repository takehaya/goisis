//go:build linux

package datalink

import (
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/takehaya/goisis/pkg/packet"
)

// requireRoot skips a test unless it can create network interfaces.
func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root for AF_PACKET + veth; run: go test -exec sudo ./pkg/datalink")
	}
}

// setupVeth creates a veth pair in the host netns and returns the two
// interface names, registering cleanup.
func setupVeth(t *testing.T) (string, string) {
	t.Helper()
	a, b := "gisistest0", "gisistest1"
	_ = exec.Command("ip", "link", "del", a).Run() // best-effort pre-clean
	if out, err := exec.Command("ip", "link", "add", a, "type", "veth", "peer", "name", b).CombinedOutput(); err != nil {
		t.Fatalf("create veth: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", a).Run() })
	for _, name := range []string{a, b} {
		if out, err := exec.Command("ip", "link", "set", name, "up").CombinedOutput(); err != nil {
			t.Fatalf("set %s up: %v: %s", name, err, out)
		}
	}
	return a, b
}

func TestLinuxTransportLoopback(t *testing.T) {
	requireRoot(t)
	a, b := setupVeth(t)

	ta, err := OpenLinux(a)
	if err != nil {
		t.Fatalf("open %s: %v", a, err)
	}
	defer func() { _ = ta.Close() }()
	tb, err := OpenLinux(b)
	if err != nil {
		t.Fatalf("open %s: %v", b, err)
	}
	defer func() { _ = tb.Close() }()

	// A minimal L1 LAN hello, sent a -> AllL1ISs, received on b.
	hello := &packet.LANHello{
		Level:       packet.Level1,
		CircuitType: packet.CircuitTypeLevel12,
		SourceID:    packet.SystemID{0, 0, 0, 0, 0, 1},
		HoldingTime: 30,
		Priority:    64,
		LANID:       packet.NodeID{0, 0, 0, 0, 0, 1, 0},
		TLVs:        []packet.TLV{&packet.AreaAddressesTLV{Addresses: []packet.AreaAddress{{0x49, 0x00, 0x01}}}},
	}
	wire, err := hello.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	recvd := make(chan Frame, 1)
	go func() {
		f, err := tb.Recv()
		if err == nil {
			recvd <- f
		}
	}()

	if err := ta.Send(AllL1ISs, wire); err != nil {
		t.Fatalf("send: %v", err)
	}

	t.Logf("ta(%s) MAC=%v  tb(%s) MAC=%v", a, ta.LocalSNPA(), b, tb.LocalSNPA())
	select {
	case f := <-recvd:
		t.Logf("received src=%v", f.Src)
		if f.Src != ta.LocalSNPA() {
			t.Errorf("src = %v, want %v", f.Src, ta.LocalSNPA())
		}
		pdu, err := packet.DecodePDU(f.PDU)
		if err != nil {
			t.Fatalf("decode received PDU: %v", err)
		}
		if pdu.PDUType() != packet.PDUTypeL1LANHello {
			t.Errorf("PDU type = %v", pdu.PDUType())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for frame on peer")
	}
}
