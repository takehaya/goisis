//go:build linux

package datalink

import (
	"bytes"
	"errors"
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

	// Read until the hello we sent turns up rather than trusting the first
	// frame: the socket delivers everything the interface sees, and a freshly
	// created veth is not quiet (IPv6 autoconfiguration alone puts multicast
	// listener reports on it the moment it comes up). Match on the PDU, not on
	// the source address: what this test guarantees is that a frame written to
	// one end of the link is read at the other, and some environments hand the
	// veth a different MAC after the transport has already read it.
	recvd := make(chan Frame, 1)
	go func() {
		for {
			f, err := tb.Recv()
			if err != nil {
				return
			}
			if bytes.Equal(f.PDU, wire) {
				recvd <- f
				return
			}
		}
	}()

	if err := ta.Send(AllL1ISs, wire); err != nil {
		t.Fatalf("send: %v", err)
	}

	t.Logf("ta(%s) MAC=%v  tb(%s) MAC=%v", a, ta.LocalSNPA(), b, tb.LocalSNPA())
	select {
	case f := <-recvd:
		t.Logf("received src=%v", f.Src)
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

// TestLinuxTransportCloseUnblocksRecv pins the Recv contract: only a Close
// reports ErrClosed, both to a reader already blocked in Recv and to one
// calling Recv afterwards. The underlying socket signals the two cases with
// different (and unexported) errors, so neither is matchable by identity.
func TestLinuxTransportCloseUnblocksRecv(t *testing.T) {
	requireRoot(t)
	a, _ := setupVeth(t)

	ta, err := OpenLinux(a)
	if err != nil {
		t.Fatalf("open %s: %v", a, err)
	}

	blocked := make(chan error, 1)
	go func() {
		_, err := ta.Recv()
		blocked <- err
	}()
	time.Sleep(100 * time.Millisecond) // let the reader reach the socket

	if err := ta.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	select {
	case err := <-blocked:
		if !errors.Is(err, ErrClosed) {
			t.Errorf("Recv blocked across Close = %v, want ErrClosed", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not unblock Recv")
	}
	if _, err := ta.Recv(); !errors.Is(err, ErrClosed) {
		t.Errorf("Recv after Close = %v, want ErrClosed", err)
	}
}
