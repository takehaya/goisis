package server

import (
	"context"
	"testing"
	"time"

	"github.com/takehaya/goisis/pkg/datalink"
	"github.com/takehaya/goisis/pkg/packet"
)

// helloRotationPair starts two linked p2p servers mid-rotation: each signs its
// hellos with its own password and accepts the passwords in its accept list.
func helloRotationPair(t *testing.T, ctx context.Context, signA string, acceptA []string, signB string, acceptB []string) (a, b *IsisServer) {
	t.Helper()
	ta := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xa1}, 1500)
	tb := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xb2}, 1500)
	datalink.Link(ta, tb)
	area := packet.AreaAddress{0x49, 0x00, 0x01}
	mk := func(name string, tr datalink.Transport, pw string, accept []string) CircuitConfig {
		c := CircuitConfig{Name: name, Transport: tr, P2P: true, Level2: true, Padding: ptrFalse(),
			HelloPassword: pw, HelloAcceptPasswords: accept}
		fastHello(&c)
		return c
	}
	a = mustServer(t, WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}), WithAreaAddresses(area), WithCircuit(mk("a", ta, signA, acceptA)))
	b = mustServer(t, WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 2}), WithAreaAddresses(area), WithCircuit(mk("b", tb, signB, acceptB)))
	go a.Serve(ctx) //nolint:errcheck // ctx shutdown
	go b.Serve(ctx) //nolint:errcheck // ctx shutdown
	return a, b
}

// TestHelloAcceptedWithAnAcceptPassword: mid-rotation A signs hellos with the
// new password and B still signs with the old one; each lists the other's
// password in its accept list, so the adjacency comes up in both directions.
func TestHelloAcceptedWithAnAcceptPassword(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a, b := helloRotationPair(t, ctx, "new", []string{"old"}, "old", []string{"new"})
	waitFor(t, "a sees b Up", func() bool { st, ok := adjState(t, a, packet.Level2); return ok && st == AdjUp })
	waitFor(t, "b sees a Up", func() bool { st, ok := adjState(t, b, packet.Level2); return ok && st == AdjUp })
}

// TestLSPAcceptedWithAnAcceptSecret: the same rotation for Level-2 LSPs and
// SNPs — A signs with the new domain key, B with the old one, and each accepts
// the other's, so the LSDB syncs.
func TestLSPAcceptedWithAnAcceptSecret(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ta := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xa1}, 1500)
	tb := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xb2}, 1500)
	datalink.Link(ta, tb)
	area := packet.AreaAddress{0x49, 0x00, 0x01}
	mk := func(name string, tr datalink.Transport) CircuitConfig {
		c := CircuitConfig{Name: name, Transport: tr, P2P: true, Level2: true, Padding: ptrFalse()}
		fastHello(&c)
		return c
	}
	a := mustServer(t, WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}), WithAreaAddresses(area), WithCircuit(mk("a", ta)),
		WithDomainAuth(AuthConfig{Secret: "new", AcceptSecrets: []string{"old"}}))
	b := mustServer(t, WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 2}), WithAreaAddresses(area), WithCircuit(mk("b", tb)),
		WithDomainAuth(AuthConfig{Secret: "old", AcceptSecrets: []string{"new"}}))
	go a.Serve(ctx) //nolint:errcheck // ctx shutdown
	go b.Serve(ctx) //nolint:errcheck // ctx shutdown
	waitFor(t, "b installs A's LSP signed with the new key", func() bool {
		return liveLSPFrom(t, b, packet.SystemID{0, 0, 0, 0, 0, 1})
	})
	waitFor(t, "a installs B's LSP signed with the old key", func() bool {
		return liveLSPFrom(t, a, packet.SystemID{0, 0, 0, 0, 0, 2})
	})
}

// TestUnknownKeyStillRejected: a key that is neither the signing key nor on the
// accept list authenticates nothing — no adjacency forms.
func TestUnknownKeyStillRejected(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, b := helloRotationPair(t, ctx, "rogue", nil, "old", []string{"new"})
	time.Sleep(1500 * time.Millisecond) // ample time for a fast-hello adjacency
	if st, ok := adjState(t, b, packet.Level2); ok && st == AdjUp {
		t.Errorf("adjacency reached %v with a password on neither list", st)
	}
}
