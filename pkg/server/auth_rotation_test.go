package server

import (
	"context"
	"testing"

	"github.com/takehaya/goisis/pkg/datalink"
	"github.com/takehaya/goisis/pkg/packet"
)

// helloRotationPair starts two linked p2p servers mid-rotation: each signs its
// hellos with its own password and accepts the passwords in its accept list.
// Clock and counter as in helloAuthPair.
func helloRotationPair(t *testing.T, ctx context.Context, signA string, acceptA []string, signB string, acceptB []string) (a, b *IsisServer, clk *fakeClock, m *countingMetrics) {
	t.Helper()
	ta := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xa1}, 1500)
	tb := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xb2}, 1500)
	datalink.Link(ta, tb)
	area := packet.AreaAddress{0x49, 0x00, 0x01}
	mk := func(name string, tr datalink.Transport, pw string, accept []string) CircuitConfig {
		c := CircuitConfig{Name: name, Transport: tr, P2P: true, Level2: true, Padding: ptrFalse(),
			HelloPassword: pw, HelloAcceptPasswords: accept}
		steadyHello(&c)
		return c
	}
	clk, m = newFakeClock(), newCountingMetrics()
	a = mustServer(t, WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}), WithAreaAddresses(area), WithCircuit(mk("a", ta, signA, acceptA)), WithClock(clk), WithMetrics(m))
	b = mustServer(t, WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 2}), WithAreaAddresses(area), WithCircuit(mk("b", tb, signB, acceptB)), WithClock(clk), WithMetrics(m))
	go a.Serve(ctx) //nolint:errcheck // ctx shutdown
	go b.Serve(ctx) //nolint:errcheck // ctx shutdown
	return a, b, clk, m
}

// TestHelloAcceptedWithAnAcceptPassword: mid-rotation A signs hellos with the
// new password and B still signs with the old one; each lists the other's
// password in its accept list, so the adjacency comes up in both directions.
func TestHelloAcceptedWithAnAcceptPassword(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a, b, clk, _ := helloRotationPair(t, ctx, "new", []string{"old"}, "old", []string{"new"})
	waitClock(t, clk, "a sees b Up", func() bool { st, ok := adjState(t, a, packet.Level2); return ok && st == AdjUp })
	waitClock(t, clk, "b sees a Up", func() bool { st, ok := adjState(t, b, packet.Level2); return ok && st == AdjUp })
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
	_, b, clk, m := helloRotationPair(t, ctx, "rogue", nil, "old", []string{"new"})
	// Three rejected hellos is more than an adjacency would have needed, and
	// the wait ends when they arrive rather than at the end of a window.
	waitDrops(t, clk, m, "b", dropAuth, 3)
	if st, ok := adjState(t, b, packet.Level2); ok && st == AdjUp {
		t.Errorf("adjacency reached %v with a password on neither list", st)
	}
}

// TestAcceptPasswordsWithoutPrimaryIsRejected: an accept list with no signing
// password is a configuration error in all three scopes. Such a scope would
// sign nothing and verify nothing — a rotation that moves the old key to the
// accept list and forgets the new primary must fail loudly, not fail open.
func TestAcceptPasswordsWithoutPrimaryIsRejected(t *testing.T) {
	tr := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xa1}, 1500)
	for name, opt := range map[string]ServerOption{
		"area":   WithAreaAuth(AuthConfig{AcceptSecrets: []string{"old"}}),
		"domain": WithDomainAuth(AuthConfig{AcceptSecrets: []string{"old"}}),
		"hello": WithCircuit(CircuitConfig{Name: "a", Transport: tr, P2P: true, Level2: true,
			HelloAcceptPasswords: []string{"old"}}),
	} {
		if _, err := NewIsisServer(WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}), opt); err == nil {
			t.Errorf("%s: NewIsisServer accepted an accept list without a primary password", name)
		}
	}
}

// TestAcceptKeysDropsEmptyEntries: an empty accept entry is dropped rather than
// becoming an empty HMAC key, which anyone could sign with.
func TestAcceptKeysDropsEmptyEntries(t *testing.T) {
	if keys := acceptKeys([]string{"", "old"}); len(keys) != 1 || string(keys[0]) != "old" {
		t.Errorf("acceptKeys([\"\", \"old\"]) = %q, want [\"old\"]", keys)
	}
}

// TestVerifyRejectsEmptyKeySignature: a PDU signed with the empty key does not
// verify against a spec whose accept list contains an empty password.
func TestVerifyRejectsEmptyKeySignature(t *testing.T) {
	h := &packet.LANHello{
		Level: packet.Level1, SourceID: packet.SystemID{0, 0, 0, 0, 0, 1}, HoldingTime: 30,
		TLVs: []packet.TLV{packet.AuthTLV(packet.AuthMD5, 0)},
	}
	raw, err := h.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	off := packet.HeaderLen(h.PDUType())
	if err := packet.PatchAuth(raw, off, packet.AuthMD5, 0, nil, false); err != nil {
		t.Fatalf("PatchAuth: %v", err)
	}
	spec := AuthConfig{Secret: "primary", AcceptSecrets: []string{""}}.spec()
	if spec.verify(raw, off, false) {
		t.Error("a PDU signed with the empty key verified against an accept list containing \"\"")
	}
}
