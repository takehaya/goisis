package server

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/takehaya/goisis/pkg/datalink"
	"github.com/takehaya/goisis/pkg/packet"
)

// endXP2PCircuit is p2pCircuit with the /64 its neighbor's global address sits
// in connected: endXNexthop hands an adjacency an End.X SID only for an address
// on one of the circuit's directly-connected prefixes.
func endXP2PCircuit(name string, snpa byte, subnet netip.Prefix) CircuitConfig {
	cfg := p2pCircuit(name, datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, snpa}, 1500))
	cfg.ConnectedPrefixes = []netip.Prefix{subnet}
	return cfg
}

// endXAdjUp is upP2PAdj plus the neighbor's global on-link address, the next
// hop an End.X SID towards it forwards to.
func endXAdjUp(c *circuit, id packet.SystemID, addr netip.Addr, now time.Time) {
	upP2PAdj(c, id, now)
	c.p2pAdj.neighborIPv6 = []netip.Addr{addr}
}

// TestAddCircuitKeepsExistingEndXFunctionValues guarantees that a circuit joins
// at the end of s.circuits, so the End.X SID of a circuit that did not change
// keeps the function value it already had — through the addition itself, and
// through the reconvergence afterwards that reallocates every SID at once.
//
// endXAdjs walks s.circuits in order and that order is what hands out function
// values. Keeping the slice in name order, or slotting a new circuit into the
// gap a deleted one left, are both tidier and both silently renumber the SID
// space of links that did not change — pointing traffic at End.X SIDs the
// neighbors have not been told about.
func TestAddCircuitKeepsExistingEndXFunctionValues(t *testing.T) {
	loc := netip.MustParsePrefix("fc00:0:1::/48")
	zSub, aSub := netip.MustParsePrefix("2001:db8:1::/64"), netip.MustParsePrefix("2001:db8:2::/64")
	zAddr, aAddr := netip.MustParseAddr("2001:db8:1::2"), netip.MustParseAddr("2001:db8:2::2")
	zNbr, aNbr := packet.SystemID{0, 0, 0, 0, 0, 0x2a}, packet.SystemID{0, 0, 0, 0, 0, 0x2b}

	s := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(endXP2PCircuit("z", 0x01, zSub)),
		WithSRv6Locator(loc),
	)
	now := time.Now()
	endXAdjUp(s.circuits[0], zNbr, zAddr, now)
	s.regenerateLSPs(false, now)
	zKey := endXKey{locator: loc, circuit: "z", neighbor: zNbr}
	before, ok := s.endXSIDs[zKey]
	if !ok {
		t.Fatalf("the fixture never allocated an End.X SID for circuit z")
	}

	// "a" sorts ahead of "z", so a slice kept in name order puts the new
	// circuit first.
	if err := s.addCircuit(endXP2PCircuit("a", 0x02, aSub), now); err != nil {
		t.Fatalf("addCircuit: %v", err)
	}
	endXAdjUp(s.circuitNamed("a"), aNbr, aAddr, now)
	s.regenerateLSPs(false, now)
	if got := s.endXSIDs[zKey].sid; got != before.sid {
		t.Errorf("End.X SID of circuit z after circuit a was added = %s, want %s", got, before.sid)
	}

	// The addition alone leaves z's allocation in place because it is keyed on
	// the circuit name. The order decides which function each circuit gets when
	// they are allocated together, which is what a reconvergence does: both
	// adjacencies go and come back, and both SIDs are released and taken again
	// in one pass.
	zc, ac := s.circuitNamed("z"), s.circuitNamed("a")
	zc.p2pAdj, ac.p2pAdj = nil, nil
	s.regenerateLSPs(false, now)
	if n := len(s.endXSIDs); n != 0 {
		t.Fatalf("End.X SIDs held after both adjacencies went down = %d, want 0", n)
	}
	endXAdjUp(zc, zNbr, zAddr, now)
	endXAdjUp(ac, aNbr, aAddr, now)
	s.regenerateLSPs(false, now)
	if got := s.endXSIDs[zKey].sid; got != before.sid {
		t.Errorf("End.X SID of circuit z after a reconvergence = %s, want %s: the added circuit took its function value",
			got, before.sid)
	}
}

// TestAddCircuitWithASmallerMTURefragmentsBeforeReturning guarantees that a
// circuit narrower than the LSPs this node already originated has re-fragmented
// them by the time the call returns, with no housekeeping tick in between.
//
// Asking the throttle for a regeneration is not enough: originate refuses to
// store a fragment over the budget and returns, so the database keeps the
// oversize fragments and the new circuit floods what it cannot transmit, once
// per retransmission interval, for as long as minLSPGenInterval holds the
// regeneration back.
func TestAddCircuitWithASmallerMTURefragmentsBeforeReturning(t *testing.T) {
	s := mustServer(t, mtuOptions(1500)...)
	now := time.Now()
	s.regenerateLSPs(false, now)
	if n := len(ownFragments(s)); n < 2 {
		t.Fatalf("the fixture originated %d fragments, want the reachability to span >= 2", n)
	}

	if err := s.addCircuit(lanCircuit("narrow", 0x77, 600), now); err != nil {
		t.Fatalf("addCircuit: %v", err)
	}
	if want := 600 - 3; s.lspBufferSize != want {
		t.Fatalf("LSP buffer size after a 600-octet circuit joined = %d, want %d", s.lspBufferSize, want)
	}
	for level, db := range s.dbs {
		for id, e := range db.entries {
			if !e.own || !e.purgedAt.IsZero() {
				continue
			}
			if len(e.raw) > s.lspBufferSize {
				t.Errorf("%v LSP %v is %d octets, over the %d the new circuit can carry",
					level, id, len(e.raw), s.lspBufferSize)
			}
		}
	}
}

// TestAddCircuitStartsALevelThatHadNoCircuit guarantees that the first circuit
// at a level brings the whole level up with it: the database it originates
// into, the level in the IS-Type this node advertises, and its own node LSP
// from sequence 1 with the ATT bit an L1L2 node owes its area.
//
// The database is created lazily and originate dereferences s.dbs[level]
// without a nil check, so the level must not reach levelCap ahead of it.
func TestAddCircuitStartsALevelThatHadNoCircuit(t *testing.T) {
	s := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(lanCircuit("l2", 0x01, 1500)),
	)
	now := time.Now()
	s.regenerateLSPs(false, now)
	if s.dbs[packet.Level1] != nil {
		t.Fatalf("the fixture already has a Level-1 database")
	}

	l1 := lanCircuit("l1", 0x02, 1500)
	l1.Level1, l1.Level2 = true, false
	if err := s.addCircuit(l1, now); err != nil {
		t.Fatalf("addCircuit: %v", err)
	}

	if got := s.isType(); got != 3 {
		t.Errorf("IS-Type after a Level-1 circuit joined a Level-2 node = %d, want 3", got)
	}
	e := s.dbs[packet.Level1].get(lspID(s.systemID, 0))
	if e == nil {
		t.Fatalf("no own Level-1 LSP after the node's first Level-1 circuit was added")
	}
	if e.lsp.SequenceNumber != 1 {
		t.Errorf("own Level-1 LSP sequence number = %d, want 1: the level has never been originated at before",
			e.lsp.SequenceNumber)
	}
	if !e.lsp.AttDefault {
		t.Errorf("own Level-1 LSP does not set ATT, though this node is now Level-2 as well")
	}
}

// dupFixture returns a stopped server running one broadcast circuit named "a",
// with this node's LSPs originated — the node a second addition of "a" meets.
func dupFixture(t *testing.T) *IsisServer {
	t.Helper()
	s := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(lanCircuit("a", 0xa1, 1500)),
	)
	s.regenerateLSPs(false, time.Now())
	return s
}

// TestAddCircuitAcceptsAnIdenticalDuplicateAsAlreadyInState guarantees that
// adding a circuit the node already runs, in the configuration it already
// runs, is refused as ErrAlreadyInState — the one refusal a configuration
// reload counts as the call having succeeded, so a batch re-issued after some
// other call was refused can still be adopted (pkg/config.Reload).
//
// Identical is read after applyDefaults on both sides, in either direction:
// the running circuit stores the timers and the metric it was given, which are
// the defaults it never named, and a caller writing those defaults out is
// asking for that same circuit rather than for a different one.
func TestAddCircuitAcceptsAnIdenticalDuplicateAsAlreadyInState(t *testing.T) {
	for _, tc := range []struct {
		what string
		edit func(*CircuitConfig)
	}{
		{"the defaults left unset", func(*CircuitConfig) {}},
		{"the defaults written out", func(c *CircuitConfig) {
			c.HelloInterval, c.HoldingMultiplier, c.Metric = DefaultHelloInterval, DefaultHoldingMultiplier, DefaultMetric
		}},
	} {
		t.Run(tc.what, func(t *testing.T) {
			s := dupFixture(t)
			running := s.circuitNamed("a")

			dup := lanCircuit("a", 0xa2, 1500)
			tc.edit(&dup)
			if err := s.addCircuit(dup, time.Now()); !errors.Is(err, ErrAlreadyInState) {
				t.Errorf("re-adding the circuit the node runs = %v, want ErrAlreadyInState: a reload that re-issues its batch can never adopt the file", err)
			}
			if len(s.circuits) != 1 || s.circuitNamed("a") != running {
				t.Errorf("circuits after the refused addition = %d, want the one that was already running", len(s.circuits))
			}
		})
	}
}

// TestAddCircuitRefusesADuplicateThatDiffersAndNamesTheField guarantees that a
// name already configured, carrying any other configuration than the one the
// node runs, is a hard error that names the fields it differs in — and never
// ErrAlreadyInState, which a reload reads as the call having succeeded: the
// circuit would keep its old hello key and its old level while the reload
// reports applied and adopts the file, with no command able to show it
// (ErrAlreadyInState's own doc rules that out).
//
// The names and never the values: half these fields are HMAC keys and this
// error reaches the daemon log. The circuit is not replaced either — replacing
// would drop the running one with its transport open and its reader goroutine
// still on it.
func TestAddCircuitRefusesADuplicateThatDiffersAndNamesTheField(t *testing.T) {
	const secret = "ROTATED-KEY"
	for _, tc := range []struct {
		what  string
		edit  func(*CircuitConfig)
		field string
	}{
		{"hello password", func(c *CircuitConfig) { c.HelloPassword = secret }, "HelloPassword"},
		{"accept passwords", func(c *CircuitConfig) { c.HelloPassword, c.HelloAcceptPasswords = secret, []string{secret + "-OLD"} }, "HelloAcceptPasswords"},
		{"level", func(c *CircuitConfig) { c.Level1 = true }, "Level1"},
		{"priority", func(c *CircuitConfig) { p := uint8(100); c.Priority = &p }, "Priority"},
		{"metric", func(c *CircuitConfig) { c.Metric = 55 }, "Metric"},
		{"padding", func(c *CircuitConfig) { c.Padding = nil }, "Padding"},
		{"hello interval", func(c *CircuitConfig) { c.HelloInterval = time.Second }, "HelloInterval"},
		{"point-to-point procedures", func(c *CircuitConfig) { c.P2P = true }, "P2P"},
		{"connected subnets", func(c *CircuitConfig) {
			c.ConnectedPrefixes = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
		}, "ConnectedPrefixes"},
	} {
		t.Run(tc.what, func(t *testing.T) {
			s := dupFixture(t)
			running := s.circuitNamed("a")

			dup := lanCircuit("a", 0xa2, 1500)
			tc.edit(&dup)
			err := s.addCircuit(dup, time.Now())
			if err == nil {
				t.Fatal("a second circuit named a was accepted; the running one is now unreachable with its transport open")
			}
			if errors.Is(err, ErrAlreadyInState) {
				t.Fatalf("adding a circuit that differs in %s = ErrAlreadyInState: a reload reports that as applied and the circuit keeps the configuration the operator replaced", tc.field)
			}
			if !strings.Contains(err.Error(), tc.field) {
				t.Errorf("error = %q, want it to name %s: which field differs is the operator's next question", err, tc.field)
			}
			if strings.Contains(err.Error(), secret) {
				t.Errorf("error = %q: it carries the key itself, and this error is logged", err)
			}
			if len(s.circuits) != 1 || s.circuitNamed("a") != running {
				t.Errorf("circuits after the refused addition = %d, want the one that was already running", len(s.circuits))
			}
		})
	}
}

// recvClosed reports whether a transport has been closed, read the way the
// delete's tests read it — Recv on a closed transport reports ErrClosed. It
// runs off the test goroutine because Recv on one that is still open parks
// until a frame arrives, which would hang a regression instead of failing it.
func recvClosed(t *testing.T, tr datalink.Transport) bool {
	t.Helper()
	got := make(chan error, 1)
	go func() {
		_, err := tr.Recv()
		got <- err
	}()
	select {
	case err := <-got:
		return errors.Is(err, datalink.ErrClosed)
	case <-time.After(2 * time.Second):
		return false
	}
}

// TestAddCircuitClosesEveryTransportItDoesNotAdd guarantees that a transport
// AddCircuit is handed and does not run a circuit on is closed by AddCircuit —
// on the refusal, on the ErrAlreadyInState sentinel, and on a context that
// never reached the loop at all.
//
// The caller cannot be the one to close it: a management operation whose
// caller's context expires while it is queued still runs (mgmtOperation
// abandons the wait, not the operation), so a caller closing on error would be
// closing the socket the instance had just taken. Ownership passes on every
// path, which leaves every path that does not add a circuit owing the close.
func TestAddCircuitClosesEveryTransportItDoesNotAdd(t *testing.T) {
	s := dupFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Serve(ctx) //nolint:errcheck // shut down via ctx

	same := lanCircuit("a", 0xa2, 1500)
	if err := s.AddCircuit(ctx, same); !errors.Is(err, ErrAlreadyInState) {
		t.Fatalf("AddCircuit over the circuit the node runs = %v, want ErrAlreadyInState", err)
	}
	if !recvClosed(t, same.Transport) {
		t.Error("the sentinel left the transport open: the call did not use it and the caller is told not to close it, so every retry over a circuit the node has leaks a socket")
	}

	differs := lanCircuit("a", 0xa3, 1500)
	differs.Metric = 55
	if err := s.AddCircuit(ctx, differs); err == nil || errors.Is(err, ErrAlreadyInState) {
		t.Fatalf("AddCircuit over a circuit that differs = %v, want a hard error", err)
	}
	if !recvClosed(t, differs.Transport) {
		t.Error("the refusal left the transport open")
	}

	dead, cancelDead := context.WithCancel(context.Background())
	cancelDead()
	never := lanCircuit("b", 0xb1, 1500)
	if err := s.AddCircuit(dead, never); !errors.Is(err, context.Canceled) {
		t.Fatalf("AddCircuit on a cancelled context = %v, want context.Canceled", err)
	}
	if !recvClosed(t, never.Transport) {
		t.Error("an addition that never reached the loop left the transport open: nothing on the loop will ever close it")
	}
}

// TestAddCircuitKeepsTheTransportOfACircuitTheLoopStillAdded guarantees the
// other half of that ownership rule. A context bounds the caller's wait and
// not the operation: an addition already queued runs whatever the caller does
// afterwards, so a call that returned a deadline error may still have added
// the circuit — and the transport it is now running on must be open.
//
// Closing it leaves a circuit goisis reports up that can never transmit a
// hello or flood a fragment, for the life of the process.
func TestAddCircuitKeepsTheTransportOfACircuitTheLoopStillAdded(t *testing.T) {
	s := dupFixture(t)
	// Not serving yet: the operation sits in mgmtCh exactly as it does behind
	// a loop too busy to reach it, and the caller's deadline expires on it.
	late := lanCircuit("b", 0xb1, 1500)
	addCtx, cancelAdd := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancelAdd()
	if err := s.AddCircuit(addCtx, late); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("AddCircuit against a loop that never answers = %v, want a deadline error", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Serve(ctx) //nolint:errcheck // shut down via ctx

	waitFor(t, "the queued addition to run", func() bool { return len(s.mgmtCh) == 0 })
	circuits, err := s.ListCircuits(ctx)
	if err != nil {
		t.Fatalf("ListCircuits: %v", err)
	}
	if len(circuits) != 2 {
		t.Fatalf("circuits = %+v, want the queued addition to have landed: this test is asserting nothing otherwise", circuits)
	}
	if recvClosed(t, late.Transport) {
		t.Error("the circuit the loop added is running on a closed transport: it can never send a hello or flood a fragment")
	}
}

// TestDeleteThenAddCircuitLeavesANodeThatCouldHaveStarted guarantees that a
// removal followed by an addition puts this node in a state it could have
// booted into: every own LSP it still holds belongs to a circuit or a level it
// still has, the IS-Type matches the circuits it has, and the octet handed to
// the new circuit is not one the area still holds a copy of.
//
// Handing the freed octet straight back is what the rotator exists to avoid:
// the purge deleteCircuit issued for it is still in this node's database and
// still in every peer's, so the new circuit's pseudonode LSP would have to
// climb over a copy that is already out there.
func TestDeleteThenAddCircuitLeavesANodeThatCouldHaveStarted(t *testing.T) {
	a := lanCircuit("a", 0xa1, 1500)
	a.Level1 = true
	s := deleteFixture(t, a, lanCircuit("b", 0xb1, 1500))
	now := time.Now()
	freed := s.circuitNamed("a").pseudonodeID
	if err := s.deleteCircuit("a", now); err != nil {
		t.Fatalf("deleteCircuit: %v", err)
	}
	purged := s.dbs[packet.Level1].get(lspID(s.systemID, 0))
	if purged == nil || purged.purgedAt.IsZero() {
		t.Fatalf("the delete left no Level-1 purge for the addition to climb over")
	}

	c := lanCircuit("c", 0xc1, 1500)
	c.Level1 = true
	if err := s.addCircuit(c, now); err != nil {
		t.Fatalf("addCircuit: %v", err)
	}

	if got := s.circuitNamed("c").pseudonodeID; got == freed {
		t.Errorf("the new circuit took octet %d straight back, while this node's purge for it is still in the database", got)
	}
	if got := s.isType(); got != 3 {
		t.Errorf("IS-Type = %d, want 3: the node has a Level-1/Level-2 circuit again", got)
	}
	e := s.dbs[packet.Level1].get(lspID(s.systemID, 0))
	if e == nil || !e.purgedAt.IsZero() {
		t.Fatalf("own Level-1 LSP after the level came back = %v, want a live one", e)
	}
	if e.lsp.SequenceNumber <= purged.lsp.SequenceNumber {
		t.Errorf("own Level-1 LSP re-originated at sequence %d, at or under the purge's %d that peers still hold",
			e.lsp.SequenceNumber, purged.lsp.SequenceNumber)
	}
	live := map[uint8]bool{}
	for _, other := range s.circuits {
		live[other.pseudonodeID] = true
	}
	for level, db := range s.dbs {
		for id, entry := range db.entries {
			if !entry.own || !entry.purgedAt.IsZero() {
				continue
			}
			if pn := id.NodeID().PseudonodeID(); pn != 0 && !live[pn] {
				t.Errorf("own %v LSP %v names pseudonode octet %d, which no circuit holds", level, id, pn)
			} else if pn == 0 && !s.levelCap.has(level) {
				t.Errorf("own %v node LSP %v at a level no circuit is at", level, id)
			}
		}
	}
}
