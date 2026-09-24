package server

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/takehaya/goisis/pkg/datalink"
	"github.com/takehaya/goisis/pkg/packet"
)

// lanCircuit returns a broadcast L2 circuit on its own mock transport.
func lanCircuit(name string, snpa byte, mtu int) CircuitConfig {
	return CircuitConfig{
		Name:      name,
		Transport: datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, snpa}, mtu),
		Level2:    true,
		Padding:   ptrFalse(),
	}
}

// deleteFixture returns a stopped server with the two given circuits, this
// node DIS on the first of them and its LSPs originated. One hello drives the
// election synchronously, so no Serve loop is needed (see disServer); the
// tests call deleteCircuit, DeleteCircuit's body, directly.
func deleteFixture(t *testing.T, a, b CircuitConfig) *IsisServer {
	t.Helper()
	s := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(a), WithCircuit(b),
	)
	nbr := packet.SystemID{0, 0, 0, 0, 0, 0xff}
	s.processLANHello(s.circuits[0], packet.SNPA{0, 0, 0, 0, 0, 0xff},
		neighborHello(nbr, 10, nodeID(nbr, 5), a.Transport.LocalSNPA()))
	s.regenerateLSPs(false, time.Now())
	return s
}

// TestDeleteCircuitPurgesThePseudonodeLSP guarantees that deleting a circuit
// this node is DIS on leaves behind no own, unpurged pseudonode LSP.
//
// Such an entry is never visited again: regeneratePseudonodeLSPs walks
// s.circuits, and ageLSPs has no branch that removes an own entry. It therefore
// sits past a refresh deadline nothing can advance, and one own entry past its
// deadline makes refreshOwnLSPs re-originate every own LSP this node has, on
// every housekeeping tick. refreshDeadline puts that 11 to 15 minutes out, so
// no other test in this suite is alive long enough to see it.
func TestDeleteCircuitPurgesThePseudonodeLSP(t *testing.T) {
	s := deleteFixture(t, lanCircuit("a", 0xa1, 1500), lanCircuit("b", 0xb1, 1500))
	if e := s.dbs[packet.Level2].get(lspIDFrag(s.systemID, 1, 0)); e == nil {
		t.Fatalf("the fixture never originated a pseudonode LSP for circuit a")
	}
	if err := s.deleteCircuit("a", time.Now()); err != nil {
		t.Fatalf("deleteCircuit: %v", err)
	}
	for level, db := range s.dbs {
		for id, e := range db.entries {
			if e.own && e.purgedAt.IsZero() && id.NodeID().PseudonodeID() != 0 {
				t.Errorf("%v LSP %v is still ours and unpurged after its circuit was deleted", level, id)
			}
		}
	}
}

// TestDeleteCircuitDoesNotForceARefreshEveryTick is the same guarantee read
// from the time axis: once the circuit is gone, this node's own LSP sequence
// numbers stop climbing. It holds an orphan out of the database by its symptom
// rather than by its shape, so a future change that reintroduces one by another
// route is caught too.
func TestDeleteCircuitDoesNotForceARefreshEveryTick(t *testing.T) {
	s := deleteFixture(t, lanCircuit("a", 0xa1, 1500), lanCircuit("b", 0xb1, 1500))
	now := time.Now()
	if err := s.deleteCircuit("a", now); err != nil {
		t.Fatalf("deleteCircuit: %v", err)
	}
	seq := func() uint32 {
		e := s.dbs[packet.Level2].get(lspID(s.systemID, 0))
		if e == nil {
			t.Fatalf("this node has no own L2 LSP left")
		}
		return e.lsp.SequenceNumber
	}
	// One tick past the longest refresh deadline. The refresh due there is
	// legitimate, and it is the last one this node owes for a long while.
	s.housekeeping(now.Add((refreshSeconds + 1) * time.Second))
	settled := seq()
	for i := 2; i <= 4; i++ {
		s.housekeeping(now.Add(time.Duration(refreshSeconds+i) * time.Second))
		if got := seq(); got != settled {
			t.Fatalf("own L2 LSP sequence number %d -> %d over tick %d: a deleted circuit is still forcing a refresh",
				settled, got, i)
		}
	}
}

// TestDeleteCircuitPurgesTheNodeLSPOfALostLevel covers the same hazard at the
// node LSP: the IS-Type this node advertises is the union of its circuits'
// levels, so the last circuit at a level takes the level with it and its own
// node LSP must be purged rather than orphaned.
func TestDeleteCircuitPurgesTheNodeLSPOfALostLevel(t *testing.T) {
	a := lanCircuit("a", 0xa1, 1500)
	a.Level1 = true
	s := deleteFixture(t, a, lanCircuit("b", 0xb1, 1500))
	if e := s.dbs[packet.Level1].get(lspID(s.systemID, 0)); e == nil {
		t.Fatalf("the fixture never originated an L1 LSP")
	}
	if err := s.deleteCircuit("a", time.Now()); err != nil {
		t.Fatalf("deleteCircuit: %v", err)
	}
	if s.levelCap.has(packet.Level1) {
		t.Errorf("this node still advertises L1 with no L1 circuit left")
	}
	if e := s.dbs[packet.Level1].get(lspID(s.systemID, 0)); e == nil || e.purgedAt.IsZero() {
		t.Errorf("own L1 LSP after losing the last L1 circuit = %v, want a purge", e)
	}
}

// TestDeleteCircuitRestoresTheLSPBufferSize guarantees that the circuit whose
// MTU held this node's LSPs down stops doing so once it is gone: the size is
// re-derived from the circuits that remain, not left at the smallest MTU the
// node ever had.
func TestDeleteCircuitRestoresTheLSPBufferSize(t *testing.T) {
	s := deleteFixture(t, lanCircuit("a", 0xa1, 1500), lanCircuit("b", 0xb1, 700))
	if s.lspBufferSize != 700-3 {
		t.Fatalf("LSP buffer size with a 700-octet circuit = %d, want %d", s.lspBufferSize, 700-3)
	}
	if err := s.deleteCircuit("b", time.Now()); err != nil {
		t.Fatalf("deleteCircuit: %v", err)
	}
	if s.lspBufferSize != packet.ReceiveLSPBufferSize {
		t.Errorf("LSP buffer size after the small circuit left = %d, want %d",
			s.lspBufferSize, packet.ReceiveLSPBufferSize)
	}
}

// TestDeleteCircuitTearsDownItsAdjacencies guarantees that the circuit's
// neighbors are reported down rather than dropped on the floor with it: a
// subscriber that saw each adjacency come up has to see it go away, and the DIS
// re-election and re-origination the teardown drives are what take the circuit
// out of what this node advertises.
func TestDeleteCircuitTearsDownItsAdjacencies(t *testing.T) {
	s := deleteFixture(t, lanCircuit("a", 0xa1, 1500), lanCircuit("b", 0xb1, 1500))
	c := s.circuits[0]
	if len(c.adjs[packet.Level2]) != 1 {
		t.Fatalf("the fixture never formed an adjacency on circuit a")
	}
	if err := s.deleteCircuit("a", time.Now()); err != nil {
		t.Fatalf("deleteCircuit: %v", err)
	}
	if n := len(c.adjs[packet.Level2]); n != 0 {
		t.Errorf("adjacencies left on the deleted circuit = %d, want 0", n)
	}
}

// TestDeleteCircuitStopsMarkingItsSubnetsConnected guarantees that the subnets
// the circuit contributed stop being directly connected. A prefix that stays
// marked connected is never installed, whoever advertises it — so keeping the
// mark would mean no route to that subnet could ever enter the RIB again, on
// this node, for as long as it runs.
func TestDeleteCircuitStopsMarkingItsSubnetsConnected(t *testing.T) {
	a := lanCircuit("a", 0xa1, 1500)
	subnet := netip.MustParsePrefix("10.0.0.0/24")
	a.ConnectedPrefixes = []netip.Prefix{subnet}
	s := deleteFixture(t, a, lanCircuit("b", 0xb1, 1500))
	if !s.connected[subnet] {
		t.Fatalf("the fixture never marked %s directly connected", subnet)
	}
	if err := s.deleteCircuit("a", time.Now()); err != nil {
		t.Fatalf("deleteCircuit: %v", err)
	}
	if s.connected[subnet] {
		t.Errorf("%s is still directly connected after its only circuit was deleted", subnet)
	}
}

func TestDeleteCircuitTwiceIsAnError(t *testing.T) {
	s := deleteFixture(t, lanCircuit("a", 0xa1, 1500), lanCircuit("b", 0xb1, 1500))
	if err := s.deleteCircuit("a", time.Now()); err != nil {
		t.Fatalf("deleteCircuit: %v", err)
	}
	if err := s.deleteCircuit("a", time.Now()); err == nil {
		t.Errorf("deleting the same circuit twice succeeded; a caller that does it has a bug worth reporting")
	}
}

// floodTransport hands a frame back on every Recv until it is closed, so the
// circuit's reader is never parked in Recv and can only be parked on its send
// to eventCh — the state a delete that waited for the reader deadlocks on.
type floodTransport struct {
	*datalink.MockTransport
	closed atomic.Bool
}

func (f *floodTransport) Recv() (datalink.Frame, error) {
	if f.closed.Load() {
		return datalink.Frame{}, datalink.ErrClosed
	}
	// Undecodable on purpose: handleRx drops it, so the loop spends as little
	// as possible per frame and the queue stays full.
	return datalink.Frame{PDU: []byte{0x83, 0x02, 0xff}, Src: packet.SNPA{0, 0, 0, 0, 0, 0xff}}, nil
}

func (f *floodTransport) Close() error {
	f.closed.Store(true)
	return f.MockTransport.Close()
}

// TestDeleteCircuitDoesNotWaitForTheReader guarantees that deleting a circuit
// whose reader is parked on its send to eventCh returns. The delete runs on the
// Serve goroutine, so nothing drains eventCh while it runs: waiting for the
// reader there deadlocks on exactly the busy circuit being removed. Closing the
// transport is the whole termination, and the reader may outlive the call by up
// to readerRetryDelay — which is why its end is read from the transport rather
// than from a goroutine count.
func TestDeleteCircuitDoesNotWaitForTheReader(t *testing.T) {
	tr := &floodTransport{MockTransport: datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xa1}, 1500)}
	cfg := CircuitConfig{Name: "a", Transport: tr, Level2: true, Padding: ptrFalse()}
	fastHello(&cfg)
	s := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(cfg),
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Serve(ctx) //nolint:errcheck // ctx shutdown

	// A full queue is what parks the reader on its send: with a frame always
	// waiting in Recv, it has nowhere else to block.
	waitFor(t, "the event queue to fill", func() bool { return len(s.eventCh) == cap(s.eventCh) })

	delCtx, delCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer delCancel()
	if err := s.DeleteCircuit(delCtx, "a"); err != nil {
		t.Fatalf("DeleteCircuit with the circuit's reader parked on eventCh: %v", err)
	}
	if _, err := tr.Recv(); !errors.Is(err, datalink.ErrClosed) {
		t.Errorf("transport Recv after the delete = %v, want ErrClosed: the reader is never told to stop", err)
	}
}

// TestDeleteCircuitRefusesEventsItsReaderAlreadyQueued guarantees that a frame,
// or a receive error, queued before the delete is dropped and dropped silently.
// The reader outlives DeleteCircuit by up to readerRetryDelay, so its events
// arrive with the circuit already gone: acting on one re-forms an adjacency on
// a circuit this node no longer has, and counting one builds back the very
// per-circuit metric series the delete dropped.
func TestDeleteCircuitRefusesEventsItsReaderAlreadyQueued(t *testing.T) {
	m := newCountingMetrics()
	a, b := lanCircuit("a", 0xa1, 1500), lanCircuit("b", 0xb1, 1500)
	s := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(a), WithCircuit(b), WithMetrics(m),
	)
	c := s.circuits[0]
	if err := s.deleteCircuit("a", time.Now()); err != nil {
		t.Fatalf("deleteCircuit: %v", err)
	}
	nbr := packet.SystemID{0, 0, 0, 0, 0, 0xff}
	raw, err := neighborHello(nbr, 10, nodeID(nbr, 5), a.Transport.LocalSNPA()).Serialize()
	if err != nil {
		t.Fatalf("serialize hello: %v", err)
	}
	s.handleEvent(&rxEvent{circuit: c, frame: datalink.Frame{PDU: raw, Src: packet.SNPA{0, 0, 0, 0, 0, 0xff}}})
	s.handleEvent(&rxErrEvent{circuit: c})

	if n := len(c.adjs[packet.Level2]); n != 0 {
		t.Errorf("adjacencies on the deleted circuit = %d, want 0: a queued hello re-formed one", n)
	}
	if n := m.count("pdu_rx", "a", pduLabel(packet.PDUTypeL2LANHello)); n != 0 {
		t.Errorf("PDUs counted on the deleted circuit = %d, want 0", n)
	}
	if n := m.count("pdu_rx_error", "a"); n != 0 {
		t.Errorf("receive errors counted on the deleted circuit = %d, want 0", n)
	}
}

// sendRecorder keeps every PDU the circuit put on the wire, so a test can ask
// what a neighbor on that segment would have seen.
type sendRecorder struct {
	*datalink.MockTransport
	mu   sync.Mutex
	sent [][]byte
}

func (r *sendRecorder) Send(dst packet.SNPA, pdu []byte) error {
	r.mu.Lock()
	r.sent = append(r.sent, append([]byte(nil), pdu...))
	r.mu.Unlock()
	return r.MockTransport.Send(dst, pdu)
}

func (r *sendRecorder) pdus(t *testing.T) []packet.PDU {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]packet.PDU, 0, len(r.sent))
	for _, raw := range r.sent {
		pdu, err := packet.DecodePDU(raw)
		if err != nil {
			continue // hellos this fixture pads differently are not the subject
		}
		out = append(out, pdu)
	}
	return out
}

// TestDeleteCircuitFloodsItsPurgeBeforeTheTransportCloses guarantees that the
// segment a circuit is leaving hears the purge of the pseudonode LSP this node
// originated for it.
//
// The purge sets SRM on every circuit at the level, and the departing one is
// the only one of them that reaches this LAN. Left unflushed the members hold
// the entry until MaxAge: harmless for forwarding, since this node's own LSP no
// longer points at the pseudonode and SPF ignores it, but twenty minutes of a
// database entry for a LAN we have left. A clean shutdown flushes for the same
// reason (shutdown).
func TestDeleteCircuitFloodsItsPurgeBeforeTheTransportCloses(t *testing.T) {
	a := lanCircuit("a", 0xa1, 1500)
	rec := &sendRecorder{MockTransport: a.Transport.(*datalink.MockTransport)}
	a.Transport = rec
	s := deleteFixture(t, a, lanCircuit("b", 0xb1, 1500))
	pn := s.circuits[0].pseudonodeID
	want := lspID(s.systemID, pn)

	if err := s.deleteCircuit("a", time.Now()); err != nil {
		t.Fatalf("deleteCircuit: %v", err)
	}
	for _, pdu := range rec.pdus(t) {
		lsp, ok := pdu.(*packet.LSP)
		if !ok || lsp.LSPID != want {
			continue
		}
		if lsp.RemainingTime != 0 {
			t.Fatalf("pseudonode LSP %s sent with remaining lifetime %d, want a purge", want, lsp.RemainingTime)
		}
		return
	}
	t.Fatalf("no purge of %s reached the segment; %d PDUs sent", want, len(rec.sent))
}
