package server

import (
	"testing"
	"time"

	"github.com/takehaya/goisis/pkg/packet"
)

// TestAgeLSPsExpiresForeign: a foreign LSP that reaches zero remaining lifetime
// is converted to a purge (purgedAt set, lifetime zeroed) so the network drops
// it (ISO 10589 7.3.16.4).
func TestAgeLSPsExpiresForeign(t *testing.T) {
	now := time.Now()
	s, _ := snpServer(t, false)
	id := lspID(packet.SystemID{0, 0, 0, 0, 0, 2}, 0)
	putEntry(s, id, 3, 1000, now)
	e := s.dbs[packet.Level2].entries[id]
	e.inserted = now.Add(-1001 * time.Second) // aged past its 1000s lifetime

	s.ageLSPs(now)

	if e.purgedAt.IsZero() {
		t.Error("expired foreign LSP was not purged")
	}
	if e.lifetime != 0 {
		t.Errorf("expired LSP lifetime = %d, want 0", e.lifetime)
	}
}

// TestAgeLSPsRemovesPurged: a purge held for >= ZeroAgeLifetime is removed.
func TestAgeLSPsRemovesPurged(t *testing.T) {
	now := time.Now()
	s, _ := snpServer(t, false)
	id := lspID(packet.SystemID{0, 0, 0, 0, 0, 2}, 0)
	putEntry(s, id, 3, 0, now)
	s.dbs[packet.Level2].entries[id].purgedAt = now.Add(-(zeroAgeSeconds + 1) * time.Second)

	s.ageLSPs(now)

	if _, ok := s.dbs[packet.Level2].entries[id]; ok {
		t.Error("purge held past ZeroAgeLifetime was not removed")
	}
}

// TestAgeLSPsOwnNeverExpires: our own LSP at zero remaining lifetime is not
// purged by aging (it is refreshed instead).
func TestAgeLSPsOwnNeverExpires(t *testing.T) {
	now := time.Now()
	s, _ := snpServer(t, false)
	id := lspID(s.systemID, 0)
	putEntry(s, id, 1, 10, now)
	e := s.dbs[packet.Level2].entries[id]
	e.own = true
	e.inserted = now.Add(-20 * time.Second) // remaining 0, but before the refresh window

	s.ageLSPs(now)

	got, ok := s.dbs[packet.Level2].entries[id]
	if !ok {
		t.Fatal("own LSP was removed by aging")
	}
	if !got.purgedAt.IsZero() {
		t.Error("own LSP was purged by aging")
	}
}

// TestRefreshOwnLSPs: an own LSP within the refresh window is re-originated
// before it can expire (sequence bumped, lifetime/insertion reset).
func TestRefreshOwnLSPs(t *testing.T) {
	now := time.Now()
	s, _ := snpServer(t, false)
	old := now.Add(-(refreshSeconds + 1) * time.Second)
	s.regenerateNodeLSP(packet.Level2, false, old) // originate at the old time (seq 1)

	id := lspID(s.systemID, 0)
	before := s.dbs[packet.Level2].entries[id]
	if before == nil || before.lsp.SequenceNumber != 1 {
		t.Fatalf("setup: own LSP not originated at seq 1 (%+v)", before)
	}

	s.refreshOwnLSPs(now)

	after := s.dbs[packet.Level2].entries[id]
	if after.lsp.SequenceNumber != 2 {
		t.Errorf("refreshed seq = %d, want 2", after.lsp.SequenceNumber)
	}
	if !after.inserted.Equal(now) {
		t.Errorf("refreshed insertion = %v, want %v", after.inserted, now)
	}
	if after.lifetime != maxAgeSeconds {
		t.Errorf("refreshed lifetime = %d, want %d", after.lifetime, maxAgeSeconds)
	}
}
