//go:build linux

package config

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

// fakeSetter records what the watcher would have pushed into the server.
type fakeSetter struct {
	addrCalls []string
	linkCalls map[string]bool
}

func (f *fakeSetter) SetCircuitAddresses(_ context.Context, name string, _, _ []netip.Addr, _ []netip.Prefix) error {
	f.addrCalls = append(f.addrCalls, name)
	return nil
}

func (f *fakeSetter) SetCircuitLinkState(_ context.Context, name string, up bool) error {
	if f.linkCalls == nil {
		f.linkCalls = map[string]bool{}
	}
	f.linkCalls[name] = up
	return nil
}

// TestApplyEventsOnlyConfiguredCircuits checks the event mapping: an interface
// named in the configuration reaches the server, anything else is ignored (the
// kernel reports every interface on the box, not just ours).
func TestApplyEventsOnlyConfiguredCircuits(t *testing.T) {
	watched := map[string]bool{"isis0": true}
	logger := slog.New(slog.DiscardHandler)
	f := &fakeSetter{}
	ctx := t.Context()

	applyAddrEvent(ctx, f, watched, "isis0", logger)
	applyAddrEvent(ctx, f, watched, "eth9", logger)
	applyLinkEvent(ctx, f, watched, "isis0", false, logger)
	applyLinkEvent(ctx, f, watched, "eth9", true, logger)

	if want := []string{"isis0"}; len(f.addrCalls) != 1 || f.addrCalls[0] != want[0] {
		t.Errorf("address calls = %v, want %v", f.addrCalls, want)
	}
	if len(f.linkCalls) != 1 {
		t.Errorf("link calls = %v, want only isis0", f.linkCalls)
	}
	if up, ok := f.linkCalls["isis0"]; !ok || up {
		t.Errorf("isis0 link state = %v (reported %v), want down", up, ok)
	}
}

// TestLinkUp pins the carrier semantics: operational state decides, and only a
// device that does not track carrier falls back to the administrative flag.
func TestLinkUp(t *testing.T) {
	tests := []struct {
		name  string
		oper  netlink.LinkOperState
		flags net.Flags
		want  bool
	}{
		{"carrier up", netlink.OperUp, net.FlagUp, true},
		{"cable pulled, still admin up", netlink.OperDown, net.FlagUp, false},
		{"admin down", netlink.OperDown, 0, false},
		{"no carrier tracking, admin up", netlink.OperUnknown, net.FlagUp, true},
		{"no carrier tracking, admin down", netlink.OperUnknown, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := linkUp(&netlink.LinkAttrs{OperState: tt.oper, Flags: tt.flags}); got != tt.want {
				t.Errorf("linkUp = %v, want %v", got, tt.want)
			}
		})
	}
}

// watchLoopError runs watchLoop against the given channels and returns its
// error. A nil channel stands for a subscription that simply never fires. The
// deadline is the point: a watcher whose subscription died must return, not
// block and not spin, so the daemon notices instead of looking healthy.
func watchLoopError(t *testing.T, addrCh <-chan netlink.AddrUpdate, linkCh <-chan netlink.LinkUpdate) error {
	t.Helper()
	errCh := make(chan error, 1)
	go func() {
		errCh <- watchLoop(t.Context(), &fakeSetter{}, map[string]bool{"isis0": true}, addrCh, linkCh, slog.New(slog.DiscardHandler))
	}()
	select {
	case err := <-errCh:
		return err
	case <-time.After(time.Second):
		t.Fatal("watchLoop did not return after the subscription closed")
		return nil
	}
}

// TestWatchLoopReturnsWhenLinkSubscriptionCloses pins the failure path of the
// link subscription: netlink closes the channel when its reader goroutine dies
// (ENOBUFS and friends), and the zero LinkUpdate that a plain receive yields
// has a nil Link, so Attrs() would panic. The watcher must report the loss.
func TestWatchLoopReturnsWhenLinkSubscriptionCloses(t *testing.T) {
	linkCh := make(chan netlink.LinkUpdate)
	close(linkCh)
	if err := watchLoopError(t, nil, linkCh); err == nil {
		t.Fatal("watchLoop returned nil, want an error naming the closed link subscription")
	}
}

// TestWatchLoopReturnsWhenAddrSubscriptionCloses is the same guarantee for the
// address subscription, where a plain receive spins on the closed channel at
// 100% CPU with the watcher already dead.
func TestWatchLoopReturnsWhenAddrSubscriptionCloses(t *testing.T) {
	addrCh := make(chan netlink.AddrUpdate)
	close(addrCh)
	if err := watchLoopError(t, addrCh, nil); err == nil {
		t.Fatal("watchLoop returned nil, want an error naming the closed address subscription")
	}
}
