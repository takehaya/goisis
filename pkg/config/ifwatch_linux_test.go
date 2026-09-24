//go:build linux

package config

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vishvananda/netlink"

	"github.com/takehaya/goisis/pkg/server"
)

// fakeSetter stands in for the server: it answers which circuits are
// configured, refuses a push for any other name the way the server does, and
// records what reached it.
type fakeSetter struct {
	circuits  []string
	addrCalls []string
	linkCalls map[string]bool
}

func (f *fakeSetter) ListCircuits(context.Context) ([]server.CircuitInfo, error) {
	out := make([]server.CircuitInfo, 0, len(f.circuits))
	for _, name := range f.circuits {
		out = append(out, server.CircuitInfo{Interface: name})
	}
	return out, nil
}

func (f *fakeSetter) SetCircuitAddresses(_ context.Context, name string, _, _ []netip.Addr, _ []netip.Prefix) error {
	if !slices.Contains(f.circuits, name) {
		return fmt.Errorf("%w: %q", server.ErrUnknownCircuit, name)
	}
	f.addrCalls = append(f.addrCalls, name)
	return nil
}

func (f *fakeSetter) SetCircuitLinkState(_ context.Context, name string, up bool) error {
	if !slices.Contains(f.circuits, name) {
		return fmt.Errorf("%w: %q", server.ErrUnknownCircuit, name)
	}
	if f.linkCalls == nil {
		f.linkCalls = map[string]bool{}
	}
	f.linkCalls[name] = up
	return nil
}

// TestAnEventForAnInterfaceWeDoNotRunIsNotAWarning pins what replaced the
// startup snapshot of the circuit set. The kernel reports every interface on
// the box, so the watcher pushes each event and lets the server say whether the
// circuit is ours; an unrelated NIC must therefore not reach the warning log,
// or every daemon on a multi-homed host would look broken.
func TestAnEventForAnInterfaceWeDoNotRunIsNotAWarning(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	f := &fakeSetter{circuits: []string{"isis0"}}
	ctx := t.Context()

	applyAddrEvent(ctx, f, "isis0", logger)
	applyAddrEvent(ctx, f, "eth9", logger)
	applyLinkEvent(ctx, f, "isis0", false, logger)
	applyLinkEvent(ctx, f, "eth9", true, logger)

	if want := []string{"isis0"}; !slices.Equal(f.addrCalls, want) {
		t.Errorf("address calls = %v, want %v", f.addrCalls, want)
	}
	if up, ok := f.linkCalls["isis0"]; !ok || up {
		t.Errorf("isis0 link state = %v (reported %v), want down", up, ok)
	}
	if len(f.linkCalls) != 1 {
		t.Errorf("link calls = %v, want only isis0", f.linkCalls)
	}
	if strings.Contains(logs.String(), "level=WARN") {
		t.Errorf("an interface we do not run was warned about:\n%s", logs.String())
	}
	// The event was handled rather than dropped in silence: an operator who
	// turns Debug on can still see the watcher deciding.
	if !strings.Contains(logs.String(), "eth9") {
		t.Errorf("the refused interface is not in the log at Debug either:\n%s", logs.String())
	}
}

// TestAResyncFollowsACircuitAddedAfterStartup is the reason the watcher holds
// no circuit set of its own. A reload adds and removes circuits, so a set read
// once at startup would leave an added circuit unfollowed for the life of the
// daemon -- no address change learned, and no adjacency torn down when its
// carrier drops, which is the failure this watcher exists for.
func TestAResyncFollowsACircuitAddedAfterStartup(t *testing.T) {
	// The loopback stands in for a real interface: reading it needs no
	// privileges, and it exists in every namespace a test can run in.
	f := &fakeSetter{}
	logger := slog.New(slog.DiscardHandler)

	resyncAll(t.Context(), f, logger)
	if len(f.addrCalls)+len(f.linkCalls) != 0 {
		t.Fatalf("a server with no circuits was pushed to: %v %v", f.addrCalls, f.linkCalls)
	}

	f.circuits = []string{"lo"} // a reload added it
	resyncAll(t.Context(), f, logger)
	if !slices.Contains(f.addrCalls, "lo") {
		t.Errorf("address calls = %v, want the circuit added after startup", f.addrCalls)
	}
	if up, ok := f.linkCalls["lo"]; !ok || !up {
		t.Errorf("lo link state = %v (reported %v), want up", up, ok)
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
		errCh <- watchLoop(t.Context(), &fakeSetter{circuits: []string{"isis0"}}, addrCh, linkCh, nil, slog.New(slog.DiscardHandler))
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

// TestResyncPushesCurrentInterfaceState pins the recovery from a lost netlink
// message: re-reading an interface pushes its carrier state and its addresses,
// and an interface that is gone is reported down — that is exactly the event
// whose loss would otherwise leave a circuit deaf and mute until a restart.
func TestResyncPushesCurrentInterfaceState(t *testing.T) {
	tests := []struct {
		name      string
		iface     string
		wantAddrs bool
		wantLink  bool // whether a link state was pushed at all
		wantUp    bool
	}{
		// The loopback stands in for a real interface: reading it needs no
		// privileges, and it exists in every namespace a test can run in.
		{"present interface", "lo", true, true, true},
		{"interface already gone", "goisis-absent0", false, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeSetter{circuits: []string{tt.iface}}
			resyncAll(t.Context(), f, slog.New(slog.DiscardHandler))

			if got := len(f.addrCalls) > 0; got != tt.wantAddrs {
				t.Errorf("addresses pushed = %v (calls %v), want %v", got, f.addrCalls, tt.wantAddrs)
			}
			up, ok := f.linkCalls[tt.iface]
			if ok != tt.wantLink {
				t.Fatalf("link state pushed = %v (calls %v), want %v", ok, f.linkCalls, tt.wantLink)
			}
			if ok && up != tt.wantUp {
				t.Errorf("%s reported up = %v, want %v", tt.iface, up, tt.wantUp)
			}
		})
	}
}

// signalSetter reports each address push on a channel, so a test can wait for
// the watcher goroutine instead of racing it.
type signalSetter struct{ addrs chan string }

func (s *signalSetter) ListCircuits(context.Context) ([]server.CircuitInfo, error) {
	return []server.CircuitInfo{{Interface: "lo"}}, nil
}

func (s *signalSetter) SetCircuitAddresses(_ context.Context, name string, _, _ []netip.Addr, _ []netip.Prefix) error {
	s.addrs <- name
	return nil
}

func (s *signalSetter) SetCircuitLinkState(context.Context, string, bool) error { return nil }

// TestWatchLoopResyncsOnTrigger: the periodic tick (and the subscription's
// ErrorCallback, which shares the channel) re-reads the watched interfaces
// without any event arriving, so a dropped RTM_NEWLINK or RTM_DELADDR is
// repaired within one interval instead of surviving until a restart.
func TestWatchLoopResyncsOnTrigger(t *testing.T) {
	s := &signalSetter{addrs: make(chan string, 1)}
	resync := make(chan struct{}, 1)
	go func() {
		_ = watchLoop(t.Context(), s, nil, nil, resync, slog.New(slog.DiscardHandler))
	}()

	resync <- struct{}{}
	select {
	case name := <-s.addrs:
		if name != "lo" {
			t.Errorf("resync pushed %q, want lo", name)
		}
	case <-time.After(time.Second):
		t.Fatal("watchLoop did not resync the watched interfaces on a tick")
	}
}
