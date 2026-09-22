//go:build linux

package config

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/takehaya/goisis/pkg/server"
)

// circuitSetter is the part of *server.IsisServer the watcher drives. It exists
// so the event mapping can be exercised without opening a netlink socket.
type circuitSetter interface {
	SetCircuitAddresses(ctx context.Context, name string, v4, v6 []netip.Addr, connected []netip.Prefix) error
	SetCircuitLinkState(ctx context.Context, name string, up bool) error
}

// WatchInterfaces follows address and link changes on the configured circuits
// and pushes them into the server, so an address added or removed after startup
// reaches the hellos (TLV 132 / 232) and the originated connected prefixes, and
// a link losing carrier tears its adjacencies down at once instead of after the
// neighbor's holding time. It returns when ctx is done.
//
// Subscribing is done before the loop and its failure is returned: a daemon
// that silently ignores link events is worse than one that refuses to start —
// the operator would find out at the next cable pull.
//
// Only changes are followed, never a dump of the current state: Options already
// read the addresses, and asserting a link state nobody asked about would risk
// tearing circuits down at boot over a driver that reports carrier late.
func WatchInterfaces(ctx context.Context, s *server.IsisServer, cfg *Config, logger *slog.Logger) error {
	watched := map[string]bool{}
	for _, cc := range cfg.Circuits {
		watched[cc.Interface] = true
	}

	// Closing done unsubscribes and lets the library's reader goroutines exit.
	done := make(chan struct{})
	defer close(done)

	addrCh := make(chan netlink.AddrUpdate, 64)
	if err := netlink.AddrSubscribeWithOptions(addrCh, done, netlink.AddrSubscribeOptions{
		ErrorCallback: func(err error) { logger.Warn("interface address subscription", "error", err) },
	}); err != nil {
		return fmt.Errorf("subscribe to interface addresses: %w", err)
	}
	linkCh := make(chan netlink.LinkUpdate, 64)
	if err := netlink.LinkSubscribeWithOptions(linkCh, done, netlink.LinkSubscribeOptions{
		ErrorCallback: func(err error) { logger.Warn("interface link subscription", "error", err) },
	}); err != nil {
		return fmt.Errorf("subscribe to link changes: %w", err)
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case u := <-addrCh:
			ifi, err := net.InterfaceByIndex(u.LinkIndex)
			if err != nil {
				continue // the interface is already gone; the link event covers it
			}
			applyAddrEvent(ctx, s, watched, ifi.Name, logger)
		case u := <-linkCh:
			attrs := u.Attrs()
			// A deleted link carries its last flags, which usually still say
			// up; the message type is the only signal that it is gone.
			up := u.Header.Type != unix.RTM_DELLINK && linkUp(attrs)
			applyLinkEvent(ctx, s, watched, attrs.Name, up, logger)
		}
	}
}

// linkUp reports whether an interface can carry traffic. RFC 2863 operational
// state is what an IGP wants: IFF_UP alone stays set through a cable pull, so
// it would never report the failure this watcher exists for. Devices that do
// not track carrier (tunnels, tap devices) report OperUnknown, and for those
// the administrative flag is all there is.
func linkUp(attrs *netlink.LinkAttrs) bool {
	if attrs.OperState == netlink.OperUnknown {
		return attrs.Flags&net.FlagUp != 0
	}
	return attrs.OperState == netlink.OperUp
}

// applyAddrEvent re-reads the interface's addresses and pushes them to the
// server. Netlink reports one change as several messages, and re-reading is
// both cheap and idempotent (an unchanged set is a no-op on the server), so
// every event is handled rather than debounced.
func applyAddrEvent(ctx context.Context, s circuitSetter, watched map[string]bool, name string, logger *slog.Logger) {
	if !watched[name] {
		return
	}
	v4, v6 := interfaceAddrs(name)
	if err := s.SetCircuitAddresses(ctx, name, v4, v6, connectedPrefixes(name)); err != nil {
		logger.Warn("apply interface address change", "circuit", name, "error", err)
	}
}

// applyLinkEvent pushes an interface's carrier state to the server.
func applyLinkEvent(ctx context.Context, s circuitSetter, watched map[string]bool, name string, up bool, logger *slog.Logger) {
	if !watched[name] {
		return
	}
	if err := s.SetCircuitLinkState(ctx, name, up); err != nil {
		logger.Warn("apply interface link change", "circuit", name, "error", err)
	}
}
