//go:build linux

package config

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/takehaya/goisis/pkg/server"
)

// netlinkReceiveBufferSize sizes the subscription sockets' SO_RCVBUF. A burst
// (an address flush, a flapping link) that overruns the default buffer ends the
// subscription with ENOBUFS, and the watcher with it. The size is not forced:
// SO_RCVBUFFORCE needs CAP_NET_ADMIN, and refusing to start over a buffer hint
// would be worse than running with the kernel's rmem_max cap.
const netlinkReceiveBufferSize = 1 << 20

// resyncInterval is how often the watched interfaces are re-read even with no
// event pending. Netlink delivery is not guaranteed — a full receive buffer
// drops messages — and a lost RTM_NEWLINK leaves a circuit marked down for as
// long as the daemon runs: deaf and mute with no event left to repair it. The
// period is long because the re-read is a safety net, not the event path.
const resyncInterval = 30 * time.Second

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
// No dump is taken at startup: Options already read the addresses, and
// asserting a link state nobody asked about would risk tearing circuits down at
// boot over a driver that reports carrier late. After that, events are the
// fast path and the periodic re-read below is what makes a lost one survivable.
func WatchInterfaces(ctx context.Context, s *server.IsisServer, cfg *Config, logger *slog.Logger) error {
	watched := map[string]bool{}
	for _, cc := range cfg.Circuits {
		watched[cc.Interface] = true
	}

	// Closing done unsubscribes and lets the library's reader goroutines exit.
	done := make(chan struct{})
	defer close(done)

	// A resync re-reads state, so one pending request covers any number of
	// triggers and the extras are dropped. That also keeps the ErrorCallbacks,
	// which run on the library's reader goroutines, from ever blocking.
	resync := make(chan struct{}, 1)
	trigger := func() {
		select {
		case resync <- struct{}{}:
		default:
		}
	}

	addrCh := make(chan netlink.AddrUpdate, 64)
	if err := netlink.AddrSubscribeWithOptions(addrCh, done, netlink.AddrSubscribeOptions{
		ErrorCallback: func(err error) {
			logger.Warn("interface address subscription", "error", err)
			trigger() // the error is a message we did not get; re-read instead
		},
		ReceiveBufferSize: netlinkReceiveBufferSize,
	}); err != nil {
		return fmt.Errorf("subscribe to interface addresses: %w", err)
	}
	linkCh := make(chan netlink.LinkUpdate, 64)
	if err := netlink.LinkSubscribeWithOptions(linkCh, done, netlink.LinkSubscribeOptions{
		ErrorCallback: func(err error) {
			logger.Warn("interface link subscription", "error", err)
			trigger()
		},
		ReceiveBufferSize: netlinkReceiveBufferSize,
	}); err != nil {
		return fmt.Errorf("subscribe to link changes: %w", err)
	}

	ticker := time.NewTicker(resyncInterval)
	defer ticker.Stop()
	go func() {
		for {
			select {
			case <-ticker.C:
				trigger()
			case <-done: // closed when this function returns
				return
			}
		}
	}()

	return watchLoop(ctx, s, watched, addrCh, linkCh, resync, logger)
}

// watchLoop maps subscription events onto the server until ctx is done.
//
// A closed channel is how the library reports that its reader goroutine gave
// up (a Receive error such as ENOBUFS): the watcher is dead and no further
// event will ever arrive, so it is returned as an error for the same reason a
// failed subscribe is — a daemon that silently stops following link events
// looks healthy until the next cable pull. Ignoring the close is not an option
// either: the zero LinkUpdate has a nil Link and would panic in Attrs(), and
// the address case would spin on the closed channel.
func watchLoop(ctx context.Context, s circuitSetter, watched map[string]bool, addrCh <-chan netlink.AddrUpdate, linkCh <-chan netlink.LinkUpdate, resync <-chan struct{}, logger *slog.Logger) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-resync:
			resyncAll(ctx, s, watched, logger)
		case u, ok := <-addrCh:
			if !ok {
				return errors.New("interface address subscription closed")
			}
			ifi, err := net.InterfaceByIndex(u.LinkIndex)
			if err != nil {
				continue // the interface is already gone; the link event covers it
			}
			applyAddrEvent(ctx, s, watched, ifi.Name, logger)
		case u, ok := <-linkCh:
			if !ok {
				return errors.New("link subscription closed")
			}
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

// resyncAll re-reads every watched interface and pushes its state, repairing a
// circuit whose last event was dropped. The setters are idempotent, so a
// resync that finds nothing changed costs two no-ops per circuit.
//
// An interface the kernel no longer has is reported down, the same conclusion
// RTM_DELLINK carries — that message going missing is precisely what this
// repairs. Any other error means the state could not be read, not that it
// changed, so the interface is left alone rather than torn down on a transient
// netlink failure.
func resyncAll(ctx context.Context, s circuitSetter, watched map[string]bool, logger *slog.Logger) {
	for name := range watched {
		link, err := netlink.LinkByName(name)
		if err != nil {
			var notFound netlink.LinkNotFoundError
			if errors.As(err, &notFound) {
				applyLinkEvent(ctx, s, watched, name, false, logger)
				continue
			}
			logger.Warn("resync interface state", "circuit", name, "error", err)
			continue
		}
		applyLinkEvent(ctx, s, watched, name, linkUp(link.Attrs()), logger)
		applyAddrEvent(ctx, s, watched, name, logger)
	}
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
