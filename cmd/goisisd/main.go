// Command goisisd is the goisis IS-IS daemon.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"connectrpc.com/grpchealth"
	"connectrpc.com/grpcreflect"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sync/errgroup"

	"github.com/takehaya/goisis/gen/goisis/v1/goisisv1connect"
	"github.com/takehaya/goisis/internal/version"
	"github.com/takehaya/goisis/pkg/config"
	"github.com/takehaya/goisis/pkg/metrics"
	"github.com/takehaya/goisis/pkg/server"
)

func main() {
	apiListen := flag.String("api-listen", "127.0.0.1:50051", "listen address for the Connect/gRPC API: host:port, or unix:///absolute/path for a unix socket")
	apiAllowRemote := flag.Bool("api-allow-remote", false, "allow binding the API beyond loopback; the API has no authentication or TLS, so it must be protected externally (firewall, network isolation)")
	configFile := flag.String("f", "", "path to the configuration file")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	slog.SetDefault(logger)

	if err := run(logger, *apiListen, *apiAllowRemote, *configFile); err != nil {
		logger.Error("goisisd exited with error", "error", err)
		os.Exit(1)
	}
}

// parseAPIListen splits the -api-listen value into arguments for net.Listen.
// A "unix://" URL selects a unix socket; the path must be absolute, since a
// relative one would resolve against the daemon's working directory and leave
// clients guessing where the socket landed.
func parseAPIListen(addr string) (network, address string, err error) {
	path, ok := strings.CutPrefix(addr, "unix://")
	if !ok {
		return "tcp", addr, nil
	}
	if !filepath.IsAbs(path) {
		return "", "", fmt.Errorf("unix socket path must be absolute: %q", addr)
	}
	return "unix", path, nil
}

// listenAPI binds the management API. A unix socket is created with group-only
// permissions: filesystem permissions are the sole access control an
// unauthenticated API has. A socket left behind by a crash is removed first,
// but only when it really is a socket, so a mistyped path cannot delete data.
func listenAPI(addr string) (net.Listener, error) {
	network, address, err := parseAPIListen(addr)
	if err != nil {
		return nil, err
	}
	if network == "unix" {
		// Lstat, not Stat: a symlink planted at the path is not a stale socket
		// of ours, whatever it points at.
		if fi, err := os.Lstat(address); err == nil {
			if fi.Mode()&os.ModeSocket == 0 {
				return nil, fmt.Errorf("refusing to replace %s: not a socket", address)
			}
			if err := os.Remove(address); err != nil {
				return nil, err
			}
		}
		// Bind under a umask rather than chmod afterwards: a chmod leaves the
		// socket world-connectable between bind and chmod, and resolves the
		// path a second time. Umask is process-wide, but listenAPI runs once,
		// at startup, before the daemon creates anything else.
		defer syscall.Umask(syscall.Umask(0o117))
	}
	// net.Listen unlinks the socket again on Close, so shutdown needs no
	// cleanup of its own.
	ln, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}
	return ln, nil
}

// nonLoopbackAPI reports whether the API listen address is reachable from off
// the host. The Connect/gRPC API is unauthenticated plaintext h2c, so binding
// it beyond loopback (a specific external IP, an empty host, or 0.0.0.0/:: for
// all interfaces) exposes routing state and requires the explicit
// -api-allow-remote opt-in. A hostname or an unparseable address is left to the
// operator's judgment.
func nonLoopbackAPI(addr string) bool {
	network, address, err := parseAPIListen(addr)
	if err != nil || network != "tcp" {
		return false // a unix socket is reachable only from this host
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	if host == "" {
		return true // ":50051" binds every interface, exactly like 0.0.0.0
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return !ip.IsLoopback()
}

func run(logger *slog.Logger, apiListen string, apiAllowRemote bool, configFile string) error {
	if nonLoopbackAPI(apiListen) && !apiAllowRemote {
		return fmt.Errorf("refusing to bind the unauthenticated management API beyond loopback (%s); pass -api-allow-remote to accept the exposure", apiListen)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector())
	opts := []server.ServerOption{
		server.WithLogger(logger),
		server.WithMetrics(metrics.NewPrometheus(reg)),
	}
	var cfg *config.Config
	if configFile != "" {
		var err error
		cfg, err = config.Load(configFile)
		if err != nil {
			return err
		}
		cfgOpts, err := cfg.Options()
		if err != nil {
			return err
		}
		opts = append(opts, cfgOpts...)
	}

	isis, err := server.NewIsisServer(opts...)
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.Handle(server.NewConnectHandler(isis))
	reflector := grpcreflect.NewStaticReflector(goisisv1connect.IsisServiceName)
	mux.Handle(grpcreflect.NewHandlerV1(reflector))
	// Many tools (grpcurl among them) still speak the v1alpha reflection API.
	mux.Handle(grpcreflect.NewHandlerV1Alpha(reflector))
	mux.Handle(grpchealth.NewHandler(grpchealth.NewStaticChecker(goisisv1connect.IsisServiceName)))
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))

	// Plaintext HTTP/2 (h2c) so gRPC clients work without TLS.
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	// Request contexts derive from reqCtx; cancelling it on shutdown unblocks
	// long-lived streaming handlers (WatchEvent / `goisis monitor`) that would
	// otherwise keep Shutdown waiting for its full timeout.
	reqCtx, cancelReq := context.WithCancel(context.Background())
	defer cancelReq()
	httpServer := &http.Server{
		Handler:     mux,
		Protocols:   protocols,
		BaseContext: func(net.Listener) context.Context { return reqCtx },
	}

	listener, err := listenAPI(apiListen)
	if err != nil {
		return err
	}

	if nonLoopbackAPI(apiListen) {
		logger.Warn("the management API is unauthenticated plaintext but is bound beyond loopback; anyone who can reach it can read and modify routing state",
			"api", apiListen)
	}

	logger.Info("starting goisisd", "version", version.Version, "api", apiListen)

	// SIGHUP is handled even without -f: its default disposition kills the
	// process, and a daemon with nothing to re-read should not die of a reload
	// request. It is deliberately not part of the shutdown NotifyContext above.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)

	g, gctx := errgroup.WithContext(ctx)
	// The management loop runs on its own context and is stopped only after
	// the HTTP server has shut down, so RPCs draining during Shutdown can
	// still reach it instead of hanging on a dead loop.
	serveCtx, stopServe := context.WithCancel(context.Background())
	defer stopServe()
	g.Go(func() error {
		return isis.Serve(serveCtx)
	})
	if cfg != nil {
		// Follow interface address and link changes for the configured
		// circuits. A failure to subscribe is fatal: a daemon that silently
		// ignores link events looks healthy until the next cable pull.
		g.Go(func() error {
			return config.WatchInterfaces(gctx, isis, cfg, logger)
		})
	}
	g.Go(func() error {
		// The reload's own view of the running configuration. It never changes
		// the circuits, so the watcher's copy stays correct and this goroutine
		// shares nothing writable with it.
		running := cfg
		for {
			select {
			case <-gctx.Done():
				return nil
			case <-hup:
				if running == nil {
					logger.Warn("SIGHUP ignored: goisisd was started without -f")
					continue
				}
				next, err := config.Reload(gctx, isis, running, configFile, logger)
				if errors.Is(err, config.ErrPartiallyApplied) {
					// The two failures are not the same operational event: this
					// one has already changed the node, and no further signal
					// repairs it by itself.
					logger.Error("configuration reload was refused part way; the node is not in the state the file describes; fix the file and send SIGHUP again", "file", configFile, "error", err)
					continue
				}
				if err != nil {
					logger.Error("configuration reload failed; the running configuration is unchanged", "error", err)
					continue
				}
				running = next
				logger.Info("configuration reloaded", "file", configFile)
			}
		}
	})
	g.Go(func() error {
		if err := httpServer.Serve(listener); !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	})
	g.Go(func() error {
		<-gctx.Done()
		cancelReq() // unblock streaming handlers so Shutdown drains promptly
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			// A slow drain shouldn't fail the process exit; force-close any
			// lingering connections instead.
			logger.Warn("http server did not drain cleanly; forcing close", "error", err)
			_ = httpServer.Close()
		}
		stopServe()
		return nil
	})
	return g.Wait()
}
