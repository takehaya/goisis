//go:build !linux

package config

import (
	"context"
	"log/slog"

	"github.com/takehaya/goisis/pkg/server"
)

// WatchInterfaces does nothing off Linux: there is no netlink to subscribe to,
// and an embedder on another platform owns the event source itself (see
// IsisServer.SetCircuitAddresses / SetCircuitLinkState).
func WatchInterfaces(_ context.Context, _ *server.IsisServer, _ *Config, _ *slog.Logger) error {
	return nil
}
