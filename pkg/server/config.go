package server

import (
	"fmt"
	"log/slog"
	"math"
	"net/netip"
	"time"

	"github.com/takehaya/goisis/pkg/datalink"
	"github.com/takehaya/goisis/pkg/packet"
)

// MaxPriority is the largest legal DIS priority (the wire field is 7 bits).
const MaxPriority = 127

// Defaults for circuit timers and DIS priority (ISO 10589 / FRR-compatible).
const (
	DefaultHelloInterval     = 3 * time.Second
	DefaultHoldingMultiplier = 10
	DefaultPriority          = 64
	housekeepInterval        = 1 * time.Second
)

// CircuitConfig describes one IS-IS circuit. The Transport is injected so
// the daemon supplies an AF_PACKET transport while tests supply a mock.
type CircuitConfig struct {
	// Name identifies the circuit (the interface name for AF_PACKET).
	Name string
	// Transport carries PDUs for this circuit.
	Transport datalink.Transport
	// P2P selects point-to-point procedures (RFC 5303 three-way) instead of
	// broadcast/DIS procedures.
	P2P bool
	// Level1/Level2 enable the respective levels on this circuit.
	Level1 bool
	Level2 bool
	// Priority is the DIS election priority on broadcast circuits (0-127).
	// nil selects the default; a pointer is used so an explicit priority of
	// 0 (least willing to be DIS) is distinguishable from "unset".
	Priority *uint8
	// HelloInterval is the time between hellos.
	HelloInterval time.Duration
	// HoldingMultiplier sets the advertised holding time to
	// HelloInterval * HoldingMultiplier.
	HoldingMultiplier int
	// Metric is the circuit's wide metric (used from M4 onward).
	Metric uint32
	// IPv4Addrs / IPv6Addrs are advertised in hellos (TLV 132 / 232). For
	// hellos the IPv6 addresses should be link-local.
	IPv4Addrs []netip.Addr
	IPv6Addrs []netip.Addr
	// Padding pads hellos toward the MTU (ISO 10589); default true.
	Padding *bool
}

func (c *CircuitConfig) levels() []packet.Level {
	var ls []packet.Level
	if c.Level1 {
		ls = append(ls, packet.Level1)
	}
	if c.Level2 {
		ls = append(ls, packet.Level2)
	}
	return ls
}

func (c *CircuitConfig) circuitType() packet.CircuitType {
	switch {
	case c.Level1 && c.Level2:
		return packet.CircuitTypeLevel12
	case c.Level2:
		return packet.CircuitTypeLevel2
	default:
		return packet.CircuitTypeLevel1
	}
}

func (c *CircuitConfig) holdingTime() uint16 {
	// Compute the full duration before converting to seconds, so a
	// fractional-second hello interval is not truncated away by the
	// multiplier (e.g. 1500ms * 10 = 15s, not 10s).
	hold := c.HelloInterval * time.Duration(c.HoldingMultiplier)
	secs := int(math.Ceil(hold.Seconds()))
	if secs < 1 {
		secs = 1
	}
	if secs > 0xffff {
		secs = 0xffff
	}
	return uint16(secs) //nolint:gosec // clamped above
}

// priority returns the resolved DIS priority (defaults applied).
func (c *CircuitConfig) priority() uint8 {
	if c.Priority == nil {
		return DefaultPriority
	}
	return *c.Priority
}

func (c *CircuitConfig) padding() bool {
	return c.Padding == nil || *c.Padding
}

func (c *CircuitConfig) applyDefaults() error {
	if c.Name == "" {
		return fmt.Errorf("circuit: empty name")
	}
	if c.Transport == nil {
		return fmt.Errorf("circuit %q: nil transport", c.Name)
	}
	if !c.Level1 && !c.Level2 {
		c.Level1, c.Level2 = true, true
	}
	if c.Priority != nil && *c.Priority > MaxPriority {
		return fmt.Errorf("circuit %q: priority %d exceeds %d", c.Name, *c.Priority, MaxPriority)
	}
	if c.HelloInterval == 0 {
		c.HelloInterval = DefaultHelloInterval
	}
	if c.HoldingMultiplier == 0 {
		c.HoldingMultiplier = DefaultHoldingMultiplier
	}
	if c.Metric == 0 {
		c.Metric = 10
	}
	return nil
}

// ServerOption configures an IsisServer.
type ServerOption func(*options)

type options struct {
	logger      *slog.Logger
	systemID    packet.SystemID
	areaAddrs   []packet.AreaAddress
	hostname    string
	circuits    []CircuitConfig
	hasSystemID bool
}

// WithLogger sets the logger used by the server. Defaults to slog.Default().
func WithLogger(l *slog.Logger) ServerOption {
	return func(o *options) { o.logger = l }
}

// WithSystemID sets the 6-octet IS-IS system identifier.
func WithSystemID(id packet.SystemID) ServerOption {
	return func(o *options) { o.systemID = id; o.hasSystemID = true }
}

// WithAreaAddresses sets the area addresses (from the NET).
func WithAreaAddresses(areas ...packet.AreaAddress) ServerOption {
	return func(o *options) { o.areaAddrs = areas }
}

// WithHostname sets the dynamic hostname advertised in LSPs (RFC 5301).
func WithHostname(name string) ServerOption {
	return func(o *options) { o.hostname = name }
}

// WithCircuit adds a circuit to the server.
func WithCircuit(cfg CircuitConfig) ServerOption {
	return func(o *options) { o.circuits = append(o.circuits, cfg) }
}
