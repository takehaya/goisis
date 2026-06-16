package server

import (
	"fmt"
	"log/slog"
	"math"
	"net/netip"
	"time"

	"github.com/takehaya/goisis/pkg/datalink"
	"github.com/takehaya/goisis/pkg/fib"
	"github.com/takehaya/goisis/pkg/packet"
)

// MaxPriority is the largest legal DIS priority (the wire field is 7 bits).
const MaxPriority = 127

// Defaults for circuit timers and DIS priority (ISO 10589 / FRR-compatible).
const (
	DefaultHelloInterval     = 3 * time.Second
	DefaultHoldingMultiplier = 10
	DefaultPriority          = 64
	DefaultMetric            = 10
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
	// HelloPassword, if set, enables HMAC authentication of hellos on this
	// circuit: hellos are signed with it and received hellos must carry a
	// matching digest or they are dropped (no adjacency). HelloAuthAlgorithm
	// selects the HMAC algorithm (default HMAC-MD5, RFC 5304; FRR's `isis
	// password md5`); HelloKeyID is the RFC 5310 key identifier for the SHA
	// family (ignored for MD5).
	HelloPassword      string
	HelloAuthAlgorithm packet.AuthAlgorithm
	HelloKeyID         uint16
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
		c.Metric = DefaultMetric
	}
	return nil
}

// ServerOption configures an IsisServer.
type ServerOption func(*options)

// AdvertisedPrefix is a prefix originated in this node's LSP (TLV 135/236).
type AdvertisedPrefix struct {
	Prefix netip.Prefix
	Metric uint32
}

// SRv6LocatorConfig is an SRv6 locator advertised by this node. goisis
// advertises it in the SRv6 Locator TLV (27), mirrors it into IPv6
// reachability (TLV 236) for legacy interop, originates an End SID at the
// locator's base address, and installs that End SID as a local seg6local
// route.
type SRv6LocatorConfig struct {
	Prefix netip.Prefix
	// Algo is the algorithm the locator is advertised for: 0 (normal SPF) or a
	// Flexible Algorithm (128-255). A non-zero algorithm makes the locator a
	// Flex-Algo locator: it is not mirrored into IPv6 reachability and its
	// route is computed over that algorithm's topology.
	Algo uint8
}

// endSID returns the locator's local End SID (its base address).
func (l SRv6LocatorConfig) endSID() netip.Addr { return l.Prefix.Masked().Addr() }

// sidStructure returns the SID structure advertised for the End SID: a 32-bit
// locator block, the remaining locator bits as the node, and a function that
// fills the rest of the 128-bit SID (16 bits where there is room). This
// matches FRR's default SRv6 SID layout for a /48 (block 32, node 16, func 16)
// while keeping block+node+function+argument <= 128 for longer locators.
func (l SRv6LocatorConfig) sidStructure() *packet.SIDStructure {
	bits := l.Prefix.Bits()
	block := 32
	if bits < block {
		block = bits
	}
	node := bits - block
	function := 16
	if block+node+function > 128 {
		function = 128 - block - node // never negative: block+node == bits <= 128
	}
	return &packet.SIDStructure{
		LocatorBlock: uint8(block),    //nolint:gosec // 0..128
		LocatorNode:  uint8(node),     //nolint:gosec // 0..128
		Function:     uint8(function), //nolint:gosec // 0..128
		Argument:     0,
	}
}

// locatorEntry builds the SRv6 Locator TLV entry advertised for this locator,
// including its local End SID at the locator's base address.
func (l SRv6LocatorConfig) locatorEntry() packet.SRv6Locator {
	return packet.SRv6Locator{
		Metric:    0,
		Algorithm: l.Algo,
		Locator:   l.Prefix.Masked(),
		EndSIDs: []*packet.SRv6EndSID{{
			Behavior:  packet.SRv6BehaviorEnd,
			SID:       l.endSID(),
			Structure: l.sidStructure(),
		}},
	}
}

// FlexAlgoConfig defines a Flexible Algorithm (RFC 9350) this node
// participates in and (optionally) advertises a definition for.
type FlexAlgoConfig struct {
	// Algo is the Flexible Algorithm number (128-255).
	Algo uint8
	// MetricType selects how path cost is measured (packet.FlexAlgoMetric*).
	// goisis computes the IGP metric initially; others are advertised so the
	// definition and winner election match peers.
	MetricType uint8
	// Priority is this node's advertised priority for the winner election
	// (higher wins; ties broken by higher System ID).
	Priority uint8
	// AdvertiseDefinition controls whether this node advertises the FAD. A
	// node may participate (compute paths for the algo) without advertising a
	// definition; at least one node in the area must advertise it.
	AdvertiseDefinition bool
}

type options struct {
	logger            *slog.Logger
	systemID          packet.SystemID
	areaAddrs         []packet.AreaAddress
	hostname          string
	circuits          []CircuitConfig
	prefixes          []AdvertisedPrefix
	connected         []netip.Prefix
	locators          []SRv6LocatorConfig
	flexAlgos         []FlexAlgoConfig
	fib               fib.FIB
	metrics           Metrics
	overloadOnStartup time.Duration
	areaAuth          AuthConfig // L1 LSP/SNP authentication
	domainAuth        AuthConfig // L2 LSP/SNP authentication
	advertiseFilter   AdvertiseFilter
	fibFilter         FIBFilter
	hasSystemID       bool
}

// AdvertiseFilter decides whether a configured prefix is originated into this
// node's LSP (TLV 135/236). Returning false suppresses the advertisement; the
// IS-IS flooding and LSDB are untouched, so the area stays consistent. A nil
// filter advertises everything. This is the IGP equivalent of an export policy
// — it gates only what this node originates, never what it floods.
type AdvertiseFilter func(AdvertisedPrefix) bool

// FIBFilter decides whether a computed route is programmed into the FIB.
// Returning false keeps the route in the RIB (ListRoutes and WatchEvent still
// report it) but does not write it to the forwarding plane — the IS-IS
// equivalent of "in the RIB but not the FIB". A nil filter programs everything.
type FIBFilter func(RouteInfo) bool

// AuthConfig describes an HMAC authentication key for one scope. Algorithm
// selects HMAC-MD5 (RFC 5304, the default) or an HMAC-SHA variant (RFC 5310);
// KeyID is the RFC 5310 key identifier (ignored for MD5). Secret is the shared
// key; an empty Secret disables authentication for the scope.
type AuthConfig struct {
	Algorithm packet.AuthAlgorithm
	KeyID     uint16
	Secret    string
}

// spec resolves an AuthConfig to an internal authSpec.
func (a AuthConfig) spec() authSpec {
	if a.Secret == "" {
		return authSpec{}
	}
	return authSpec{algo: a.Algorithm, keyID: a.KeyID, key: []byte(a.Secret)}
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

// WithAdvertisedPrefix originates a prefix in this node's LSP. The metric
// defaults to 0 when unset.
func WithAdvertisedPrefix(prefix netip.Prefix, metric uint32) ServerOption {
	return func(o *options) {
		o.prefixes = append(o.prefixes, AdvertisedPrefix{Prefix: prefix, Metric: metric})
	}
}

// WithFIB sets the forwarding sink that SPF results are programmed into.
// Defaults to fib.Noop.
func WithFIB(f fib.FIB) ServerOption {
	return func(o *options) { o.fib = f }
}

// WithAdvertiseFilter installs an export policy: only prefixes for which f
// returns true are originated into this node's LSP. Flooding and the LSDB are
// not affected, so the area's link-state databases stay consistent. See
// AdvertiseFilter.
func WithAdvertiseFilter(f AdvertiseFilter) ServerOption {
	return func(o *options) { o.advertiseFilter = f }
}

// WithFIBFilter installs a FIB policy: only routes for which f returns true are
// programmed into the forwarding plane. Filtered routes remain visible in the
// RIB (ListRoutes, WatchEvent), so a watch-only consumer can still act on them.
// See FIBFilter.
func WithFIBFilter(f FIBFilter) ServerOption {
	return func(o *options) { o.fibFilter = f }
}

// WithMetrics sets the observability sink. Defaults to NoopMetrics. Wire a
// Prometheus collector with pkg/metrics, or supply a custom implementation.
func WithMetrics(m Metrics) ServerOption {
	return func(o *options) { o.metrics = m }
}

// WithConnectedPrefix marks a prefix as directly connected: it is never
// installed into the FIB (the kernel already has the connected route), even
// when a neighbor also advertises it.
func WithConnectedPrefix(prefix netip.Prefix) ServerOption {
	return func(o *options) { o.connected = append(o.connected, prefix.Masked()) }
}

// WithSRv6Locator advertises an SRv6 locator from this node. The locator is
// announced in the SRv6 Locator TLV (27) with a local End SID, mirrored into
// IPv6 reachability (TLV 236) for legacy interop, and — when a FIB is
// configured — installed as a local End SID seg6local route. The node also
// advertises the SRv6 Capabilities sub-TLV in its Router Capability TLV (242).
func WithSRv6Locator(prefix netip.Prefix) ServerOption {
	return func(o *options) { o.locators = append(o.locators, SRv6LocatorConfig{Prefix: prefix}) }
}

// WithSRv6LocatorForAlgo advertises an SRv6 locator bound to a Flexible
// Algorithm (algo 128-255). Unlike a plain locator it is not mirrored into IPv6
// reachability, and its route is computed over the algorithm's pruned topology.
func WithSRv6LocatorForAlgo(prefix netip.Prefix, algo uint8) ServerOption {
	return func(o *options) { o.locators = append(o.locators, SRv6LocatorConfig{Prefix: prefix, Algo: algo}) }
}

// WithFlexAlgo makes this node participate in a Flexible Algorithm (RFC 9350):
// the algorithm is listed in the SR-Algorithm sub-TLV (19), and — when
// AdvertiseDefinition is set — its definition is advertised in the FAD sub-TLV
// (26), both in the Router Capability TLV (242).
func WithFlexAlgo(cfg FlexAlgoConfig) ServerOption {
	return func(o *options) { o.flexAlgos = append(o.flexAlgos, cfg) }
}

// WithAreaPassword enables HMAC-MD5 authentication (RFC 5304) of Level-1 LSPs
// and SNPs with the given key (FRR's `area-password md5`). Received L1 LSPs/SNPs
// must carry a matching digest or they are dropped. For HMAC-SHA (RFC 5310) use
// WithAreaAuth.
func WithAreaPassword(pw string) ServerOption {
	return func(o *options) { o.areaAuth = AuthConfig{Secret: pw} }
}

// WithDomainPassword enables HMAC-MD5 authentication (RFC 5304) of Level-2 LSPs
// and SNPs with the given key (FRR's `domain-password md5`).
func WithDomainPassword(pw string) ServerOption {
	return func(o *options) { o.domainAuth = AuthConfig{Secret: pw} }
}

// WithAreaAuth enables authentication of Level-1 LSPs/SNPs with an explicit
// algorithm (HMAC-MD5 or an HMAC-SHA variant) and key ID.
func WithAreaAuth(cfg AuthConfig) ServerOption {
	return func(o *options) { o.areaAuth = cfg }
}

// WithDomainAuth enables authentication of Level-2 LSPs/SNPs with an explicit
// algorithm and key ID.
func WithDomainAuth(cfg AuthConfig) ServerOption {
	return func(o *options) { o.domainAuth = cfg }
}

// WithOverloadOnStartup sets the overload bit (ISO 10589) in this node's own
// LSP for the given duration after startup, then clears it. While set, peers
// keep the node reachable for its own prefixes but route no transit traffic
// through it — giving routes time to settle (e.g. a BGP load) before the node
// carries transit. A zero or negative duration disables the behavior.
func WithOverloadOnStartup(d time.Duration) ServerOption {
	return func(o *options) { o.overloadOnStartup = d }
}
