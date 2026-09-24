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
	DefaultAdjacencyLimit    = 128
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
	// IPv4Addrs / IPv6Addrs are the circuit's interface addresses. Pass all of
	// them: they are advertised in two places, for two different jobs.
	// IPv4Addrs and the link-local IPv6 addresses go in hellos (TLV 132 / 232),
	// where a neighbor takes them as its next hop towards us — RFC 5308 3 keeps
	// the IIH link-local, so the global IPv6 addresses are filtered out of it.
	// Those instead go in TLV 232 of this node's own LSP, which is where a peer
	// looks for an on-link global address to point an End.X SID at.
	IPv4Addrs []netip.Addr
	IPv6Addrs []netip.Addr
	// ConnectedPrefixes are the circuit's directly-connected subnets. They are
	// originated at the circuit's metric and marked connected (as
	// WithAdvertisedPrefix + WithConnectedPrefix would), but stay attributable
	// to this circuit, so SetCircuitAddresses can withdraw exactly what the
	// circuit contributed when its addresses change.
	ConnectedPrefixes []netip.Prefix
	// Padding pads hellos toward the MTU (ISO 10589); default true.
	Padding *bool
	// AdjacencyLimit caps the number of neighbors this circuit takes on. At
	// the cap, hellos from a System ID the circuit holds no adjacency for are
	// dropped; the adjacencies it already has are untouched. nil selects
	// DefaultAdjacencyLimit and zero or negative disables the cap (the
	// convention WithLSDBEntryLimit uses) — a pointer, because the default is
	// not the zero value here. Every neighbor admitted costs an End.X SID, an
	// IS reachability entry, a RIB/FIB route and the netlink writes behind
	// them, and on an unauthenticated segment a station reaches Up merely by
	// echoing our SNPA; the LSDB cap bounds the database, not this.
	AdjacencyLimit *int
	// HelloPassword, if set, enables HMAC authentication of hellos on this
	// circuit: hellos are signed with it and received hellos must carry a
	// matching digest or they are dropped (no adjacency). HelloAuthAlgorithm
	// selects the HMAC algorithm (default HMAC-MD5, RFC 5304; FRR's `isis
	// password md5`); HelloKeyID is the RFC 5310 key identifier for the SHA
	// family (ignored for MD5). HelloAcceptPasswords are additional keys
	// accepted on received hellos (same algorithm and key ID) but never used
	// to sign: during a rotation a circuit keeps accepting the peer's old key
	// while it signs with the new one.
	HelloPassword        string
	HelloAuthAlgorithm   packet.AuthAlgorithm
	HelloKeyID           uint16
	HelloAcceptPasswords []string
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

// adjacencyLimit returns the resolved neighbor cap; zero or less is no cap.
func (c *CircuitConfig) adjacencyLimit() int {
	if c.AdjacencyLimit == nil {
		return DefaultAdjacencyLimit
	}
	return *c.AdjacencyLimit
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
	if err := requirePrimaryPassword(fmt.Sprintf("circuit %q hello authentication", c.Name), c.HelloPassword, c.HelloAcceptPasswords); err != nil {
		return err
	}
	return nil
}

// ServerOption configures an IsisServer.
type ServerOption func(*options)

// ValidateOptions reports whether NewIsisServer would accept this option set,
// building nothing and owning nothing. It runs every check that needs no
// transport; what it leaves out is the circuits, whose transport a restart
// alone can open (the LSP size the MTU dictates, and applyDefaults' nil-
// transport check). That split is what lets a configuration reload refuse a
// file a restart would refuse, without opening a socket per interface — see
// config.Diff.
func ValidateOptions(opts ...ServerOption) error {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	return o.validate()
}

// validate is the transport-free half of NewIsisServer's checks, kept in one
// place so the startup path and a reload cannot drift apart on what is valid.
func (o *options) validate() error {
	if err := requirePrimaryPassword("goisis: area authentication", o.areaAuth.Secret, o.areaAuth.AcceptSecrets); err != nil {
		return err
	}
	if err := requirePrimaryPassword("goisis: domain authentication", o.domainAuth.Secret, o.domainAuth.AcceptSecrets); err != nil {
		return err
	}
	for _, p := range o.prefixes {
		if err := checkAdvertisedPrefix(p); err != nil {
			return err
		}
	}
	participated := map[uint8]bool{}
	for _, fa := range o.flexAlgos {
		if fa.Algo < 128 {
			return fmt.Errorf("goisis: Flex-Algo %d is reserved; use 128-255", fa.Algo)
		}
		if participated[fa.Algo] {
			return fmt.Errorf("goisis: duplicate Flex-Algo %d configuration", fa.Algo)
		}
		participated[fa.Algo] = true
	}
	for _, lc := range o.locators {
		if a := lc.Prefix.Addr(); !a.Is6() || a.Is4In6() {
			return fmt.Errorf("goisis: SRv6 locator %s must be IPv6", lc.Prefix)
		}
		// A non-zero-algorithm locator is only reachable if the node also
		// participates in that Flex-Algo (advertises it in SR-Algorithm and
		// computes its topology); otherwise the locator is an unreachable black
		// hole. Require explicit participation rather than advertising silently.
		if lc.Algo != 0 && !participated[lc.Algo] {
			return fmt.Errorf("goisis: SRv6 locator %s is bound to Flex-Algo %d but the node does not participate in it (add WithFlexAlgo)", lc.Prefix, lc.Algo)
		}
	}
	return nil
}

// checkAdvertisedPrefix is the trust boundary on what this node originates:
// whatever passes is flooded area-wide and installed by every peer. The
// configuration and AddPrefix share it so that a file the daemon starts on is
// a file a reload of it can apply.
func checkAdvertisedPrefix(p AdvertisedPrefix) error {
	if !p.Prefix.IsValid() {
		return fmt.Errorf("goisis: prefix %s is not a valid prefix", p.Prefix)
	}
	want := p.Prefix.Masked()
	// Prefixes that no unicast forwarding entry can ever serve are refused
	// rather than advertised. The default route is not one of them:
	// default-information origination is legitimate, and suppressing it is
	// policy.advertise's job.
	if a := want.Addr(); a.Is4In6() || a.IsMulticast() || a.IsLinkLocalUnicast() || (a.IsUnspecified() && want.Bits() != 0) {
		return fmt.Errorf("goisis: prefix %s is not routable; multicast, unspecified, link-local and IPv4-mapped prefixes are never originated", want)
	}
	// RFC 5305 §4: a metric at or above the ceiling means "not reachable",
	// so advertising one would be a black hole no SPF would ever use.
	if p.Metric >= maxPathMetric {
		return fmt.Errorf("goisis: prefix %s metric %d is at or above the reachability ceiling %d", want, p.Metric, uint32(maxPathMetric))
	}
	return nil
}

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
	l2LeakFilter      AdvertiseFilter
	fibFilter         FIBFilter
	lsdbEntryLimit    int
	lspMTU            int
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
// key; an empty Secret disables authentication for the scope. AcceptSecrets are
// additional keys accepted on receive but never used to sign, so a key can be
// rotated node by node instead of everywhere at once.
type AuthConfig struct {
	Algorithm     packet.AuthAlgorithm
	KeyID         uint16
	Secret        string
	AcceptSecrets []string
}

// spec resolves an AuthConfig to an internal authSpec.
func (a AuthConfig) spec() authSpec {
	if a.Secret == "" {
		return authSpec{}
	}
	return authSpec{algo: a.Algorithm, keyID: a.KeyID, key: []byte(a.Secret), acceptKeys: acceptKeys(a.AcceptSecrets)}
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

// WithL2LeakFilter turns on Level-2 to Level-1 route leaking (ISO 10589 7.2.9,
// RFC 5305 §4.1 / RFC 5308 §2) and gates it: an L1L2 node originates the
// Level-2 prefixes for which f returns true into its Level-1 LSP, with the
// up/down bit set so nobody sends them back up. Leaking is off when this option
// is absent — pushing a whole Level-2 table into an area is an operator's
// decision, not a default. f is the only gate on leaked prefixes; the
// AdvertiseFilter governs what this node originates of its own.
func WithL2LeakFilter(f AdvertiseFilter) ServerOption {
	return func(o *options) { o.l2LeakFilter = f }
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
// reachability, its route is computed over the algorithm's pruned topology, and
// its End.X SIDs go only to adjacencies that participate in the algorithm.
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

// WithLSDBEntryLimit caps the number of LSPs held per level. Once a level's
// database holds n entries, LSPs with previously-unseen LSP IDs are dropped
// (updates to known IDs and this node's own LSPs are unaffected). This is a
// defense-in-depth guard against LSDB exhaustion by an attacker flooding
// fabricated source IDs on an unauthenticated segment — authentication
// (WithAreaAuth / WithDomainAuth) is the primary mitigation. Zero or negative
// disables the cap (the default). Size the limit well above the legitimate
// area's LSP count: a dropped legitimate LSP means an incomplete topology.
func WithLSDBEntryLimit(n int) ServerOption {
	return func(o *options) { o.lsdbEntryLimit = n }
}

// minLSPMTU is the smallest LSP size this node will originate into. ISO 10589
// requires every LSP to carry the fixed header plus the area-address and
// protocols-supported TLVs, so anything near that leaves no room for
// reachability; 512 is a floor below which the configuration is a mistake
// rather than a tight link.
const minLSPMTU = 512

// WithLSPMTU caps the size of the LSPs this node originates. Zero (the
// default) derives the cap from the circuits — the smallest circuit MTU less
// the 3-octet LLC header, itself capped at the architectural 1492-octet
// receive buffer. Set it when an interface MTU overstates what the path
// actually carries (a tunnel that fragments, an overlay adding headers);
// FRR spells the same knob `lsp-mtu`. NewIsisServer rejects a resulting cap
// below 512 octets.
func WithLSPMTU(n int) ServerOption {
	return func(o *options) { o.lspMTU = n }
}

// WithOverloadOnStartup sets the overload bit (ISO 10589) in this node's own
// LSP for the given duration after startup, then clears it. While set, peers
// keep the node reachable for its own prefixes but route no transit traffic
// through it — giving routes time to settle (e.g. a BGP load) before the node
// carries transit. A zero or negative duration disables the behavior.
func WithOverloadOnStartup(d time.Duration) ServerOption {
	return func(o *options) { o.overloadOnStartup = d }
}
