// Package config loads a goisisd configuration file and translates it into
// server options. The schema is intentionally small for now; richer,
// API-driven configuration is planned for a later milestone.
package config

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"golang.org/x/sys/unix"

	"github.com/takehaya/goisis/pkg/datalink"
	"github.com/takehaya/goisis/pkg/fib"
	"github.com/takehaya/goisis/pkg/packet"
	"github.com/takehaya/goisis/pkg/server"
)

// Config is the goisisd file configuration.
type Config struct {
	NET      string           `yaml:"net"`
	Hostname string           `yaml:"hostname"`
	FIB      bool             `yaml:"fib"`
	Circuits []CircuitConfig  `yaml:"circuits"`
	Prefixes []string         `yaml:"prefixes"`
	SRv6     *SRv6Config      `yaml:"srv6"`
	FlexAlgo []FlexAlgoConfig `yaml:"flex-algo"`
	// Policy filters which prefixes are originated (advertise) and which
	// computed routes are programmed into the FIB (fib).
	Policy *PolicyConfig `yaml:"policy"`
	// OverloadOnStartup, if set (a Go duration like "30s"), sets the overload
	// bit for that long after startup.
	OverloadOnStartup string `yaml:"overload-on-startup"`
	// AreaPassword / DomainPassword enable authentication of Level-1 / Level-2
	// LSPs and SNPs. The algorithm defaults to HMAC-MD5 (RFC 5304); set
	// *-auth-algorithm to an HMAC-SHA variant (RFC 5310) with a *-key-id.
	AreaPassword        string `yaml:"area-password"`
	AreaAuthAlgorithm   string `yaml:"area-auth-algorithm"`
	AreaKeyID           uint16 `yaml:"area-key-id"`
	DomainPassword      string `yaml:"domain-password"`
	DomainAuthAlgorithm string `yaml:"domain-auth-algorithm"`
	DomainKeyID         uint16 `yaml:"domain-key-id"`
	// LSDBEntryLimit caps the number of LSPs held per level as a
	// defense-in-depth guard against LSDB exhaustion; zero or negative
	// disables the cap. Size it well above the legitimate area's LSP count.
	LSDBEntryLimit int `yaml:"lsdb-entry-limit"`
	// OpenCircuit, when non-nil, replaces how Options opens each circuit's
	// transport and reads its hello source addresses — the only impure part
	// of Options (the default opens an AF_PACKET socket on the interface).
	// Instance-scoped so tests and embedders can supply mock transports; not
	// part of the YAML schema.
	OpenCircuit func(ifname string) (tr datalink.Transport, v4, v6 []netip.Addr, err error) `yaml:"-"`
}

// SRv6Config configures SRv6 locator advertisement.
type SRv6Config struct {
	// Locators are IPv6 locator prefixes advertised in the SRv6 Locator TLV.
	Locators []string `yaml:"locators"`
}

// FlexAlgoConfig configures one Flexible Algorithm (RFC 9350).
type FlexAlgoConfig struct {
	// Algo is the Flexible Algorithm number (128-255).
	Algo uint8 `yaml:"algo"`
	// MetricType is "igp" (default), "delay", or "te".
	MetricType string `yaml:"metric-type"`
	// Priority is the advertised election priority.
	Priority uint8 `yaml:"priority"`
	// Advertise controls whether this node advertises the FAD definition.
	Advertise bool `yaml:"advertise"`
	// Locator, if set, is an SRv6 locator advertised bound to this algorithm.
	Locator string `yaml:"locator"`
}

// PolicyConfig configures prefix-list route policy. Advertise gates which
// prefixes are originated; FIB gates which computed routes are programmed into
// the forwarding plane (filtered routes stay in the RIB).
type PolicyConfig struct {
	Advertise *PrefixListConfig `yaml:"advertise"`
	FIB       *PrefixListConfig `yaml:"fib"`
}

// PrefixListConfig is an ordered prefix-list. Each rule is "permit: CIDR" or
// "deny: CIDR" with optional ge/le length bounds. The first matching rule wins;
// when none match, Default ("permit" or "deny") decides — an unset Default is
// "deny" (so a list of permit rules is an allowlist).
type PrefixListConfig struct {
	Default string             `yaml:"default"`
	Rules   []PrefixRuleConfig `yaml:"rules"`
}

// PrefixRuleConfig is one prefix-list rule. Exactly one of Permit/Deny is the
// CIDR to match; GE/LE bound the matched prefix length.
type PrefixRuleConfig struct {
	Permit string `yaml:"permit"`
	Deny   string `yaml:"deny"`
	GE     int    `yaml:"ge"`
	LE     int    `yaml:"le"`
}

// CircuitConfig configures one circuit.
type CircuitConfig struct {
	Interface string `yaml:"interface"`
	Level     string `yaml:"level"` // "1", "2", or "12" (default "12")
	P2P       bool   `yaml:"p2p"`
	Priority  *uint8 `yaml:"priority"`
	Metric    uint32 `yaml:"metric"`
	// HelloPassword enables HMAC authentication of hellos. The algorithm
	// defaults to HMAC-MD5 (RFC 5304); hello-auth-algorithm selects an HMAC-SHA
	// variant (RFC 5310) with hello-key-id.
	HelloPassword      string `yaml:"hello-password"`
	HelloAuthAlgorithm string `yaml:"hello-auth-algorithm"`
	HelloKeyID         uint16 `yaml:"hello-key-id"`
}

// Load reads and parses a configuration file.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("config %q: %w", path, err)
	}
	if c.NET == "" {
		return nil, fmt.Errorf("config %q: net is required", path)
	}
	if len(c.Circuits) == 0 {
		return nil, fmt.Errorf("config %q: at least one circuit is required", path)
	}
	return &c, nil
}

// Options translates the configuration into server options, opening an
// AF_PACKET transport per circuit and reading interface addresses for hellos.
func (c *Config) Options() ([]server.ServerOption, error) {
	area, sysID, err := packet.ParseNET(c.NET)
	if err != nil {
		return nil, err
	}
	opts := []server.ServerOption{
		server.WithSystemID(sysID),
		server.WithAreaAddresses(area),
	}
	if c.Hostname != "" {
		opts = append(opts, server.WithHostname(c.Hostname))
	}
	if c.FIB {
		opts = append(opts, server.WithFIB(fib.NewNetlink(unix.RT_TABLE_MAIN)))
	}
	for _, p := range c.Prefixes {
		prefix, err := netip.ParsePrefix(p)
		if err != nil {
			return nil, fmt.Errorf("prefix %q: %w", p, err)
		}
		opts = append(opts, server.WithAdvertisedPrefix(prefix, 10))
	}
	if c.SRv6 != nil {
		for _, l := range c.SRv6.Locators {
			prefix, err := netip.ParsePrefix(l)
			if err != nil {
				return nil, fmt.Errorf("srv6 locator %q: %w", l, err)
			}
			opts = append(opts, server.WithSRv6Locator(prefix))
		}
	}
	for _, fa := range c.FlexAlgo {
		mt, err := flexAlgoMetricType(fa.MetricType)
		if err != nil {
			return nil, fmt.Errorf("flex-algo %d: %w", fa.Algo, err)
		}
		opts = append(opts, server.WithFlexAlgo(server.FlexAlgoConfig{
			Algo:                fa.Algo,
			MetricType:          mt,
			Priority:            fa.Priority,
			AdvertiseDefinition: fa.Advertise,
		}))
		if fa.Locator != "" {
			prefix, err := netip.ParsePrefix(fa.Locator)
			if err != nil {
				return nil, fmt.Errorf("flex-algo %d locator %q: %w", fa.Algo, fa.Locator, err)
			}
			opts = append(opts, server.WithSRv6LocatorForAlgo(prefix, fa.Algo))
		}
	}
	if c.LSDBEntryLimit > 0 {
		opts = append(opts, server.WithLSDBEntryLimit(c.LSDBEntryLimit))
	}
	if c.OverloadOnStartup != "" {
		d, err := time.ParseDuration(c.OverloadOnStartup)
		if err != nil {
			return nil, fmt.Errorf("overload-on-startup %q: %w", c.OverloadOnStartup, err)
		}
		opts = append(opts, server.WithOverloadOnStartup(d))
	}
	if c.Policy != nil {
		if c.Policy.Advertise != nil {
			pl, err := c.Policy.Advertise.prefixList()
			if err != nil {
				return nil, fmt.Errorf("policy.advertise: %w", err)
			}
			opts = append(opts, server.WithAdvertiseFilter(pl.AdvertiseFilter()))
		}
		if c.Policy.FIB != nil {
			pl, err := c.Policy.FIB.prefixList()
			if err != nil {
				return nil, fmt.Errorf("policy.fib: %w", err)
			}
			opts = append(opts, server.WithFIBFilter(pl.FIBFilter()))
		}
	}
	if c.AreaPassword != "" {
		algo, err := authAlgorithm(c.AreaAuthAlgorithm)
		if err != nil {
			return nil, fmt.Errorf("area-auth-algorithm: %w", err)
		}
		opts = append(opts, server.WithAreaAuth(server.AuthConfig{Algorithm: algo, KeyID: c.AreaKeyID, Secret: c.AreaPassword}))
	}
	if c.DomainPassword != "" {
		algo, err := authAlgorithm(c.DomainAuthAlgorithm)
		if err != nil {
			return nil, fmt.Errorf("domain-auth-algorithm: %w", err)
		}
		opts = append(opts, server.WithDomainAuth(server.AuthConfig{Algorithm: algo, KeyID: c.DomainKeyID, Secret: c.DomainPassword}))
	}
	open := c.OpenCircuit
	if open == nil {
		open = defaultOpenCircuit
	}
	for _, cc := range c.Circuits {
		cfg, err := cc.circuit(open)
		if err != nil {
			return nil, err
		}
		opts = append(opts, server.WithCircuit(cfg))
		// Advertise the circuit's connected subnets at the circuit's effective
		// metric (the default is applied here too, since server-side defaulting
		// runs later and only on the circuit's IS-reachability), but mark them
		// connected so we never install a neighbor's copy over the kernel's
		// connected route (which would break next-hop reachability).
		metric := cc.Metric
		if metric == 0 {
			metric = server.DefaultMetric
		}
		for _, p := range connectedPrefixes(cc.Interface) {
			opts = append(opts, server.WithAdvertisedPrefix(p, metric), server.WithConnectedPrefix(p))
		}
	}
	return opts, nil
}

// connectedPrefixes returns an interface's directly-connected subnets (IPv4
// and global IPv6), masked to their network address.
func connectedPrefixes(name string) []netip.Prefix {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return nil
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil
	}
	var out []netip.Prefix
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ad, ok := netip.AddrFromSlice(ipnet.IP)
		if !ok {
			continue
		}
		ad = ad.Unmap()
		if ad.Is6() && ad.IsLinkLocalUnicast() {
			continue
		}
		ones, _ := ipnet.Mask.Size()
		out = append(out, netip.PrefixFrom(ad, ones).Masked())
	}
	return out
}

// defaultOpenCircuit opens the AF_PACKET transport for a circuit's interface
// and reads its hello source addresses. Config.OpenCircuit overrides it.
func defaultOpenCircuit(ifname string) (tr datalink.Transport, v4, v6 []netip.Addr, err error) {
	tr, err = datalink.OpenLinux(ifname)
	if err != nil {
		return nil, nil, nil, err
	}
	v4, v6 = interfaceAddrs(ifname)
	return tr, v4, v6, nil
}

func (cc CircuitConfig) circuit(open func(string) (datalink.Transport, []netip.Addr, []netip.Addr, error)) (server.CircuitConfig, error) {
	l1, l2, err := levels(cc.Level)
	if err != nil {
		return server.CircuitConfig{}, fmt.Errorf("circuit %q: %w", cc.Interface, err)
	}
	helloAlgo, err := authAlgorithm(cc.HelloAuthAlgorithm)
	if err != nil {
		return server.CircuitConfig{}, fmt.Errorf("circuit %q hello-auth-algorithm: %w", cc.Interface, err)
	}
	tr, v4, v6, err := open(cc.Interface)
	if err != nil {
		return server.CircuitConfig{}, err
	}
	return server.CircuitConfig{
		Name:               cc.Interface,
		Transport:          tr,
		P2P:                cc.P2P,
		Level1:             l1,
		Level2:             l2,
		Priority:           cc.Priority,
		Metric:             cc.Metric,
		IPv4Addrs:          v4,
		IPv6Addrs:          v6,
		HelloPassword:      cc.HelloPassword,
		HelloAuthAlgorithm: helloAlgo,
		HelloKeyID:         cc.HelloKeyID,
	}, nil
}

// prefixList converts a YAML prefix-list into a server.PrefixList.
func (pc PrefixListConfig) prefixList() (server.PrefixList, error) {
	pl := server.PrefixList{}
	switch strings.TrimSpace(pc.Default) {
	case "", "deny":
		pl.Default = server.Deny
	case "permit":
		pl.Default = server.Permit
	default:
		return pl, fmt.Errorf("invalid default %q (want permit or deny)", pc.Default)
	}
	for i, r := range pc.Rules {
		var action server.PrefixAction
		var cidr string
		switch {
		case r.Permit != "" && r.Deny == "":
			action, cidr = server.Permit, r.Permit
		case r.Deny != "" && r.Permit == "":
			action, cidr = server.Deny, r.Deny
		default:
			return pl, fmt.Errorf("rule %d: exactly one of permit/deny is required", i)
		}
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return pl, fmt.Errorf("rule %d: %w", i, err)
		}
		pl.Rules = append(pl.Rules, server.PrefixRule{
			Action: action, Prefix: prefix, MinLen: r.GE, MaxLen: r.LE,
		})
	}
	return pl, nil
}

// authAlgorithm maps a YAML algorithm name to its code. The default (empty) is
// HMAC-MD5; the SHA names accept both short ("sha256") and FRR-style
// ("hmac-sha-256") spellings.
func authAlgorithm(s string) (packet.AuthAlgorithm, error) {
	switch strings.TrimSpace(s) {
	case "", "md5", "hmac-md5":
		return packet.AuthMD5, nil
	case "sha1", "sha-1", "hmac-sha-1":
		return packet.AuthSHA1, nil
	case "sha256", "sha-256", "hmac-sha-256":
		return packet.AuthSHA256, nil
	case "sha384", "sha-384", "hmac-sha-384":
		return packet.AuthSHA384, nil
	case "sha512", "sha-512", "hmac-sha-512":
		return packet.AuthSHA512, nil
	default:
		return 0, fmt.Errorf("invalid auth algorithm %q (want md5, sha1, sha256, sha384, or sha512)", s)
	}
}

// flexAlgoMetricType maps the YAML metric-type name to its code point.
func flexAlgoMetricType(s string) (uint8, error) {
	switch strings.TrimSpace(s) {
	case "", "igp":
		return packet.FlexAlgoMetricIGP, nil
	case "delay":
		return packet.FlexAlgoMetricMinDelay, nil
	case "te":
		return packet.FlexAlgoMetricTE, nil
	default:
		return 0, fmt.Errorf("invalid metric-type %q (want igp, delay, or te)", s)
	}
}

func levels(s string) (l1, l2 bool, err error) {
	switch strings.TrimSpace(s) {
	case "1":
		return true, false, nil
	case "2":
		return false, true, nil
	case "", "12":
		return true, true, nil
	default:
		return false, false, fmt.Errorf("invalid level %q (want 1, 2, or 12)", s)
	}
}

// interfaceAddrs returns an interface's non-link-local IPv4 and link-local
// IPv6 addresses (advertised in hellos via TLV 132 / 232).
func interfaceAddrs(name string) (v4, v6 []netip.Addr) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return nil, nil
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil, nil
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ad, ok := netip.AddrFromSlice(ipnet.IP)
		if !ok {
			continue
		}
		ad = ad.Unmap()
		switch {
		case ad.Is4():
			v4 = append(v4, ad)
		case ad.Is6() && ad.IsLinkLocalUnicast():
			v6 = append(v6, ad)
		}
	}
	return v4, v6
}
