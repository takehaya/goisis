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

// CircuitConfig configures one circuit.
type CircuitConfig struct {
	Interface string `yaml:"interface"`
	Level     string `yaml:"level"` // "1", "2", or "12" (default "12")
	P2P       bool   `yaml:"p2p"`
	Priority  *uint8 `yaml:"priority"`
	Metric    uint32 `yaml:"metric"`
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
	for _, cc := range c.Circuits {
		cfg, err := cc.circuit()
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

func (cc CircuitConfig) circuit() (server.CircuitConfig, error) {
	l1, l2, err := levels(cc.Level)
	if err != nil {
		return server.CircuitConfig{}, fmt.Errorf("circuit %q: %w", cc.Interface, err)
	}
	tr, err := datalink.OpenLinux(cc.Interface)
	if err != nil {
		return server.CircuitConfig{}, err
	}
	v4, v6 := interfaceAddrs(cc.Interface)
	return server.CircuitConfig{
		Name:      cc.Interface,
		Transport: tr,
		P2P:       cc.P2P,
		Level1:    l1,
		Level2:    l2,
		Priority:  cc.Priority,
		Metric:    cc.Metric,
		IPv4Addrs: v4,
		IPv6Addrs: v6,
	}, nil
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
