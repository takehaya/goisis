package config

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"reflect"
	"slices"

	"github.com/takehaya/goisis/pkg/server"
)

// Changes is the difference between two configurations, split into the calls
// that apply it and the keys that cannot be applied at all. The fields are
// applied in declaration order, which is the order the server's own rules
// require: a locator is withdrawn before the Flexible Algorithm it names is
// deleted, and an algorithm is added before a locator binds to it.
type Changes struct {
	DeleteLocators  []netip.Prefix
	DeleteFlexAlgos []uint8
	AddFlexAlgos    []server.FlexAlgoConfig
	AddLocators     []server.SRv6LocatorConfig
	DeletePrefixes  []netip.Prefix
	AddPrefixes     []server.AdvertisedPrefix
	// Ignored names every difference a reload leaves unapplied, by the key it
	// is written under in the file ("net", "circuits: eth1 added"). Values are
	// never included: half of these keys are secrets. A difference that is
	// neither applied nor named here would be a reload that quietly ran half
	// the file, which is worse than one that refuses.
	Ignored []string
}

// restartOnly names every configuration key no runtime API expresses, paired
// with the value a reload compares. It is a table rather than a chain of ifs
// because that is what lets a test check it against the fields of Config: a
// key added later and forgotten here would be reported by nothing.
var restartOnly = []struct {
	key string
	of  func(*Config) any
}{
	{"net", func(c *Config) any { return c.NET }},
	{"hostname", func(c *Config) any { return c.Hostname }},
	{"fib", func(c *Config) any { return c.FIB }},
	{"fib-table", func(c *Config) any { return c.FIBTable }},
	{"overload-on-startup", func(c *Config) any { return c.OverloadOnStartup }},
	{"lsp-mtu", func(c *Config) any { return c.LSPMTU }},
	{"lsdb-entry-limit", func(c *Config) any { return c.LSDBEntryLimit }},
	{"area-password", func(c *Config) any { return c.AreaPassword }},
	{"area-accept-passwords", func(c *Config) any { return c.AreaAcceptPasswords }},
	{"area-auth-algorithm", func(c *Config) any { return c.AreaAuthAlgorithm }},
	{"area-key-id", func(c *Config) any { return c.AreaKeyID }},
	{"domain-password", func(c *Config) any { return c.DomainPassword }},
	{"domain-accept-passwords", func(c *Config) any { return c.DomainAcceptPasswords }},
	{"domain-auth-algorithm", func(c *Config) any { return c.DomainAuthAlgorithm }},
	{"domain-key-id", func(c *Config) any { return c.DomainKeyID }},
	{"policy", func(c *Config) any { return c.Policy }},
}

// Diff computes what takes a daemon running old to the configuration in next.
// It is pure: it parses and compares, and touches neither the server nor the
// filesystem, so a reload can be reasoned about without one.
//
// An error means next is unusable (a malformed prefix, locator or metric
// type) and nothing should be applied from it — the same validation Options
// runs at startup, so a reload refuses the file a restart would refuse.
func Diff(old, next *Config) (Changes, error) {
	var ch Changes

	oldAlgos, err := flexAlgoSet(old)
	if err != nil {
		return Changes{}, err
	}
	newAlgos, err := flexAlgoSet(next)
	if err != nil {
		return Changes{}, err
	}
	// A definition that changed is deleted and re-added: the runtime API has
	// no update for one, and a changed priority or metric type is a new
	// definition to the rest of the area either way.
	for algo, fa := range oldAlgos {
		if n, ok := newAlgos[algo]; !ok || n != fa {
			ch.DeleteFlexAlgos = append(ch.DeleteFlexAlgos, algo)
		}
	}
	for algo, fa := range newAlgos {
		if o, ok := oldAlgos[algo]; !ok || o != fa {
			ch.AddFlexAlgos = append(ch.AddFlexAlgos, fa)
		}
	}

	oldLocs, err := locatorSet(old)
	if err != nil {
		return Changes{}, err
	}
	newLocs, err := locatorSet(next)
	if err != nil {
		return Changes{}, err
	}
	// A locator bound to an algorithm that is being re-added goes with it,
	// unchanged though it is: the server refuses to delete a Flexible
	// Algorithm while a locator still names it (DeleteFlexAlgo), so the
	// locator has to step aside and come back after.
	for prefix, algo := range oldLocs {
		if n, ok := newLocs[prefix]; !ok || n != algo || slices.Contains(ch.DeleteFlexAlgos, algo) {
			ch.DeleteLocators = append(ch.DeleteLocators, prefix)
		}
	}
	for prefix, algo := range newLocs {
		if o, ok := oldLocs[prefix]; !ok || o != algo || slices.ContainsFunc(ch.AddFlexAlgos, func(fa server.FlexAlgoConfig) bool { return fa.Algo == algo }) {
			ch.AddLocators = append(ch.AddLocators, server.SRv6LocatorConfig{Prefix: prefix, Algo: algo})
		}
	}

	oldPrefixes, err := prefixSet(old)
	if err != nil {
		return Changes{}, err
	}
	newPrefixes, err := prefixSet(next)
	if err != nil {
		return Changes{}, err
	}
	// A metric change is likewise a withdrawal and a re-advertisement: the
	// server rejects adding a prefix it already originates.
	for prefix, metric := range oldPrefixes {
		if n, ok := newPrefixes[prefix]; !ok || n != metric {
			ch.DeletePrefixes = append(ch.DeletePrefixes, prefix)
		}
	}
	for prefix, metric := range newPrefixes {
		if o, ok := oldPrefixes[prefix]; !ok || o != metric {
			ch.AddPrefixes = append(ch.AddPrefixes, server.AdvertisedPrefix{Prefix: prefix, Metric: metric})
		}
	}

	// Map iteration order is random; a reload that applies the same file twice
	// must issue the same calls in the same order.
	slices.Sort(ch.DeleteFlexAlgos)
	slices.SortFunc(ch.AddFlexAlgos, func(a, b server.FlexAlgoConfig) int { return int(a.Algo) - int(b.Algo) })
	slices.SortFunc(ch.DeleteLocators, func(a, b netip.Prefix) int { return a.Compare(b) })
	slices.SortFunc(ch.AddLocators, func(a, b server.SRv6LocatorConfig) int { return a.Prefix.Compare(b.Prefix) })
	slices.SortFunc(ch.DeletePrefixes, func(a, b netip.Prefix) int { return a.Compare(b) })
	slices.SortFunc(ch.AddPrefixes, func(a, b server.AdvertisedPrefix) int { return a.Prefix.Compare(b.Prefix) })

	for _, f := range restartOnly {
		if !reflect.DeepEqual(f.of(old), f.of(next)) {
			ch.Ignored = append(ch.Ignored, f.key)
		}
	}
	ch.Ignored = append(ch.Ignored, ignoredCircuits(old, next)...)
	return ch, nil
}

// ignoredCircuits names the circuits a reload cannot touch. Adding or removing
// one needs a transport and a reader goroutine to appear or go away, which the
// Serve loop has no operation for; changing one (its level, its timers, its
// keys) would mean taking it apart and rebuilding it the same way. What a
// circuit can change at runtime — its addresses and its carrier — is the
// interface watcher's job, not the file's.
func ignoredCircuits(old, next *Config) []string {
	var out []string
	before := make(map[string]CircuitConfig, len(old.Circuits))
	for _, cc := range old.Circuits {
		before[cc.Interface] = cc
	}
	after := make(map[string]bool, len(next.Circuits))
	for _, cc := range next.Circuits {
		after[cc.Interface] = true
		prev, ok := before[cc.Interface]
		switch {
		case !ok:
			out = append(out, fmt.Sprintf("circuits: %s added", cc.Interface))
		case !reflect.DeepEqual(prev, cc):
			out = append(out, fmt.Sprintf("circuits: %s changed", cc.Interface))
		}
	}
	for _, cc := range old.Circuits {
		if !after[cc.Interface] {
			out = append(out, fmt.Sprintf("circuits: %s removed", cc.Interface))
		}
	}
	return out
}

// prefixSet returns the configured prefixes keyed by their masked form — the
// key the RIB, the FIB and the runtime API all agree on, so the same subnet
// written two ways is one prefix.
func prefixSet(c *Config) (map[netip.Prefix]uint32, error) {
	out := make(map[netip.Prefix]uint32, len(c.Prefixes))
	for _, p := range c.Prefixes {
		prefix, err := netip.ParsePrefix(p.Prefix)
		if err != nil {
			return nil, fmt.Errorf("prefix %q: %w", p.Prefix, err)
		}
		out[prefix.Masked()] = p.metric()
	}
	return out, nil
}

// locatorSet returns every configured SRv6 locator keyed by masked prefix,
// mapped to the algorithm it is advertised for: the srv6 list is algorithm 0,
// and a flex-algo's own locator is that algorithm's.
func locatorSet(c *Config) (map[netip.Prefix]uint8, error) {
	out := map[netip.Prefix]uint8{}
	if c.SRv6 != nil {
		for _, l := range c.SRv6.Locators {
			prefix, err := netip.ParsePrefix(l)
			if err != nil {
				return nil, fmt.Errorf("srv6 locator %q: %w", l, err)
			}
			out[prefix.Masked()] = 0
		}
	}
	for _, fa := range c.FlexAlgo {
		if fa.Locator == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(fa.Locator)
		if err != nil {
			return nil, fmt.Errorf("flex-algo %d locator %q: %w", fa.Algo, fa.Locator, err)
		}
		out[prefix.Masked()] = fa.Algo
	}
	return out, nil
}

// flexAlgoSet returns the configured Flexible Algorithms keyed by number, in
// the form the runtime API takes.
func flexAlgoSet(c *Config) (map[uint8]server.FlexAlgoConfig, error) {
	out := make(map[uint8]server.FlexAlgoConfig, len(c.FlexAlgo))
	for _, fa := range c.FlexAlgo {
		mt, err := flexAlgoMetricType(fa.MetricType)
		if err != nil {
			return nil, fmt.Errorf("flex-algo %d: %w", fa.Algo, err)
		}
		out[fa.Algo] = server.FlexAlgoConfig{
			Algo:                fa.Algo,
			MetricType:          mt,
			Priority:            fa.Priority,
			AdvertiseDefinition: fa.Advertise,
		}
	}
	return out, nil
}

// Reload re-reads path, applies the part of the difference the runtime API
// expresses, and logs every other difference by name. It is what a daemon
// wires SIGHUP to; everything it applies goes through the server's public
// methods, so the Serve loop remains the only writer of protocol state.
//
// It returns the configuration the daemon is now running: the file's values
// for the keys that were applied, and the running ones for the keys that were
// not. Keeping the unapplied keys is what makes a second SIGHUP name them
// again rather than treat a file the daemon never adopted as the truth.
//
// A file that will not load or will not parse leaves the daemon exactly as it
// was, and is returned as an error rather than ending it: a typo in an edited
// configuration must not take down a running IGP.
func Reload(ctx context.Context, s *server.IsisServer, cur *Config, path string, logger *slog.Logger) (*Config, error) {
	next, err := Load(path)
	if err != nil {
		return cur, err
	}
	ch, err := Diff(cur, next)
	if err != nil {
		return cur, err
	}
	for _, key := range ch.Ignored {
		logger.Warn("configuration reload: this change needs a restart and was not applied", "key", key)
	}
	if err := ch.apply(ctx, s); err != nil {
		// Every call is independent, so one refusal (an unroutable prefix, say)
		// does not hold back the rest, and the running configuration advances
		// regardless: the operator fixes the file and the next reload diffs
		// from what it meant to apply, not from what it managed to.
		logger.Error("configuration reload: some changes were refused", "error", err)
	}

	running := *cur
	running.Prefixes, running.SRv6, running.FlexAlgo = next.Prefixes, next.SRv6, next.FlexAlgo
	return &running, nil
}

// apply pushes the changes through the server's runtime API, in the field
// order Changes documents.
func (ch Changes) apply(ctx context.Context, s *server.IsisServer) error {
	var errs []error
	for _, prefix := range ch.DeleteLocators {
		errs = append(errs, s.DeleteLocator(ctx, prefix))
	}
	for _, algo := range ch.DeleteFlexAlgos {
		errs = append(errs, s.DeleteFlexAlgo(ctx, algo))
	}
	for _, fa := range ch.AddFlexAlgos {
		errs = append(errs, s.AddFlexAlgo(ctx, fa))
	}
	for _, lc := range ch.AddLocators {
		errs = append(errs, s.AddLocator(ctx, lc))
	}
	for _, prefix := range ch.DeletePrefixes {
		errs = append(errs, s.DeletePrefix(ctx, prefix))
	}
	for _, p := range ch.AddPrefixes {
		errs = append(errs, s.AddPrefix(ctx, p))
	}
	return errors.Join(errs...)
}
