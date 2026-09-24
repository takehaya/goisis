package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/takehaya/goisis/pkg/datalink"
	"github.com/takehaya/goisis/pkg/fib"
	"github.com/takehaya/goisis/pkg/packet"
	"github.com/takehaya/goisis/pkg/server"
)

// reloadBase is the running configuration every Diff case below starts from.
const reloadBase = `net: 49.0001.0000.0000.0001.00
area-password: secret
domain-password: secret
prefixes:
  - 192.0.2.0/24
srv6:
  locators:
    - fc00:0:1::/48
flex-algo:
  - algo: 128
    priority: 100
    advertise: true
    locator: fc00:128:1::/48
circuits:
  - interface: mock0
    level: "2"
`

// TestDiffAppliesRuntimeKeysAndNamesTheRest is the specification of a reload:
// a difference the runtime API can express comes back as the calls that apply
// it, and every other difference comes back named, never applied.
func TestDiffAppliesRuntimeKeysAndNamesTheRest(t *testing.T) {
	old := loadConfig(t, reloadBase)
	for name, tc := range map[string]struct {
		next string
		want Changes
	}{
		"prefix added": {
			next: strings.Replace(reloadBase, "  - 192.0.2.0/24\n", "  - 192.0.2.0/24\n  - 198.51.100.0/24\n", 1),
			want: Changes{AddPrefixes: []server.AdvertisedPrefix{
				{Prefix: netip.MustParsePrefix("198.51.100.0/24"), Metric: server.DefaultMetric},
			}},
		},
		"prefix removed": {
			next: strings.Replace(reloadBase, "prefixes:\n  - 192.0.2.0/24\n", "", 1),
			want: Changes{DeletePrefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}},
		},
		"prefix metric changed": {
			next: strings.Replace(reloadBase, "  - 192.0.2.0/24\n", "  - {prefix: 192.0.2.0/24, metric: 50}\n", 1),
			want: Changes{
				DeletePrefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
				AddPrefixes:    []server.AdvertisedPrefix{{Prefix: netip.MustParsePrefix("192.0.2.0/24"), Metric: 50}},
			},
		},
		"locator changed": {
			next: strings.Replace(reloadBase, "    - fc00:0:1::/48\n", "    - fc00:0:2::/48\n", 1),
			want: Changes{
				DeleteLocators: []netip.Prefix{netip.MustParsePrefix("fc00:0:1::/48")},
				AddLocators:    []server.SRv6LocatorConfig{{Prefix: netip.MustParsePrefix("fc00:0:2::/48")}},
			},
		},
		// A Flex-Algo definition has no runtime update, so it is re-added --
		// and the locator bound to it has to step aside and come back, since
		// the server refuses to delete an algorithm a locator still names.
		"flex-algo definition changed": {
			next: strings.Replace(reloadBase, "    priority: 100\n", "    priority: 200\n", 1),
			want: Changes{
				DeleteLocators:  []netip.Prefix{netip.MustParsePrefix("fc00:128:1::/48")},
				DeleteFlexAlgos: []uint8{128},
				AddFlexAlgos: []server.FlexAlgoConfig{
					{Algo: 128, MetricType: packet.FlexAlgoMetricIGP, Priority: 200, AdvertiseDefinition: true},
				},
				AddLocators: []server.SRv6LocatorConfig{{Prefix: netip.MustParsePrefix("fc00:128:1::/48"), Algo: 128}},
			},
		},
		"circuit added": {
			next: reloadBase + "  - interface: mock1\n",
			want: Changes{AddCircuits: []CircuitConfig{{Interface: "mock1"}}},
		},
		// Retiming a circuit, or moving it between levels, is the edit an
		// operator is likeliest to make, and it comes out as a removal and an
		// addition: no runtime call changes a circuit's level, timers or keys,
		// and almost every one of them drops the adjacency by protocol rule
		// anyway. The deletion is first so the name and the pseudonode octet
		// are free before the addition asks for them.
		"circuit changed": {
			next: strings.Replace(reloadBase, "    level: \"2\"\n", "    level: \"1\"\n", 1),
			want: Changes{
				DeleteCircuits: []string{"mock0"},
				AddCircuits:    []CircuitConfig{{Interface: "mock0", Level: "1"}},
			},
		},
		"circuit replaced": {
			next: strings.Replace(reloadBase, "  - interface: mock0\n", "  - interface: mock1\n", 1),
			want: Changes{
				DeleteCircuits: []string{"mock0"},
				AddCircuits:    []CircuitConfig{{Interface: "mock1", Level: "2"}},
			},
		},
		"system id changed": {
			next: strings.Replace(reloadBase, "0000.0000.0001.00", "0000.0000.0009.00", 1),
			want: Changes{Ignored: []string{"net"}},
		},
		"auth key changed": {
			next: strings.Replace(reloadBase, "area-password: secret", "area-password: rotated", 1),
			want: Changes{Ignored: []string{"area-password"}},
		},
	} {
		got, err := Diff(old, loadConfig(t, tc.next))
		if err != nil {
			t.Errorf("%s: Diff: %v", name, err)
			continue
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s:\n got %+v\nwant %+v", name, got, tc.want)
		}
	}
}

// TestDiffNamesEveryConfigKey guards the promise the warnings make: every
// configuration key is either applied by a reload or named as needing a
// restart. A key added to Config later and wired into neither is reported by
// nothing, which is the silent half-applied reload this whole path exists to
// avoid.
//
// The walk covers Config and the three nested structs Diff re-maps field by
// field (prefixSet, locatorSet, flexAlgoSet), because a field added to one of
// those is as silent as a new top-level key. The other nested types need no
// entries: Diff compares CircuitConfig and the policy structs whole with
// reflect.DeepEqual, so a new field in one of them is named by that comparison
// without anything here knowing it exists.
func TestDiffNamesEveryConfigKey(t *testing.T) {
	flexAlgo := func(fa FlexAlgoConfig) func(*Config) {
		// Every mutation replaces a slice or pointer rather than editing
		// through it: the copy the loop below mutates is shallow, so editing
		// an element in place would change old as well and leave Diff
		// comparing a configuration with itself.
		return func(c *Config) { c.FlexAlgo = []FlexAlgoConfig{fa} }
	}
	// One mutation per field of each walked type. A nil mutation is a field
	// that is not a configuration key at all.
	mutations := map[string]func(*Config){
		"Config.NET":                   func(c *Config) { c.NET = "49.0009.0000.0000.0009.00" },
		"Config.Hostname":              func(c *Config) { c.Hostname = "r9" },
		"Config.FIB":                   func(c *Config) { c.FIB = !c.FIB },
		"Config.FIBTable":              func(c *Config) { c.FIBTable = 99 },
		"Config.Circuits":              func(c *Config) { c.Circuits = append(slices.Clone(c.Circuits), CircuitConfig{Interface: "mock9"}) },
		"Config.Prefixes":              func(c *Config) { c.Prefixes = append(slices.Clone(c.Prefixes), PrefixConfig{Prefix: "203.0.113.0/24"}) },
		"Config.SRv6":                  func(c *Config) { c.SRv6 = &SRv6Config{Locators: []string{"fc00:9::/48"}} },
		"Config.FlexAlgo":              func(c *Config) { c.FlexAlgo = nil },
		"Config.Policy":                func(c *Config) { c.Policy = &PolicyConfig{Advertise: &PrefixListConfig{Default: "permit"}} },
		"Config.OverloadOnStartup":     func(c *Config) { c.OverloadOnStartup = "60s" },
		"Config.AreaPassword":          func(c *Config) { c.AreaPassword = "rotated" },
		"Config.AreaAcceptPasswords":   func(c *Config) { c.AreaAcceptPasswords = []string{"old"} },
		"Config.AreaAuthAlgorithm":     func(c *Config) { c.AreaAuthAlgorithm = "sha256" },
		"Config.AreaKeyID":             func(c *Config) { c.AreaKeyID = 7 },
		"Config.DomainPassword":        func(c *Config) { c.DomainPassword = "rotated" },
		"Config.DomainAcceptPasswords": func(c *Config) { c.DomainAcceptPasswords = []string{"old"} },
		"Config.DomainAuthAlgorithm":   func(c *Config) { c.DomainAuthAlgorithm = "sha256" },
		"Config.DomainKeyID":           func(c *Config) { c.DomainKeyID = 7 },
		"Config.LSDBEntryLimit":        func(c *Config) { c.LSDBEntryLimit = 5000 },
		"Config.LSPMTU":                func(c *Config) { c.LSPMTU = 1400 },
		"Config.OpenCircuit":           nil, // the embedder's transport seam, not a YAML key

		"PrefixConfig.Prefix": func(c *Config) { c.Prefixes = []PrefixConfig{{Prefix: "203.0.113.0/24"}} },
		"PrefixConfig.Metric": func(c *Config) { c.Prefixes = []PrefixConfig{{Prefix: "192.0.2.0/24", Metric: 50}} },

		"SRv6Config.Locators": func(c *Config) { c.SRv6 = &SRv6Config{Locators: []string{"fc00:9::/48"}} },

		"FlexAlgoConfig.Algo":       flexAlgo(FlexAlgoConfig{Algo: 129, Priority: 100, Advertise: true, Locator: "fc00:128:1::/48"}),
		"FlexAlgoConfig.MetricType": flexAlgo(FlexAlgoConfig{Algo: 128, MetricType: "delay", Priority: 100, Advertise: true, Locator: "fc00:128:1::/48"}),
		"FlexAlgoConfig.Priority":   flexAlgo(FlexAlgoConfig{Algo: 128, Priority: 200, Advertise: true, Locator: "fc00:128:1::/48"}),
		"FlexAlgoConfig.Advertise":  flexAlgo(FlexAlgoConfig{Algo: 128, Priority: 100, Locator: "fc00:128:1::/48"}),
		"FlexAlgoConfig.Locator":    flexAlgo(FlexAlgoConfig{Algo: 128, Priority: 100, Advertise: true, Locator: "fc00:129:1::/48"}),
	}

	old := loadConfig(t, reloadBase)
	before := *old
	for _, typ := range []reflect.Type{
		reflect.TypeOf(Config{}),
		reflect.TypeOf(PrefixConfig{}),
		reflect.TypeOf(SRv6Config{}),
		reflect.TypeOf(FlexAlgoConfig{}),
	} {
		for i := range typ.NumField() {
			key := typ.Name() + "." + typ.Field(i).Name
			mutate, ok := mutations[key]
			if !ok {
				t.Errorf("configuration key %s has no mutation here: add it to this table, and to whichever of Diff or restartOnly owns it", key)
				continue
			}
			if mutate == nil {
				continue
			}
			next := *old
			mutate(&next)
			got, err := Diff(old, &next)
			if err != nil {
				t.Errorf("%s: Diff: %v", key, err)
				continue
			}
			if reflect.DeepEqual(got, Changes{}) {
				t.Errorf("changing %s is reported by nothing: a reload would ignore it silently", key)
			}
		}
	}
	// The mutations edit a shallow copy, so one that reached through a slice or
	// a pointer would have changed old too -- and every Diff after it would
	// have compared a configuration against itself and found nothing.
	if !reflect.DeepEqual(before, *old) {
		t.Error("a mutation edited the baseline configuration through a shared slice or pointer; every case after it was vacuous")
	}
}

// TestReloadAppliesPrefixesAndCircuitsFromOneFile drives the whole path against
// a running server: the file's new prefix reaches the node's own LSP, the
// circuit the file grew appears, and the configuration the reload returns is
// the file, so a second signal has nothing left to do.
func TestReloadAppliesPrefixesAndCircuitsFromOneFile(t *testing.T) {
	const initial = `net: 49.0001.1921.6800.1001.00
prefixes:
  - 192.0.2.0/24
circuits:
  - interface: mock0
    level: "2"
`
	// The prefix is swapped and a second circuit appears: one half of the file
	// is applicable, the other half is not.
	const next = `net: 49.0001.1921.6800.1001.00
prefixes:
  - 198.51.100.0/24
circuits:
  - interface: mock0
    level: "2"
  - interface: mock1
    level: "2"
`
	cfg, s, path := runningServer(t, initial)
	ctx := t.Context()
	if err := os.WriteFile(path, []byte(next), 0o600); err != nil {
		t.Fatal(err)
	}
	running, err := Reload(ctx, s, cfg, path, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}

	waitFor(t, "the reloaded prefix in our own LSP", func() bool { return ownLSPHas(t, s, "198.51.100.0/24") })
	if ownLSPHas(t, s, "192.0.2.0/24") {
		t.Error("the prefix the file dropped is still advertised")
	}
	if got := circuitNames(t, s); !slices.Equal(got, []string{"mock0", "mock1"}) {
		t.Errorf("circuits = %v, want both the file names", got)
	}

	// The returned configuration is what the daemon runs, and it now runs the
	// whole file: a further signal has nothing to apply and nothing to warn
	// about.
	again, err := Diff(running, loadConfigFile(t, path))
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if !reflect.DeepEqual(again, Changes{}) {
		t.Errorf("a second reload still diffs %+v: the baseline never adopted the file", again)
	}
}

// circuitNames lists the configured circuits by interface name, in order.
func circuitNames(t *testing.T, s *server.IsisServer) []string {
	t.Helper()
	circuits, err := s.ListCircuits(t.Context())
	if err != nil {
		t.Fatalf("ListCircuits: %v", err)
	}
	out := make([]string, len(circuits))
	for i, c := range circuits {
		out[i] = c.Interface
	}
	return out
}

// mockTransports is a Config.OpenCircuit that hands out a *new* mock transport
// on every call over the named interfaces. A shared one would not do: a circuit
// a reload rebuilds gets its transport from a second open, and the first was
// closed by the deletion that came before it.
func mockTransports(names ...string) func(string) (datalink.Transport, []netip.Addr, []netip.Addr, error) {
	var n byte
	return func(ifname string) (datalink.Transport, []netip.Addr, []netip.Addr, error) {
		if !slices.Contains(names, ifname) {
			return nil, nil, nil, fmt.Errorf("no mock circuit for %q", ifname)
		}
		n++
		return datalink.NewMockTransport(packet.SNPA{2, 0, 0, 0, 0, n}, 1500), nil, nil, nil
	}
}

// loadConfigFile loads a configuration from a path (loadConfig writes its own).
func loadConfigFile(t *testing.T, path string) *Config {
	t.Helper()
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return c
}

// ownLSPHas reports whether the node's own LSP carries the given prefix. The
// detail form is what renders the TLV text this reads.
func ownLSPHas(t *testing.T, s *server.IsisServer, prefix string) bool {
	t.Helper()
	lsps, err := s.ListLSDBDetail(t.Context())
	if err != nil {
		t.Fatalf("ListLSDBDetail: %v", err)
	}
	for _, l := range lsps {
		if l.Own && slices.ContainsFunc(l.TLVs, func(line string) bool { return strings.Contains(line, prefix) }) {
			return true
		}
	}
	return false
}

// TestDiffRefusesAFileARestartWouldRefuse pins that a reload validates the new
// file the way startup does, before it issues a single call. Half of these
// defects only surface inside NewIsisServer or Options, which a reload never
// reached: the file was accepted, the withdrawals ran, and the operator found
// out from the refusal of whatever came after them.
func TestDiffRefusesAFileARestartWouldRefuse(t *testing.T) {
	old := loadConfig(t, reloadBase)
	for name, next := range map[string]string{
		"malformed net":           strings.Replace(reloadBase, "net: 49.0001.0000.0000.0001.00", "net: 49.0001.0000.0000.0001", 1),
		"unknown circuit level":   strings.Replace(reloadBase, `level: "2"`, `level: "3"`, 1),
		"invalid overload window": reloadBase + "overload-on-startup: 30x\n",
		"invalid policy rule":     reloadBase + "policy:\n  advertise:\n    rules:\n      - permit: 192.0.2.0\n",
		"unknown auth algorithm":  reloadBase + "area-auth-algorithm: sha999\n",
		// The three the server itself checks, and the reload did not: a
		// reserved Flex-Algo number, the same number twice, and a locator that
		// is not an IPv6 prefix. Each used to reach apply and detonate there,
		// with the withdrawals it came after already issued.
		"reserved flex-algo number":     strings.Replace(reloadBase, "- algo: 128", "- algo: 100", 1),
		"duplicate flex-algo":           strings.Replace(reloadBase, "flex-algo:\n", "flex-algo:\n  - algo: 128\n    priority: 200\n", 1),
		"srv6 locator that is not IPv6": strings.Replace(reloadBase, "- fc00:0:1::/48", "- 10.0.0.0/8", 1),
	} {
		if _, err := Diff(old, loadConfig(t, next)); err == nil {
			t.Errorf("%s: Diff accepted a file a restart would refuse", name)
		}
	}
}

// TestReloadAppliesEveryFileAStartupAccepts pins the other direction of the
// same contract, the one that is easy to forget: a file goisisd starts on has
// to be a file a reload of that same file applies. Two checks lived in
// AddPrefix alone -- the routability of the prefix and the reachability
// ceiling on its metric -- so a node started on such a file could not reload
// it, and the attempt left the node part way through the batch.
func TestReloadAppliesEveryFileAStartupAccepts(t *testing.T) {
	const base = `net: 49.0001.1921.6800.1001.00
prefixes:
  - 192.0.2.0/24
circuits:
  - interface: mock0
    level: "2"
`
	for name, entry := range map[string]string{
		"multicast prefix": "  - 224.0.0.0/4\n",
		// 0xfe000000 is the RFC 5305 reachability ceiling; a prefix at or
		// above it is unusable, which is why AddPrefix refuses it.
		"metric at the reachability ceiling": "  - prefix: 198.51.100.0/24\n    metric: 4261412864\n",
	} {
		t.Run(name, func(t *testing.T) {
			next := strings.Replace(base, "  - 192.0.2.0/24\n", "  - 192.0.2.0/24\n"+entry, 1)
			cfg, s, path := runningServer(t, base)
			if err := os.WriteFile(path, []byte(next), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := Reload(t.Context(), s, cfg, path, slog.New(slog.NewTextHandler(io.Discard, nil)))
			if startupAccepts(t, next) {
				if err != nil {
					t.Fatalf("goisisd starts on this file, but a reload of the very same file fails: %v", err)
				}
				return
			}
			// The other way round is just as much a disagreement, and the
			// reload must reach it in Diff: refusing in the middle of apply
			// leaves the node in neither configuration.
			if err == nil {
				t.Fatal("the reload applied a file goisisd would not start on")
			}
			if errors.Is(err, ErrPartiallyApplied) {
				t.Fatalf("the reload found the defect only after it had begun mutating: %v", err)
			}
		})
	}
}

// startupAccepts reports whether goisisd would start on this file: the whole
// startup path over a mock transport, with the server it builds discarded.
func startupAccepts(t *testing.T, yaml string) bool {
	t.Helper()
	cfg := loadConfig(t, yaml)
	cfg.OpenCircuit = mockCircuits(map[string]mockCircuit{
		"mock0": {tr: datalink.NewMockTransport(packet.SNPA{2, 0, 0, 0, 0, 2}, 1500)},
	})
	opts, err := cfg.Options()
	if err != nil {
		return false
	}
	_, err = server.NewIsisServer(opts...)
	return err == nil
}

// TestDiffOpensNoSockets pins what Diff is: a pure function. It validates the
// whole file, which means it walks the circuits too -- so the one impure step
// in Options is replaced, not taken. The circuits a reload adds are opened
// while the batch is applied, and Reload calls Diff before it decides to apply
// anything: a Diff that opened sockets would take one per interface for a
// reload then refused on an unrelated key, and leak every one of them.
func TestDiffOpensNoSockets(t *testing.T) {
	old := loadConfig(t, reloadBase)
	next := loadConfig(t, strings.Replace(reloadBase, "192.0.2.0/24", "198.51.100.0/24", 1))
	opened := 0
	next.OpenCircuit = func(string) (datalink.Transport, []netip.Addr, []netip.Addr, error) {
		opened++
		return datalink.NewMockTransport(packet.SNPA{2, 0, 0, 0, 0, 3}, 1500), nil, nil, nil
	}
	if _, err := Diff(old, next); err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if opened != 0 {
		t.Errorf("Diff opened %d circuits; validation must not take a socket", opened)
	}
}

// TestReloadKeepsItsBaselineWhenAnApplyIsRefused is the contract a refusal
// part way through a reload has to honour. There is no rollback -- undoing the
// calls that landed needs the inverse of every mutator, and stopping leaves a
// state the operator can see -- so what is left is honesty: the caller is told
// (goisisd logs a failure instead of "configuration reloaded"), and the
// baseline does not advance, so the next SIGHUP re-diffs the same change
// rather than treating a file the node never adopted as the truth.
func TestReloadKeepsItsBaselineWhenAnApplyIsRefused(t *testing.T) {
	const initial = `net: 49.0001.1921.6800.1001.00
prefixes:
  - 192.0.2.0/24
circuits:
  - interface: mock0
    level: "2"
`
	// What can still reach apply is state the file cannot describe: Diff
	// validates the file against the file a restart would run, never against
	// the node. Here the operator advertised a prefix through the management
	// API at metric 20 and then wrote that same prefix into the file without a
	// metric, which is metric 10 -- a file a restart would run perfectly -- so
	// the swap comes out as a withdrawal that lands and an addition the server
	// refuses, because the file asks for a value the node does not have. That
	// disagreement is a refusal and not an ErrAlreadyInState: silently keeping
	// metric 20 while reporting the file applied is the outcome this whole
	// path exists to rule out.
	next := strings.Replace(initial, "  - 192.0.2.0/24\n", "  - 198.51.100.0/24\n", 1)
	const runtimePrefix = "198.51.100.0/24"

	path := filepath.Join(t.TempDir(), "goisisd.yaml")
	write := func(s string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(initial)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	cfg.OpenCircuit = mockCircuits(map[string]mockCircuit{
		"mock0": {tr: datalink.NewMockTransport(packet.SNPA{2, 0, 0, 0, 0, 1}, 1500)},
	})
	opts, err := cfg.Options()
	if err != nil {
		t.Fatalf("Options: %v", err)
	}
	s, err := server.NewIsisServer(opts...)
	if err != nil {
		t.Fatalf("NewIsisServer: %v", err)
	}
	ctx := t.Context()
	go s.Serve(ctx) //nolint:errcheck // shut down via ctx
	if err := s.AddPrefix(ctx, server.AdvertisedPrefix{Prefix: netip.MustParsePrefix(runtimePrefix), Metric: 20}); err != nil {
		t.Fatalf("AddPrefix: %v", err)
	}

	write(next)
	want, err := Diff(cfg, loadConfigFile(t, path))
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}

	var logs bytes.Buffer
	running, err := Reload(ctx, s, cfg, path, slog.New(slog.NewTextHandler(&logs, nil)))
	if err == nil {
		t.Fatal("Reload reported success after a refused call; goisisd would log \"configuration reloaded\"")
	}
	if !errors.Is(err, ErrPartiallyApplied) {
		t.Errorf("Reload error is not an ErrPartiallyApplied, so goisisd cannot tell an untouched node from a half-changed one: %v", err)
	}

	// The refusal is destructive by design: the prefix the file dropped was
	// withdrawn before the addition was refused. That is what the caller has
	// to be told, and it is why the baseline must not move.
	waitFor(t, "the withdrawn prefix to leave our own LSP", func() bool { return !ownLSPHas(t, s, "192.0.2.0/24") })

	again, err := Diff(running, loadConfigFile(t, path))
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if !reflect.DeepEqual(again, want) {
		t.Errorf("the next SIGHUP diffs\n got %+v\nwant %+v: the refused change is no longer retried", again, want)
	}
}

// TestReloadAdoptsACorrectedFileOnTheNextSignal is the other half of the
// baseline rule above, and the reason the baseline can be kept at all. Keeping
// it means the next SIGHUP re-issues the whole batch, including the calls the
// refused attempt already landed -- so unless those calls succeed the second
// time, the recovery the daemon prints ("fix the file and send SIGHUP again")
// is an instruction to signal forever. The file is authoritative for what it
// names, so a call that asks for the state the node is already in is this
// reload succeeding at it: one signal after the correction, the node is running
// the file and nothing is left to retry.
func TestReloadAdoptsACorrectedFileOnTheNextSignal(t *testing.T) {
	const initial = `net: 49.0001.1921.6800.1001.00
prefixes:
  - 192.0.2.0/24
circuits:
  - interface: mock0
    level: "2"
`
	cfg, s, path := runningServer(t, initial)
	ctx := t.Context()
	write := func(s string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// The operator advertised a prefix with `goisis` at metric 20, then wrote
	// it into the file so it survives a restart -- and left the metric out,
	// which is metric 10.
	if err := s.AddPrefix(ctx, server.AdvertisedPrefix{Prefix: netip.MustParsePrefix("198.51.100.0/24"), Metric: 20}); err != nil {
		t.Fatalf("AddPrefix: %v", err)
	}
	write(strings.Replace(initial, "  - 192.0.2.0/24\n", "  - 198.51.100.0/24\n", 1))
	running, err := Reload(ctx, s, cfg, path, logger)
	if !errors.Is(err, ErrPartiallyApplied) {
		t.Fatalf("the first reload is %v, want ErrPartiallyApplied: this fixture no longer reaches a refused apply", err)
	}
	waitFor(t, "the withdrawn prefix to leave our own LSP", func() bool { return !ownLSPHas(t, s, "192.0.2.0/24") })

	// The correction. Everything this file asks for is already true of the
	// node: the prefix it drops is gone, and the one it names is advertised at
	// exactly the metric it now gives.
	write(strings.Replace(initial, "  - 192.0.2.0/24\n", "  - {prefix: 198.51.100.0/24, metric: 20}\n", 1))
	running, err = Reload(ctx, s, running, path, logger)
	if err != nil {
		t.Fatalf("the corrected file was refused again: %v", err)
	}
	if !ownLSPHas(t, s, "198.51.100.0/24") {
		t.Error("the adopted file's prefix is not in our own LSP")
	}
	// The baseline moved: a further signal has nothing left to do, which is
	// what distinguishes adoption from a reload that merely stopped erroring.
	again, err := Diff(running, loadConfigFile(t, path))
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if !reflect.DeepEqual(again, Changes{}) {
		t.Errorf("the next SIGHUP still diffs %+v: the baseline never advanced", again)
	}
}

// TestReloadAdoptsAPrefixTheManagementAPIAlreadyAdvertises is the ordinary way
// an operator makes a runtime change permanent: add it with `goisis`, then
// write it into the file so a restart keeps it. The file and the node then say
// the same thing, and a reload that refused it would make the documented
// workflow unusable -- and, with the baseline rule above, unrepairable.
func TestReloadAdoptsAPrefixTheManagementAPIAlreadyAdvertises(t *testing.T) {
	const initial = `net: 49.0001.1921.6800.1001.00
prefixes:
  - 192.0.2.0/24
circuits:
  - interface: mock0
    level: "2"
`
	cfg, s, path := runningServer(t, initial)
	ctx := t.Context()
	const added = "198.51.100.0/24"
	if err := s.AddPrefix(ctx, server.AdvertisedPrefix{Prefix: netip.MustParsePrefix(added), Metric: server.DefaultMetric}); err != nil {
		t.Fatalf("AddPrefix: %v", err)
	}
	next := strings.Replace(initial, "  - 192.0.2.0/24\n", "  - 192.0.2.0/24\n  - "+added+"\n", 1)
	if err := os.WriteFile(path, []byte(next), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Reload(ctx, s, cfg, path, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if !ownLSPHas(t, s, added) {
		t.Errorf("%s left our own LSP: the reload was supposed to find it already there", added)
	}
}

// sidRecorder counts the local SID writes a reload causes. It embeds fib.Noop
// so only the two SID methods need an implementation, and guards its counters
// because they are written on the management goroutine and read from the test's.
type sidRecorder struct {
	fib.Noop
	mu      sync.Mutex
	removed map[netip.Addr]int
}

func (r *sidRecorder) RemoveLocalSID(sid netip.Addr) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.removed == nil {
		r.removed = map[netip.Addr]int{}
	}
	r.removed[sid]++
	return nil
}

func (r *sidRecorder) removals(sid netip.Addr) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.removed[sid]
}

// TestReloadDoesNotChurnAnEndSIDTheFileStillNames is the dataplane cost of a
// reload that cannot be adopted. A Flexible Algorithm has no runtime update, so
// a changed definition withdraws the locator bound to it and advertises it
// again -- one unprogram and reprogram of that locator's End SID, which the
// change genuinely calls for. What must not happen is that cost repeating: a
// reload the node has already satisfied but which is reported refused keeps its
// baseline, so every further signal re-issues the same withdrawal and tears
// down forwarding state the file has never stopped naming.
func TestReloadDoesNotChurnAnEndSIDTheFileStillNames(t *testing.T) {
	const initial = `net: 49.0001.1921.6800.1001.00
prefixes:
  - 192.0.2.0/24
flex-algo:
  - algo: 128
    priority: 100
    advertise: true
    locator: fc00:128:1::/48
circuits:
  - interface: mock0
    level: "2"
`
	rec := &sidRecorder{}
	cfg, s, path := runningServer(t, initial, server.WithFIB(rec))
	ctx := t.Context()
	// The same file-versus-node disagreement as above, on a key that has
	// nothing to do with the locator: the reload's refusal comes after the
	// locator work, and the retry redoes all of it.
	if err := s.AddPrefix(ctx, server.AdvertisedPrefix{Prefix: netip.MustParsePrefix("198.51.100.0/24"), Metric: server.DefaultMetric}); err != nil {
		t.Fatalf("AddPrefix: %v", err)
	}
	next := strings.Replace(initial, "priority: 100", "priority: 200", 1)
	next = strings.Replace(next, "  - 192.0.2.0/24\n", "  - 192.0.2.0/24\n  - 198.51.100.0/24\n", 1)
	if err := os.WriteFile(path, []byte(next), 0o600); err != nil {
		t.Fatal(err)
	}

	// Two signals: the one that changes the definition, and the one an
	// operator sends after it. The second has nothing to apply.
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	for i := range 2 {
		running, err := Reload(ctx, s, cfg, path, logger)
		if err != nil {
			t.Errorf("reload %d: %v", i+1, err)
		}
		cfg = running
	}

	endSID := netip.MustParseAddr("fc00:128:1::")
	if got := rec.removals(endSID); got != 1 {
		t.Errorf("End SID %s was unprogrammed %d times, want 1: the file never stopped naming it", endSID, got)
	}
	locators, err := s.ListLocators(ctx)
	if err != nil {
		t.Fatalf("ListLocators: %v", err)
	}
	if !slices.ContainsFunc(locators, func(l server.LocatorInfo) bool { return l.Prefix == netip.MustParsePrefix("fc00:128:1::/48") }) {
		t.Errorf("the locator the file still names is gone: %v", locators)
	}
}

// reloadMetrics records the outcomes the server reported. It embeds
// server.NoopMetrics so only the method under test needs an implementation,
// and guards its map because the report is made on the management goroutine
// while the test reads it from its own.
type reloadMetrics struct {
	server.NoopMetrics
	mu        sync.Mutex
	outcomes  map[string]int
	unapplied []int
}

func (m *reloadMetrics) ConfigReload(outcome string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.outcomes == nil {
		m.outcomes = map[string]int{}
	}
	m.outcomes[outcome]++
}

func (m *reloadMetrics) count(outcome string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.outcomes[outcome]
}

func (m *reloadMetrics) ConfigReloadUnapplied(n int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.unapplied = append(m.unapplied, n)
}

// unappliedCounts returns every count reported so far, in order. The sequence
// and not the last value, because a reload that never compared the two files
// reports nothing at all, which a last value alone cannot tell from one that
// reported the same number again.
func (m *reloadMetrics) unappliedCounts() []int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.unapplied)
}

// TestReloadReportsEveryOutcome pins the three states an operator has to be
// able to tell apart without reading the log. "Applied" is the file running.
// "Refused" left the node exactly as it was, so the running configuration is
// still a configuration someone wrote. "Partial" is the one that matters: the
// node is in neither, and no further signal repairs it by itself.
//
// Reload runs on the daemon's own goroutine, so this also pins that the report
// reaches the sink at all: Metrics is called only from the management
// goroutine, and a report made anywhere else would be a data race rather than
// a count.
func TestReloadReportsEveryOutcome(t *testing.T) {
	const initial = `net: 49.0001.1921.6800.1001.00
prefixes:
  - 192.0.2.0/24
srv6:
  locators:
    - fc00:0:1::/48
flex-algo:
  - algo: 128
    priority: 100
    locator: fc00:128:1::/48
circuits:
  - interface: mock0
    level: "2"
`
	path := filepath.Join(t.TempDir(), "goisisd.yaml")
	write := func(s string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(initial)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	cfg.OpenCircuit = mockCircuits(map[string]mockCircuit{
		"mock0": {tr: datalink.NewMockTransport(packet.SNPA{2, 0, 0, 0, 0, 1}, 1500)},
	})
	opts, err := cfg.Options()
	if err != nil {
		t.Fatalf("Options: %v", err)
	}
	m := &reloadMetrics{}
	s, err := server.NewIsisServer(append(opts, server.WithMetrics(m))...)
	if err != nil {
		t.Fatalf("NewIsisServer: %v", err)
	}
	ctx := t.Context()
	go s.Serve(ctx) //nolint:errcheck // shut down via ctx
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))

	// A difference the runtime API expresses, and nothing else.
	write(strings.Replace(initial, "192.0.2.0/24", "198.51.100.0/24", 1))
	if _, err := Reload(ctx, s, cfg, path, logger); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if got := m.count("applied"); got != 1 {
		t.Errorf("applied reloads = %d, want 1", got)
	}

	// A file a restart would refuse: validated before the first call goes out,
	// so nothing changed.
	write(strings.Replace(initial, "net: 49.0001.1921.6800.1001.00", "net: 49.0001.1921.6800.1001", 1))
	if _, err := Reload(ctx, s, cfg, path, logger); err == nil {
		t.Fatal("Reload accepted a file a restart would refuse")
	}
	if got := m.count("refused"); got != 1 {
		t.Errorf("refused reloads = %d, want 1", got)
	}

	// A call the running server refuses, which after validation can only be one
	// the file cannot foresee: the node's own state. Of the two additions below
	// one is the prefix the reload above already advertised, which the node
	// satisfies and so is not a refusal at all; the other is advertised through
	// the management API at a metric the file contradicts, which no repetition
	// of the signal can settle.
	if err := s.AddPrefix(ctx, server.AdvertisedPrefix{Prefix: netip.MustParsePrefix("203.0.113.0/24"), Metric: 20}); err != nil {
		t.Fatalf("AddPrefix: %v", err)
	}
	write(strings.Replace(initial, "  - 192.0.2.0/24\n", "  - 198.51.100.0/24\n  - 203.0.113.0/24\n", 1))
	if _, err := Reload(ctx, s, cfg, path, logger); !errors.Is(err, ErrPartiallyApplied) {
		t.Fatalf("Reload error = %v, want an ErrPartiallyApplied", err)
	}
	if got := m.count("partial"); got != 1 {
		t.Errorf("partially applied reloads = %d, want 1", got)
	}
	if got := m.count("applied"); got != 1 {
		t.Errorf("applied reloads = %d after a refusal, want the first one only", got)
	}
}

// TestReloadCountsWhatItLeftArmedForTheNextRestart pins the part of a declined
// change the log does not carry: the difference stays in the file, and the file
// is the next restart's configuration -- a restart `Restart=on-failure` makes
// with nobody present, hours after the warning scrolled past. The count is the
// running configuration's distance from the file, so monitoring can see "this
// node is not running this file" rather than an operator having to remember.
func TestReloadCountsWhatItLeftArmedForTheNextRestart(t *testing.T) {
	const initial = `net: 49.0001.1921.6800.1001.00
hostname: before
prefixes:
  - 192.0.2.0/24
circuits:
  - interface: mock0
    level: "2"
`
	m := &reloadMetrics{}
	cfg, s, path := runningServer(t, initial, server.WithMetrics(m))
	ctx := t.Context()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	reload := func(yaml string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
			t.Fatal(err)
		}
		running, err := Reload(ctx, s, cfg, path, logger)
		if err != nil {
			t.Fatalf("Reload: %v", err)
		}
		cfg = running
	}

	// A restart-only key next to one the reload applies: the reload succeeds,
	// and the file it leaves behind describes a node this one is not.
	reload(strings.NewReplacer(
		"hostname: before", "hostname: after",
		"192.0.2.0/24", "198.51.100.0/24",
	).Replace(initial))
	if got := m.unappliedCounts(); !slices.Equal(got, []int{1}) {
		t.Fatalf("unapplied counts = %v, want [1]: the hostname change is still in the file", got)
	}

	// A file that will not load is not a count of zero: nothing was compared,
	// so the divergence the reload before it left is still there, and a gauge
	// reset here would read as resolved.
	if err := os.WriteFile(path, []byte("net: 49.0001.1921.6800.1001\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Reload(ctx, s, cfg, path, logger); err == nil {
		t.Fatal("Reload accepted a file a restart would refuse")
	}
	if got := m.unappliedCounts(); !slices.Equal(got, []int{1}) {
		t.Errorf("unapplied counts = %v, want [1] still: a file that will not load was never compared", got)
	}

	// Resolved reads as resolved. The operator puts the running hostname back,
	// so the file and the node agree again and the count has to follow down
	// rather than hold its last value.
	reload(strings.Replace(initial, "192.0.2.0/24", "203.0.113.0/24", 1))
	if got := m.unappliedCounts(); !slices.Equal(got, []int{1, 0}) {
		t.Errorf("unapplied counts = %v, want [1 0]: the file is what the node runs again", got)
	}
}

// A reload that lands nothing is reported "partial" like one that lands half,
// and that is deliberate. Since apply counts an already-satisfied call as
// success, an error that reaches the outcome is the file and the node
// disagreeing about a value, which no repetition of the signal settles; whether
// a sibling call happened to land first changes neither what the operator has
// to do nor what the next SIGHUP will try, and with no rollback and no ordering
// guarantee against the refusal it is not even stable between two signals over
// the same file. "Refused" keeps its narrower meaning -- the file rejected
// before a single call went out -- because that is the one outcome that says
// the server was never touched.
func TestAReloadWhoseOnlyCallIsRefusedIsPartialNotRefused(t *testing.T) {
	const initial = `net: 49.0001.1921.6800.1001.00
prefixes:
  - 192.0.2.0/24
circuits:
  - interface: mock0
    level: "2"
`
	m := &reloadMetrics{}
	cfg, s, path := runningServer(t, initial, server.WithMetrics(m))
	ctx := t.Context()

	// The same disagreement the refused-apply test uses, reduced to one call:
	// a prefix advertised through the management API at a metric the file
	// contradicts. Everything else in the file is already true of the node.
	if err := s.AddPrefix(ctx, server.AdvertisedPrefix{
		Prefix: netip.MustParsePrefix("198.51.100.0/24"), Metric: 20,
	}); err != nil {
		t.Fatalf("AddPrefix: %v", err)
	}
	if err := os.WriteFile(path, []byte(strings.Replace(initial,
		"  - 192.0.2.0/24\n", "  - 192.0.2.0/24\n  - 198.51.100.0/24\n", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	ch, err := Diff(cfg, loadConfigFile(t, path))
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if n := len(ch.DeleteCircuits) + len(ch.DeleteLocators) + len(ch.DeleteFlexAlgos) +
		len(ch.AddFlexAlgos) + len(ch.AddLocators) + len(ch.DeletePrefixes) +
		len(ch.AddPrefixes) + len(ch.AddCircuits); n != 1 {
		t.Fatalf("the reload makes %d calls, not the single refused one this test is about: %+v", n, ch)
	}

	if _, err := Reload(ctx, s, cfg, path, slog.New(slog.NewTextHandler(io.Discard, nil))); !errors.Is(err, ErrPartiallyApplied) {
		t.Fatalf("Reload error = %v, want an ErrPartiallyApplied", err)
	}
	if got := m.count(string(server.ReloadPartial)); got != 1 {
		t.Errorf("partial reloads = %d, want 1", got)
	}
	if got := m.count(string(server.ReloadRefused)); got != 0 {
		t.Errorf("refused reloads = %d, want 0: nothing was refused before the calls went out", got)
	}

	// Nothing landed: this is the shape the outcome above is claimed for, so
	// the test is worth no more than its fixture.
	if !ownLSPHas(t, s, "198.51.100.0/24 metric 20") {
		t.Error("the refused call landed after all; this reload was meant to change nothing")
	}
	if !ownLSPHas(t, s, "192.0.2.0/24") {
		t.Error("the prefix the file still names left our own LSP; this reload was meant to change nothing")
	}
}

// reloadOrderingBase fills every slice of Changes with more than one entry, so
// the order they come out in is observable at all. reloadBase cannot: with one
// prefix, one locator and one algorithm, map iteration order has nowhere to
// show.
const reloadOrderingBase = `net: 49.0001.0000.0000.0001.00
prefixes:
  - {prefix: 192.0.2.0/24, metric: 10}
  - {prefix: 198.51.100.0/24, metric: 10}
  - {prefix: 203.0.113.0/24, metric: 10}
srv6:
  locators:
    - fc00:0:1::/48
    - fc00:0:2::/48
flex-algo:
  - algo: 128
    priority: 100
  - algo: 129
    priority: 100
circuits:
  - interface: mock0
    level: "2"
`

// TestChangesAreOrderedDeterministically pins what a reload owes an operator
// who applies the same file twice: the same calls in the same order. Diff reads
// its three sets out of maps, whose iteration order Go randomizes per range, so
// without the sorts the second SIGHUP would withdraw and re-add the same
// prefixes in a different order -- and a diff of two daemons' logs, or a test
// comparing Changes, would disagree for no reason at all.
func TestChangesAreOrderedDeterministically(t *testing.T) {
	old := loadConfig(t, reloadOrderingBase)
	next := loadConfig(t, strings.NewReplacer(
		"metric: 10", "metric: 20",
		"fc00:0:1::/48", "fc00:1:1::/48",
		"fc00:0:2::/48", "fc00:1:2::/48",
		"priority: 100", "priority: 200",
	).Replace(reloadOrderingBase))

	first, err := Diff(old, next)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	// Every slice has to carry at least two entries, or the repetition below
	// proves nothing about the one it does not exercise.
	for name, n := range map[string]int{
		"DeleteLocators": len(first.DeleteLocators), "DeleteFlexAlgos": len(first.DeleteFlexAlgos),
		"AddFlexAlgos": len(first.AddFlexAlgos), "AddLocators": len(first.AddLocators),
		"DeletePrefixes": len(first.DeletePrefixes), "AddPrefixes": len(first.AddPrefixes),
	} {
		if n < 2 {
			t.Fatalf("%s has %d entries: this fixture cannot show an ordering at all", name, n)
		}
	}

	// Diff is pure, so repetition is the whole test: only map iteration order
	// can make two runs over the same pair of configurations differ.
	for i := range 20 {
		got, err := Diff(old, next)
		if err != nil {
			t.Fatalf("Diff: %v", err)
		}
		if !reflect.DeepEqual(got, first) {
			t.Fatalf("run %d disagrees with the first about the order of the calls:\n got %+v\nwant %+v", i+1, got, first)
		}
	}
}

// runningServer writes yaml to a file, builds a server from it over a mock
// transport and starts its management loop. It returns the three things Reload
// takes: the configuration the daemon is running, the server, and the path.
// extra is appended to the file's own options, for a test that has to watch a
// sink the file cannot name.
func runningServer(t *testing.T, yaml string, extra ...server.ServerOption) (*Config, *server.IsisServer, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "goisisd.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	cfg.OpenCircuit = mockTransports("mock0", "mock1", "mock2")
	opts, err := cfg.Options()
	if err != nil {
		t.Fatalf("Options: %v", err)
	}
	s, err := server.NewIsisServer(append(opts, extra...)...)
	if err != nil {
		t.Fatalf("NewIsisServer: %v", err)
	}
	go s.Serve(t.Context()) //nolint:errcheck // shut down via ctx
	return cfg, s, path
}

// TestReloadReplacesAFlexAlgoWithoutLosingItsLocator drives the half of apply
// no other test reaches, against a running server. A Flexible Algorithm has no
// runtime update, so a changed definition is a withdrawal and a re-add -- and
// the server refuses to delete an algorithm while a locator still names it, so
// Diff makes the locator step aside and come back. That ordering is asserted
// against Diff's output elsewhere; the rule it exists to satisfy lives in the
// server. Only running the calls binds the two: a change to either side leaves
// this reload refused part way, with the locator withdrawn and not restored.
func TestReloadReplacesAFlexAlgoWithoutLosingItsLocator(t *testing.T) {
	const initial = `net: 49.0001.1921.6800.1001.00
srv6:
  locators:
    - fc00:0:1::/48
flex-algo:
  - algo: 128
    priority: 100
    advertise: true
    locator: fc00:128:1::/48
circuits:
  - interface: mock0
    level: "2"
`
	cfg, s, path := runningServer(t, initial)
	ctx := t.Context()
	if err := os.WriteFile(path, []byte(strings.Replace(initial, "priority: 100", "priority: 200", 1)), 0o600); err != nil {
		t.Fatal(err)
	}

	var logs bytes.Buffer
	if _, err := Reload(ctx, s, cfg, path, slog.New(slog.NewTextHandler(&logs, nil))); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	// The definition is read back from the elected FAD in the LSDB, so this
	// waits out the LSP generation throttle rather than reading the request
	// back from the option it came from.
	waitFor(t, "the reloaded Flex-Algo definition to be elected", func() bool {
		fas, err := s.ListFlexAlgos(ctx)
		if err != nil {
			return false
		}
		return slices.ContainsFunc(fas, func(fa server.FlexAlgoInfo) bool {
			return fa.Algo == 128 && fa.Definition != nil && fa.Definition.Priority == 200
		})
	})

	locators, err := s.ListLocators(ctx)
	if err != nil {
		t.Fatalf("ListLocators: %v", err)
	}
	want := map[netip.Prefix]uint8{
		netip.MustParsePrefix("fc00:0:1::/48"):   0,
		netip.MustParsePrefix("fc00:128:1::/48"): 128,
	}
	got := map[netip.Prefix]uint8{}
	for _, l := range locators {
		got[l.Prefix] = l.Algorithm
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("locators after the reload = %v, want %v (the one that stepped aside has to come back)", got, want)
	}
}

// TestReloadNamesAChangedSecretWithoutLoggingIt pins the contract every reload
// warning is written under: it carries keys and circuit names, never values,
// because half of these keys are authentication secrets. An operator rotating a
// password sends SIGHUP -- the area key is declined, the hello key is applied by
// rebuilding the circuit -- and must not find either password in the daemon's
// log, wherever that log is shipped to.
func TestReloadNamesAChangedSecretWithoutLoggingIt(t *testing.T) {
	const (
		oldArea  = "s3cr3t-area"
		newArea  = "r0tat3d-area"
		oldHello = "s3cr3t-hello"
		newHello = "r0tat3d-hello"
	)
	initial := `net: 49.0001.1921.6800.1001.00
area-password: ` + oldArea + `
circuits:
  - interface: mock0
    level: "2"
    hello-password: ` + oldHello + `
`
	cfg, s, path := runningServer(t, initial)
	next := strings.NewReplacer(oldArea, newArea, oldHello, newHello).Replace(initial)
	if err := os.WriteFile(path, []byte(next), 0o600); err != nil {
		t.Fatal(err)
	}

	var logs bytes.Buffer
	if _, err := Reload(t.Context(), s, cfg, path, slog.New(slog.NewTextHandler(&logs, nil))); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	// Both rotations are named -- the area password by key, the hello password
	// as the circuit that is rebuilt to carry it -- so the log really did have
	// both values in reach when it wrote the warnings.
	for _, key := range []string{"area-password", "its adjacencies will drop"} {
		if !strings.Contains(logs.String(), key) {
			t.Fatalf("the log does not name %q, so it never came near either secret:\n%s", key, logs.String())
		}
	}
	for _, secret := range []string{oldArea, newArea, oldHello, newHello} {
		if strings.Contains(logs.String(), secret) {
			t.Errorf("the reload logged the secret %q:\n%s", secret, logs.String())
		}
	}
}

// shortTimeouts narrows the reload's two deadlines for a test and restores
// them. The tests below are the only writers, and they do not run in parallel.
func shortTimeouts(t *testing.T, apply, report time.Duration) {
	t.Helper()
	a, r := applyTimeout, reportTimeout
	applyTimeout, reportTimeout = apply, report
	t.Cleanup(func() { applyTimeout, reportTimeout = a, r })
}

// blockingFIB holds the management loop inside the first local-SID write, the
// way a wedged sink does, and releases it after a fixed delay.
type blockingFIB struct {
	fib.Noop
	once sync.Once
	hold time.Duration
}

func (b *blockingFIB) AddLocalSID(fib.LocalSID) error {
	b.once.Do(func() { time.Sleep(b.hold) })
	return nil
}

// A reload reports how it went even when its own apply deadline expired. That
// outcome is the one worth having: the counter exists to expose a management
// loop too slow to answer, and sharing the apply's expired context with the
// report is exactly the case in which nothing would be recorded.
func TestAPartialApplyIsCountedWhenItsDeadlineExpires(t *testing.T) {
	shortTimeouts(t, 20*time.Millisecond, 5*time.Second)
	m := &reloadMetrics{}
	cfg, s, path := runningServer(t, reloadBase,
		server.WithMetrics(m), server.WithFIB(&blockingFIB{hold: 300 * time.Millisecond}))

	// Any change that reaches a local SID will do: the first write blocks past
	// the apply deadline, and the loop is free again well inside the report's.
	if err := os.WriteFile(path, []byte(strings.Replace(reloadBase,
		"    - fc00:0:1::/48", "    - fc00:0:1::/48\n    - fc00:0:2::/48", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Reload(t.Context(), s, cfg, path, slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
		t.Fatal("Reload: want the apply deadline to expire, got nil")
	}
	if got := m.count(string(server.ReloadPartial)); got != 1 {
		t.Errorf("partial reloads recorded = %d, want 1", got)
	}
}

// A reload is bounded even when the management loop never answers at all. The
// signal handler is behind this call, so an unbounded report would make one
// wedged loop swallow every later SIGHUP as well as this one.
func TestAReloadReturnsWhenTheManagementLoopNeverAnswers(t *testing.T) {
	shortTimeouts(t, 20*time.Millisecond, 20*time.Millisecond)
	path := filepath.Join(t.TempDir(), "goisisd.yaml")
	if err := os.WriteFile(path, []byte(reloadBase), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	cfg.OpenCircuit = mockCircuits(map[string]mockCircuit{
		"mock0": {tr: datalink.NewMockTransport(packet.SNPA{2, 0, 0, 0, 0, 1}, 1500)},
	})
	opts, err := cfg.Options()
	if err != nil {
		t.Fatalf("Options: %v", err)
	}
	// Never Serve: every mgmtOperation parks on the unread channel, which is
	// what a loop wedged on a slow sink looks like from here.
	s, err := server.NewIsisServer(opts...)
	if err != nil {
		t.Fatalf("NewIsisServer: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		// A file that will not load takes the earliest report path, the one
		// that runs before the apply has a deadline of its own.
		_, _ = Reload(t.Context(), s, cfg, filepath.Join(t.TempDir(), "absent.yaml"),
			slog.New(slog.NewTextHandler(io.Discard, nil)))
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Reload did not return; the outcome report is unbounded")
	}
}

// circuitOpener is a Config.OpenCircuit that keeps every transport it handed
// out, per interface, and can refuse one the way a NIC that is not there yet
// does. Only the goroutine running the reload calls it.
type circuitOpener struct {
	refuse map[string]bool
	opened map[string][]*datalink.MockTransport
	n      byte
}

func (o *circuitOpener) open(ifname string) (datalink.Transport, []netip.Addr, []netip.Addr, error) {
	if o.refuse[ifname] {
		return nil, nil, nil, fmt.Errorf("open %s: no such device", ifname)
	}
	o.n++
	tr := datalink.NewMockTransport(packet.SNPA{2, 0, 0, 0, 0, o.n}, 1500)
	if o.opened == nil {
		o.opened = map[string][]*datalink.MockTransport{}
	}
	o.opened[ifname] = append(o.opened[ifname], tr)
	return tr, nil, nil, nil
}

// closedTransport reports whether a mock transport has been closed. Send and
// not Recv: Recv blocks on a transport that is still open, so a regression
// would hang the test instead of failing it.
func closedTransport(tr *datalink.MockTransport) bool {
	return errors.Is(tr.Send(packet.SNPA{}, nil), datalink.ErrClosed)
}

// TestReloadAddsACircuitAndRetriesTheOneThatCannotOpen is what a reload owes an
// operator who adds circuits to the file while the node runs. It pins four
// decisions together because each is what makes the next one worth anything.
//
// An interface that cannot be opened -- written into the file before it exists,
// or a minute from coming up -- costs its own circuit and nothing else: apply
// issues the whole batch, so a sibling circuit in the same file still lands.
// The reload is then ErrPartiallyApplied and keeps its baseline, so the next
// signal re-diffs the whole change and tries the refused one again. That retry
// re-issues the addition that already landed, which the server answers as
// ErrAlreadyInState -- handing back the transport it did not take, which the
// reload must close or every further signal leaks a socket.
func TestReloadAddsACircuitAndRetriesTheOneThatCannotOpen(t *testing.T) {
	const initial = `net: 49.0001.1921.6800.1001.00
circuits:
  - interface: mock0
    level: "2"
`
	const next = initial + `  - interface: mock1
    level: "2"
  - interface: mock2
    level: "2"
`
	o := &circuitOpener{refuse: map[string]bool{"mock1": true}}
	path := filepath.Join(t.TempDir(), "goisisd.yaml")
	write := func(s string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(initial)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	cfg.OpenCircuit = o.open
	opts, err := cfg.Options()
	if err != nil {
		t.Fatalf("Options: %v", err)
	}
	s, err := server.NewIsisServer(opts...)
	if err != nil {
		t.Fatalf("NewIsisServer: %v", err)
	}
	ctx := t.Context()
	go s.Serve(ctx) //nolint:errcheck // shut down via ctx
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	write(next)
	running, err := Reload(ctx, s, cfg, path, logger)
	if !errors.Is(err, ErrPartiallyApplied) {
		t.Fatalf("Reload error = %v, want an ErrPartiallyApplied: an interface that cannot be opened is not a reload that ran", err)
	}
	if got := circuitNames(t, s); !slices.Equal(got, []string{"mock0", "mock2"}) {
		t.Errorf("circuits = %v, want mock2 beside mock0: one interface that cannot be opened must not take the rest of the batch with it", got)
	}

	again, err := Diff(running, loadConfigFile(t, path))
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(again.AddCircuits) != 2 {
		t.Fatalf("the next signal adds %+v, want both circuits again: the baseline advanced over a change the node never took", again.AddCircuits)
	}

	// The interface came up. One signal, and the node is running the file.
	o.refuse = nil
	running, err = Reload(ctx, s, running, path, logger)
	if err != nil {
		t.Fatalf("the retry was refused: %v", err)
	}
	if got := circuitNames(t, s); !slices.Equal(got, []string{"mock0", "mock2", "mock1"}) {
		t.Errorf("circuits = %v, want all three the file names", got)
	}
	if again, err := Diff(running, loadConfigFile(t, path)); err != nil {
		t.Fatalf("Diff: %v", err)
	} else if !reflect.DeepEqual(again, Changes{}) {
		t.Errorf("a further signal still diffs %+v: the baseline never adopted the file", again)
	}

	// The retry opened mock2 a second time and the server refused it, so that
	// socket is the reload's to close -- while the one the circuit is running
	// on is not.
	mock2 := o.opened["mock2"]
	if len(mock2) != 2 {
		t.Fatalf("mock2 was opened %d times, want 2 (the reload and its retry)", len(mock2))
	}
	if !closedTransport(mock2[1]) {
		t.Error("the transport the server refused was left open: every retry over a circuit the node already has leaks one")
	}
	if closedTransport(mock2[0]) {
		t.Error("the running circuit's transport was closed by the retry")
	}
}

// TestReloadRebuildsAChangedCircuitAndDropsOneTheFileStoppedNaming pins the
// half of the batch order that only shows when both ends of it run. A circuit
// whose definition changed is a removal and an addition under one name, so the
// removals have to be issued first -- against a node that still holds the old
// circuit, AddCircuit refuses the name, and the reload ends part applied with
// the circuit gone. A circuit the file stopped naming is removed in the same
// pass and stays removed.
func TestReloadRebuildsAChangedCircuitAndDropsOneTheFileStoppedNaming(t *testing.T) {
	const initial = `net: 49.0001.1921.6800.1001.00
circuits:
  - interface: mock0
    level: "2"
    metric: 10
  - interface: mock1
    level: "2"
`
	const next = `net: 49.0001.1921.6800.1001.00
circuits:
  - interface: mock0
    level: "2"
    metric: 55
`
	cfg, s, path := runningServer(t, initial)
	ctx := t.Context()
	if err := os.WriteFile(path, []byte(next), 0o600); err != nil {
		t.Fatal(err)
	}
	running, err := Reload(ctx, s, cfg, path, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}

	circuits, err := s.ListCircuits(ctx)
	if err != nil {
		t.Fatalf("ListCircuits: %v", err)
	}
	if len(circuits) != 1 || circuits[0].Interface != "mock0" {
		t.Fatalf("circuits = %+v, want only the one the file still names", circuits)
	}
	if circuits[0].Metric != 55 {
		t.Errorf("mock0 metric = %d, want the file's 55: the circuit was not rebuilt", circuits[0].Metric)
	}
	if again, err := Diff(running, loadConfigFile(t, path)); err != nil {
		t.Fatalf("Diff: %v", err)
	} else if !reflect.DeepEqual(again, Changes{}) {
		t.Errorf("a further signal still diffs %+v", again)
	}
}
