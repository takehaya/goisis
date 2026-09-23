package config

import (
	"bytes"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/takehaya/goisis/pkg/datalink"
	"github.com/takehaya/goisis/pkg/packet"
	"github.com/takehaya/goisis/pkg/server"
)

// reloadBase is the running configuration every Diff case below starts from.
const reloadBase = `net: 49.0001.0000.0000.0001.00
area-password: secret
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
			want: Changes{Ignored: []string{"circuits: mock1 added"}},
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
func TestDiffNamesEveryConfigKey(t *testing.T) {
	// One mutation per Config field. A nil mutation is a field that is not a
	// configuration key at all.
	mutations := map[string]func(*Config){
		"NET":                   func(c *Config) { c.NET = "49.0009.0000.0000.0009.00" },
		"Hostname":              func(c *Config) { c.Hostname = "r9" },
		"FIB":                   func(c *Config) { c.FIB = !c.FIB },
		"FIBTable":              func(c *Config) { c.FIBTable = 99 },
		"Circuits":              func(c *Config) { c.Circuits = append(slices.Clone(c.Circuits), CircuitConfig{Interface: "mock9"}) },
		"Prefixes":              func(c *Config) { c.Prefixes = append(slices.Clone(c.Prefixes), PrefixConfig{Prefix: "203.0.113.0/24"}) },
		"SRv6":                  func(c *Config) { c.SRv6 = &SRv6Config{Locators: []string{"fc00:9::/48"}} },
		"FlexAlgo":              func(c *Config) { c.FlexAlgo = nil },
		"Policy":                func(c *Config) { c.Policy = &PolicyConfig{Advertise: &PrefixListConfig{Default: "permit"}} },
		"OverloadOnStartup":     func(c *Config) { c.OverloadOnStartup = "60s" },
		"AreaPassword":          func(c *Config) { c.AreaPassword = "rotated" },
		"AreaAcceptPasswords":   func(c *Config) { c.AreaAcceptPasswords = []string{"old"} },
		"AreaAuthAlgorithm":     func(c *Config) { c.AreaAuthAlgorithm = "sha256" },
		"AreaKeyID":             func(c *Config) { c.AreaKeyID = 7 },
		"DomainPassword":        func(c *Config) { c.DomainPassword = "rotated" },
		"DomainAcceptPasswords": func(c *Config) { c.DomainAcceptPasswords = []string{"old"} },
		"DomainAuthAlgorithm":   func(c *Config) { c.DomainAuthAlgorithm = "sha256" },
		"DomainKeyID":           func(c *Config) { c.DomainKeyID = 7 },
		"LSDBEntryLimit":        func(c *Config) { c.LSDBEntryLimit = 5000 },
		"LSPMTU":                func(c *Config) { c.LSPMTU = 1400 },
		"OpenCircuit":           nil, // the embedder's transport seam, not a YAML key
	}

	old := loadConfig(t, reloadBase)
	typ := reflect.TypeOf(Config{})
	for i := range typ.NumField() {
		name := typ.Field(i).Name
		mutate, ok := mutations[name]
		if !ok {
			t.Errorf("Config field %s has no mutation here: add it to this table, and to whichever of Diff or restartOnly owns it", name)
			continue
		}
		if mutate == nil {
			continue
		}
		next := *old
		mutate(&next)
		got, err := Diff(old, &next)
		if err != nil {
			t.Errorf("%s: Diff: %v", name, err)
			continue
		}
		if reflect.DeepEqual(got, Changes{}) {
			t.Errorf("changing %s is reported by nothing: a reload would ignore it silently", name)
		}
	}
}

// TestReloadAppliesPrefixesAndLeavesCircuitsToARestart drives the whole path
// against a running server: the file's new prefix reaches the node's own LSP,
// the circuit the file grew does not appear, and it is named in the log.
func TestReloadAppliesPrefixesAndLeavesCircuitsToARestart(t *testing.T) {
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

	var logs bytes.Buffer
	write(next)
	running, err := Reload(ctx, s, cfg, path, slog.New(slog.NewTextHandler(&logs, nil)))
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}

	waitFor(t, "the reloaded prefix in our own LSP", func() bool { return ownLSPHas(t, s, "198.51.100.0/24") })
	if ownLSPHas(t, s, "192.0.2.0/24") {
		t.Error("the prefix the file dropped is still advertised")
	}
	circuits, err := s.ListCircuits(ctx)
	if err != nil {
		t.Fatalf("ListCircuits: %v", err)
	}
	if len(circuits) != 1 || circuits[0].Interface != "mock0" {
		t.Errorf("circuits = %+v, want only mock0: a reload never adds one", circuits)
	}
	if !strings.Contains(logs.String(), "mock1") {
		t.Errorf("the ignored circuit is not named in the log:\n%s", logs.String())
	}

	// The returned configuration is what the daemon runs, not what the file
	// says: the circuit it could not add is still absent from it, so the next
	// reload warns about it again instead of forgetting it.
	again, err := Diff(running, loadConfigFile(t, path))
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if !slices.Contains(again.Ignored, "circuits: mock1 added") {
		t.Errorf("a second reload reports %v, want the circuit named again", again.Ignored)
	}
	if len(again.AddPrefixes)+len(again.DeletePrefixes) != 0 {
		t.Errorf("a second reload re-applies prefixes: %+v", again)
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
