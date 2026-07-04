package config

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/takehaya/goisis/pkg/datalink"
	"github.com/takehaya/goisis/pkg/packet"
	"github.com/takehaya/goisis/pkg/server"
)

// mockCircuit is what the openCircuit seam hands out for one interface name.
type mockCircuit struct {
	tr     datalink.Transport
	v4, v6 []netip.Addr
}

// mockCircuits returns a Config.OpenCircuit implementation resolving each
// interface name to a mock transport and synthetic hello addresses instead of
// an AF_PACKET socket.
func mockCircuits(circuits map[string]mockCircuit) func(string) (datalink.Transport, []netip.Addr, []netip.Addr, error) {
	return func(ifname string) (datalink.Transport, []netip.Addr, []netip.Addr, error) {
		mc, ok := circuits[ifname]
		if !ok {
			return nil, nil, nil, fmt.Errorf("no mock circuit for %q", ifname)
		}
		return mc.tr, mc.v4, mc.v6, nil
	}
}

// loadConfig writes a YAML config to a temp file and loads it.
func loadConfig(t *testing.T, yaml string) *Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return c
}

// waitFor polls fn until it reports success or the deadline passes.
func waitFor(t *testing.T, what string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// TestOptionsBuildServer runs the whole YAML -> Options -> NewIsisServer seam
// with a mock transport and asserts the resulting server's observable state.
func TestOptionsBuildServer(t *testing.T) {
	open := mockCircuits(map[string]mockCircuit{
		"mock0": {
			tr: datalink.NewMockTransport(packet.SNPA{2, 0, 0, 0, 0, 1}, 1500),
			v4: []netip.Addr{netip.MustParseAddr("10.0.0.1")},
		},
	})
	c := loadConfig(t, `net: 49.0001.1921.6800.1001.00
hostname: r1
lsdb-entry-limit: 5000
prefixes:
  - 192.0.2.0/24
srv6:
  locators:
    - fc00:0:1::/48
flex-algo:
  - algo: 128
    metric-type: igp
    priority: 100
    advertise: true
    locator: fc00:128:1::/48
area-password: as
area-auth-algorithm: sha256
area-key-id: 1
domain-password: ds
domain-auth-algorithm: sha512
domain-key-id: 2
circuits:
  - interface: mock0
    level: "2"
    p2p: true
    metric: 20
    hello-password: hp
`)
	c.OpenCircuit = open
	if c.LSDBEntryLimit != 5000 {
		t.Errorf("lsdb-entry-limit = %d, want 5000", c.LSDBEntryLimit)
	}

	opts, err := c.Options()
	if err != nil {
		t.Fatalf("Options: %v", err)
	}
	s, err := server.NewIsisServer(opts...)
	if err != nil {
		t.Fatalf("NewIsisServer: %v", err)
	}
	ctx := t.Context()
	go s.Serve(ctx) //nolint:errcheck // shut down via ctx

	g, err := s.GetGlobal(ctx)
	if err != nil {
		t.Fatalf("GetGlobal: %v", err)
	}
	if want := (packet.SystemID{0x19, 0x21, 0x68, 0x00, 0x10, 0x01}); g.SystemID != want {
		t.Errorf("SystemID = %v, want %v", g.SystemID, want)
	}

	circuits, err := s.ListCircuits(ctx)
	if err != nil {
		t.Fatalf("ListCircuits: %v", err)
	}
	if len(circuits) != 1 {
		t.Fatalf("circuits = %+v, want one", circuits)
	}
	cc := circuits[0]
	if cc.Interface != "mock0" || !cc.P2P || cc.Level1 || !cc.Level2 || cc.Metric != 20 {
		t.Errorf("circuit = %+v, want mock0 p2p L2-only metric 20", cc)
	}

	locators, err := s.ListLocators(ctx)
	if err != nil {
		t.Fatalf("ListLocators: %v", err)
	}
	want := map[netip.Prefix]uint8{
		netip.MustParsePrefix("fc00:0:1::/48"):   0,
		netip.MustParsePrefix("fc00:128:1::/48"): 128,
	}
	if len(locators) != len(want) {
		t.Fatalf("locators = %+v, want %d entries", locators, len(want))
	}
	for _, l := range locators {
		algo, ok := want[l.Prefix]
		if !ok || l.Algorithm != algo {
			t.Errorf("locator %s algo %d unexpected (want %v)", l.Prefix, l.Algorithm, want)
		}
	}
}

// TestOptionsErrors covers Options rejecting malformed fields. All errors fire
// before any transport is opened, so no seam substitution is needed beyond a
// guard that fails the test if a transport were requested.
func TestOptionsErrors(t *testing.T) {
	open := mockCircuits(nil) // any circuit open fails the Options call
	for name, yaml := range map[string]string{
		"invalid net":         "net: bogus\ncircuits:\n  - interface: eth0\n",
		"invalid prefix":      "net: 49.0001.0000.0000.0001.00\nprefixes:\n  - not-a-cidr\ncircuits:\n  - interface: eth0\n",
		"invalid locator":     "net: 49.0001.0000.0000.0001.00\nsrv6:\n  locators:\n    - bogus\ncircuits:\n  - interface: eth0\n",
		"invalid metric-type": "net: 49.0001.0000.0000.0001.00\nflex-algo:\n  - algo: 128\n    metric-type: bogus\ncircuits:\n  - interface: eth0\n",
		"invalid auth":        "net: 49.0001.0000.0000.0001.00\narea-password: x\narea-auth-algorithm: bogus\ncircuits:\n  - interface: eth0\n",
		"invalid overload":    "net: 49.0001.0000.0000.0001.00\noverload-on-startup: soon\ncircuits:\n  - interface: eth0\n",
	} {
		c := loadConfig(t, yaml)
		c.OpenCircuit = open
		if _, err := c.Options(); err == nil {
			t.Errorf("%s: Options succeeded, want error", name)
		}
	}
}

// TestOptionsTwoNodeConvergence builds two servers entirely from YAML (via the
// openCircuit seam), links their circuits, and asserts they exchange
// authenticated hellos and LSPs: the peer learns the advertised prefix, the
// route resolves to the configured hello address, and the Flex-Algo definition
// is elected from the advertiser's LSP.
func TestOptionsTwoNodeConvergence(t *testing.T) {
	ta := datalink.NewMockTransport(packet.SNPA{2, 0, 0, 0, 0, 0xa}, 1500)
	tb := datalink.NewMockTransport(packet.SNPA{2, 0, 0, 0, 0, 0xb}, 1500)
	datalink.Link(ta, tb)
	open := mockCircuits(map[string]mockCircuit{
		"ifa": {tr: ta, v4: []netip.Addr{netip.MustParseAddr("10.0.0.1")}},
		"ifb": {tr: tb, v4: []netip.Addr{netip.MustParseAddr("10.0.0.2")}},
	})

	const auth = `domain-password: ds
domain-auth-algorithm: sha256
domain-key-id: 7
`
	cfgA := loadConfig(t, `net: 49.0001.0000.0000.000a.00
hostname: ra
prefixes:
  - 192.0.2.0/24
flex-algo:
  - algo: 128
    priority: 100
    advertise: true
    locator: fc00:128:a::/48
`+auth+`circuits:
  - interface: ifa
    level: "2"
    p2p: true
    hello-password: hp
    hello-auth-algorithm: sha256
    hello-key-id: 3
`)
	cfgB := loadConfig(t, `net: 49.0001.0000.0000.000b.00
hostname: rb
`+auth+`circuits:
  - interface: ifb
    level: "2"
    p2p: true
    hello-password: hp
    hello-auth-algorithm: sha256
    hello-key-id: 3
`)

	ctx := t.Context()
	var servers [2]*server.IsisServer
	for i, cfg := range []*Config{cfgA, cfgB} {
		cfg.OpenCircuit = open
		opts, err := cfg.Options()
		if err != nil {
			t.Fatalf("Options[%d]: %v", i, err)
		}
		s, err := server.NewIsisServer(opts...)
		if err != nil {
			t.Fatalf("NewIsisServer[%d]: %v", i, err)
		}
		go s.Serve(ctx) //nolint:errcheck // shut down via ctx
		servers[i] = s
	}
	sb := servers[1]
	sysA := packet.SystemID{0, 0, 0, 0, 0, 0xa}

	waitFor(t, "adjacency up on B", func() bool {
		adjs, err := sb.ListAdjacencies(ctx)
		if err != nil {
			return false
		}
		for _, a := range adjs {
			if a.SystemID == sysA && a.State == server.AdjUp {
				return true
			}
		}
		return false
	})
	waitFor(t, "B to learn A's route", func() bool {
		routes, err := sb.ListRoutes(ctx)
		if err != nil {
			return false
		}
		for _, r := range routes {
			if r.Prefix == netip.MustParsePrefix("192.0.2.0/24") && r.Algorithm == 0 &&
				len(r.NextHops) == 1 && r.NextHops[0].Gateway == netip.MustParseAddr("10.0.0.1") {
				return true
			}
		}
		return false
	})
	waitFor(t, "B to elect A's Flex-Algo definition", func() bool {
		fas, err := sb.ListFlexAlgos(ctx)
		if err != nil {
			return false
		}
		for _, fa := range fas {
			if fa.Algo == 128 && fa.Definition != nil &&
				fa.Definition.Advertiser == sysA && fa.Definition.Priority == 100 {
				return true
			}
		}
		return false
	})
}
