package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/takehaya/goisis/pkg/packet"
)

func TestAuthAlgorithm(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want packet.AuthAlgorithm
		ok   bool
	}{
		{"", packet.AuthMD5, true},
		{"md5", packet.AuthMD5, true},
		{"sha1", packet.AuthSHA1, true},
		{"sha256", packet.AuthSHA256, true},
		{"hmac-sha-512", packet.AuthSHA512, true},
		{"bogus", 0, false},
	} {
		got, err := authAlgorithm(tc.in)
		if (err == nil) != tc.ok {
			t.Errorf("authAlgorithm(%q) ok=%v, want %v (err=%v)", tc.in, err == nil, tc.ok, err)
		}
		if tc.ok && got != tc.want {
			t.Errorf("authAlgorithm(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestLoadAuth(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.yaml")
	cfg := `net: 49.0001.0000.0000.0001.00
area-password: areasecret
area-auth-algorithm: sha256
area-key-id: 5
circuits:
  - interface: eth0
    hello-password: hp
    hello-auth-algorithm: sha512
    hello-key-id: 9
`
	if err := os.WriteFile(path, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.AreaPassword != "areasecret" || c.AreaAuthAlgorithm != "sha256" || c.AreaKeyID != 5 {
		t.Errorf("area auth = %q/%q/%d", c.AreaPassword, c.AreaAuthAlgorithm, c.AreaKeyID)
	}
	cc := c.Circuits[0]
	if cc.HelloPassword != "hp" || cc.HelloAuthAlgorithm != "sha512" || cc.HelloKeyID != 9 {
		t.Errorf("hello auth = %q/%q/%d", cc.HelloPassword, cc.HelloAuthAlgorithm, cc.HelloKeyID)
	}
}

func TestLoadSRv6Locators(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.yaml")
	cfg := `net: 49.0001.0000.0000.0001.00
circuits:
  - interface: eth0
srv6:
  locators:
    - fc00:0:1::/48
    - fc00:0:2::/48
`
	if err := os.WriteFile(path, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.SRv6 == nil || len(c.SRv6.Locators) != 2 {
		t.Fatalf("srv6 locators not parsed: %+v", c.SRv6)
	}
	if c.SRv6.Locators[0] != "fc00:0:1::/48" || c.SRv6.Locators[1] != "fc00:0:2::/48" {
		t.Errorf("locators = %v", c.SRv6.Locators)
	}
}

func TestLoadFlexAlgo(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.yaml")
	cfg := `net: 49.0001.0000.0000.0001.00
circuits:
  - interface: eth0
flex-algo:
  - algo: 128
    metric-type: igp
    priority: 100
    advertise: true
    locator: fc00:128:1::/48
`
	if err := os.WriteFile(path, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(c.FlexAlgo) != 1 {
		t.Fatalf("flex-algo not parsed: %+v", c.FlexAlgo)
	}
	fa := c.FlexAlgo[0]
	if fa.Algo != 128 || fa.MetricType != "igp" || fa.Priority != 100 || !fa.Advertise || fa.Locator != "fc00:128:1::/48" {
		t.Errorf("flex-algo = %+v", fa)
	}
}

func TestLoadOverloadOnStartup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.yaml")
	cfg := "net: 49.0001.0000.0000.0001.00\noverload-on-startup: 30s\ncircuits:\n  - interface: eth0\n"
	if err := os.WriteFile(path, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.OverloadOnStartup != "30s" {
		t.Errorf("overload-on-startup = %q, want 30s", c.OverloadOnStartup)
	}
}

func TestFlexAlgoMetricType(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want uint8
		ok   bool
	}{
		{"", 0, true},
		{"igp", 0, true},
		{"delay", 1, true},
		{"te", 2, true},
		{"bogus", 0, false},
	} {
		got, err := flexAlgoMetricType(tc.in)
		if (err == nil) != tc.ok {
			t.Errorf("flexAlgoMetricType(%q) ok=%v, want %v", tc.in, err == nil, tc.ok)
		}
		if tc.ok && got != tc.want {
			t.Errorf("flexAlgoMetricType(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestLevels(t *testing.T) {
	for _, tc := range []struct {
		in         string
		l1, l2, ok bool
	}{
		{"1", true, false, true},
		{"2", false, true, true},
		{"12", true, true, true},
		{"", true, true, true},
		{"l2", false, false, false}, // typo must error, not silently become L1L2
		{"21", false, false, false},
	} {
		l1, l2, err := levels(tc.in)
		if (err == nil) != tc.ok {
			t.Errorf("levels(%q) ok=%v, want %v (err=%v)", tc.in, err == nil, tc.ok, err)
		}
		if tc.ok && (l1 != tc.l1 || l2 != tc.l2) {
			t.Errorf("levels(%q) = (%v,%v), want (%v,%v)", tc.in, l1, l2, tc.l1, tc.l2)
		}
	}
}
