package config

import (
	"os"
	"path/filepath"
	"testing"
)

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
