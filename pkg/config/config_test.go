package config

import "testing"

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
