package packet

import (
	"bytes"
	"testing"
)

func TestParseNET(t *testing.T) {
	area, sysID, err := ParseNET("49.0001.0000.0000.0001.00")
	if err != nil {
		t.Fatalf("ParseNET: %v", err)
	}
	if area.String() != "49.0001" {
		t.Errorf("area = %q, want 49.0001", area)
	}
	if sysID.String() != "0000.0000.0001" {
		t.Errorf("sysID = %q, want 0000.0000.0001", sysID)
	}
}

// FuzzParseNET exercises the NET string parser over arbitrary input: it must
// never panic, and any accepted NET must re-parse identically from its
// canonical dotted-hex re-formatting.
func FuzzParseNET(f *testing.F) {
	f.Add("49.0001.0000.0000.0001.00")
	f.Add("49.0001.0000.0000.0001.01")                       // nonzero NSEL
	f.Add("0000.0000.0001.00")                               // too short
	f.Add("49.0001.0203.0405.0607.0809.0000.0000.0001.00")   // 13-octet area
	f.Add("49.0001.0203.0405.0607.08090a.0000.0000.0001.00") // too long
	f.Add("zz.0001.0000.0000.0001.00")                       // bad hex
	f.Add("....")
	f.Fuzz(func(t *testing.T, s string) {
		area, sysID, err := ParseNET(s)
		if err != nil {
			return // rejected input is fine; we only require no panic
		}
		if len(area) < 1 || len(area) > 13 {
			t.Fatalf("ParseNET(%q) accepted a %d-octet area", s, len(area))
		}
		// Round-trip: the canonical re-formatting must parse to the same pair.
		canon := area.String() + "." + sysID.String() + ".00"
		area2, sysID2, err := ParseNET(canon)
		if err != nil {
			t.Fatalf("canonical NET %q of %q failed to parse: %v", canon, s, err)
		}
		if !bytes.Equal(area2, area) || sysID2 != sysID {
			t.Fatalf("round-trip mismatch for %q via %q: %v/%v != %v/%v", s, canon, area, sysID, area2, sysID2)
		}
	})
}

func TestParseNETErrors(t *testing.T) {
	for _, net := range []string{
		"49.0001.0000.0000.0001.01", // nonzero NSEL
		"0000.0000.0001.00",         // too short (no area)
		"zz.0001.0000.0000.0001.00", // bad hex
	} {
		if _, _, err := ParseNET(net); err == nil {
			t.Errorf("ParseNET(%q) = nil error, want error", net)
		}
	}
}
