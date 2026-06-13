package packet

import "testing"

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
