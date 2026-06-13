package packet

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// ParseNET parses an IS-IS Network Entity Title in dotted-hex form (e.g.
// "49.0001.0000.0000.0001.00") into its area address and system ID. The NET
// is an NSAP whose last octet (the NSEL) must be zero; the six octets before
// it are the system ID, and the remaining leading octets are the area address
// (1-13 octets).
func ParseNET(net string) (AreaAddress, SystemID, error) {
	raw, err := hex.DecodeString(strings.ReplaceAll(net, ".", ""))
	if err != nil {
		return nil, SystemID{}, fmt.Errorf("NET %q: %w", net, err)
	}
	// area(1-13) + system ID(6) + NSEL(1) = 8-20 octets.
	if len(raw) < 8 || len(raw) > 20 {
		return nil, SystemID{}, fmt.Errorf("NET %q: length %d octets out of range 8-20", net, len(raw))
	}
	if raw[len(raw)-1] != 0 {
		return nil, SystemID{}, fmt.Errorf("NET %q: NSEL must be 00", net)
	}
	var sysID SystemID
	copy(sysID[:], raw[len(raw)-7:len(raw)-1])
	area := AreaAddress(append([]byte(nil), raw[:len(raw)-7]...))
	return area, sysID, nil
}
