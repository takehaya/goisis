package server

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"unicode"

	"github.com/takehaya/goisis/pkg/packet"
)

// tlvSummaries renders an LSP's TLVs for `goisis database --detail`, in wire
// order. A TLV carrying a list renders one line per entry, so the result is
// usually longer than the TLV count; a list TLV with no entries renders
// nothing at all rather than a blank line.
func tlvSummaries(tlvs []packet.TLV) []string {
	out := make([]string, 0, len(tlvs))
	for _, tlv := range tlvs {
		out = append(out, tlvSummary(tlv)...)
	}
	return out
}

// displayString makes a peer-supplied string fit to leave the daemon. Two
// reasons, both of them reachable from one hostile TLV 137: a proto3 string
// field must hold valid UTF-8, so invalid bytes fail the Marshal of the whole
// response and break `goisis database`/`goisis neighbor` for every operator
// until the LSP ages out; and a control character is either an escape sequence
// the operator's terminal obeys or a newline that forges a line of --detail
// output. RFC 5301 constrains neither the octets of TLV 137 nor their
// encoding, so neither case is hypothetical. The codec keeps the bytes as
// received; only display is sanitized.
func displayString(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return '?'
		}
		return r
	}, strings.ToValidUTF8(s, "\uFFFD"))
}

// tlvSummary renders one TLV as human-readable text, one line per entry. It
// lives here and not in pkg/packet because that package is a pure codec. A TLV
// this switch does not name falls back to its type and length, so the output
// stays useful in front of a peer advertising what goisis does not decode.
func tlvSummary(tlv packet.TLV) []string {
	switch t := tlv.(type) {
	case *packet.AreaAddressesTLV:
		areas := make([]string, 0, len(t.Addresses))
		for _, a := range t.Addresses {
			areas = append(areas, a.String())
		}
		return []string{"Area Addresses: " + strings.Join(areas, " ")}

	case *packet.ProtocolsSupportedTLV:
		return []string{"Protocols Supported: " + strings.Join(nlpidNames(t.NLPIDs), " ")}

	case *packet.DynamicHostnameTLV:
		return []string{"Dynamic Hostname: " + displayString(t.Hostname)}

	case *packet.ExtendedISReachabilityTLV:
		return isReachSummaries("IS Reachability", t.Neighbors)

	case *packet.MTISReachabilityTLV:
		return isReachSummaries("IS Reachability"+mtTag(t.MTID), t.Neighbors)

	case *packet.ExtendedIPReachabilityTLV:
		lines := make([]string, 0, len(t.Prefixes))
		for _, p := range t.Prefixes {
			lines = append(lines, "IPv4 Reachability: "+prefixSummary(p.Prefix, p.Metric, p.Down))
		}
		return lines

	case *packet.MTIPReachabilityTLV:
		lines := make([]string, 0, len(t.Prefixes))
		for _, p := range t.Prefixes {
			lines = append(lines, "IPv4 Reachability"+mtTag(t.MTID)+": "+prefixSummary(p.Prefix, p.Metric, p.Down))
		}
		return lines

	case *packet.IPv6ReachabilityTLV:
		lines := make([]string, 0, len(t.Prefixes))
		for _, p := range t.Prefixes {
			lines = append(lines, "IPv6 Reachability: "+prefixSummary(p.Prefix, p.Metric, p.Down))
		}
		return lines

	case *packet.MTIPv6ReachabilityTLV:
		lines := make([]string, 0, len(t.Prefixes))
		for _, p := range t.Prefixes {
			lines = append(lines, "IPv6 Reachability"+mtTag(t.MTID)+": "+prefixSummary(p.Prefix, p.Metric, p.Down))
		}
		return lines

	case *packet.MTopologiesTLV:
		if len(t.Topologies) == 0 {
			break // an empty participation set says nothing; show it as the raw TLV
		}
		ids := make([]string, 0, len(t.Topologies))
		for _, e := range t.Topologies {
			id := strconv.Itoa(int(e.MTID))
			if e.Overload {
				id += "/overload"
			}
			if e.Attached {
				id += "/attached"
			}
			ids = append(ids, id)
		}
		return []string{"Topologies: " + strings.Join(ids, " ")}

	case *packet.SRv6LocatorTLV:
		lines := make([]string, 0, len(t.Locators))
		for _, l := range t.Locators {
			line := fmt.Sprintf("SRv6 Locator: %s algo %d metric %d", l.Locator, l.Algorithm, l.Metric)
			for _, sid := range l.EndSIDs {
				line += " End " + sid.SID.String()
			}
			lines = append(lines, line)
		}
		return lines

	case *packet.RouterCapabilityTLV:
		return []string{routerCapSummary(t)}

	case *packet.AuthenticationTLV:
		return []string{authSummary(t)}

	case *packet.UnknownTLV:
		// TLV 13 has no decoder (RFC 6232 is carried opaquely), but an
		// operator chasing a purge wants to see who sent it.
		if t.TLVType == packet.TLVTypePurgeOriginatorID {
			if s, ok := purgeOriginatorSummary(t.Value); ok {
				return []string{s}
			}
		}
	}
	return []string{rawTLVSummary(tlv)}
}

// isReachSummaries renders the neighbor list shared by TLVs 22 and 222; label
// carries the MT tag for the latter.
func isReachSummaries(label string, neighbors []packet.ExtendedISReachEntry) []string {
	lines := make([]string, 0, len(neighbors))
	for _, n := range neighbors {
		line := fmt.Sprintf("%s: %s metric %d", label, n.NeighborID, n.Metric)
		if len(n.SubTLVs) > 0 {
			line += fmt.Sprintf(" (%d sub-TLVs)", len(n.SubTLVs))
		}
		lines = append(lines, line)
	}
	return lines
}

// mtTag names the topology an RFC 5120 TLV advertises for. It is always shown,
// including for MT #0, because a TLV 222/235/237 carrying MT #0 is one the
// decision process ignores and an operator reading --detail needs to see why.
func mtTag(mtid uint16) string { return fmt.Sprintf(" (MT %d)", mtid) }

func prefixSummary(p netip.Prefix, metric uint32, down bool) string {
	s := fmt.Sprintf("%s metric %d", p, metric)
	if down {
		s += " down"
	}
	return s
}

func nlpidNames(nlpids []byte) []string {
	out := make([]string, 0, len(nlpids))
	for _, n := range nlpids {
		switch n {
		case packet.NLPIDIPv4:
			out = append(out, "IPv4")
		case packet.NLPIDIPv6:
			out = append(out, "IPv6")
		default:
			out = append(out, fmt.Sprintf("0x%02x", n))
		}
	}
	return out
}

// routerCapSummary renders TLV 242: the router ID plus the capability sub-TLVs
// an operator looks for. Sub-TLVs goisis preserves but does not interpret are
// left out; --detail is a readable summary, not a hex dump.
func routerCapSummary(t *packet.RouterCapabilityTLV) string {
	parts := []string{"Router Capability:"}
	if t.RouterID.IsValid() && !t.RouterID.IsUnspecified() {
		parts = append(parts, "router-id "+t.RouterID.String())
	}
	for _, st := range t.SubTLVs {
		switch s := st.(type) {
		case *packet.SRAlgorithmSubTLV:
			algos := make([]string, 0, len(s.Algorithms))
			for _, a := range s.Algorithms {
				algos = append(algos, strconv.Itoa(int(a)))
			}
			parts = append(parts, "SR-Algorithm "+strings.Join(algos, ","))
		case *packet.FlexAlgoDefinitionSubTLV:
			parts = append(parts, fmt.Sprintf("FAD %d (metric %s, prio %d)",
				s.FlexAlgo, flexAlgoMetricName(s.MetricType), s.Priority))
		case *packet.SRv6CapabilitiesSubTLV:
			parts = append(parts, "SRv6")
		}
	}
	return strings.Join(parts, " ")
}

func flexAlgoMetricName(mt uint8) string {
	switch mt {
	case packet.FlexAlgoMetricIGP:
		return "igp"
	case packet.FlexAlgoMetricMinDelay:
		return "delay"
	case packet.FlexAlgoMetricTE:
		return "te"
	default:
		return strconv.Itoa(int(mt))
	}
}

// flexAlgoConstraintSummaries renders a FAD's constraint sub-sub-TLVs for
// `goisis flex-algo`, one line each, in wire order. It lives here and not in
// pkg/packet for the same reason tlvSummary does: that package is a pure
// codec. goisis does not prune on these constraints (see the Limitations
// table), so this rendering is the only place an operator sees that the area's
// winning definition asks for them.
func flexAlgoConstraintSummaries(ss []packet.FlexAlgoSubSubTLV) []string {
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		out = append(out, flexAlgoConstraintSummary(s))
	}
	return out
}

// flexAlgoConstraintSummary renders one constraint sub-sub-TLV (RFC 9350
// section 6). A value whose length RFC 9350 rules out — an admin group or an
// SRLG list that is not a whole number of 4-octet units — falls back to type
// and length rather than being rendered as something it is not, the way an
// unrecognised sub-sub-TLV does.
func flexAlgoConstraintSummary(ss packet.FlexAlgoSubSubTLV) string {
	switch ss.SubSubTLVType {
	case packet.FlexAlgoSubSubExcludeAdminGroup:
		if s, ok := adminGroupSummary("exclude-admin-group", ss.Value); ok {
			return s
		}
	case packet.FlexAlgoSubSubIncludeAnyAdminGroup:
		if s, ok := adminGroupSummary("include-any-admin-group", ss.Value); ok {
			return s
		}
	case packet.FlexAlgoSubSubIncludeAllAdminGroup:
		if s, ok := adminGroupSummary("include-all-admin-group", ss.Value); ok {
			return s
		}
	case packet.FlexAlgoSubSubDefinitionFlags:
		// The flags length is a plain octet count, not a multiple of 4, so
		// nothing here can be malformed.
		return "flags " + flexAlgoFlagNames(ss.Value)
	case packet.FlexAlgoSubSubExcludeSRLG:
		if words, ok := flexAlgoWords(ss.Value); ok {
			srlgs := make([]string, 0, len(words))
			for _, w := range words {
				srlgs = append(srlgs, strconv.FormatUint(uint64(w), 10))
			}
			return "exclude-srlg " + strings.Join(srlgs, ",")
		}
	}
	return fmt.Sprintf("sub-sub-TLV %d: %d octets", ss.SubSubTLVType, len(ss.Value))
}

// adminGroupSummary renders an Extended Admin Group (RFC 7308) in the 4-octet
// units it is defined in. The value is a bitmask of colors, not a number, and
// RFC 7308 numbers the bits per unit; printing the mask keeps the output the
// same shape as the operator's configuration instead of committing this node
// to one reading of that numbering.
func adminGroupSummary(name string, v []byte) (string, bool) {
	words, ok := flexAlgoWords(v)
	if !ok {
		return "", false
	}
	groups := make([]string, 0, len(words))
	for _, w := range words {
		groups = append(groups, fmt.Sprintf("0x%08x", w))
	}
	return name + " " + strings.Join(groups, ","), true
}

// flexAlgoWords splits a constraint value into the 4-octet units RFC 9350
// section 6 requires of an admin group and an SRLG list. It reports false for
// any other length so the caller falls back to type and length.
func flexAlgoWords(v []byte) ([]uint32, bool) {
	if len(v) == 0 || len(v)%4 != 0 {
		return nil, false
	}
	out := make([]uint32, 0, len(v)/4)
	for i := 0; i < len(v); i += 4 {
		out = append(out, binary.BigEndian.Uint32(v[i:i+4]))
	}
	return out, true
}

// flexAlgoFlagNames renders the definition flags (RFC 9350 section 6.4). Bit 0
// is the M-flag; the rest are unassigned and are named by position, because
// the RFC makes an unsupported bit a reason to stop participating — an
// operator chasing that needs to see the bit, not a blank.
func flexAlgoFlagNames(v []byte) string {
	var names []string
	for i, b := range v {
		for bit := 0; bit < 8; bit++ {
			mask := byte(0x80) >> bit
			switch {
			case b&mask == 0:
			case i == 0 && mask == packet.FlexAlgoFlagM:
				names = append(names, "M")
			default:
				names = append(names, fmt.Sprintf("bit %d", i*8+bit))
			}
		}
	}
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, ",")
}

// authSummary names the scheme only: the TLV value is a digest or, for
// cleartext authentication, the password itself, and neither belongs in
// operator-facing output.
func authSummary(t *packet.AuthenticationTLV) string {
	switch t.AuthType {
	case packet.AuthTypeCleartext:
		return "Authentication: cleartext"
	case packet.AuthTypeHMACMD5:
		return "Authentication: HMAC-MD5"
	case packet.AuthTypeGeneric:
		if len(t.Value) < 2 {
			return "Authentication: HMAC-SHA"
		}
		return fmt.Sprintf("Authentication: HMAC-SHA (key %d)", binary.BigEndian.Uint16(t.Value))
	default:
		return fmt.Sprintf("Authentication: type %d", t.AuthType)
	}
}

// purgeOriginatorSummary decodes the Purge Originator Identification TLV (RFC
// 6232): a system-ID count followed by that many system IDs. It reports false
// for a malformed value so the caller falls back to type and length.
func purgeOriginatorSummary(v []byte) (string, bool) {
	if len(v) < 1 || v[0] == 0 || len(v) < 1+int(v[0])*6 {
		return "", false
	}
	ids := make([]string, 0, v[0])
	for i := 0; i < int(v[0]); i++ {
		ids = append(ids, packet.SystemID(v[1+i*6:7+i*6]).String())
	}
	return "Purge Originator: " + strings.Join(ids, " "), true
}

// rawTLVSummary is the fallback: type code and value length, taken from the
// encoded form so an unknown TLV and a known one this renderer skips read the
// same.
func rawTLVSummary(tlv packet.TLV) string {
	b, err := tlv.Serialize()
	if err != nil {
		return fmt.Sprintf("TLV %d", tlv.Type())
	}
	return fmt.Sprintf("TLV %d: %d octets", tlv.Type(), len(b)-2)
}
