package server

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/takehaya/goisis/pkg/packet"
)

// tlvSummaries renders an LSP's TLVs for `goisis database --detail`, in wire
// order. A TLV carrying a list renders one line per entry, so the result is
// usually longer than the TLV count; a list TLV with no entries renders
// nothing at all rather than a blank line.
func tlvSummaries(tlvs []packet.TLV) []string {
	out := make([]string, 0, len(tlvs))
	for _, tlv := range tlvs {
		if s := tlvSummary(tlv); s != "" {
			out = append(out, strings.Split(s, "\n")...)
		}
	}
	return out
}

// tlvSummary renders one TLV as human-readable text, entries separated by
// newlines. It lives here and not in pkg/packet because that package is a pure
// codec. A TLV this switch does not name falls back to its type and length, so
// the output stays useful in front of a peer advertising what goisis does not
// decode.
func tlvSummary(tlv packet.TLV) string {
	switch t := tlv.(type) {
	case *packet.AreaAddressesTLV:
		areas := make([]string, 0, len(t.Addresses))
		for _, a := range t.Addresses {
			areas = append(areas, a.String())
		}
		return "Area Addresses: " + strings.Join(areas, " ")

	case *packet.ProtocolsSupportedTLV:
		return "Protocols Supported: " + strings.Join(nlpidNames(t.NLPIDs), " ")

	case *packet.DynamicHostnameTLV:
		return "Dynamic Hostname: " + t.Hostname

	case *packet.ExtendedISReachabilityTLV:
		lines := make([]string, 0, len(t.Neighbors))
		for _, n := range t.Neighbors {
			line := fmt.Sprintf("IS Reachability: %s metric %d", n.NeighborID, n.Metric)
			if len(n.SubTLVs) > 0 {
				line += fmt.Sprintf(" (%d sub-TLVs)", len(n.SubTLVs))
			}
			lines = append(lines, line)
		}
		return strings.Join(lines, "\n")

	case *packet.ExtendedIPReachabilityTLV:
		lines := make([]string, 0, len(t.Prefixes))
		for _, p := range t.Prefixes {
			lines = append(lines, "IPv4 Reachability: "+prefixSummary(p.Prefix, p.Metric, p.Down))
		}
		return strings.Join(lines, "\n")

	case *packet.IPv6ReachabilityTLV:
		lines := make([]string, 0, len(t.Prefixes))
		for _, p := range t.Prefixes {
			lines = append(lines, "IPv6 Reachability: "+prefixSummary(p.Prefix, p.Metric, p.Down))
		}
		return strings.Join(lines, "\n")

	case *packet.SRv6LocatorTLV:
		lines := make([]string, 0, len(t.Locators))
		for _, l := range t.Locators {
			line := fmt.Sprintf("SRv6 Locator: %s algo %d metric %d", l.Locator, l.Algorithm, l.Metric)
			for _, sid := range l.EndSIDs {
				line += " End " + sid.SID.String()
			}
			lines = append(lines, line)
		}
		return strings.Join(lines, "\n")

	case *packet.RouterCapabilityTLV:
		return routerCapSummary(t)

	case *packet.AuthenticationTLV:
		return authSummary(t)

	case *packet.UnknownTLV:
		// TLV 13 has no decoder (RFC 6232 is carried opaquely), but an
		// operator chasing a purge wants to see who sent it.
		if t.TLVType == packet.TLVTypePurgeOriginatorID {
			if s, ok := purgeOriginatorSummary(t.Value); ok {
				return s
			}
		}
	}
	return rawTLVSummary(tlv)
}

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
