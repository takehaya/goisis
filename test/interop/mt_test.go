package interop

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/takehaya/goisis/pkg/packet"
)

// TestFRRMultiTopologyIPv6 puts goisis in front of an FRR configured with
// `topology ipv6-unicast`, which moves its IPv6 prefixes out of TLV 236 and
// into TLV 237 under MT #2 (RFC 5120 section 7.4). Before TLV 237 was decoded
// this configuration cost goisis every IPv6 route from that peer, silently.
//
// The MT #2 assertion comes before the route assertion on purpose: it is what
// distinguishes this test from TestRouteInteropPing. An FRR that ignored the
// configuration and kept using TLV 236 would still produce the route, so
// without that check the test would pass while proving nothing.
func TestFRRMultiTopologyIPv6(t *testing.T) {
	requireInterop(t)
	frr := startFRR(t, true, "", " topology ipv6-unicast")

	// FRR advertises its connected IPv6 prefixes; the harness gives eth0 only
	// a link-local, so give it something global to put in TLV 237. goisis's
	// end of the veth keeps none, so the prefix can only be learned from FRR.
	prefix := netip.MustParsePrefix("2001:db8:ff::/64")
	pid := strings.TrimSpace(run(t, "docker", "inspect", "-f", "{{.State.Pid}}", frr.name))
	run(t, "nsenter", "-t", pid, "-n", "ip", "addr", "add", "2001:db8:ff::255/64", "dev", "eth0")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := startGoisis(t, ctx, frr.hostVeth, true, "")
	frrSysID := packet.SystemID{0, 0, 0, 0, 0, 0xff}

	waitUp(t, "goisis adjacency with FRR", func() bool { return goisisSeesUp(t, s, frrSysID) })
	waitUp(t, "FRR's LSP in the goisis LSDB", func() bool { return goisisHasLSPFrom(t, s, frrSysID) })

	waitUp(t, "FRR advertising IPv6 reachability under MT 2", func() bool {
		lsps, err := s.ListLSDBDetail(ctx)
		if err != nil {
			return false
		}
		for _, l := range lsps {
			if l.LSPID.NodeID().SystemID() != frrSysID {
				continue
			}
			for _, line := range l.TLVs {
				if strings.HasPrefix(line, "IPv6 Reachability (MT 2): "+prefix.String()) {
					return true
				}
			}
		}
		return false
	})

	waitUp(t, "goisis route for FRR's MT 2 prefix", func() bool {
		routes, err := s.ListRoutes(ctx)
		if err != nil {
			return false
		}
		for _, r := range routes {
			if r.Prefix == prefix {
				return true
			}
		}
		return false
	})
}
