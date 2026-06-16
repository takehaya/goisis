// Package interop runs goisis against a real FRR isisd over a veth pair.
// The tests need root (AF_PACKET + veth) and a working `docker` (via the
// invoking user); they skip otherwise. CI runs them with sudo.
package interop

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/takehaya/goisis/pkg/datalink"
	"github.com/takehaya/goisis/pkg/packet"
	"github.com/takehaya/goisis/pkg/server"
)

const frrImage = "quay.io/frrouting/frr:10.6.1"

func requireInterop(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("interop needs root for AF_PACKET + veth; run with sudo")
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skip("interop needs a working docker")
	}
}

func run(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return string(out)
}

// frrNode is a running FRR container with one veth end inside it; the peer
// end stays in the host netns for goisis to open.
type frrNode struct {
	name     string
	hostVeth string
	sysID    string // FRR system id, dotted (e.g. 0000.0000.00ff)
}

// startFRR brings up an FRR isisd container wired to the host by a veth pair.
// p2p selects point-to-point on the FRR side. routerExtra lines are appended
// inside the `router isis 1` stanza (e.g. a flex-algo definition).
func startFRR(t *testing.T, p2p bool, routerExtra ...string) *frrNode {
	t.Helper()
	name := "goisis-interop-frr"
	hostVeth := "gisisI0"
	contVeth := "gisisI1"

	_ = exec.Command("docker", "rm", "-f", name).Run()
	_ = exec.Command("ip", "link", "del", hostVeth).Run()

	dir := t.TempDir()
	daemons := run(t, "docker", "run", "--rm", "--entrypoint", "cat", frrImage, "/etc/frr/daemons")
	daemons = strings.Replace(daemons, "isisd=no", "isisd=yes", 1)
	if err := os.WriteFile(dir+"/daemons", []byte(daemons), 0o644); err != nil {
		t.Fatal(err)
	}
	ptp := ""
	if p2p {
		ptp = " isis network point-to-point\n"
	}
	extra := ""
	if len(routerExtra) > 0 {
		extra = strings.Join(routerExtra, "\n") + "\n"
	}
	conf := fmt.Sprintf(`hostname frr
!
interface eth0
 ip router isis 1
 ipv6 router isis 1
%s!
router isis 1
 net 49.0001.0000.0000.00ff.00
 is-type level-1-2
 metric-style wide
%s!
`, ptp, extra)
	if err := os.WriteFile(dir+"/frr.conf", []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}

	run(t, "docker", "run", "-d", "--name", name, "--network", "none", "--privileged",
		"-v", dir+"/daemons:/etc/frr/daemons:ro",
		"-v", dir+"/frr.conf:/etc/frr/frr.conf:ro", frrImage)
	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "-f", name).Run()
		_ = exec.Command("ip", "link", "del", hostVeth).Run()
	})

	pid := strings.TrimSpace(run(t, "docker", "inspect", "-f", "{{.State.Pid}}", name))

	run(t, "ip", "link", "add", hostVeth, "type", "veth", "peer", "name", contVeth)
	run(t, "ip", "link", "set", contVeth, "netns", pid)
	run(t, "nsenter", "-t", pid, "-n", "ip", "link", "set", contVeth, "name", "eth0")
	run(t, "nsenter", "-t", pid, "-n", "ip", "link", "set", "eth0", "up")
	run(t, "nsenter", "-t", pid, "-n", "ip", "addr", "add", "10.0.0.255/24", "dev", "eth0")
	run(t, "ip", "link", "set", hostVeth, "up")
	run(t, "ip", "addr", "add", "10.0.0.10/24", "dev", hostVeth)

	return &frrNode{name: name, hostVeth: hostVeth, sysID: "0000.0000.00ff"}
}

// neighborUp reports whether FRR shows the given system id as an Up neighbor.
func (n *frrNode) neighborUp(t *testing.T, sysID string) bool {
	t.Helper()
	out, err := exec.Command("docker", "exec", n.name, "vtysh", "-c", "show isis neighbor").CombinedOutput()
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, sysID) && strings.Contains(line, "Up") {
			return true
		}
	}
	return false
}

// ifaceAddrs returns an interface's non-link-local IPv4 and link-local IPv6
// addresses, as advertised in hellos (TLV 132 / 232).
func ifaceAddrs(t *testing.T, ifname string) (v4, v6 []netip.Addr) {
	t.Helper()
	ifi, err := net.InterfaceByName(ifname)
	if err != nil {
		t.Fatalf("InterfaceByName(%s): %v", ifname, err)
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		t.Fatalf("Addrs: %v", err)
	}
	for _, a := range addrs {
		pfx, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ad, ok := netip.AddrFromSlice(pfx.IP)
		if !ok {
			continue
		}
		ad = ad.Unmap()
		if ad.Is4() {
			v4 = append(v4, ad)
		} else if ad.Is6() && ad.IsLinkLocalUnicast() {
			v6 = append(v6, ad)
		}
	}
	return v4, v6
}

// startGoisis builds and runs a goisis instance on the host veth end. Extra
// options (e.g. WithFlexAlgo) are appended after the defaults.
func startGoisis(t *testing.T, ctx context.Context, ifname string, p2p bool, extra ...server.ServerOption) *server.IsisServer {
	t.Helper()
	tr, err := datalink.OpenLinux(ifname)
	if err != nil {
		t.Fatalf("OpenLinux(%s): %v", ifname, err)
	}
	v4, v6 := ifaceAddrs(t, ifname)
	cfg := server.CircuitConfig{
		Name:      ifname,
		Transport: tr,
		P2P:       p2p,
		Level1:    true,
		Level2:    true,
		IPv4Addrs: v4,
		IPv6Addrs: v6,
	}
	opts := append([]server.ServerOption{
		server.WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		server.WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		server.WithHostname("goisis"),
		server.WithCircuit(cfg),
	}, extra...)
	s, err := server.NewIsisServer(opts...)
	if err != nil {
		t.Fatal(err)
	}
	go s.Serve(ctx) //nolint:errcheck // ctx shutdown
	return s
}

func goisisSeesUp(t *testing.T, s *server.IsisServer, frrSysID packet.SystemID) bool {
	t.Helper()
	adjs, err := s.ListAdjacencies(context.Background())
	if err != nil {
		return false
	}
	for _, a := range adjs {
		if a.SystemID == frrSysID && a.State == server.AdjUp {
			return true
		}
	}
	return false
}

// goisisHasLSPFrom reports whether goisis's LSDB holds an LSP originated by
// the given system id.
func goisisHasLSPFrom(t *testing.T, s *server.IsisServer, sysID packet.SystemID) bool {
	t.Helper()
	lsps, err := s.ListLSDB(context.Background())
	if err != nil {
		return false
	}
	for _, l := range lsps {
		if l.LSPID.NodeID().SystemID() == sysID && l.SequenceNumber > 0 {
			return true
		}
	}
	return false
}

// databaseContains reports whether FRR's IS-IS database output mentions the
// given substring (an LSP ID or hostname).
func (n *frrNode) databaseContains(t *testing.T, substr string) bool {
	t.Helper()
	out, err := exec.Command("docker", "exec", n.name, "vtysh", "-c", "show isis database").CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), substr)
}

// seg6localSupported reports whether the host kernel honors seg6local route
// encapsulation (CONFIG_IPV6_SEG6_LWTUNNEL). Containers share the host kernel,
// so this gates SRv6 End SID dataplane assertions. It probes by adding a
// temporary End route on lo and checking the encap survives readback.
func seg6localSupported(t *testing.T) bool {
	t.Helper()
	const probe = "fc00:6109:ca1::/128"
	if err := exec.Command("ip", "-6", "route", "add", probe, "encap", "seg6local", "action", "End", "dev", "lo").Run(); err != nil {
		return false
	}
	out, _ := exec.Command("ip", "-6", "route", "show", probe).CombinedOutput()
	_ = exec.Command("ip", "-6", "route", "del", probe).Run()
	return strings.Contains(string(out), "seg6local")
}

func waitUp(t *testing.T, what string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(40 * time.Second)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// waitUpSoft polls fn up to maxSeconds and reports whether it became true,
// without failing the test (the caller decides how to report).
func waitUpSoft(t *testing.T, maxSeconds int, fn func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(time.Duration(maxSeconds) * time.Second)
	for time.Now().Before(deadline) {
		if fn() {
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}
