package interop

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// waitLAN is waitUp with a budget sized for the broadcast path: FRR's LAN LSP
// regeneration alone takes ~40s, on top of DIS election and CSNP-driven
// database synchronization. Success returns as soon as fn is true, so the wider
// budget only lengthens the genuine-failure path.
func waitLAN(t *testing.T, what string, fn func() bool) {
	t.Helper()
	if !waitUpSoft(t, 150, fn) {
		t.Fatalf("timed out waiting for %s", what)
	}
}

// TestRouteInteropPingLAN is the broadcast counterpart of
// TestRouteInteropPing: goisis and FRR share a LAN (neither side configures
// point-to-point), each advertises a loopback, and both must install the
// other's route and reach it.
func TestRouteInteropPingLAN(t *testing.T) {
	requireInterop(t)
	buildGoisisImage(t)

	dir := t.TempDir()
	giConf := `net: 49.0001.0000.0000.0001.00
hostname: goisis
fib: true
circuits:
  - interface: eth0
    level: "12"
prefixes:
  - 10.1.1.1/32
`
	if err := os.WriteFile(dir+"/gi.yaml", []byte(giConf), 0o644); err != nil {
		t.Fatal(err)
	}
	daemons := strings.Replace(run(t, "docker", "run", "--rm", "--entrypoint", "cat", frrImage, "/etc/frr/daemons"), "isisd=no", "isisd=yes", 1)
	_ = os.WriteFile(dir+"/daemons", []byte(daemons), 0o644)
	frrConf := `hostname frr
!
interface eth0
 ip router isis 1
!
interface lo1
 ip router isis 1
!
router isis 1
 net 49.0001.0000.0000.00ff.00
 is-type level-1-2
 metric-style wide
!
`
	_ = os.WriteFile(dir+"/frr.conf", []byte(frrConf), 0o644)

	_ = exec.Command("docker", "rm", "-f", "gi", "fr").Run()
	_ = exec.Command("ip", "link", "del", "giveth").Run()
	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "-f", "gi", "fr").Run()
		_ = exec.Command("ip", "link", "del", "giveth").Run()
	})

	run(t, "docker", "run", "-d", "--name", "gi", "--network", "none", "--privileged",
		"--entrypoint", "sleep", "-v", dir+"/gi.yaml:/etc/goisis.yaml:ro", "goisis:interop", "infinity")
	run(t, "docker", "run", "-d", "--name", "fr", "--network", "none", "--privileged",
		"-v", dir+"/daemons:/etc/frr/daemons:ro", "-v", dir+"/frr.conf:/etc/frr/frr.conf:ro", frrImage)

	pgi := strings.TrimSpace(run(t, "docker", "inspect", "-f", "{{.State.Pid}}", "gi"))
	pfr := strings.TrimSpace(run(t, "docker", "inspect", "-f", "{{.State.Pid}}", "fr"))

	run(t, "ip", "link", "add", "giveth", "type", "veth", "peer", "name", "frveth")
	run(t, "ip", "link", "set", "giveth", "netns", pgi)
	run(t, "ip", "link", "set", "frveth", "netns", pfr)
	nsenter(t, pgi, "ip", "link", "set", "giveth", "name", "eth0")
	nsenter(t, pgi, "ip", "link", "set", "eth0", "up")
	nsenter(t, pgi, "ip", "addr", "add", "10.0.0.1/24", "dev", "eth0")
	nsenter(t, pgi, "ip", "link", "add", "lo1", "type", "dummy")
	nsenter(t, pgi, "ip", "link", "set", "lo1", "up")
	nsenter(t, pgi, "ip", "addr", "add", "10.1.1.1/32", "dev", "lo1")
	nsenter(t, pfr, "ip", "link", "set", "frveth", "name", "eth0")
	nsenter(t, pfr, "ip", "link", "set", "eth0", "up")
	nsenter(t, pfr, "ip", "addr", "add", "10.0.0.2/24", "dev", "eth0")
	nsenter(t, pfr, "ip", "link", "add", "lo1", "type", "dummy")
	nsenter(t, pfr, "ip", "link", "set", "lo1", "up")
	nsenter(t, pfr, "ip", "addr", "add", "10.2.2.2/32", "dev", "lo1")

	// Start goisisd now that eth0 exists.
	run(t, "docker", "exec", "-d", "gi", "sh", "-c", "/usr/local/bin/goisisd -f /etc/goisis.yaml > /var/log/goisisd.log 2>&1")

	// goisis must install FRR's loopback into its kernel FIB.
	waitLAN(t, "goisis installs 10.2.2.2/32 (proto isis)", func() bool {
		out, _ := exec.Command("nsenter", "-t", pgi, "-n", "ip", "route", "show", "proto", "isis").CombinedOutput()
		return strings.Contains(string(out), "10.2.2.2")
	})
	// FRR must install goisis's loopback.
	waitLAN(t, "FRR installs 10.1.1.1/32", func() bool {
		out, _ := exec.Command("docker", "exec", "fr", "vtysh", "-c", "show ip route isis").CombinedOutput()
		return strings.Contains(string(out), "10.1.1.1")
	})

	// End-to-end reachability both ways.
	if out, err := exec.Command("nsenter", "-t", pgi, "-n", "ping", "-c", "2", "-W", "2", "10.2.2.2").CombinedOutput(); err != nil {
		t.Fatalf("goisis -> FRR loopback ping failed: %v\n%s", err, out)
	}
	if out, err := exec.Command("docker", "exec", "fr", "ping", "-c", "2", "-W", "2", "10.1.1.1").CombinedOutput(); err != nil {
		t.Fatalf("FRR -> goisis loopback ping failed: %v\n%s", err, out)
	}

	// The goisis CLI (in-container) must show the adjacency and the route.
	nbr := run(t, "docker", "exec", "gi", "/usr/local/bin/goisis", "neighbor")
	if !strings.Contains(nbr, "0000.0000.00ff") || !strings.Contains(nbr, "Up") {
		t.Errorf("goisis neighbor did not show FRR Up:\n%s", nbr)
	}
	rt := run(t, "docker", "exec", "gi", "/usr/local/bin/goisis", "route")
	if !strings.Contains(rt, "10.2.2.2/32") {
		t.Errorf("goisis route did not show FRR's loopback:\n%s", rt)
	}
}
