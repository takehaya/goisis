package interop

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestSRv6LocatorInterop brings up goisis and FRR on a point-to-point link,
// each advertising an SRv6 locator, and verifies the two exchange locators:
// FRR learns goisis's locator, goisis installs FRR's locator into its kernel
// FIB, and goisis instantiates its own End SID as a seg6local route.
//
// It does not assert data-plane reachability to a locator: an End-only
// implementation answers traffic only when it carries an SRH selecting a SID,
// which is beyond this milestone's scope (no SR policy / SID-list encap yet).
func TestSRv6LocatorInterop(t *testing.T) {
	requireInterop(t)
	buildGoisisImage(t)

	dir := t.TempDir()
	giConf := `net: 49.0001.0000.0000.0001.00
hostname: goisis
fib: true
circuits:
  - interface: eth0
    level: "12"
    p2p: true
srv6:
  locators:
    - fc00:0:1::/48
`
	if err := os.WriteFile(dir+"/gi.yaml", []byte(giConf), 0o644); err != nil {
		t.Fatal(err)
	}
	daemons := strings.Replace(run(t, "docker", "run", "--rm", "--entrypoint", "cat", frrImage, "/etc/frr/daemons"), "isisd=no", "isisd=yes", 1)
	_ = os.WriteFile(dir+"/daemons", []byte(daemons), 0o644)
	// FRR SRv6 stanza is the validated form from test/fixturegen/capture_srv6.sh
	// (block-len + node-len must equal the /48 locator length).
	frrConf := `hostname frr
!
segment-routing
 srv6
  locators
   locator loc1
    prefix fc00:0:2::/48 block-len 32 node-len 16 func-bits 16
   exit
  exit
 exit
!
interface eth0
 ip router isis 1
 ipv6 router isis 1
 isis network point-to-point
!
router isis 1
 net 49.0001.0000.0000.00ff.00
 is-type level-1-2
 metric-style wide
 segment-routing srv6
  locator loc1
 exit
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
	nsenter(t, pgi, "ip", "addr", "add", "2001:db8::1/64", "dev", "eth0")
	nsenter(t, pfr, "ip", "link", "set", "frveth", "name", "eth0")
	nsenter(t, pfr, "ip", "link", "set", "eth0", "up")
	nsenter(t, pfr, "ip", "addr", "add", "10.0.0.2/24", "dev", "eth0")
	nsenter(t, pfr, "ip", "addr", "add", "2001:db8::2/64", "dev", "eth0")

	// Start goisisd now that eth0 exists.
	run(t, "docker", "exec", "-d", "gi", "sh", "-c", "/usr/local/bin/goisisd -f /etc/goisis.yaml > /var/log/goisisd.log 2>&1")

	// goisis instantiates its own End SID (the locator base) as a seg6local
	// route on the loopback.
	waitUp(t, "goisis installs its End SID seg6local route", func() bool {
		out, _ := exec.Command("nsenter", "-t", pgi, "-n", "ip", "-6", "route", "show").CombinedOutput()
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "fc00:0:1::") && strings.Contains(line, "seg6local") && strings.Contains(line, "End") {
				return true
			}
		}
		return false
	})

	// goisis must install FRR's locator into its kernel FIB (proto isis).
	waitUp(t, "goisis installs FRR locator fc00:0:2::/48", func() bool {
		out, _ := exec.Command("nsenter", "-t", pgi, "-n", "ip", "-6", "route", "show", "proto", "isis").CombinedOutput()
		return strings.Contains(string(out), "fc00:0:2::/48")
	})

	// FRR must learn goisis's locator.
	waitUp(t, "FRR learns goisis locator fc00:0:1::/48", func() bool {
		out, _ := exec.Command("docker", "exec", "fr", "vtysh", "-c", "show ipv6 route isis").CombinedOutput()
		return strings.Contains(string(out), "fc00:0:1::/48")
	})

	// The goisis CLI must show FRR's locator route.
	rt := run(t, "docker", "exec", "gi", "/usr/local/bin/goisis", "route")
	if !strings.Contains(rt, "fc00:0:2::/48") {
		t.Errorf("goisis route did not show FRR's locator:\n%s", rt)
	}
}
