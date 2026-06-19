package interop

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestRouteInteropFragmentation has goisis advertise enough prefixes to span
// several LSP fragments (1..N), and verifies FRR learns prefixes from both the
// first and the last fragment — i.e., FRR receives every fragment and goisis
// originated them correctly. This is the cross-vendor check for LSP
// fragmentation that the in-process tests cannot provide.
func TestRouteInteropFragmentation(t *testing.T) {
	requireInterop(t)
	buildGoisisImage(t)

	const n = 300 // ~9 octets/entry → well past one 1492-octet LSP fragment
	prefix := func(i int) string { return fmt.Sprintf("10.10.%d.%d/32", i/256, i%256) }
	first, last := prefix(0), prefix(n-1)

	var b strings.Builder
	b.WriteString("net: 49.0001.0000.0000.0001.00\nhostname: goisis\ncircuits:\n  - interface: eth0\n    level: \"12\"\n    p2p: true\nprefixes:\n")
	for i := 0; i < n; i++ {
		b.WriteString("  - " + prefix(i) + "\n")
	}

	dir := t.TempDir()
	if err := os.WriteFile(dir+"/gi.yaml", []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	daemons := strings.Replace(run(t, "docker", "run", "--rm", "--entrypoint", "cat", frrImage, "/etc/frr/daemons"), "isisd=no", "isisd=yes", 1)
	_ = os.WriteFile(dir+"/daemons", []byte(daemons), 0o644)
	frrConf := `hostname frr
!
interface eth0
 ip router isis 1
 isis network point-to-point
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
	nsenter(t, pfr, "ip", "link", "set", "frveth", "name", "eth0")
	nsenter(t, pfr, "ip", "link", "set", "eth0", "up")
	nsenter(t, pfr, "ip", "addr", "add", "10.0.0.2/24", "dev", "eth0")

	run(t, "docker", "exec", "-d", "gi", "sh", "-c", "/usr/local/bin/goisisd -f /etc/goisis.yaml > /var/log/goisisd.log 2>&1")

	// FRR must learn both the first prefix (fragment 0) and the last (a higher
	// fragment) — proving every fragment arrived and was processed.
	frrHas := func(p string) bool {
		out, _ := exec.Command("docker", "exec", "fr", "vtysh", "-c", "show ip route isis").CombinedOutput()
		// vtysh prints prefixes without the /32 host suffix collapsed; match the
		// address with its mask.
		return strings.Contains(string(out), p)
	}
	waitUp(t, "FRR learns the first-fragment prefix "+first, func() bool { return frrHas(first) })
	waitUp(t, "FRR learns the last-fragment prefix "+last, func() bool { return frrHas(last) })

	// goisis must have originated multiple fragments for its own LSP.
	db := run(t, "docker", "exec", "gi", "/usr/local/bin/goisis", "database")
	frags := strings.Count(db, "0000.0000.0001.00-")
	if frags < 2 {
		t.Errorf("expected goisis to originate >=2 LSP fragments, saw %d in:\n%s", frags, db)
	}
}
