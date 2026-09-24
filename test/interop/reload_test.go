package interop

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestFRRAcceptsThePurgeOfACircuitARemovedBySIGHUP is the only test that shows
// a foreign implementation taking our pseudonode purge. Everything else about
// DeleteCircuit is asserted against our own database; what an operator actually
// needs is that the other nodes on the segment let go of the LAN we left,
// rather than holding our pseudonode LSP until MaxAge with nothing to withdraw
// it.
//
// It has to run here, and it could not be written until now: this harness
// drives goisisd as a container from a configuration file, so the only way in
// is SIGHUP -- and a circuit is deliberately not an RPC.
//
// The node keeps a second circuit, because a configuration with no circuits at
// all is not a configuration goisisd loads.
func TestFRRAcceptsThePurgeOfACircuitARemovedBySIGHUP(t *testing.T) {
	requireInterop(t)
	buildGoisisImage(t)

	const (
		gi      = "gihup"
		fr      = "frhup"
		giVeth  = "gihupv"
		frVeth  = "frhupv"
		lspHost = "goisis.01-00"
		lspID   = "0000.0000.0001.01-00"
	)

	dir := t.TempDir()
	// Broadcast, not point-to-point: a pseudonode LSP exists only on a LAN, and
	// the priority makes this node the DIS so the LSP is ours to purge.
	writeConf := func(circuits string) {
		t.Helper()
		conf := "net: 49.0001.0000.0000.0001.00\nhostname: goisis\n" + circuits
		if err := os.WriteFile(dir+"/gi.yaml", []byte(conf), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	const both = `circuits:
  - interface: eth0
    level: "12"
    priority: 127
  - interface: isis1
    level: "12"
`
	const kept = `circuits:
  - interface: isis1
    level: "12"
`
	writeConf(both)

	daemons := strings.Replace(run(t, "docker", "run", "--rm", "--entrypoint", "cat", frrImage, "/etc/frr/daemons"), "isisd=no", "isisd=yes", 1)
	if err := os.WriteFile(dir+"/daemons", []byte(daemons), 0o644); err != nil {
		t.Fatal(err)
	}
	frrConf := `hostname frr
!
interface eth0
 ip router isis 1
!
router isis 1
 net 49.0001.0000.0000.00ff.00
 is-type level-1-2
 metric-style wide
!
`
	if err := os.WriteFile(dir+"/frr.conf", []byte(frrConf), 0o644); err != nil {
		t.Fatal(err)
	}

	_ = exec.Command("docker", "rm", "-f", gi, fr).Run()
	_ = exec.Command("ip", "link", "del", giVeth).Run()
	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "-f", gi, fr).Run()
		_ = exec.Command("ip", "link", "del", giVeth).Run()
	})

	// The directory and not the file: the reload re-reads the path, and a
	// single-file bind mount is a promise about one inode.
	run(t, "docker", "run", "-d", "--name", gi, "--network", "none", "--privileged",
		"--entrypoint", "sleep", "-v", dir+":/etc/goisis:ro", "goisis:interop", "infinity")
	run(t, "docker", "run", "-d", "--name", fr, "--network", "none", "--privileged",
		"-v", dir+"/daemons:/etc/frr/daemons:ro", "-v", dir+"/frr.conf:/etc/frr/frr.conf:ro", frrImage)

	pgi := strings.TrimSpace(run(t, "docker", "inspect", "-f", "{{.State.Pid}}", gi))
	pfr := strings.TrimSpace(run(t, "docker", "inspect", "-f", "{{.State.Pid}}", fr))

	run(t, "ip", "link", "add", giVeth, "type", "veth", "peer", "name", frVeth)
	run(t, "ip", "link", "set", giVeth, "netns", pgi)
	run(t, "ip", "link", "set", frVeth, "netns", pfr)
	nsenter(t, pgi, "ip", "link", "set", giVeth, "name", "eth0")
	nsenter(t, pgi, "ip", "link", "set", "eth0", "up")
	nsenter(t, pgi, "ip", "addr", "add", "10.0.0.1/24", "dev", "eth0")
	// The circuit that survives the reload. Its peer end stays in the same
	// namespace with nobody on it: it only has to be an interface an AF_PACKET
	// socket opens.
	nsenter(t, pgi, "ip", "link", "add", "isis1", "type", "veth", "peer", "name", "isis1p")
	nsenter(t, pgi, "ip", "link", "set", "isis1", "up")
	nsenter(t, pgi, "ip", "link", "set", "isis1p", "up")
	nsenter(t, pfr, "ip", "link", "set", frVeth, "name", "eth0")
	nsenter(t, pfr, "ip", "link", "set", "eth0", "up")
	nsenter(t, pfr, "ip", "addr", "add", "10.0.0.2/24", "dev", "eth0")

	run(t, "docker", "exec", "-d", gi, "sh", "-c", "/usr/local/bin/goisisd -f /etc/goisis/gi.yaml > /var/log/goisisd.log 2>&1")

	frr := &frrNode{name: fr}
	goisisLog := func() string {
		out, _ := exec.Command("docker", "exec", gi, "cat", "/var/log/goisisd.log").CombinedOutput()
		return string(out)
	}
	waitLAN(t, "FRR to see goisis Up", func() bool { return frr.neighborUp(t, "0000.0000.0001") })
	waitLAN(t, "FRR to hold our pseudonode LSP", func() bool {
		return frr.databaseContains(t, lspHost) || frr.databaseContains(t, lspID)
	})

	writeConf(kept)
	run(t, "docker", "exec", gi, "sh", "-c", "kill -HUP $(pidof goisisd)")

	// The adjacency goes with the circuit: FRR times its side out, having heard
	// no hello since the reload.
	waitLAN(t, "FRR to drop the adjacency", func() bool { return !frr.neighborUp(t, "0000.0000.0001") })
	// And the purge is accepted rather than the LSP being left to age out: the
	// entry leaves FRR's database well inside the 20 minutes MaxAge would take.
	if !waitUpSoft(t, 150, func() bool {
		return !frr.databaseContains(t, lspHost) && !frr.databaseContains(t, lspID)
	}) {
		t.Errorf("FRR still holds our pseudonode LSP after the circuit was removed:\n%s\ngoisisd log:\n%s",
			run(t, "docker", "exec", fr, "vtysh", "-c", "show isis database"), goisisLog())
	}
}
