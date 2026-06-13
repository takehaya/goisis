package interop

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// buildGoisisImage builds the goisis binaries and a local container image
// "goisis:interop". It is idempotent; the COPY layer rebuilds when the
// binaries change.
func buildGoisisImage(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	root := repoRoot(t)
	for _, bin := range []string{"goisisd", "goisis"} {
		cmd := exec.Command("go", "build", "-o", dir+"/"+bin, "./cmd/"+bin)
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v\n%s", bin, err, out)
		}
	}
	dockerfile := "FROM alpine:3.22\n" +
		"RUN apk add --no-cache iproute2 iputils\n" +
		"COPY goisisd /usr/local/bin/goisisd\nCOPY goisis /usr/local/bin/goisis\n" +
		"ENTRYPOINT [\"/usr/local/bin/goisisd\"]\n"
	if err := os.WriteFile(dir+"/Dockerfile", []byte(dockerfile), 0o644); err != nil {
		t.Fatal(err)
	}
	run(t, "docker", "build", "-t", "goisis:interop", dir)
}

// repoRoot returns the module root (two levels up from this test file).
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot determine source path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func nsenter(t *testing.T, pid string, args ...string) {
	t.Helper()
	run(t, "nsenter", append([]string{"-t", pid, "-n"}, args...)...)
}

// TestRouteInteropPing brings up goisis and FRR as containers on a
// point-to-point link, each advertising a loopback, and verifies that both
// install the other's route and can ping the other's loopback.
func TestRouteInteropPing(t *testing.T) {
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
 isis network point-to-point
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
	waitUp(t, "goisis installs 10.2.2.2/32 (proto isis)", func() bool {
		out, _ := exec.Command("nsenter", "-t", pgi, "-n", "ip", "route", "show", "proto", "isis").CombinedOutput()
		return strings.Contains(string(out), "10.2.2.2")
	})
	// FRR must install goisis's loopback.
	waitUp(t, "FRR installs 10.1.1.1/32", func() bool {
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
}
