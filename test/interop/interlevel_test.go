package interop

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// cliRoute is the part of goisisv1.Route these assertions read, as
// `goisis route -o json` renders it (protojson: camelCase field names, zero
// values omitted). Parsing rather than substring-matching is the point: every
// assertion below is about which level and which preference class won a
// prefix, and a substring cannot tell one path to 10.3.3.3/32 from the other.
type cliRoute struct {
	Prefix     string `json:"prefix"`
	Metric     uint32 `json:"metric"`
	Level      string `json:"level"`
	Preference uint32 `json:"preference"`
	NextHops   []struct {
		Interface string `json:"interface"`
		Gateway   string `json:"gateway"`
	} `json:"nextHops"`
}

// goisisRoute returns the route a goisis container holds for prefix, and
// whether it holds one. A failed CLI call and an absent prefix are the same
// answer, so this can be polled; no assertion below is satisfied by its
// returning false.
func goisisRoute(t *testing.T, container, prefix string) (cliRoute, bool) {
	t.Helper()
	// Output, not CombinedOutput: a warning on stderr would not be JSON.
	out, err := exec.Command("docker", "exec", container, "/usr/local/bin/goisis", "route", "-o", "json").Output()
	if err != nil {
		return cliRoute{}, false
	}
	var res struct {
		Routes []cliRoute `json:"routes"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		return cliRoute{}, false
	}
	for _, r := range res.Routes {
		if r.Prefix == prefix {
			return r, true
		}
	}
	return cliRoute{}, false
}

// goisisNeighborUp reports whether a goisis container shows the given system
// id as an Up adjacency.
func goisisNeighborUp(t *testing.T, container, sysID string) bool {
	t.Helper()
	out, err := exec.Command("docker", "exec", container, "/usr/local/bin/goisis", "neighbor").Output()
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

// frrLine returns the first line of a vtysh command's output that contains
// substr, or "" when vtysh failed or nothing matched. Returning the line and
// not just a bool is what lets a caller go on to read the flags FRR printed
// beside the prefix.
func frrLine(t *testing.T, container, vtyshCmd, substr string) string {
	t.Helper()
	out, err := exec.Command("docker", "exec", container, "vtysh", "-c", vtyshCmd).Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, substr) {
			return line
		}
	}
	return ""
}

// p2pLink wires a veth pair between two container network namespaces, renaming
// each end and addressing it. Both ends leave the host namespace, so removing
// the containers removes the link; the tmp names exist only between the add
// and the move.
func p2pLink(t *testing.T, tmpA, tmpB, aPID, aName, aAddr, bPID, bName, bAddr string) {
	t.Helper()
	run(t, "ip", "link", "add", tmpA, "type", "veth", "peer", "name", tmpB)
	for _, e := range []struct{ tmp, pid, name, addr string }{
		{tmpA, aPID, aName, aAddr},
		{tmpB, bPID, bName, bAddr},
	} {
		run(t, "ip", "link", "set", e.tmp, "netns", e.pid)
		nsenter(t, e.pid, "ip", "link", "set", e.tmp, "name", e.name)
		nsenter(t, e.pid, "ip", "link", "set", e.name, "up")
		nsenter(t, e.pid, "ip", "addr", "add", e.addr, "dev", e.name)
	}
}

// TestInterLevelInteropAcrossTwoAreas is the only interop test with two areas,
// and so the only one in which the inter-level machinery has anything to do.
// Every other test here puts goisis and FRR in one area at level-1-2, where
// Level-1-to-Level-2 propagation, Level-2-to-Level-1 leaking and the
// ATT-derived default are all no-ops: they have been exercised goisis against
// goisis only, and the last three review rounds each found a blocker in
// exactly that code.
//
// The topology is three point-to-point links (p2p, not a LAN: FRR's LAN LSP
// regeneration alone takes ~40s, and nothing here needs a pseudonode):
//
//	area 49.0001                                    |  area 49.0002
//	  gil1 --- eth0/eth0 10.0.1.0/24 --- eth0 \     |
//	  (goisis, L1-only)                       gibr eth2 --- eth0 frl2
//	  frl1 --- eth0/eth1 10.0.2.0/24 --- eth1 /     |  10.0.3.0/24  (FRR, L2-only)
//	  (FRR, L1-only)                (goisis, L1L2)  |
//
// What each node contributes: gil1 advertises reachability that exists only
// inside the Level-1 area, frl2 advertises reachability that exists only at
// Level 2, frl1 is a foreign Level-1 witness inside our area, and gibr is the
// border under test.
//
// On the up/down bit, one direction is all this can reach. FRR implements no
// Level-2-to-Level-1 leaking and emits the bit clear, so it can only be the
// observer of a down-marked advertisement of ours, never the source of one:
// goisis's handling of a *received* down bit has no foreign witness here and
// keeps the in-process tests as its only cover. Nor can "a down-marked prefix
// never travels back up" be witnessed from outside, for a topological reason:
// the second border that would have to re-export it needs a Level-2 adjacency
// to a foreign node for that node to see anything, and having one gives it its
// own Level-2 route to the prefix, which outranks the leaked copy and stops
// the export for a different reason entirely. That assertion would pass
// whether or not the down bit worked, so it is not written here.
func TestInterLevelInteropAcrossTwoAreas(t *testing.T) {
	requireInterop(t)
	buildGoisisImage(t)

	const (
		gil1 = "gixl1"
		gibr = "gixbr"
		frl1 = "frxl1"
		frl2 = "frxl2"

		gil1SysID = "0000.0000.0001"
		gibrSysID = "0000.0000.0002"
		frl1SysID = "0000.0000.00f1"
		frl2SysID = "0000.0000.00f2"

		// Reachable only inside the Level-1 area: gil1 originates it and
		// nothing at Level 2 has another copy.
		l1Only = "10.1.1.1/32"
		// Reachable only at Level 2: frl2's loopback, in the other area.
		l2Only = "10.2.2.2/32"
		// Reachable both ways: gil1 advertises it at Level 1 with metric 1000
		// and frl2 at Level 2 with metric 1, so the class-1 path is also the
		// expensive one.
		bothWays = "10.3.3.3/32"
	)

	dir := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(dir+"/"+name, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// gil1: Level-1 only, so it has no Level-2 topology of its own and falls
	// back on the ATT bit. It needs no loopback interface -- an originated
	// prefix is not a connected one.
	write("gil1.yaml", `net: 49.0001.0000.0000.0001.00
hostname: gil1
circuits:
  - interface: eth0
    level: "1"
    p2p: true
prefixes:
  - `+l1Only+`
  - prefix: `+bothWays+`
    metric: 1000
`)
	// gibr: the border. Two Level-1 circuits into its own area, one Level-2
	// circuit into the other one -- the level split is what makes this a
	// border rather than the level-1-2-everywhere shape the rest of the suite
	// uses. The leak policy names one prefix, so the deny-by-default covers
	// everything else frl2 advertises.
	write("gibr.yaml", `net: 49.0001.0000.0000.0002.00
hostname: gibr
circuits:
  - interface: eth0
    level: "1"
    p2p: true
  - interface: eth1
    level: "1"
    p2p: true
  - interface: eth2
    level: "2"
    p2p: true
policy:
  leak-l2-to-l1:
    rules:
      - permit: `+l2Only+`
`)

	daemons := strings.Replace(run(t, "docker", "run", "--rm", "--entrypoint", "cat", frrImage, "/etc/frr/daemons"), "isisd=no", "isisd=yes", 1)
	write("daemons", daemons)
	// lsp-gen-interval 2 on both FRR nodes: the propagation chains below cross
	// two FRR regeneration delays in series, and the default 30s would put a
	// healthy convergence within sight of the poll budget. It changes when FRR
	// speaks, never what it says, so no assertion rests on it.
	write("frl1.conf", `hostname frl1
!
interface eth0
 ip router isis 1
 isis network point-to-point
!
router isis 1
 net 49.0001.0000.0000.00f1.00
 is-type level-1
 metric-style wide
 lsp-gen-interval 2
!
`)
	write("frl2.conf", `hostname frl2
!
interface eth0
 ip router isis 1
 isis network point-to-point
!
interface lo1
 ip router isis 1
!
interface lo2
 ip router isis 1
 isis metric 1
!
router isis 1
 net 49.0002.0000.0000.00f2.00
 is-type level-2-only
 metric-style wide
 lsp-gen-interval 2
!
`)

	tmpVeths := []string{"ilvA0", "ilvA1", "ilvB0", "ilvB1", "ilvC0", "ilvC1"}
	cleanup := func() {
		_ = exec.Command("docker", append([]string{"rm", "-f"}, gil1, gibr, frl1, frl2)...).Run()
		for _, v := range tmpVeths {
			_ = exec.Command("ip", "link", "del", v).Run()
		}
	}
	cleanup()
	t.Cleanup(cleanup)
	// Registered after cleanup, so it runs before it (t.Cleanup is LIFO) and
	// the containers are still answering. A four-node topology times out in
	// too many places for a bare "timed out waiting for ..." to be actionable.
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		for _, c := range []string{gil1, gibr} {
			out, _ := exec.Command("docker", "exec", c, "cat", "/var/log/goisisd.log").CombinedOutput()
			t.Logf("=== %s goisisd log ===\n%s", c, out)
			out, _ = exec.Command("docker", "exec", c, "/usr/local/bin/goisis", "route").CombinedOutput()
			t.Logf("=== %s routes ===\n%s", c, out)
		}
		for _, c := range []string{frl1, frl2} {
			out, _ := exec.Command("docker", "exec", c, "vtysh", "-c", "show isis database detail").CombinedOutput()
			t.Logf("=== %s database ===\n%s", c, out)
			out, _ = exec.Command("docker", "exec", c, "vtysh", "-c", "show ip route isis").CombinedOutput()
			t.Logf("=== %s routes ===\n%s", c, out)
		}
	})

	for _, g := range []string{gil1, gibr} {
		run(t, "docker", "run", "-d", "--name", g, "--network", "none", "--privileged",
			"--entrypoint", "sleep", "-v", dir+":/etc/goisis:ro", "goisis:interop", "infinity")
	}
	// The configuration file is named for the node, not for the container: the
	// container names carry a prefix that keeps them clear of the other tests'.
	// A mount whose source does not exist is a silently created empty
	// directory, and FRR then comes up with every daemon running and no
	// configuration at all -- which reads exactly like an adjacency that will
	// not form.
	for _, f := range []struct{ container, conf string }{{frl1, "frl1"}, {frl2, "frl2"}} {
		run(t, "docker", "run", "-d", "--name", f.container, "--network", "none", "--privileged",
			"-v", dir+"/daemons:/etc/frr/daemons:ro", "-v", dir+"/"+f.conf+".conf:/etc/frr/frr.conf:ro", frrImage)
	}
	pid := func(name string) string {
		t.Helper()
		return strings.TrimSpace(run(t, "docker", "inspect", "-f", "{{.State.Pid}}", name))
	}
	pgil1, pgibr, pfrl1, pfrl2 := pid(gil1), pid(gibr), pid(frl1), pid(frl2)

	p2pLink(t, "ilvA0", "ilvA1", pgil1, "eth0", "10.0.1.1/24", pgibr, "eth0", "10.0.1.2/24")
	p2pLink(t, "ilvB0", "ilvB1", pfrl1, "eth0", "10.0.2.1/24", pgibr, "eth1", "10.0.2.2/24")
	p2pLink(t, "ilvC0", "ilvC1", pgibr, "eth2", "10.0.3.1/24", pfrl2, "eth0", "10.0.3.2/24")
	// frl2's advertised reachability. lo2 carries the prefix that also exists
	// at Level 1, at the interface metric its configuration pinned to 1.
	for _, lo := range []struct{ name, addr string }{{"lo1", l2Only}, {"lo2", bothWays}} {
		nsenter(t, pfrl2, "ip", "link", "add", lo.name, "type", "dummy")
		nsenter(t, pfrl2, "ip", "link", "set", lo.name, "up")
		nsenter(t, pfrl2, "ip", "addr", "add", lo.addr, "dev", lo.name)
	}

	// goisisd opens its circuits by name at startup, so every interface has to
	// exist first.
	run(t, "docker", "exec", "-d", gil1, "sh", "-c", "/usr/local/bin/goisisd -f /etc/goisis/gil1.yaml > /var/log/goisisd.log 2>&1")
	run(t, "docker", "exec", "-d", gibr, "sh", "-c", "/usr/local/bin/goisisd -f /etc/goisis/gibr.yaml > /var/log/goisisd.log 2>&1")

	// All three adjacencies from the border's own view: an absent one would
	// otherwise surface below as a missing route with no hint why.
	for _, peer := range []struct{ what, sysID string }{
		{"gil1 at Level 1", gil1SysID},
		{"frl1 at Level 1", frl1SysID},
		{"frl2 at Level 2, across the area boundary", frl2SysID},
	} {
		waitUp(t, "gibr to see "+peer.what, func() bool { return goisisNeighborUp(t, gibr, peer.sysID) })
	}

	// 1. The ATT-derived default, before anything advertises one.
	//
	// gibr is Level-1-2, so its Level-1 LSP carries the ATT bit; gil1 is
	// Level-1 only, has no Level-2 topology, and must fall back on it
	// (RFC 1195 section 3.2). Nothing advertises a default yet, so a default
	// route existing at all is that fallback -- which is why its class and
	// metric can be read as an assertion rather than waited for.
	waitUp(t, "gil1 to install a default route", func() bool {
		_, ok := goisisRoute(t, gil1, "0.0.0.0/0")
		return ok
	})
	att, _ := goisisRoute(t, gil1, "0.0.0.0/0")
	// Class 3, below anything advertised: the fallback carries no metric of
	// its own (RFC 5302 section 1.1), and metric 10 is simply the distance to
	// gibr, the attached IS it points at.
	if att.Preference != 3 || att.Metric != 10 {
		t.Errorf("the ATT default on gil1 is preference %d metric %d, want preference 3 metric 10", att.Preference, att.Metric)
	}
	if len(att.NextHops) != 1 || att.NextHops[0].Gateway != "10.0.1.2" {
		t.Errorf("the ATT default on gil1 points at %v, want 10.0.1.2 (gibr, the attached IS)", att.NextHops)
	}

	// 2. goisis exports Level-1 reachability into Level 2, and FRR takes it.
	//
	// l1Only exists only inside area 49.0001, so the only way it reaches frl2
	// is gibr putting it in its Level-2 LSP (ISO 10589 7.2.9 / RFC 1195
	// section 3.1). frl2 is level-2-only and keeps no Level-1 database, so
	// finding it there is finding it at Level 2.
	waitUp(t, "frl2 to hold "+l1Only+" in its Level-2 database", func() bool {
		return frrLine(t, frl2, "show isis database detail", l1Only) != ""
	})
	waitUp(t, "frl2 to install a route to "+l1Only, func() bool {
		return frrLine(t, frl2, "show ip route isis", l1Only) != ""
	})

	// 3. goisis takes FRR's Level-2 reachability and ranks it under its own
	// Level-1 path.
	//
	// bothWays is reachable two ways from gibr: intra-area at Level 1 through
	// gil1 for 10 + 1000, and via Level 2 from frl2 for 10 + 1. RFC 5302
	// section 3.2 ranks the class before the metric, so class 1 takes it at a
	// metric roughly a hundred times worse.
	//
	// The two markers first, or this proves nothing: before frl2's LSP is in
	// the database "the Level-1 path won" is true because it is the only path
	// there is. l1Only in the RIB says gil1's LSP has been processed and
	// l2Only says frl2's has; the RIB is recomputed on every change, so once
	// both are in it, the reading below was taken with both LSPs present.
	waitUp(t, "gibr to hold reachability from both sides", func() bool {
		l1, ok := goisisRoute(t, gibr, l1Only)
		if !ok || l1.Level != "LEVEL_1" {
			return false
		}
		l2, ok := goisisRoute(t, gibr, l2Only)
		return ok && l2.Level == "LEVEL_2"
	})
	r, ok := goisisRoute(t, gibr, bothWays)
	if !ok {
		t.Fatalf("gibr has no route to %s at all", bothWays)
	}
	if r.Level != "LEVEL_1" || r.Preference != 1 {
		t.Errorf("gibr routes %s at %s preference %d, want LEVEL_1 preference 1: the Level-2 path won on metric, which RFC 5302 section 3.2 ranks after the class",
			bothWays, r.Level, r.Preference)
	}
	if len(r.NextHops) != 1 || r.NextHops[0].Gateway != "10.0.1.1" {
		t.Errorf("gibr sends %s to %v, want 10.0.1.1 (gil1, inside the area) and not 10.0.3.2 (frl2, over Level 2)", bothWays, r.NextHops)
	}
	// 1010 = the circuit metric to gil1 plus the 1000 gil1 advertises; the
	// Level-2 alternative was 11. Naming it is what makes the point that the
	// worse metric is the one installed.
	if r.Metric != 1010 {
		t.Errorf("gibr routes %s at metric %d, want 1010 (the Level-1 path); 11 would be the Level-2 one", bothWays, r.Metric)
	}

	// 4. goisis leaks a Level-2 prefix down into Level 1 with the up/down bit
	// set, and a foreign implementation reads both the prefix and the bit.
	//
	// frl1 is level-1 and keeps no Level-2 database, and l2Only lives in the
	// other area, so the only thing that can put it in front of frl1 is
	// gibr's leak (RFC 5305 section 4.1 / RFC 5308 section 2). The flag match
	// is on the word FRR prints beside a down-marked reachability entry; a
	// rendering change on FRR's side lands here as a failure, which is the
	// right way round -- the alternative is asserting nothing about the bit.
	waitUp(t, "frl1 to hold the leaked "+l2Only+" in its Level-1 database", func() bool {
		return frrLine(t, frl1, "show isis database detail", l2Only) != ""
	})
	if line := frrLine(t, frl1, "show isis database detail", l2Only); !strings.Contains(strings.ToLower(line), "down") {
		t.Errorf("FRR reads our leaked %s without the up/down bit: %q", l2Only, strings.TrimSpace(line))
	}
	waitUp(t, "frl1 to install the leaked "+l2Only, func() bool {
		return frrLine(t, frl1, "show ip route isis", l2Only) != ""
	})

	// 5. An advertised default outranks the ATT-derived one.
	//
	// Last, because it changes frl1's configuration. frl1 is two hops from
	// gil1 (through gibr), so the advertised default is both a class-1 route
	// and the more expensive one -- exactly the case where ranking the class
	// first changes the answer. It also puts the comparison's other side in a
	// foreign implementation's hands: the default gil1 must prefer is one FRR
	// originated. This does lean on FRR emitting the up/down bit clear on it,
	// as it does everywhere else; were the bit set, the advertisement would
	// land in class 3 beside the fallback and lose to it on metric.
	run(t, "docker", "exec", frl1, "vtysh", "-c", "configure terminal",
		"-c", "router isis 1", "-c", "default-information originate ipv4 level-1 always")
	waitUp(t, "gil1 to prefer frl1's advertised default", func() bool {
		d, ok := goisisRoute(t, gil1, "0.0.0.0/0")
		return ok && d.Preference == 1
	})
	adv, _ := goisisRoute(t, gil1, "0.0.0.0/0")
	// Strictly worse than the fallback's 10 (the distance to frl1 alone is
	// 20), so preference 1 above cannot have been reached by the advertised
	// default happening to be cheaper.
	if adv.Metric <= att.Metric {
		t.Errorf("the advertised default on gil1 costs %d, not more than the ATT fallback's %d: this no longer shows the class outranking the metric",
			adv.Metric, att.Metric)
	}
}
