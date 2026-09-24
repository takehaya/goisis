package interop

import (
	"context"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"github.com/takehaya/goisis/pkg/server"
)

// TestFRRRestartLeavesTheAdjacencyUp is the RFC 5306 helper half put in front
// of a foreign implementation that performs the restarting half -- and there
// is not one here.
//
// FRR 10.6.1's isisd has no graceful-restart command at all: no command under
// `router isis` begins with "g", and no captured FRR hello in this repository
// carries TLV 211. So FRR cannot be made to send a Restart Request, and the
// half of RFC 5306 goisis now implements cannot be driven from this side. The
// helper is covered against a peer that does signal by the in-process tests in
// pkg/server; what is left for interop is the other half of the claim.
//
// That half is worth having on its own. A peer that restarts *without*
// signalling must still lose its adjacency, on the hold timer, exactly as
// before -- a helper that held an adjacency for a neighbour that never asked
// would be a silent black hole, and it is the failure mode a bug in the new
// hold path produces. This is the regression guard for it.
//
// Point-to-point, like the other route tests: a LAN takes ~40s to reconverge
// against FRR, which is most of the 30-second holding time this is about.
func TestFRRRestartWithoutSignallingDropsTheAdjacency(t *testing.T) {
	requireInterop(t)
	node := startFRR(t, true, "")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := startGoisis(t, ctx, node.hostVeth, true, "")

	waitUp(t, "goisis sees FRR Up", func() bool { return goisisSeesUp(t, s, frrSysID) })
	waitUp(t, "FRR sees goisis Up", func() bool { return node.neighborUp(t, "0000.0000.0001") })

	// Watch rather than poll: an adjacency that leaves Up and comes back
	// between two polls is exactly the outage this test is about, and the
	// event stream cannot miss it.
	watch := watchAdjacencyLeavingUp(t, s)

	before := node.isisdPID(t)
	// Signal isisd and let watchfrr respawn it, which is what watchfrr is
	// there for. frrinit.sh refuses in this image -- it wants a per-daemon
	// /etc/frr/isisd/daemons the container does not ship -- and the PID check
	// below is what distinguishes a real restart from a command that quietly
	// did nothing, which would satisfy the assertion for the wrong reason.
	run(t, "docker", "exec", node.name, "sh", "-c", "kill $(pidof isisd)")
	waitUp(t, "FRR to see goisis Up again after its restart",
		func() bool { return node.neighborUp(t, "0000.0000.0001") })
	after := node.isisdPID(t)
	if before == after || after == "" {
		t.Fatalf("isisd PID is %q before and %q after: nothing restarted, so the assertion below proves nothing", before, after)
	}

	if !watch() {
		t.Errorf("goisis held the adjacency across a restart FRR never signalled; want it dropped.\nFRR isisd log:\n%s\nFRR neighbors:\n%s",
			node.isisdLog(t), run(t, "docker", "exec", node.name, "vtysh", "-c", "show isis neighbor detail"))
	}
}

// watchAdjacencyLeavingUp subscribes to the server's events and returns a
// function that ends the subscription and reports whether the adjacency to FRR
// was ever seen in any state but Up.
func watchAdjacencyLeavingUp(t *testing.T, s *server.IsisServer) func() bool {
	t.Helper()
	sub, err := s.Subscribe(context.Background())
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	var mu sync.Mutex
	var left bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		for ev := range sub.Events {
			if ev.Adjacency == nil || ev.Adjacency.SystemID != frrSysID || ev.Adjacency.State == server.AdjUp {
				continue
			}
			mu.Lock()
			left = true
			mu.Unlock()
		}
	}()
	return func() bool {
		sub.Unsubscribe()
		<-done
		if sub.Lagged() {
			t.Fatal("the event subscription was dropped for lagging: it saw only part of the restart")
		}
		mu.Lock()
		defer mu.Unlock()
		return left
	}
}

// isisdPID returns the PID of the container's isisd, or "" if it is not
// running. It is how a restart is told from a no-op.
func (n *frrNode) isisdPID(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("docker", "exec", n.name, "sh", "-c", "pidof isisd || true").CombinedOutput()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// isisdLog returns the container's isisd log, for a failure to be diagnosed
// from: whether FRR signalled a restart at all is the first question.
func (n *frrNode) isisdLog(t *testing.T) string {
	t.Helper()
	out, _ := exec.Command("docker", "exec", n.name, "sh", "-c", "cat /var/log/frr/isisd.log 2>/dev/null || true").CombinedOutput()
	return string(out)
}
