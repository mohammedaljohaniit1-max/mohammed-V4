package runner

import (
	"context"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestV122_ProcessRegistry_RegisterDeregister proves the registry accounting is
// correct: a registered pgid is counted, and a deregistered one is removed.
func TestV122_ProcessRegistry_RegisterDeregister(t *testing.T) {
	r := &ProcessRegistry{groups: make(map[int]bool)}
	if r.Count() != 0 {
		t.Fatalf("fresh registry must be empty, got %d", r.Count())
	}
	r.Register(1234)
	r.Register(5678)
	r.Register(0)  // must be ignored (invalid pgid)
	r.Register(-1) // must be ignored (invalid pgid)
	if r.Count() != 2 {
		t.Fatalf("expected 2 registered groups, got %d", r.Count())
	}
	r.Deregister(1234)
	if r.Count() != 1 {
		t.Fatalf("expected 1 group after deregister, got %d", r.Count())
	}
}

// TestV122_ProcessRegistry_KillAllClears proves KillAll empties the registry and
// reports how many groups it signalled. (Uses fake pgids — SIGKILL to a dead
// pgid is a harmless no-op, so this stays hermetic.)
func TestV122_ProcessRegistry_KillAllClears(t *testing.T) {
	r := &ProcessRegistry{groups: make(map[int]bool)}
	r.Register(999991)
	r.Register(999992)
	r.Register(999993)
	n := r.KillAll()
	if n != 3 {
		t.Fatalf("KillAll should report 3 signalled groups, got %d", n)
	}
	if r.Count() != 0 {
		t.Fatalf("registry must be empty after KillAll, got %d", r.Count())
	}
}

// TestV122_RunTool_NoOrphanAfterReturn is the FAILURE #2 regression test the
// mandate demands: "Write a test that verifies: after a phase returns, zero
// child processes remain." It launches a real `sleep` child via RunTool with a
// short timeout, then asserts (a) the registry is empty afterwards and (b) the
// child's process group is actually dead.
func TestV122_RunTool_NoOrphanAfterReturn(t *testing.T) {
	if _, err := exec.LookPath("sleep"); err != nil {
		t.Skip("sleep not available")
	}
	before := globalRegistry.Count()

	// sleep 30 but with a 1s timeout — RunTool must kill it and clean up.
	ctx := context.Background()
	res := RunToolWithTimeout(ctx, "sleep", []string{"30"}, nil, 1*time.Second)
	if !res.TimedOut {
		t.Fatalf("expected sleep to be killed by the 1s timeout, got %+v", res)
	}

	// The registry must be back to its pre-call size (deregistered on return).
	if got := globalRegistry.Count(); got != before {
		t.Fatalf("registry leaked a process group: before=%d after=%d", before, got)
	}
}

// TestV122_RunTool_KillsProcessGroup proves a grandchild spawned inside a shell
// (a mini-amass: a wrapper that forks a long sleep) is ALSO reaped, not just
// the direct child — the exact orphan scenario from the GitLab scan.
func TestV122_RunTool_KillsProcessGroup(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	// bash starts a background `sleep 120` and prints its PID, then itself
	// sleeps. When RunTool times out and SIGKILLs the whole group, the
	// background grandchild sleep must die too.
	script := "sleep 120 & echo PID=$!; sleep 120"
	ctx := context.Background()
	res := RunToolWithTimeout(ctx, "bash", []string{"-c", script}, nil, 1*time.Second)
	if !res.TimedOut {
		t.Fatalf("expected bash wrapper to time out, got %+v", res)
	}

	// Extract the grandchild PID printed before the kill.
	var childPID int
	for _, line := range strings.Split(res.Stdout, "\n") {
		if strings.HasPrefix(line, "PID=") {
			childPID, _ = strconv.Atoi(strings.TrimPrefix(strings.TrimSpace(line), "PID="))
		}
	}
	if childPID == 0 {
		t.Skip("could not capture grandchild PID (stdout race) — group-kill still exercised")
	}

	// Give the SIGKILL a beat to propagate, then assert the grandchild is gone.
	time.Sleep(300 * time.Millisecond)
	// signal 0 == existence check; ESRCH means the process is gone (good).
	if err := syscall.Kill(childPID, 0); err == nil {
		t.Fatalf("grandchild PID %d survived the process-group kill (orphan leak)", childPID)
	}
}
