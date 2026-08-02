package runner

// ═══════════════════════════════════════════════════════════════════════════
// V12.2 PROCESS CRISIS · FAILURE #2 FIX — Global Process Registry
// ---------------------------------------------------------------------------
// EMPIRICAL EVIDENCE (live GitLab scan, 8 hours wasted):
//
//	PID: 18967 | COMMAND: bbot | %CPU: 89.7% | TIME: 55:31.43
//
// Phase 04 ended at 01:52:37 but the recon process (PID 18967) was STILL
// running at 05:20:10 — consuming ~90% CPU for 3+ hours AFTER the phase that
// spawned it had returned, starving Phase 12 of CPU.
//
// Root cause: runToolInternal only killed a child on timeout/cancel. When a
// tool WAS still running and the shared scan context was cancelled (Ctrl+C) or
// a per-phase deadline fired elsewhere, nothing guaranteed the orphaned process
// group was reaped.
//
// The fix is a package-global registry of every live child process group. Every
// RunTool call Register()s its pgid on start and Deregister()s on exit, and any
// shutdown path (Ctrl+C, phase timeout, program exit) calls KillAll() to
// SIGKILL every surviving process group. This is the "guaranteed cleanup"
// mandated by Section 2.3.
// ═══════════════════════════════════════════════════════════════════════════

import (
	"sync"
	"syscall"
)

// ProcessRegistry tracks every child process group spawned by the scanner so
// they can be force-killed on shutdown. Keyed by pgid (== the child's own pid
// because we always start children with Setpgid=true, making pid==pgid).
type ProcessRegistry struct {
	mu     sync.Mutex
	groups map[int]bool // pgid -> alive
}

// globalRegistry is the single process registry shared by the whole binary.
// RunTool auto-registers into it; main's signal handler and the orchestrator's
// per-phase timeout both call KillAllChildren() through it.
var globalRegistry = &ProcessRegistry{groups: make(map[int]bool)}

// Registry returns the shared global process registry.
func Registry() *ProcessRegistry { return globalRegistry }

// Register records a live child process group (thread-safe).
func (r *ProcessRegistry) Register(pgid int) {
	if pgid <= 0 {
		return
	}
	r.mu.Lock()
	r.groups[pgid] = true
	r.mu.Unlock()
}

// Deregister removes a process group after it has exited normally (thread-safe).
func (r *ProcessRegistry) Deregister(pgid int) {
	if pgid <= 0 {
		return
	}
	r.mu.Lock()
	delete(r.groups, pgid)
	r.mu.Unlock()
}

// Count returns how many process groups are currently registered as alive.
func (r *ProcessRegistry) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.groups)
}

// KillAll SIGKILLs every registered process group and clears the registry.
// Returns the number of groups it signalled. Safe to call repeatedly and from
// any goroutine — this is the guaranteed-cleanup entry point invoked on Ctrl+C,
// per-phase timeout, and program exit (FAILURE #2 + #4).
func (r *ProcessRegistry) KillAll() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for pgid := range r.groups {
		// Negative pid == "the whole process group". SIGKILL is unblockable so
		// even a wedged bbot/naabu child is reaped immediately.
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
		delete(r.groups, pgid)
		n++
	}
	return n
}

// KillAllChildren is the package-level convenience wrapper around
// globalRegistry.KillAll() for callers outside this package.
func KillAllChildren() int { return globalRegistry.KillAll() }
