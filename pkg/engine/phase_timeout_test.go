package engine

import (
	"context"
	"testing"
	"time"
)

// TestV122_PhaseTimeout_PortScanningCapped is the FAILURE #3 unit guard: Port
// Scanning MUST have a 15-minute hard cap (it ran 4h38m in the field).
func TestV122_PhaseTimeout_PortScanningCapped(t *testing.T) {
	if got := PhaseTimeout("Port Scanning"); got != 15*time.Minute {
		t.Fatalf("Port Scanning cap = %v, want 15m", got)
	}
	// An unknown phase falls back to the default cap (never unbounded).
	if got := PhaseTimeout("Totally Unknown Phase XYZ"); got != DefaultPhaseTimeout {
		t.Fatalf("unknown phase cap = %v, want default %v", got, DefaultPhaseTimeout)
	}
	// No configured cap may be zero/negative (which would mean "no deadline").
	for name, d := range phaseTimeouts {
		if d <= 0 {
			t.Fatalf("phase %q has non-positive cap %v", name, d)
		}
	}
}

// hangPhase blocks until its context is cancelled, then returns. It models a
// wedged naabu that only stops when the phase deadline fires.
type hangPhase struct{ done chan struct{} }

func (p *hangPhase) Name() string        { return "Port Scanning" } // 15m cap in map
func (p *hangPhase) Description() string  { return "hangs until ctx cancel" }
func (p *hangPhase) Execute(ctx context.Context, s *State) error {
	<-ctx.Done()
	if p.done != nil {
		close(p.done)
	}
	return ctx.Err()
}

// TestV122_Orchestrator_EnforcesPhaseTimeout proves the orchestrator cancels a
// phase that overruns its cap instead of letting it run forever. We shrink the
// Port Scanning cap to 200ms for the test so it stays fast, run a phase that
// would otherwise hang indefinitely, and assert Run() returns promptly with the
// phase's ctx cancelled (the tool would have been process-group-killed live).
func TestV122_Orchestrator_EnforcesPhaseTimeout(t *testing.T) {
	// Temporarily override the Port Scanning cap; restore afterwards.
	orig, had := phaseTimeouts["Port Scanning"]
	phaseTimeouts["Port Scanning"] = 200 * time.Millisecond
	defer func() {
		if had {
			phaseTimeouts["Port Scanning"] = orig
		} else {
			delete(phaseTimeouts, "Port Scanning")
		}
	}()

	st := &State{
		OutputFolder: t.TempDir(),
		StartTime:    time.Now(),
		WAFProtected: map[string]bool{},
	}
	o := NewOrchestrator(st)
	hp := &hangPhase{done: make(chan struct{})}
	o.RegisterPhase(hp)

	runDone := make(chan struct{})
	go func() {
		_ = o.Run(context.Background())
		close(runDone)
	}()

	select {
	case <-hp.done:
		// Phase saw its context cancelled by the deadline — the fix works.
	case <-time.After(5 * time.Second):
		t.Fatal("phase was NOT cancelled by its hard timeout — FAILURE #3 not fixed")
	}

	select {
	case <-runDone:
	case <-time.After(5 * time.Second):
		t.Fatal("orchestrator did not return after phase timeout")
	}
}
