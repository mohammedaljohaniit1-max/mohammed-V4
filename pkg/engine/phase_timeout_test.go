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

// TestV123_CalculateAdaptiveTimeout is the FAILURE #2 unit guard: the per-phase
// cap MUST scale with host count so nuclei/ffuf/gau are never starved on large
// targets, while small/passive scans keep tight caps and every result is still
// bounded by maxAdaptiveTimeout.
func TestV123_CalculateAdaptiveTimeout(t *testing.T) {
	base := 15 * time.Minute
	cases := []struct {
		name    string
		hosts   int
		profile string
		want    time.Duration
	}{
		{"tiny scope ×1", 50, "medium", 15 * time.Minute},
		{"boundary 1000 ×1", 1000, "medium", 15 * time.Minute},
		{"large >1000 ×2", 5000, "medium", 30 * time.Minute},
		{"boundary 5000 ×2", 5000, "large", 30 * time.Minute},
		{"enterprise >5000 ×3", 14000, "large", 45 * time.Minute},
		{"passive caps at ×2", 14000, "passive", 30 * time.Minute},
		{"small caps at ×2", 9000, "small", 30 * time.Minute},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := CalculateAdaptiveTimeout(base, tc.hosts, tc.profile)
			if got != tc.want {
				t.Fatalf("CalculateAdaptiveTimeout(%v, %d, %q) = %v, want %v",
					base, tc.hosts, tc.profile, got, tc.want)
			}
		})
	}

	// The result must NEVER exceed the absolute ceiling, even with a huge base.
	if got := CalculateAdaptiveTimeout(60*time.Minute, 20000, "large"); got != maxAdaptiveTimeout {
		t.Fatalf("adaptive timeout must be clamped to %v, got %v", maxAdaptiveTimeout, got)
	}
	// The result must NEVER be smaller than the base cap.
	if got := CalculateAdaptiveTimeout(base, 0, "large"); got < base {
		t.Fatalf("adaptive timeout %v must be >= base %v", got, base)
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
