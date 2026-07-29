package phases

import (
	"strings"
	"testing"

	"github.com/mohammed-v3/core/pkg/config"
	"github.com/mohammed-v3/core/pkg/engine"
)

// ─────────────────────────────────────────────────────────────────────────
// V9.0 ABSOLUTE APEX — orchestration helper tests.
// ─────────────────────────────────────────────────────────────────────────

func newApexState(threads int) *engine.State {
	cfg := &config.Config{Threads: threads}
	scope := &config.Scope{Domains: []string{"example.com"}}
	return engine.NewState(cfg, scope)
}

func TestApex_SharedGovernorIsSingletonAndSized(t *testing.T) {
	s := newApexState(30)
	g1 := sharedStealthGovernor(s)
	g2 := sharedStealthGovernor(s)
	if g1 != g2 {
		t.Fatalf("sharedStealthGovernor must return the same instance per scan")
	}
	if g1.CurrentLimit() != 30 {
		t.Fatalf("governor max concurrency = %d, want 30 (from config Threads)", g1.CurrentLimit())
	}
}

func TestApex_PostureMentionsAdaptiveAndPool(t *testing.T) {
	s := newApexState(40)
	p := apexPosture(s)
	for _, want := range []string{"adaptive-concurrency=40", "backoff=429", "cooldown=30s", "5-gate=simhash"} {
		if !strings.Contains(p, want) {
			t.Fatalf("apexPosture missing %q: %s", want, p)
		}
	}
}

func TestApex_OrchestrationPhaseMetadata(t *testing.T) {
	p := &ApexOrchestrationPhase{}
	if p.Name() == "" || !strings.Contains(p.Description(), "Phase 54") {
		t.Fatalf("apex phase metadata wrong: name=%q desc=%q", p.Name(), p.Description())
	}
	if len(ApexPhases()) != 1 {
		t.Fatalf("ApexPhases() should return exactly the orchestration phase")
	}
}

func TestApex_HostOnlyAndOriginHelpers(t *testing.T) {
	if got := hostOnly("https://api.example.com:8443/v1/users?x=1"); got != "api.example.com" {
		t.Fatalf("hostOnly = %q, want api.example.com", got)
	}
	if got := originString("https://api.example.com/v1/users"); got != "https://api.example.com" {
		t.Fatalf("originString = %q, want https://api.example.com", got)
	}
}
