package phases

import (
	"strings"
	"testing"

	"github.com/mohammed-v3/core/pkg/exploit"
)

// ─────────────────────────────────────────────────────────────────────────
// V10.0 SOVEREIGN — orchestration + phase metadata tests.
// ─────────────────────────────────────────────────────────────────────────

func TestSovereign_PhasesReturnsSixPhases(t *testing.T) {
	ph := SovereignPhases()
	if len(ph) != 6 {
		t.Fatalf("SovereignPhases() must return the 6 V10 phases (55-60), got %d", len(ph))
	}
}

func TestSovereign_PhaseMetadataAndOrdering(t *testing.T) {
	want := []struct {
		name      string
		descChunk string
	}{
		{"Sovereign Orchestration", "Phase 55"},
		{"Autonomous Account Bootstrap", "Phase 56"},
		{"DOM XSS & postMessage", "Phase 57"},
		{"Client-Side Secret & CORS", "Phase 58"},
		{"Stateful Attack Graph", "Phase 59"},
		{"AI Payload Mutation", "Phase 60"},
	}
	ph := SovereignPhases()
	for i, w := range want {
		if ph[i].Name() != w.name {
			t.Fatalf("phase %d name = %q, want %q", i, ph[i].Name(), w.name)
		}
		if !strings.Contains(ph[i].Description(), w.descChunk) {
			t.Fatalf("phase %q description missing %q: %s", w.name, w.descChunk, ph[i].Description())
		}
	}
}

func TestSovereign_BootstrappedAuthContextsFallSafe(t *testing.T) {
	// Reset the package singleton so this test is order-independent.
	sovereignBootstrap = bootstrappedIdentities{}
	_, _, ok := bootstrappedAuthContexts()
	if ok {
		t.Fatal("bootstrappedAuthContexts must report not-ok before any bootstrap")
	}

	sovereignBootstrap = bootstrappedIdentities{
		userA:   exploit.Identity{Role: "A", Token: "tokA", Registered: true},
		userB:   exploit.Identity{Role: "B", Token: "tokB", Registered: true},
		origin:  "https://t",
		present: true,
	}
	priv, std, ok := bootstrappedAuthContexts()
	if !ok {
		t.Fatal("expected ok after bootstrap present")
	}
	if !strings.Contains(priv.Headers["Authorization"], "tokA") {
		t.Fatalf("privileged ctx should carry User A token, got %v", priv.Headers)
	}
	if !strings.Contains(std.Headers["Authorization"], "tokB") {
		t.Fatalf("standard ctx should carry User B token, got %v", std.Headers)
	}
	sovereignBootstrap = bootstrappedIdentities{} // cleanup
}

func TestSovereign_LooksBlockedDetectsWAF(t *testing.T) {
	if !looksBlocked(exploit.Response{Status: 403}) {
		t.Fatal("403 must be treated as blocked")
	}
	if !looksBlocked(exploit.Response{Status: 200, Body: "Just a moment... Cloudflare"}) {
		t.Fatal("challenge body must be treated as blocked")
	}
	if looksBlocked(exploit.Response{Status: 200, Body: "welcome home"}) {
		t.Fatal("a clean 200 must NOT be treated as blocked")
	}
}

func TestSovereign_SameOrigin(t *testing.T) {
	if !sameOrigin("https://t/a", "https://t/b?x=1") {
		t.Fatal("same host+scheme must be same origin")
	}
	if sameOrigin("https://t/a", "https://other/a") {
		t.Fatal("different hosts must not be same origin")
	}
}
