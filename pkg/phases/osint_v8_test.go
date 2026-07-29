package phases

import (
	"strings"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────────────
// V8.0 GAP 1 — OSINT source count + dynamic wordlist generator tests.
// ─────────────────────────────────────────────────────────────────────────────

func TestOSINTSources_AtLeast70(t *testing.T) {
	total := len(osintSources()) + len(osintSourcesV8())
	if total < 70 {
		t.Fatalf("V8 mandate requires 70+ OSINT sources, got %d", total)
	}
}

func TestOSINTSourcesV8_NoDuplicateNames(t *testing.T) {
	seen := map[string]bool{}
	for _, s := range append(osintSources(), osintSourcesV8()...) {
		if seen[s.name] {
			t.Fatalf("duplicate OSINT source name: %q", s.name)
		}
		seen[s.name] = true
	}
}

func TestDynamicWordlist_BrandAndTechSeeded(t *testing.T) {
	wl := DynamicWordlist(
		[]string{"acme-corp.com", "acme.io"},
		[]string{"Nginx", "React", "Kubernetes"},
		[]string{"fintech payments"},
	)
	if len(wl) == 0 {
		t.Fatalf("expected a non-empty wordlist")
	}
	joined := strings.Join(wl, "\n")

	// Brand token must appear (bare and permuted).
	if !contains(wl, "acme") {
		t.Fatalf("expected brand token 'acme' in wordlist")
	}
	if !strings.Contains(joined, "acme-dev") && !strings.Contains(joined, "dev-acme") {
		t.Fatalf("expected an env-permuted brand token like acme-dev/dev-acme")
	}
	// A base keyword must always be present.
	if !contains(wl, "api") {
		t.Fatalf("expected base keyword 'api' in wordlist")
	}
	// Deterministic + deduped: no duplicates, sorted.
	seen := map[string]bool{}
	prev := ""
	for _, w := range wl {
		if seen[w] {
			t.Fatalf("duplicate wordlist entry: %q", w)
		}
		seen[w] = true
		if prev != "" && w < prev {
			t.Fatalf("wordlist must be sorted; %q came after %q", w, prev)
		}
		prev = w
		// DNS-label sanity.
		if strings.ContainsAny(w, ". _/") {
			t.Fatalf("wordlist entry has invalid DNS chars: %q", w)
		}
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
