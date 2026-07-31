package proxy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════
// V12.2 §2.6 REGRESSION TESTS — Burp smart proxy gate
// ---------------------------------------------------------------------------
// Proves high-value traffic is forwarded and noise (static assets / 404 / CDN
// errors / out-of-scope) is dropped, that the counter line is emitted, that
// the rate limiter throttles forwards, and that burp_scope.json exports.
// ═══════════════════════════════════════════════════════════════════════════

func TestV122_EvaluateBurpForward_ForwardVsDrop(t *testing.T) {
	cases := []struct {
		name string
		c    GateCandidate
		want bool
	}{
		{"api path", GateCandidate{URL: "https://app.gitlab.com/api/v4/projects", InScope: true}, true},
		{"login", GateCandidate{URL: "https://gitlab.com/users/sign_in", InScope: true}, true},
		{"admin", GateCandidate{URL: "https://gitlab.com/admin/dashboard", InScope: true}, true},
		{"upload", GateCandidate{URL: "https://gitlab.com/uploads/thing", InScope: true}, true},
		{"params on any path", GateCandidate{URL: "https://gitlab.com/search?q=x", InScope: true}, true},
		{"json endpoint", GateCandidate{URL: "https://gitlab.com/data.json", InScope: true}, true},
		{"crawl dynamic route", GateCandidate{URL: "https://gitlab.com/some/route", Source: "crawl", InScope: true}, true},

		{"static js", GateCandidate{URL: "https://gitlab.com/assets/app.js", InScope: true}, false},
		{"static css no params", GateCandidate{URL: "https://gitlab.com/style.css", InScope: true}, false},
		{"404", GateCandidate{URL: "https://gitlab.com/missing", Status: 404, InScope: true}, false},
		{"cdn 502 error", GateCandidate{URL: "https://cdn.gitlab.com/x", Status: 502, InScope: true}, false},
		{"out of scope", GateCandidate{URL: "https://service-now.com/api/x", InScope: false}, false},
		{"unparseable", GateCandidate{URL: "://bad", InScope: true}, false},
	}
	for _, tc := range cases {
		got := EvaluateBurpForward(tc.c).Forward
		if got != tc.want {
			t.Errorf("%s: EvaluateBurpForward(%q)=%v, want %v", tc.name, tc.c.URL, got, tc.want)
		}
	}
}

func TestV122_SmartGate_CountersAndScopeExport(t *testing.T) {
	g := NewSmartGate(0) // no rate limit for counting test
	g.Allow(GateCandidate{URL: "https://gitlab.com/api/v4/x", InScope: true})   // fwd
	g.Allow(GateCandidate{URL: "https://gitlab.com/api/v4/y", InScope: true})   // fwd (same host)
	g.Allow(GateCandidate{URL: "https://gitlab.com/app.js", InScope: true})     // drop
	g.Allow(GateCandidate{URL: "https://service-now.com/api", InScope: false})  // drop

	p, f := g.Counts()
	if p != 2 || f != 2 {
		t.Fatalf("counts: proxied=%d filtered=%d, want 2/2", p, f)
	}
	if line := g.CounterLine(); line != "Burp: 2 proxied, 2 filtered" {
		t.Fatalf("counter line = %q", line)
	}

	targets := g.ForwardedTargets()
	if len(targets) != 1 || targets[0] != "https://gitlab.com" {
		t.Fatalf("forwarded targets = %v, want [https://gitlab.com]", targets)
	}

	dir := t.TempDir()
	path, err := g.ExportScope(dir)
	if err != nil {
		t.Fatalf("ExportScope: %v", err)
	}
	if filepath.Base(path) != "burp_scope.json" {
		t.Fatalf("unexpected export path %q", path)
	}
	data, _ := os.ReadFile(path)
	var out burpScopeFile
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("burp_scope.json invalid: %v", err)
	}
	if out.Proxied != 2 || out.Filtered != 2 || len(out.Targets) != 1 {
		t.Fatalf("exported scope wrong: %+v", out)
	}
}

func TestV122_SmartGate_RateLimit(t *testing.T) {
	g := NewSmartGate(10) // 10 req/s → 100ms min gap
	var slept []time.Duration
	base := time.Unix(0, 0)
	var virtual time.Duration
	g.nowFn = func() time.Time { return base.Add(virtual) }
	g.sleepFn = func(d time.Duration) { slept = append(slept, d); virtual += d }

	// Three back-to-back forwards with no real time passing: the 2nd and 3rd
	// must each be throttled to the 100ms minimum gap.
	for i := 0; i < 3; i++ {
		g.Allow(GateCandidate{URL: "https://gitlab.com/api/v4/x", InScope: true})
	}
	if len(slept) < 2 {
		t.Fatalf("expected >=2 throttle sleeps, got %d (%v)", len(slept), slept)
	}
	for _, d := range slept {
		if d > 100*time.Millisecond {
			t.Fatalf("throttle sleep %v exceeds 100ms gap", d)
		}
	}
}
