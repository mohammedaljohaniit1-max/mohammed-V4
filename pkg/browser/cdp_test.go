package browser

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestEngine_FailsOpenWhenNoBrowser verifies the CDP engine degrades safely
// when no Chromium can be launched. We force an impossible binary so launch
// deterministically fails; every method must return Unavailable/false, never
// panic. This guarantees the scan continues on the HTTP path in locked-down CI.
func TestEngine_FailsOpenWhenNoBrowser(t *testing.T) {
	e := NewEngine(Options{PageTimeout: 2 * time.Second, BinPath: "/nonexistent/definitely-not-chrome"})
	if e.Available() {
		t.Skip("a browser was unexpectedly launchable; skipping fail-open assertion")
	}
	ctx := context.Background()
	if r := e.Render(ctx, "https://example.com"); !r.Unavailable {
		t.Fatal("Render must report Unavailable when no browser")
	}
	if _, ok := e.HarvestStorage(ctx, "https://example.com"); ok {
		t.Fatal("HarvestStorage must report not-ok when no browser")
	}
	if p := e.VerifyCORS(ctx, "https://a.com", "https://b.com"); !p.Unavailable {
		t.Fatal("VerifyCORS must report Unavailable when no browser")
	}
	if p := e.ScanDOMXSS(ctx, "https://example.com#x", "mohxssdead"); !p.Unavailable {
		t.Fatal("ScanDOMXSS must report Unavailable when no browser")
	}
	e.Close() // must be safe on a never-launched engine
}

func TestClassifyStorageSecret(t *testing.T) {
	cases := []struct {
		key, val string
		want     bool
	}{
		{"auth_token", "whatever", true},
		{"jwt", "x", true},
		{"theme", "dark", false},
		{"random", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig", true}, // JWT-shaped value
		{"cart", "12", false},
		{"apiKey", "AKIA1234567890ABCDEF1234567890", true},
	}
	for _, c := range cases {
		got, _ := classifyStorageSecret(c.key, c.val)
		if got != c.want {
			t.Fatalf("classifyStorageSecret(%q,%q)=%v want %v", c.key, c.val, got, c.want)
		}
	}
}

func TestRedactMasksSecret(t *testing.T) {
	if r := Redact("supersecrettoken123456"); strings.Contains(r, "secret") {
		t.Fatalf("Redact leaked the secret body: %q", r)
	}
	if Redact("") != "" {
		t.Fatal("Redact of empty string must stay empty")
	}
	if Redact("short") != "****" {
		t.Fatal("Redact of short string must be masked")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// V12.1 FIX #6 — Chrome recovery governor tests (pure, network-free).
// ─────────────────────────────────────────────────────────────────────────────

// TestFix6_ParseStatmRSSPages proves the /proc/<pid>/statm parser extracts the
// resident-pages field (2nd column) and rejects malformed input.
func TestFix6_ParseStatmRSSPages(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"1000 250 40 12 0 300 0", 250},   // canonical statm line → 250 resident pages
		{"1000 250 40 12 0 300 0\n", 250}, // trailing newline tolerated
		{"", 0},                           // empty
		{"onlyonefield", 0},               // too few fields
		{"1000 notanumber 40", 0},         // non-numeric resident field
	}
	for _, tc := range cases {
		if got := parseStatmRSSPages(tc.in); got != tc.want {
			t.Errorf("parseStatmRSSPages(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// TestFix6_ProcRSSZeroForBadPID proves a bogus/absent PID never triggers a
// spurious restart (returns 0 MB rather than erroring).
func TestFix6_ProcRSSZeroForBadPID(t *testing.T) {
	if got := procRSSMegabytes(0); got != 0 {
		t.Errorf("procRSSMegabytes(0) = %d, want 0", got)
	}
	if got := procRSSMegabytes(-5); got != 0 {
		t.Errorf("procRSSMegabytes(-5) = %d, want 0", got)
	}
	// PID 1 exists but statm read is fine either way; must be >= 0 and never panic.
	if got := procRSSMegabytes(999999999); got != 0 {
		t.Errorf("procRSSMegabytes(nonexistent) = %d, want 0", got)
	}
}

// TestFix6_GuardMemoryDisabled proves a non-positive limit disables the guard so
// it can never restart Chrome by accident.
func TestFix6_GuardMemoryDisabled(t *testing.T) {
	e := NewEngine(Options{PageTimeout: time.Second, BinPath: "/nonexistent/chrome"})
	if e.GuardMemory(0) {
		t.Error("GuardMemory(0) must be a no-op")
	}
	if e.GuardMemory(-1) {
		t.Error("GuardMemory(-1) must be a no-op")
	}
}

// TestFix6_RecoverFailsOpen proves Recover on an engine that can never launch a
// browser returns false (so the caller degrades to HTTP) instead of panicking.
func TestFix6_RecoverFailsOpen(t *testing.T) {
	e := NewEngine(Options{PageTimeout: time.Second, BinPath: "/nonexistent/definitely-not-chrome"})
	if e.Recover() {
		t.Error("Recover() must be false when no browser can launch")
	}
	// Restarts counter increments even on failed relaunch attempts.
	if e.Restarts() < 1 {
		t.Errorf("expected >=1 restart attempt recorded, got %d", e.Restarts())
	}
}
