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
