package engine

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mohammed-v3/core/pkg/config"
)

// TestCheckpointRoundtrip is the regression guard for FLAW #2: state saved to
// checkpoint.json must be restorable byte-for-byte into a fresh State, with
// completed phases marked so the orchestrator skips them on resume.
func TestCheckpointRoundtrip(t *testing.T) {
	dir := t.TempDir()

	orig := &State{
		Scope:           &config.Scope{Domains: []string{"whatnot.com"}},
		OutputFolder:    dir,
		StartTime:       time.Now().Add(-30 * time.Minute),
		Subdomains:      []string{"api.whatnot.com", "www.whatnot.com"},
		LiveHosts:       []string{"https://api.whatnot.com"},
		URLs:            []string{"https://api.whatnot.com/graphql"},
		Parameters:      map[string][]string{"https://api.whatnot.com": {"id", "token"}},
		Findings:        []map[string]interface{}{{"title": "CORS", "severity": "Medium"}},
		CompletedPhases: []string{"OSINT Intelligence Gathering", "Passive Subdomain Enumeration"},
	}

	if err := orig.SaveCheckpoint(); err != nil {
		t.Fatalf("SaveCheckpoint failed: %v", err)
	}

	cpPath := filepath.Join(dir, "checkpoint.json")
	if _, err := os.Stat(cpPath); err != nil {
		t.Fatalf("checkpoint.json not written: %v", err)
	}

	cp, err := LoadCheckpoint(cpPath)
	if err != nil {
		t.Fatalf("LoadCheckpoint failed: %v", err)
	}

	restored := &State{OutputFolder: dir, Parameters: map[string][]string{}}
	cp.RestoreInto(restored)

	if len(restored.Subdomains) != 2 {
		t.Errorf("subdomains: got %d want 2", len(restored.Subdomains))
	}
	if len(restored.URLs) != 1 || restored.URLs[0] != "https://api.whatnot.com/graphql" {
		t.Errorf("URLs not restored: %v", restored.URLs)
	}
	if len(restored.Findings) != 1 {
		t.Errorf("findings: got %d want 1", len(restored.Findings))
	}
	// The two completed phases must be skip-flagged; an unrun phase must not.
	if !restored.IsComplete("OSINT Intelligence Gathering") {
		t.Error("OSINT phase should be marked complete after restore")
	}
	if restored.IsComplete("Vulnerability Scan") {
		t.Error("unrun phase must NOT be marked complete")
	}
}

// TestFindLatestCheckpoint proves --resume auto discovers the newest scan.
func TestFindLatestCheckpoint(t *testing.T) {
	base := t.TempDir()

	older := filepath.Join(base, "old_target")
	newer := filepath.Join(base, "new_target")
	os.MkdirAll(older, 0755)
	os.MkdirAll(newer, 0755)

	os.WriteFile(filepath.Join(older, "checkpoint.json"), []byte(`{"version":1}`), 0644)
	// Make the older file genuinely older.
	old := time.Now().Add(-1 * time.Hour)
	os.Chtimes(filepath.Join(older, "checkpoint.json"), old, old)

	os.WriteFile(filepath.Join(newer, "checkpoint.json"), []byte(`{"version":1}`), 0644)

	got := FindLatestCheckpoint(base)
	want := filepath.Join(newer, "checkpoint.json")
	if got != want {
		t.Errorf("FindLatestCheckpoint = %q, want %q", got, want)
	}

	if FindLatestCheckpoint(filepath.Join(base, "does-not-exist")) != "" {
		t.Error("expected empty string for missing base dir")
	}
}

// TestMarkCompleteIdempotent ensures duplicate MarkComplete calls don't bloat.
func TestMarkCompleteIdempotent(t *testing.T) {
	s := &State{}
	s.MarkComplete("A")
	s.MarkComplete("A")
	s.MarkComplete("B")
	if len(s.CompletedPhases) != 2 {
		t.Errorf("CompletedPhases = %v, want [A B]", s.CompletedPhases)
	}
}
