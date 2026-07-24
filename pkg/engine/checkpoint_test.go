package engine

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mohammed-v3/core/pkg/config"
)

// newTestState builds a minimal State pointed at a temp output folder.
func newTestState(t *testing.T, dir string) *State {
	t.Helper()
	return &State{
		Scope:        &config.Scope{Domains: []string{"whatnot.com"}},
		Subdomains:   []string{"api.whatnot.com", "www.whatnot.com"},
		LiveHosts:    []string{"https://api.whatnot.com"},
		URLs:         []string{"https://api.whatnot.com/graphql"},
		Parameters:   map[string][]string{"https://api.whatnot.com": {"id", "token"}},
		Findings:     []map[string]interface{}{{"title": "CORS", "severity": "Medium"}},
		OutputFolder: dir,
		StartTime:    time.Now().Add(-5 * time.Minute),
	}
}

// TestCheckpointRoundTrip proves Save → Load → RestoreInto preserves all data
// and correctly marks completed phases as skippable.
func TestCheckpointRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s := newTestState(t, dir)
	s.MarkComplete("OSINT Intelligence Gathering")
	s.MarkComplete("Passive Subdomain Enumeration")

	if err := s.SaveCheckpoint(); err != nil {
		t.Fatalf("SaveCheckpoint: %v", err)
	}

	cpPath := filepath.Join(dir, "checkpoint.json")
	if _, err := os.Stat(cpPath); err != nil {
		t.Fatalf("checkpoint.json not written: %v", err)
	}

	cp, err := LoadCheckpoint(cpPath)
	if err != nil {
		t.Fatalf("LoadCheckpoint: %v", err)
	}

	// Restore into a brand-new state, as --resume would.
	restored := &State{Scope: &config.Scope{Domains: []string{"whatnot.com"}}, Parameters: map[string][]string{}}
	cp.RestoreInto(restored)

	if len(restored.Subdomains) != 2 {
		t.Errorf("subdomains not restored: got %d want 2", len(restored.Subdomains))
	}
	if len(restored.Findings) != 1 {
		t.Errorf("findings not restored: got %d want 1", len(restored.Findings))
	}
	if !restored.IsComplete("OSINT Intelligence Gathering") {
		t.Error("completed OSINT phase should be skippable after restore")
	}
	if !restored.IsComplete("Passive Subdomain Enumeration") {
		t.Error("completed passive phase should be skippable after restore")
	}
	if restored.IsComplete("Nuclei Vulnerability Scan") {
		t.Error("a never-run phase must NOT be marked complete")
	}
}

// TestMarkCompleteIdempotent ensures duplicate MarkComplete calls don't bloat
// the completed list (phases can be re-marked on retry paths).
func TestMarkCompleteIdempotent(t *testing.T) {
	s := &State{}
	s.MarkComplete("A")
	s.MarkComplete("A")
	s.MarkComplete("B")
	if len(s.CompletedPhases) != 2 {
		t.Fatalf("expected 2 unique completed phases, got %d", len(s.CompletedPhases))
	}
}

// TestFindLatestCheckpoint verifies auto-detect picks the newest scan folder.
func TestFindLatestCheckpoint(t *testing.T) {
	base := t.TempDir()

	older := filepath.Join(base, "old_target")
	newer := filepath.Join(base, "new_target")
	os.MkdirAll(older, 0755)
	os.MkdirAll(newer, 0755)
	os.WriteFile(filepath.Join(older, "checkpoint.json"), []byte(`{"version":1}`), 0644)
	os.WriteFile(filepath.Join(newer, "checkpoint.json"), []byte(`{"version":1}`), 0644)

	// Make `newer` unambiguously more recent.
	future := time.Now().Add(2 * time.Hour)
	os.Chtimes(filepath.Join(newer, "checkpoint.json"), future, future)

	got := FindLatestCheckpoint(base)
	want := filepath.Join(newer, "checkpoint.json")
	if got != want {
		t.Fatalf("FindLatestCheckpoint = %q, want %q", got, want)
	}
}

// TestLoadCheckpointRejectsUnversioned guards against loading corrupt/legacy
// files with no version field.
func TestLoadCheckpointRejectsUnversioned(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "checkpoint.json")
	os.WriteFile(p, []byte(`{"target":"x"}`), 0644)
	if _, err := LoadCheckpoint(p); err == nil {
		t.Fatal("expected error loading unversioned checkpoint, got nil")
	}
}
