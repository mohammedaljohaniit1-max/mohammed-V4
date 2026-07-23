package engine

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mohammed-v3/core/pkg/config"
)

// newTestState builds a minimal State rooted at a temp output folder.
func newTestState(t *testing.T, outDir string) *State {
	t.Helper()
	return &State{
		Scope:        &config.Scope{Domains: []string{"whatnot.com"}},
		OutputFolder: outDir,
		StartTime:    time.Now().Add(-5 * time.Minute),
		Parameters:   map[string][]string{},
		Findings:     []map[string]interface{}{},
	}
}

// TestCheckpointRoundTrip verifies Save → Load → RestoreInto preserves all
// discovered data and the completed-phase skip set (FLAW #2).
func TestCheckpointRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s := newTestState(t, dir)
	s.Subdomains = []string{"api.whatnot.com", "www.whatnot.com"}
	s.LiveHosts = []string{"https://api.whatnot.com"}
	s.URLs = []string{"https://api.whatnot.com/v1"}
	s.Parameters["https://api.whatnot.com"] = []string{"id", "token"}
	s.AddFinding(map[string]interface{}{"type": "CORS", "severity": "Medium"})
	s.MarkComplete("OSINT Intelligence Gathering")
	s.MarkComplete("Passive Subdomain Enumeration")

	if err := s.SaveCheckpoint(); err != nil {
		t.Fatalf("SaveCheckpoint: %v", err)
	}

	cpPath := filepath.Join(dir, checkpointFileName)
	if _, err := os.Stat(cpPath); err != nil {
		t.Fatalf("checkpoint.json not written: %v", err)
	}

	cp, err := LoadCheckpoint(cpPath)
	if err != nil {
		t.Fatalf("LoadCheckpoint: %v", err)
	}

	fresh := newTestState(t, dir)
	cp.RestoreInto(fresh)

	if len(fresh.Subdomains) != 2 {
		t.Errorf("subdomains not restored: got %d want 2", len(fresh.Subdomains))
	}
	if len(fresh.LiveHosts) != 1 || len(fresh.URLs) != 1 {
		t.Errorf("live/urls not restored: live=%d urls=%d", len(fresh.LiveHosts), len(fresh.URLs))
	}
	if len(fresh.Findings) != 1 {
		t.Errorf("findings not restored: got %d want 1", len(fresh.Findings))
	}
	if got := fresh.Parameters["https://api.whatnot.com"]; len(got) != 2 {
		t.Errorf("parameters not restored: got %v want [id token]", got)
	}
	if !fresh.IsComplete("OSINT Intelligence Gathering") {
		t.Error("OSINT phase should be marked complete after restore")
	}
	if !fresh.IsComplete("Passive Subdomain Enumeration") {
		t.Error("Passive phase should be marked complete after restore")
	}
	if fresh.IsComplete("Nuclei Vulnerability Scan") {
		t.Error("uncompleted phase must NOT be skipped")
	}
}

// TestIsCompleteWithoutResume ensures a fresh (non-resumed) scan skips nothing.
func TestIsCompleteWithoutResume(t *testing.T) {
	s := newTestState(t, t.TempDir())
	if s.IsComplete("anything") {
		t.Error("fresh scan must never report phases complete")
	}
}

// TestFindLatestCheckpoint verifies auto-detection picks the newest scan dir.
func TestFindLatestCheckpoint(t *testing.T) {
	base := t.TempDir()

	older := filepath.Join(base, "old_target")
	newer := filepath.Join(base, "new_target")
	_ = os.MkdirAll(older, 0755)
	_ = os.MkdirAll(newer, 0755)

	oldCP := filepath.Join(older, checkpointFileName)
	newCP := filepath.Join(newer, checkpointFileName)
	if err := os.WriteFile(oldCP, []byte(`{"version":1}`), 0644); err != nil {
		t.Fatal(err)
	}
	// Make the older one genuinely older.
	old := time.Now().Add(-1 * time.Hour)
	_ = os.Chtimes(oldCP, old, old)

	if err := os.WriteFile(newCP, []byte(`{"version":1}`), 0644); err != nil {
		t.Fatal(err)
	}

	got := FindLatestCheckpoint(base)
	if got != newCP {
		t.Errorf("FindLatestCheckpoint = %q, want %q", got, newCP)
	}
}

// TestLoadCheckpointRejectsVersionless guards against loading garbage.
func TestLoadCheckpointRejectsVersionless(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	_ = os.WriteFile(bad, []byte(`{"target":"x"}`), 0644)
	if _, err := LoadCheckpoint(bad); err == nil {
		t.Error("expected error loading versionless checkpoint")
	}
}
