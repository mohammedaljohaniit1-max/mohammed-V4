package engine

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mohammed-v3/core/pkg/config"
)

// newTestState builds a minimal State whose OutputFolder is a temp dir.
func newTestState(t *testing.T, dir string) *State {
	t.Helper()
	return &State{
		Scope:        &config.Scope{Domains: []string{"whatnot.com"}},
		OutputFolder: dir,
		StartTime:    time.Now().Add(-5 * time.Minute),
		Subdomains:   []string{"api.whatnot.com", "www.whatnot.com"},
		LiveHosts:    []string{"https://api.whatnot.com"},
		URLs:         []string{"https://api.whatnot.com/graphql"},
		Parameters:   map[string][]string{"https://api.whatnot.com": {"id", "q"}},
		Findings:     []map[string]interface{}{{"type": "cors", "severity": "Medium"}},
	}
}

// TestCheckpointRoundTrip proves state survives a save → load → restore cycle
// (the core of the FLAW #2 resume engine).
func TestCheckpointRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s := newTestState(t, dir)
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

	// Restore into a brand-new empty state.
	fresh := &State{Scope: &config.Scope{Domains: []string{"whatnot.com"}}}
	cp.RestoreInto(fresh)

	if len(fresh.Subdomains) != 2 {
		t.Errorf("subdomains not restored: got %d want 2", len(fresh.Subdomains))
	}
	if len(fresh.URLs) != 1 {
		t.Errorf("urls not restored: got %d want 1", len(fresh.URLs))
	}
	if len(fresh.Findings) != 1 {
		t.Errorf("findings not restored: got %d want 1", len(fresh.Findings))
	}
	if !fresh.IsComplete("OSINT Intelligence Gathering") {
		t.Error("completed phase OSINT not marked complete after restore")
	}
	if !fresh.IsComplete("Passive Subdomain Enumeration") {
		t.Error("completed phase Passive not marked complete after restore")
	}
	if fresh.IsComplete("Vulnerability Scanning") {
		t.Error("uncompleted phase wrongly marked complete")
	}
}

// TestFindLatestCheckpoint proves auto-detect picks the newest scan folder.
func TestFindLatestCheckpoint(t *testing.T) {
	base := t.TempDir()

	older := filepath.Join(base, "old_com")
	newer := filepath.Join(base, "new_com")
	if err := os.MkdirAll(older, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(newer, 0755); err != nil {
		t.Fatal(err)
	}
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

	if FindLatestCheckpoint(filepath.Join(base, "does-not-exist")) != "" {
		t.Error("expected empty path for missing base dir")
	}
}

// TestLoadCheckpointRejectsVersionless guards against loading garbage.
func TestLoadCheckpointRejectsVersionless(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`{"subdomains":["x.com"]}`), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCheckpoint(bad); err == nil {
		t.Error("expected error loading versionless checkpoint")
	}
}
