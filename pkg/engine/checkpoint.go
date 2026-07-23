package engine

// ═══════════════════════════════════════════════════════════════════════════
// Scan State Checkpointing & Resume (FLAW #2 FIX)
// ---------------------------------------------------------------------------
// Before this file existed, interrupting a 40-minute scan at phase 25 meant
// restarting from phase 01 — and the SIGINT handler even printed "Saving
// progress..." while saving nothing. This module serializes the recon State
// into {OutputFolder}/checkpoint.json after EVERY phase, and reloads it with
// --resume so completed phases are skipped and their data is restored.
// ═══════════════════════════════════════════════════════════════════════════

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// checkpointFileName is the fixed filename written inside each scan's output
// folder. Auto-resume discovers scans by scanning output/*/checkpoint.json.
const checkpointFileName = "checkpoint.json"

// Checkpoint is the serializable snapshot of a scan's progress. Only exported,
// JSON-safe fields are persisted (no mutexes, no live *ai.Client, etc.).
type Checkpoint struct {
	Version         int                      `json:"version"`
	Target          string                   `json:"target"`
	OutputFolder    string                   `json:"output_folder"`
	SavedAt         string                   `json:"saved_at"`
	StartTimeUnix   int64                    `json:"start_time_unix"`
	CompletedPhases []string                 `json:"completed_phases"`
	Subdomains      []string                 `json:"subdomains"`
	LiveHosts       []string                 `json:"live_hosts"`
	URLs            []string                 `json:"urls"`
	Parameters      map[string][]string      `json:"parameters"`
	Findings        []map[string]interface{} `json:"findings"`
}

// checkpointPath returns the canonical checkpoint path for a state.
func (s *State) checkpointPath() string {
	return filepath.Join(s.OutputFolder, checkpointFileName)
}

// SaveCheckpoint atomically writes the current state to checkpoint.json.
// It writes to a temp file then renames, so an interrupt mid-write can never
// corrupt an existing good checkpoint. Errors are returned (non-fatal to caller
// — a scan continues even if a checkpoint write fails, it just logs).
func (s *State) SaveCheckpoint() error {
	target := "target"
	if s.Scope != nil && len(s.Scope.Domains) > 0 {
		target = s.Scope.Domains[0]
	}

	s.findingsMu.Lock()
	cp := Checkpoint{
		Version:         1,
		Target:          target,
		OutputFolder:    s.OutputFolder,
		SavedAt:         time.Now().Format(time.RFC3339),
		StartTimeUnix:   s.StartTime.Unix(),
		CompletedPhases: append([]string(nil), s.CompletedPhases...),
		Subdomains:      append([]string(nil), s.Subdomains...),
		LiveHosts:       append([]string(nil), s.LiveHosts...),
		URLs:            append([]string(nil), s.URLs...),
		Parameters:      s.Parameters,
		Findings:        s.Findings,
	}
	s.findingsMu.Unlock()

	data, err := json.MarshalIndent(cp, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal checkpoint: %w", err)
	}

	if err := os.MkdirAll(s.OutputFolder, 0755); err != nil {
		return fmt.Errorf("ensure output dir: %w", err)
	}

	tmp := s.checkpointPath() + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return fmt.Errorf("write checkpoint tmp: %w", err)
	}
	if err := os.Rename(tmp, s.checkpointPath()); err != nil {
		return fmt.Errorf("rename checkpoint: %w", err)
	}
	return nil
}

// LoadCheckpoint reads and parses a checkpoint.json from an explicit path.
func LoadCheckpoint(path string) (*Checkpoint, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read checkpoint: %w", err)
	}
	var cp Checkpoint
	if err := json.Unmarshal(data, &cp); err != nil {
		return nil, fmt.Errorf("parse checkpoint: %w", err)
	}
	if cp.Version == 0 {
		return nil, fmt.Errorf("checkpoint has no version — refusing to load")
	}
	return &cp, nil
}

// RestoreInto populates a fresh State from a checkpoint: restores all
// discovered data and marks completed phases so the orchestrator skips them.
func (cp *Checkpoint) RestoreInto(s *State) {
	s.Subdomains = append([]string(nil), cp.Subdomains...)
	s.LiveHosts = append([]string(nil), cp.LiveHosts...)
	s.URLs = append([]string(nil), cp.URLs...)
	if cp.Parameters != nil {
		s.Parameters = cp.Parameters
	}
	if cp.Findings != nil {
		s.Findings = cp.Findings
	}
	s.CompletedPhases = append([]string(nil), cp.CompletedPhases...)

	// Build the O(1) skip set that IsComplete() consults.
	s.completedSet = make(map[string]bool, len(cp.CompletedPhases))
	for _, n := range cp.CompletedPhases {
		s.completedSet[n] = true
	}

	// Preserve the original scan's wall-clock start so elapsed time is honest.
	if cp.StartTimeUnix > 0 {
		s.StartTime = time.Unix(cp.StartTimeUnix, 0)
	}
	// Keep resuming into the SAME output folder so artifacts stay together.
	if cp.OutputFolder != "" {
		s.OutputFolder = cp.OutputFolder
	}
}

// FindLatestCheckpoint scans a base output directory (e.g. "output/") for the
// most-recently-modified checkpoint.json and returns its path. Empty string if
// none found. Used by `--resume` with no explicit path (auto-detect last scan).
func FindLatestCheckpoint(baseDir string) string {
	entries, err := os.ReadDir(baseDir)
	if err != nil {
		return ""
	}

	type cand struct {
		path    string
		modTime time.Time
	}
	var cands []cand

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		cpPath := filepath.Join(baseDir, e.Name(), checkpointFileName)
		info, err := os.Stat(cpPath)
		if err != nil {
			continue
		}
		cands = append(cands, cand{path: cpPath, modTime: info.ModTime()})
	}
	if len(cands) == 0 {
		return ""
	}
	sort.Slice(cands, func(i, j int) bool {
		return cands[i].modTime.After(cands[j].modTime)
	})
	return cands[0].path
}
