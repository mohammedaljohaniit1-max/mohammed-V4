package engine

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReconTools_Inventory(t *testing.T) {
	if len(reconTools) < 45 {
		t.Fatalf("readiness must inventory the full 45-tool recon set, got %d", len(reconTools))
	}
	for _, tool := range reconTools {
		if tool.Name == "" {
			t.Fatalf("recon tool with empty name")
		}
		if tool.InstallCmd == "" {
			t.Fatalf("recon tool %q missing an install hint", tool.Name)
		}
	}
}

// TestReconTools_V121ModernToolsPresent is the V12.1 Section 3 proof: every one
// of the 7 new modern tools MUST be in the inventory with an install command.
func TestReconTools_V121ModernToolsPresent(t *testing.T) {
	want := []string{"chaos", "alterx", "cdncheck", "uncover", "cariddi", "trufflehog", "ppmap"}
	have := map[string]string{}
	for _, tool := range reconTools {
		have[tool.Name] = tool.InstallCmd
	}
	for _, name := range want {
		cmd, ok := have[name]
		if !ok {
			t.Errorf("V12.1 tool %q missing from reconTools inventory", name)
			continue
		}
		if cmd == "" {
			t.Errorf("V12.1 tool %q has no install command", name)
		}
	}
}

func TestProbeReconTools_Populates(t *testing.T) {
	got := probeReconTools()
	if len(got) != len(reconTools) {
		t.Fatalf("probeReconTools should return every tool, got %d want %d", len(got), len(reconTools))
	}
}

// TestFindInBinDirs_SudoSecurePathFallback proves the V12.5 fix: a tool that
// exists in a known bin dir ($HOME/.local/bin here) is found by findInBinDirs
// EVEN THOUGH it is not on the test process $PATH — the exact "12/45" bug where
// sudo's secure_path hid /usr/local/bin and /root/go/bin.
func TestFindInBinDirs_SudoSecurePathFallback(t *testing.T) {
	tmpHome := t.TempDir()
	localBin := filepath.Join(tmpHome, ".local", "bin")
	if err := os.MkdirAll(localBin, 0o755); err != nil {
		t.Fatal(err)
	}
	// A fake executable that is NOT on $PATH.
	toolName := "mohammed_fake_recon_tool"
	toolPath := filepath.Join(localBin, toolName)
	if err := os.WriteFile(toolPath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", tmpHome)

	got := findInBinDirs(toolName)
	if got != toolPath {
		t.Fatalf("findInBinDirs should locate %q at %q via the HOME/.local/bin fallback, got %q", toolName, toolPath, got)
	}

	// A non-executable file with the same name must NOT be treated as present.
	noExec := filepath.Join(localBin, "not_executable_tool")
	if err := os.WriteFile(noExec, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if p := findInBinDirs("not_executable_tool"); p != "" {
		t.Fatalf("findInBinDirs must ignore non-executable files, got %q", p)
	}

	// A tool that exists nowhere must return "".
	if p := findInBinDirs("definitely_does_not_exist_zzz"); p != "" {
		t.Fatalf("findInBinDirs must return \"\" for a missing tool, got %q", p)
	}
}

// TestCandidateBinDirs_IncludesSudoStrippedDirs asserts the fallback dir list
// covers the exact locations sudo's secure_path drops (proven present on the
// user's Kali box: /usr/local/bin, /root/go/bin).
func TestCandidateBinDirs_IncludesSudoStrippedDirs(t *testing.T) {
	dirs := candidateBinDirs()
	set := map[string]bool{}
	for _, d := range dirs {
		set[d] = true
	}
	for _, must := range []string{"/usr/local/bin", "/root/go/bin", "/usr/bin"} {
		if !set[must] {
			t.Errorf("candidateBinDirs must include %q (a sudo-secure_path-stripped location)", must)
		}
	}
}

func TestOverallPosture(t *testing.T) {
	ready := ReadinessReport{OllamaReachable: true, BrowserAvailable: true, ToolsPresent: 38, ToolsTotal: 38}
	if overallPosture(ready) != "READY" {
		t.Fatalf("all-green must be READY")
	}
	degraded := ReadinessReport{ToolsPresent: 20, ToolsTotal: 38}
	if overallPosture(degraded) != "DEGRADED" {
		t.Fatalf("half tools should be DEGRADED")
	}
	minimal := ReadinessReport{ToolsPresent: 2, ToolsTotal: 38}
	if overallPosture(minimal) != "MINIMAL" {
		t.Fatalf("few tools should be MINIMAL")
	}
}

func TestDiffCascade(t *testing.T) {
	pulled := diffCascade("fast=none deep=none reasoning=none", "fast=llama3.2:3b deep=qwen2.5:7b reasoning=none")
	if len(pulled) != 2 {
		t.Fatalf("diffCascade should detect 2 pulled models, got %v", pulled)
	}
}
