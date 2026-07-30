package engine

import "testing"

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
