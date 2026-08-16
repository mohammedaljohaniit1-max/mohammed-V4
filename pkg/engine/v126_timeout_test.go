package engine

import (
	"testing"
	"time"
)

// V12.6: compute-bound phases must be EXEMPT from host-count adaptive scaling
// so a large host count no longer inflates Advanced Web / SSTI / Google Dorking
// caps (the Kali ~75m-wasted bug).

func TestIsComputeBound_Classification(t *testing.T) {
	bound := []string{
		"Advanced Web (Smuggling/Cache/SSTI)",
		"SSTI (Arithmetic Oracle)",
		"Google Dorking",
	}
	for _, n := range bound {
		if !IsComputeBound(n) {
			t.Errorf("expected %q to be compute-bound", n)
		}
	}
	notBound := []string{
		"Vulnerability Scanning (Nuclei)",
		"Port Scanning",
		"DNS Resolution & Enrichment",
	}
	for _, n := range notBound {
		if IsComputeBound(n) {
			t.Errorf("expected %q to NOT be compute-bound", n)
		}
	}
}

func TestComputeBoundPhase_FlatCapNotInflated(t *testing.T) {
	// Advanced Web base cap is 12m. With 2000 live hosts, a NON-compute-bound
	// phase would be scaled ×2. A compute-bound phase must stay flat.
	base := PhaseTimeout("Advanced Web (Smuggling/Cache/SSTI)")
	if base != 12*time.Minute {
		t.Fatalf("expected 12m base cap, got %v", base)
	}
	// Adaptive would inflate to 24m — confirm the raw adaptive helper does that
	// (so the exemption in engine.go is the thing that prevents it).
	adaptive := CalculateAdaptiveTimeout(base, 2000, "bugbounty")
	if adaptive != 24*time.Minute {
		t.Fatalf("expected adaptive to compute 24m for a non-exempt phase, got %v", adaptive)
	}
	// The exemption is applied at the call site (engine.go): IsComputeBound gates
	// whether CalculateAdaptiveTimeout is used at all.
	if !IsComputeBound("Advanced Web (Smuggling/Cache/SSTI)") {
		t.Fatalf("Advanced Web must be compute-bound to receive the flat cap")
	}
}
