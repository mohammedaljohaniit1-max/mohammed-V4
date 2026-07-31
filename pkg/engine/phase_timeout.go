package engine

// ═══════════════════════════════════════════════════════════════════════════
// V12.2 PROCESS CRISIS · FAILURE #3 FIX — Per-Phase Hard Timeout System
// ---------------------------------------------------------------------------
// EMPIRICAL EVIDENCE (live GitLab scan):
//   Phase 12 (Port Scanning) ran 02:21:39 → 05:20:10 (2h58m) before the user
//   killed it, then on --resume ran AGAIN 00:00:30 → 01:40:04 (1h40m) before
//   being killed a second time. Total wasted on ONE phase: 4h38m.
//
// Root cause: no phase had a maximum wall-clock runtime. When naabu received
// 14,000+ hosts it entered an unbounded network-I/O wait with no hard deadline.
//
// The fix: every phase now runs under a wall-clock deadline. When a phase
// exceeds its cap the orchestrator cancels its context (which SIGKILLs the
// tool's process group via the runner) AND force-reaps any surviving child
// groups via runner.KillAllChildren(), then proceeds to the next phase with
// whatever partial results were collected. A phase can NEVER again run for
// hours.
//
// Timeouts are keyed by phase Name() (NOT slice index) because the run order
// is profile-dependent and phases are inserted/reordered between versions —
// the exact fragility the codebase already avoids for profile membership.
// ═══════════════════════════════════════════════════════════════════════════

import "time"

// DefaultPhaseTimeout is the wall-clock cap applied to any phase that does not
// have a specific override in phaseTimeouts. Generous enough that a normal
// phase never trips it, small enough that a wedged phase can't burn an hour.
const DefaultPhaseTimeout = 20 * time.Minute

// phaseTimeouts maps a phase's Name() to its hard wall-clock cap. The values
// mirror Section 2.1 of the V12.2 mandate. Phases not listed use
// DefaultPhaseTimeout. Heavy discovery/exploit phases get more; the pathological
// Port Scanning phase is capped at 15 minutes — THE FIX for the 4h38m bug.
var phaseTimeouts = map[string]time.Duration{
	// ── The FAILURE #3 fix: Port Scanning can never run for hours again. ──
	"Port Scanning": 15 * time.Minute,

	// ── Recon phases (amass/bbot are slow but bounded) ──
	"Passive Subdomain Enumeration": 20 * time.Minute,
	"Active Subdomain Bruteforce":   15 * time.Minute,
	"DNS Resolution & Enrichment":   8 * time.Minute,
	"Subdomain Takeover Check":      6 * time.Minute,
	"HTTP Probing & Tech Fingerprinting": 12 * time.Minute,

	// ── Content/URL discovery ──
	"Wayback & Historical URL Mining": 10 * time.Minute,
	"Web Crawling & Spidering":        15 * time.Minute,
	"Directory & Content Fuzzing":     15 * time.Minute,
	"JS Analysis & Secret Extraction": 10 * time.Minute,

	// ── Vulnerability engines ──
	"Vulnerability Scanning (Nuclei)": 20 * time.Minute,
	"SQL Injection Testing":           12 * time.Minute,
	"XSS Testing":                     12 * time.Minute,
}

// PhaseTimeout returns the hard wall-clock cap for a phase by Name(), falling
// back to DefaultPhaseTimeout for any phase without an explicit override.
func PhaseTimeout(name string) time.Duration {
	if d, ok := phaseTimeouts[name]; ok {
		return d
	}
	return DefaultPhaseTimeout
}
