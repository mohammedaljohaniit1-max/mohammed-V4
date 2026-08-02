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

import (
	"strings"
	"time"
)

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

	// ── Recon phases (bbot/subfinder are slow but bounded) ──
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

// ═══════════════════════════════════════════════════════════════════════════
// V12.3 RUTHLESS · FAILURE #2 — SCALE-ADAPTIVE TIMEOUTS
// ---------------------------------------------------------------------------
// EMPIRICAL EVIDENCE (9h42m GitLab scan): the FIXED 15m/20m caps STARVED
// nuclei, ffuf and gau on a 14,000+ host target — those tools were killed with
// 0 results because a fixed cap that is fine for 50 hosts is catastrophically
// too short for 14,000. A single flat cap cannot serve both a 10-host app and a
// 14,000-host enterprise scope.
//
// CalculateAdaptiveTimeout scales the base cap by the live host count:
//   >5000 hosts → ×3   (enterprise scope — nuclei needs real time)
//   >1000 hosts → ×2   (large scope)
//   otherwise   → ×1   (the base cap is already generous)
//
// The multiplier is further nudged by the profile: the 'passive'/'small'
// profiles never need the ×3 blow-up, while 'large'/'bugbounty' always get at
// least the host-count multiplier. The result is ALWAYS bounded (there is still
// a hard cap — it just scales), so a phase can never again run unbounded.
// ═══════════════════════════════════════════════════════════════════════════

// maxAdaptiveTimeout is the absolute ceiling no adaptive scaling can exceed.
// Even a ×3 blow-up on the 20-minute default lands at 60m; this ceiling guards
// against any future base cap producing an unreasonable value.
const maxAdaptiveTimeout = 90 * time.Minute

// CalculateAdaptiveTimeout scales baseCap by the number of live hosts (and the
// scan profile) so heavy phases get proportionally more time on large targets
// while small targets keep tight caps. The return value is always bounded by
// maxAdaptiveTimeout.
func CalculateAdaptiveTimeout(baseCap time.Duration, hostCount int, profile string) time.Duration {
	multiplier := 1
	switch {
	case hostCount > 5000:
		multiplier = 3
	case hostCount > 1000:
		multiplier = 2
	}

	// Profile modulation. Passive/small scans never fan out to the intrusive
	// tools that need the ×3 budget, so cap their multiplier at ×2. Large /
	// bugbounty scans keep the full host-count multiplier (already applied).
	switch strings.ToLower(strings.TrimSpace(profile)) {
	case "passive", "small":
		if multiplier > 2 {
			multiplier = 2
		}
	}

	out := time.Duration(int64(baseCap) * int64(multiplier))
	if out > maxAdaptiveTimeout {
		return maxAdaptiveTimeout
	}
	if out < baseCap {
		return baseCap
	}
	return out
}
