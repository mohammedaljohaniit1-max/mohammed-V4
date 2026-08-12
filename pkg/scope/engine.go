package scope

import (
	"fmt"
	"sort"
	"strings"
)

// engine.go — the BRIDGE from a program's legal policy (ScopeFile) to concrete
// MOHAMMED engine settings. It answers: "given this program's rules, how should
// the REAL scanner (cmd/mohammed) be driven?" — which profile, which rate, and
// which hosts belong in the generated scope.txt.
//
// This is what replaces the weak recon/*.sh bash: instead of a parallel
// half-scanner, we compute the correct flags and let the real engine (governor,
// WAF-bypass, AI cascade, 65+ phases) do the work — at the legally-correct
// intensity for each program.

// EnginePlan is the computed driving plan for one program.
type EnginePlan struct {
	// Profile is the mohammed --profile value: "passive" | "small" | "large".
	Profile string
	// RatePerMin is the mohammed --rate value (requests/MINUTE). Derived from
	// the program's MaxRPS (requests/second) where one is published; otherwise a
	// safe default for the policy.
	RatePerMin int
	// Threads is a recommended --threads value, scaled to the intensity.
	Threads int
	// WAFBypass suggests enabling --waf-bypass (only for full-automation modes;
	// never for passive/forbidden targets).
	WAFBypass bool
	// UserAgent is the required UA substring, if the program mandates one.
	UserAgent string
	// PassiveOnly is true when the program forbids active traffic. The bridge
	// still runs the engine, but pinned to --profile passive.
	PassiveOnly bool
	// Rationale is a human-readable one-liner explaining the choice.
	Rationale string
}

// FullPlan computes the plan for a FULL (maximum-intensity legal) scan.
// It respects the program policy: forbidden/sensitive/reports-rejected targets
// are automatically downgraded to passive, so calling FullPlan on a forbidden
// target is SAFE — it will not send active traffic.
func (sf *ScopeFile) FullPlan() EnginePlan {
	// Sensitive gov or explicitly-forbidden automation => passive, always.
	if sf.SensitiveGov {
		return EnginePlan{
			Profile: "passive", RatePerMin: 60, Threads: 5, WAFBypass: false,
			UserAgent: sf.RequiredUA, PassiveOnly: true,
			Rationale: "sensitive/gov target — engine pinned to PASSIVE (no active traffic)",
		}
	}
	switch sf.Automation {
	case AutoForbidden:
		return EnginePlan{
			Profile: "passive", RatePerMin: 60, Threads: 5, WAFBypass: false,
			UserAgent: sf.RequiredUA, PassiveOnly: true,
			Rationale: "program FORBIDS automation (legal-action clause) — engine pinned to PASSIVE",
		}
	case AutoReportsRejected:
		// Tool-only reports rejected: run active recon+light probing but NOT the
		// aggressive vuln-scan intensity. "small" keeps aggressive phases off.
		return EnginePlan{
			Profile: "small", RatePerMin: 120, Threads: 15, WAFBypass: false,
			UserAgent: sf.RequiredUA, PassiveOnly: false,
			Rationale: "reports-rejected — active recon allowed, aggressive scan off; human validates",
		}
	case AutoRateLimited, AutoWildcardBounty:
		// Full automation, capped at the program's published rate.
		rpm := rpsToRPM(sf.MaxRPS)
		return EnginePlan{
			Profile: "large", RatePerMin: rpm, Threads: threadsForRPS(sf.MaxRPS),
			WAFBypass: true, UserAgent: sf.RequiredUA, PassiveOnly: false,
			Rationale: fmt.Sprintf("automation permitted — FULL engine, capped at %d req/s (%d req/min)", sf.MaxRPS, rpm),
		}
	default:
		return EnginePlan{
			Profile: "passive", RatePerMin: 60, Threads: 5, PassiveOnly: true,
			UserAgent: sf.RequiredUA,
			Rationale: "unknown policy — safe default PASSIVE",
		}
	}
}

// PassivePlan always returns a PASSIVE plan for any program — the dedicated
// "passive scan" command uses this regardless of what the policy would allow,
// so the operator can gather OSINT everywhere with zero active traffic.
func (sf *ScopeFile) PassivePlan() EnginePlan {
	rpm := 60
	if sf.MaxRPS > 0 {
		rpm = rpsToRPM(sf.MaxRPS)
	}
	return EnginePlan{
		Profile: "passive", RatePerMin: rpm, Threads: 5, WAFBypass: false,
		UserAgent: sf.RequiredUA, PassiveOnly: true,
		Rationale: "explicit PASSIVE scan — public OSINT only, no active payloads",
	}
}

// rpsToRPM converts a per-second cap to the per-minute value mohammed's --rate
// expects. It stays STRICTLY at/under the ceiling (never rounds up past it) and
// applies a small safety margin (90%) so bursts don't cross the published line.
func rpsToRPM(rps int) int {
	if rps <= 0 {
		return 60 // conservative default: 1 req/s
	}
	rpm := rps * 60 * 9 / 10 // 90% of the ceiling, integer math
	if rpm < 1 {
		rpm = 1
	}
	return rpm
}

// threadsForRPS scales concurrency to the allowed rate so we don't spawn 30
// workers to share a 5 req/s budget (they'd just block). Small, honest scaling.
func threadsForRPS(rps int) int {
	switch {
	case rps <= 0:
		return 5
	case rps <= 5:
		return 5
	case rps <= 20:
		return 10
	case rps <= 50:
		return 20
	default:
		return 30
	}
}

// ScopeHosts returns the concrete host lines to write into a mohammed scope.txt:
//   - in_scope entries: URL prefixes reduced to their host; wildcards kept as
//     the apex (so the engine enumerates the zone); plain hosts kept as-is.
//   - out_of_scope entries: emitted with a leading '!' (mohammed's exclude
//     marker) so the engine NEVER enumerates them.
//
// The result is deterministic (sorted, de-duplicated) so generated scope files
// are stable across runs.
func (sf *ScopeFile) ScopeHosts() []string {
	inSet := map[string]bool{}
	for _, raw := range sf.InScope {
		h := hostForScope(raw)
		if h != "" {
			inSet[h] = true
		}
	}
	outSet := map[string]bool{}
	for _, raw := range sf.OutOfScope {
		h := hostForScope(raw)
		if h != "" {
			outSet["!"+h] = true
		}
	}
	lines := make([]string, 0, len(inSet)+len(outSet))
	for h := range inSet {
		lines = append(lines, h)
	}
	for h := range outSet {
		lines = append(lines, h)
	}
	sort.Strings(lines)
	return lines
}

// hostForScope normalises one in/out-of-scope entry to a host mohammed accepts.
// "https://api.example.com/" -> "api.example.com"; "*.example.com" -> "example.com".
func hostForScope(raw string) string {
	s := strings.TrimSpace(strings.ToLower(raw))
	if s == "" {
		return ""
	}
	// strip scheme
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	// strip path/query
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	// strip a leading wildcard label: "*.example.com" -> "example.com"
	s = strings.TrimPrefix(s, "*.")
	// strip trailing dot / port
	s = strings.TrimSuffix(s, ".")
	if i := strings.Index(s, ":"); i >= 0 {
		s = s[:i]
	}
	// reject anything that still isn't a plausible host
	if s == "" || strings.ContainsAny(s, " \t") {
		return ""
	}
	return s
}
