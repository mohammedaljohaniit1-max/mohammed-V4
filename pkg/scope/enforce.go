package scope

import "strings"

// ToolClass buckets MOHAMMED's 25 external tools by how intrusive they are.
type ToolClass string

const (
	// ClassPassive: no active traffic to the target's own app — uses public
	// OSINT sources / archives. Safe even where automation is forbidden.
	ClassPassive ToolClass = "passive"
	// ClassProbe: light, low-volume liveness/fingerprint requests to the target.
	ClassProbe ToolClass = "probe"
	// ClassActive: crawlers / parameter miners that generate real traffic.
	ClassActive ToolClass = "active"
	// ClassAggressive: high-volume fuzzers, brute-forcers, port scanners, vuln
	// scanners. These are what programs mean by "automated scanning".
	ClassAggressive ToolClass = "aggressive"
)

// toolClasses maps each known tool to its intrusiveness. Anything unknown is
// treated as aggressive (safest default).
var toolClasses = map[string]ToolClass{
	// subdomain / OSINT (passive: query third-party sources, not the target)
	"subfinder":   ClassPassive,
	"findomain":   ClassPassive,
	"chaos":       ClassPassive,
	"assetfinder": ClassPassive,
	"amass":       ClassPassive, // amass passive mode; active mode must be off
	"gau":         ClassPassive,
	"waybackurls": ClassPassive,
	"cariddi":     ClassPassive,
	"trufflehog":  ClassPassive,
	"cdncheck":    ClassPassive,
	"uncover":     ClassPassive,

	// DNS resolution (probe: touches resolvers/target DNS lightly)
	"dnsx":  ClassProbe,
	"httpx": ClassProbe,

	// crawlers / miners (active traffic to the target app)
	"katana":    ClassActive,
	"gospider":  ClassActive,
	"hakrawler": ClassActive,
	"arjun":     ClassActive,
	"notify":    ClassPassive, // notification only

	// aggressive: bruteforce / fuzz / portscan / vuln-scan
	"puredns": ClassAggressive, // DNS bruteforce
	"alterx":  ClassActive,     // permutation generator (harmless alone)
	"bbot":    ClassAggressive, // full automated scanner
	"naabu":   ClassAggressive, // port scanner
	"nuclei":  ClassAggressive, // vuln scanner
	"dalfox":  ClassAggressive, // XSS scanner
	"ppmap":   ClassAggressive, // prototype-pollution scanner
	"ffuf":    ClassAggressive, // content/parameter fuzzer
	"nmap":    ClassAggressive, // port scanner
}

// ClassOf returns the intrusiveness class of a tool (unknown -> aggressive).
func ClassOf(tool string) ToolClass {
	if c, ok := toolClasses[strings.ToLower(strings.TrimSpace(tool))]; ok {
		return c
	}
	return ClassAggressive
}

// ToolAllowed decides whether a tool may run under this program's rules.
// The decision is deliberately conservative:
//
//   - SensitiveGov targets: only passive tools, full stop (idea #2 — even nmap
//     may be banned on limited/under-load gov infra).
//   - AutoForbidden: only passive tools (anything touching the target actively
//     risks the "legal action" clause).
//   - AutoReportsRejected: passive + probe + active allowed (a human still
//     drives), but aggressive scanners denied (tool-only reports are rejected
//     AND aggressive scanning is what gets you flagged).
//   - AutoRateLimited: everything allowed EXCEPT that the caller must also honour
//     MaxRPS; aggressive tools are allowed only when MaxRPS is set.
//
// It returns (allowed, reason) so the reason can be shown to the operator.
func (sf *ScopeFile) ToolAllowed(tool string) (bool, string) {
	class := ClassOf(tool)

	if sf.SensitiveGov {
		if class == ClassPassive {
			return true, "passive tool on sensitive/gov target"
		}
		return false, "DENIED: sensitive/gov target — only passive OSINT is permitted (idea #2)"
	}

	switch sf.Automation {
	case AutoForbidden:
		if class == ClassPassive {
			return true, "passive tool (no active traffic to target)"
		}
		return false, "DENIED: program forbids automated scanning (possible legal action) — passive-only"
	case AutoReportsRejected:
		if class == ClassAggressive {
			return false, "DENIED: aggressive scanner — program rejects tool-only reports; drive manually"
		}
		return true, "allowed (passive/probe/active) — but validate findings manually before reporting"
	case AutoRateLimited:
		if class == ClassAggressive && sf.MaxRPS <= 0 {
			return false, "DENIED: aggressive tool needs an explicit max_rps ceiling for this program"
		}
		return true, "allowed — caller MUST cap traffic at max_rps"
	default:
		return false, "DENIED: unknown automation policy (safe default)"
	}
}

// AllowedTools returns the subset of the given tools that may run, with reasons
// for the denied ones — handy for a pre-flight summary.
func (sf *ScopeFile) AllowedTools(tools []string) (allowed []string, denied map[string]string) {
	denied = map[string]string{}
	for _, t := range tools {
		if ok, reason := sf.ToolAllowed(t); ok {
			allowed = append(allowed, t)
		} else {
			denied[t] = reason
		}
	}
	return allowed, denied
}

// AllKnownTools returns every tool MOHAMMED integrates (for pre-flight reports).
func AllKnownTools() []string {
	out := make([]string, 0, len(toolClasses))
	for t := range toolClasses {
		out = append(out, t)
	}
	return out
}
