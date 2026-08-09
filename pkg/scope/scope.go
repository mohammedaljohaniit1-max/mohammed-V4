// Package scope loads a bug-bounty program's scope + rules and ENFORCES them
// before the scanner runs anything. It exists because the Saudi (and most)
// programs the operator targets EXPLICITLY forbid automated scanning — several
// warn of "legal action" for violations. Running MOHAMMED's aggressive tools on
// such a target is therefore a legal liability, not a feature.
//
// This package is the guard-rail: given a program's ScopeFile, it answers two
// questions deterministically and offline:
//
//  1. InScope(url)      — is this asset actually in scope? (wildcards supported)
//  2. ToolAllowed(tool) — may we run this tool here, per the program's rules?
//
// It NEVER phones home and NEVER guesses; if a rule is not explicitly set, the
// SAFE default is applied (deny aggressive tooling).
package scope

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Automation captures a program's stance on automated tooling. Parsed straight
// from the human-written policy so the operator can encode each program once.
type Automation string

const (
	// AutoForbidden: automated scanning explicitly prohibited (often "legal
	// action"). NO aggressive tool may run. e.g. ejada, Mobily.
	AutoForbidden Automation = "forbidden"
	// AutoReportsRejected: scanning not criminalised, but tool-only reports are
	// rejected. Passive recon OK; aggressive active scanning strongly discouraged.
	AutoReportsRejected Automation = "reports_rejected"
	// AutoRateLimited: automation allowed under a request/second ceiling.
	AutoRateLimited Automation = "rate_limited"
)

// ScopeFile is the on-disk descriptor for one program (JSON). It is authored by
// the operator from the program's published policy — no scraping.
type ScopeFile struct {
	Program     string   `json:"program"`
	Platform    string   `json:"platform"`     // e.g. "bugbounty.sa"
	InScope     []string `json:"in_scope"`     // hosts / wildcard hosts / URL prefixes
	OutOfScope  []string `json:"out_of_scope"` // explicit exclusions (checked first)
	Automation  Automation `json:"automation"`
	MaxRPS      int      `json:"max_rps"`      // 0 = unspecified; only meaningful for rate_limited
	// SensitiveGov marks limited/under-load infra where even a port scan may be
	// banned (operator idea #2). Forces Gentle Mode regardless of Automation.
	SensitiveGov bool     `json:"sensitive_gov"`
	// EmailConvention is the required researcher email/account naming, if any
	// (e.g. "BugBounty_[username]@example.com"). Informational.
	EmailConvention string `json:"email_convention,omitempty"`
	// Notes carries verbatim policy caveats worth surfacing to the operator.
	Notes []string `json:"notes,omitempty"`
}

// Load reads and validates a ScopeFile from disk.
func Load(path string) (*ScopeFile, error) {
	b, err := os.ReadFile(path) //nolint:gosec // operator-provided scope path
	if err != nil {
		return nil, fmt.Errorf("scope: read %s: %w", path, err)
	}
	var sf ScopeFile
	if err := json.Unmarshal(b, &sf); err != nil {
		return nil, fmt.Errorf("scope: parse %s: %w", path, err)
	}
	if err := sf.Validate(); err != nil {
		return nil, err
	}
	return &sf, nil
}

// Validate enforces the invariants that keep the guard-rail safe.
func (sf *ScopeFile) Validate() error {
	if strings.TrimSpace(sf.Program) == "" {
		return fmt.Errorf("scope: program name is required")
	}
	if len(sf.InScope) == 0 {
		return fmt.Errorf("scope: in_scope must list at least one asset")
	}
	switch sf.Automation {
	case AutoForbidden, AutoReportsRejected, AutoRateLimited:
	case "":
		// Unspecified automation is treated as the SAFEST option.
		sf.Automation = AutoForbidden
	default:
		return fmt.Errorf("scope: unknown automation %q", sf.Automation)
	}
	return nil
}
