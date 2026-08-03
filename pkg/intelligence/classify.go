package intelligence

import "strings"

// ClassifyInput holds the observable + caller-supplied signals used to place a
// target into a hardening class (mandate §1.2). We keep the inputs explicit and
// caller-provided so the decision is deterministic and unit-testable rather than
// reaching out to the network from inside the classifier.
type ClassifyInput struct {
	// ResolvedReports is the program's public resolved-report count if known
	// (e.g. from a HackerOne program page the operator pasted in). -1 = unknown.
	ResolvedReports int

	// HasBugBountyProgram is true when a formal paid program exists.
	HasBugBountyProgram bool

	// WAFVendor is the detected WAF/CDN vendor ("" if none detected).
	WAFVendor string

	// RateLimited is true if the target returned 429s under light probing.
	RateLimited bool

	// LegacyStack is true when signals indicate an old stack (PHP 5.x, classic
	// ASP, EOL Java) — a strong ClassD indicator.
	LegacyStack bool

	// KnownUltraHardened lets the operator assert a target is a top-tier program
	// (GitLab/Google/Meta/GitHub/Shopify) when they already know it. This is an
	// explicit operator fact, not a guess.
	KnownUltraHardened bool
}

// Classify computes a TargetClass and its Strategy from the given signals, then
// stores both on the core. It returns the class for convenience.
//
// The ranking is intentionally conservative: when signals are ambiguous we bias
// toward the MORE hardened class, because treating a hard target as soft is the
// mistake that produced the 12-hour zero-result scan (blasting generic nuclei at
// GitLab). Over-estimating hardening merely shifts effort toward manual/business
// -logic testing, which is the safer failure mode.
func (ic *IntelligenceCore) Classify(in ClassifyInput) TargetClass {
	class := decideClass(in)
	strat := strategyFor(class)

	ic.mu.Lock()
	ic.class = class
	ic.strategy = strat
	if v := strings.TrimSpace(in.WAFVendor); v != "" {
		ic.wafPresent = true
		ic.wafVendor = v
		ic.tech.CDNorWAF = v
	}
	ic.mu.Unlock()
	return class
}

func decideClass(in ClassifyInput) TargetClass {
	// Operator-asserted top tier always wins.
	if in.KnownUltraHardened {
		return ClassA
	}

	r := in.ResolvedReports

	// ClassA: very mature program (1000+ resolved) — matches the mandate's
	// "Ultra-Hardened" definition.
	if r >= 1000 {
		return ClassA
	}
	// ClassB: active program, 100-999 resolved reports.
	if r >= 100 {
		return ClassB
	}
	// ClassC: small/new program (<100 resolved) OR a program exists but we have
	// no count.
	if in.HasBugBountyProgram {
		if r >= 0 && r < 100 {
			return ClassC
		}
		// program exists, count unknown -> treat as C (don't assume soft).
		return ClassC
	}

	// No formal program. A legacy stack with no program and no WAF is the
	// classic ClassD (responsible-disclosure legacy box).
	if in.LegacyStack && strings.TrimSpace(in.WAFVendor) == "" {
		return ClassD
	}

	// No program but modern/hardened signals (WAF present or rate limiting)
	// -> treat as C, not D. Absence of a program does not mean it's soft.
	if strings.TrimSpace(in.WAFVendor) != "" || in.RateLimited {
		return ClassC
	}

	// Truly unknown with no hardening signals and no program -> D.
	return ClassD
}

// strategyFor returns the fixed strategy profile for a class (mandate §1.2).
func strategyFor(c TargetClass) Strategy {
	switch c {
	case ClassA:
		return Strategy{
			ManualPercent:      70,
			AutomationPercent:  30,
			RunGenericNuclei:   false, // filtered/patched — pure noise on ClassA
			RunAutomatedXSS:    false,
			FocusBusinessLogic: true,
			Description: "Ultra-hardened. Abandon generic nuclei/XSS/SQLi (all patched or WAF-filtered). " +
				"Invest in business logic, authorization matrices, and multi-step chains.",
		}
	case ClassB:
		return Strategy{
			ManualPercent:      40,
			AutomationPercent:  60,
			RunGenericNuclei:   true,
			RunAutomatedXSS:    true,
			FocusBusinessLogic: true,
			Description: "Well-hardened. Mix automated API/auth testing with manual business-logic " +
				"and multi-step chain analysis.",
		}
	case ClassC:
		return Strategy{
			ManualPercent:      40,
			AutomationPercent:  60,
			RunGenericNuclei:   true,
			RunAutomatedXSS:    true,
			FocusBusinessLogic: false,
			Description: "Partially secured. Systematic automated scanning is effective; look for " +
				"missing auth, mass assignment, predictable-ID IDOR, weak JWT.",
		}
	case ClassD:
		return Strategy{
			ManualPercent:      10,
			AutomationPercent:  90,
			RunGenericNuclei:   true,
			RunAutomatedXSS:    true,
			FocusBusinessLogic: false,
			Description: "Unprotected/legacy. Full automated scanning + known-CVE checks against " +
				"identified versions; classic vuln classes likely present.",
		}
	default:
		return Strategy{
			ManualPercent:      50,
			AutomationPercent:  50,
			RunGenericNuclei:   false,
			RunAutomatedXSS:    false,
			FocusBusinessLogic: true,
			Description: "Unclassified. Default to conservative (manual-leaning) strategy until " +
				"classification signals are available.",
		}
	}
}
