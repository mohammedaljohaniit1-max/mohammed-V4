// Package reporting implements the V13 pre-report suppression layer
// (mandate §6.1: the "rejection-suppression list").
//
// PROBLEM THIS SOLVES
//
// Hardened bug-bounty programs — GitLab, GitHub, Shopify, and most mature
// HackerOne programs — auto-close or reject a well-known set of low/no-impact
// report classes ("missing security headers", "self-XSS", "clickjacking on a
// page with no sensitive action", "verbose version banners", "no rate limit on
// login", …). Submitting these damages the researcher's signal/reputation and
// wastes triage time. A scanner that "found 40 issues" that are all in this
// bucket has, for practical purposes, found nothing — which is exactly the
// 12-hour / zero-reportable-vuln outcome the V13 mandate exists to fix.
//
// DESIGN
//
//   - This layer is PURELY a filter over findings. It never invents findings and
//     never raises confidence. It can only SUPPRESS a finding, with a recorded,
//     auditable reason and a policy citation.
//   - It is deliberately CONSERVATIVE: a rule only fires when the finding clearly
//     matches a known-rejected class. When in doubt it keeps the finding (a human
//     can still triage it) — because silently dropping a real bug is worse than
//     keeping a borderline one.
//   - Findings are the same map[string]interface{} shape the rest of the report
//     pipeline already uses, so this drops in with a single call before report
//     generation. No existing behaviour is modified by importing this package.
//
// This file has NO external dependencies and is fully unit-tested offline.
package reporting

import (
	"fmt"
	"regexp"
	"strings"
)

// Finding is the loose finding shape shared across the report pipeline.
type Finding = map[string]interface{}

// SuppressionRule is one auditable "this will be rejected" rule.
type SuppressionRule struct {
	// ID is a stable identifier, e.g. "SUP-MISSING-HEADERS".
	ID string
	// Reason is the human explanation shown in the suppression log.
	Reason string
	// Policy is the citation (which programs reject this and why).
	Policy string
	// match returns true when the rule applies to a finding.
	match func(f Finding) bool
}

// Decision is the outcome for one finding.
type Decision struct {
	Finding    Finding
	Suppressed bool
	RuleID     string // empty when kept
	Reason     string // empty when kept
	Policy     string // empty when kept
}

// Result is the outcome of filtering a batch of findings.
type Result struct {
	Kept       []Finding
	Suppressed []Decision // only the suppressed ones (with reasons)
	Decisions  []Decision // every finding, in input order
}

// KeptCount / SuppressedCount are convenience counters.
func (r Result) KeptCount() int       { return len(r.Kept) }
func (r Result) SuppressedCount() int { return len(r.Suppressed) }

// --- field helpers (defensive against the loose map shape) ---

func str(f Finding, key string) string {
	if f == nil {
		return ""
	}
	if v, ok := f[key]; ok {
		return strings.TrimSpace(fmt.Sprintf("%v", v))
	}
	return ""
}

func lower(f Finding, key string) string { return strings.ToLower(str(f, key)) }

func confidence(f Finding) int {
	switch v := f["confidence"].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	}
	return 0
}

func severity(f Finding) string {
	return strings.ToLower(strings.TrimSpace(str(f, "severity")))
}

// text concatenates the human-readable fields we match against.
func text(f Finding) string {
	return strings.ToLower(strings.Join([]string{
		str(f, "title"), str(f, "name"), str(f, "type"),
		str(f, "template"), str(f, "template_id"), str(f, "tool"),
		str(f, "evidence"), str(f, "description"),
	}, " \n "))
}

// --- pre-compiled matchers (never compile in the hot path) ---

var (
	reMissingHeaders = regexp.MustCompile(`(?i)\b(missing|absent|no)\b.{0,40}\b(security header|x-frame-options|content-security-policy|csp|hsts|strict-transport-security|x-content-type-options|x-xss-protection|referrer-policy|permissions-policy)\b`)
	reHeaderName     = regexp.MustCompile(`(?i)\b(x-frame-options|content-security-policy|strict-transport-security|x-content-type-options|referrer-policy|permissions-policy)\b`)

	reClickjacking = regexp.MustCompile(`(?i)clickjack|x-frame-options.*(missing|not set)|ui[- ]?redress`)
	reSelfXSS      = regexp.MustCompile(`(?i)self[- ]?xss|requires user to paste|paste.{0,20}console`)
	reVerboseBanner = regexp.MustCompile(`(?i)(version|banner|fingerprint) (disclosure|leak)|server version|software version disclosed|x-powered-by header`)
	reNoRateLimit   = regexp.MustCompile(`(?i)(no|missing|lack of) rate[- ]?limit|rate[- ]?limit(ing)? (not|missing)|brute[- ]?force possible`)
	reCookieFlags   = regexp.MustCompile(`(?i)cookie.{0,20}(without|missing) (secure|httponly|samesite)|(secure|httponly|samesite) (flag|attribute) (missing|not set)`)
	reAutocomplete  = regexp.MustCompile(`(?i)autocomplete (enabled|on)|password field autocomplete`)
	reTLSWeak       = regexp.MustCompile(`(?i)(tls 1\.0|tls 1\.1|sslv3|weak cipher|deprecated tls)`)
	reOptions       = regexp.MustCompile(`(?i)(http )?options method (enabled|allowed)|allow header discloses`)
	reEmailNoSPF    = regexp.MustCompile(`(?i)(missing|no) (spf|dmarc|dkim) record`)
	reOpenPortInfo  = regexp.MustCompile(`(?i)open port|port scan|service detected on port`)
	reDirListing    = regexp.MustCompile(`(?i)directory listing`)
	reSoftInfo      = regexp.MustCompile(`(?i)\b(informational|info)\b`)
)

// DefaultRules is the curated GitLab/HackerOne "known-rejected" rule set
// (mandate §6.1). Each rule matches a class of report that mature programs
// auto-close as out-of-scope / not-a-vulnerability.
//
// Every rule is GATED so it only suppresses LOW-IMPACT instances: a rule fires
// only when severity is low/info/none/medium — it will NOT suppress a finding
// that some upstream stage rated high/critical, because that combination is a
// signal the finding is more than the generic banner-noise the rule targets.
func DefaultRules() []SuppressionRule {
	lowImpact := func(f Finding) bool {
		switch severity(f) {
		case "critical", "high":
			return false // never suppress high/critical, even if wording matches
		}
		return true
	}
	rule := func(id, reason, policy string, m func(Finding) bool) SuppressionRule {
		return SuppressionRule{ID: id, Reason: reason, Policy: policy, match: func(f Finding) bool {
			return lowImpact(f) && m(f)
		}}
	}

	return []SuppressionRule{
		// NOTE: order matters — more SPECIFIC rules come first so that, e.g., a
		// clickjacking/X-Frame-Options finding is attributed to the clickjacking
		// rule rather than the generic missing-header rule.
		rule("SUP-CLICKJACKING-NO-ACTION",
			"Clickjacking / missing X-Frame-Options without a sensitive state-changing action.",
			"Clickjacking on pages with no sensitive action is explicitly out-of-scope on GitLab & many programs.",
			func(f Finding) bool { return reClickjacking.MatchString(text(f)) }),

		rule("SUP-MISSING-HEADERS",
			"Missing/optional security header with no demonstrated impact.",
			"GitLab & most H1 programs auto-close 'missing security header' reports lacking a working exploit.",
			func(f Finding) bool {
				t := text(f)
				return reMissingHeaders.MatchString(t) ||
					(reHeaderName.MatchString(t) && (strings.Contains(t, "missing") || strings.Contains(t, "not set")))
			}),

		rule("SUP-SELF-XSS",
			"Self-XSS requiring the victim to paste attacker-supplied input.",
			"Self-XSS is universally rejected; it requires social-engineering the victim into the console.",
			func(f Finding) bool { return reSelfXSS.MatchString(text(f)) }),

		rule("SUP-VERSION-BANNER",
			"Software version / banner disclosure with no linked exploitable CVE.",
			"Version disclosure alone (Server / X-Powered-By banners) is informational and auto-closed.",
			func(f Finding) bool { return reVerboseBanner.MatchString(text(f)) }),

		rule("SUP-NO-RATE-LIMIT",
			"Missing rate limiting / theoretical brute-force without demonstrated account takeover.",
			"'No rate limit' reports without a working ATO/DoS impact are out-of-scope on GitLab & similar.",
			func(f Finding) bool { return reNoRateLimit.MatchString(text(f)) }),

		rule("SUP-COOKIE-FLAGS",
			"Missing cookie Secure/HttpOnly/SameSite flag with no demonstrated session impact.",
			"Cookie-flag findings without a session-hijack chain are treated as best-practice, not a vuln.",
			func(f Finding) bool { return reCookieFlags.MatchString(text(f)) }),

		rule("SUP-AUTOCOMPLETE",
			"Password-field autocomplete enabled.",
			"Autocomplete-on-password is explicitly listed as a non-issue by GitLab and most programs.",
			func(f Finding) bool { return reAutocomplete.MatchString(text(f)) }),

		rule("SUP-WEAK-TLS-CONFIG",
			"Weak/deprecated TLS version or cipher advertised, with no demonstrated MITM.",
			"TLS best-practice config findings without a working downgrade/MITM are informational.",
			func(f Finding) bool { return reTLSWeak.MatchString(text(f)) }),

		rule("SUP-OPTIONS-METHOD",
			"HTTP OPTIONS method enabled / Allow header enumeration.",
			"Enabled OPTIONS and Allow-header enumeration are non-issues absent a concrete exploit.",
			func(f Finding) bool { return reOptions.MatchString(text(f)) }),

		rule("SUP-EMAIL-DNS-BESTPRACTICE",
			"Missing SPF/DKIM/DMARC on a non-email-sending / out-of-scope host.",
			"Generic 'missing SPF/DMARC' is only accepted with a working spoof PoC on an in-scope sender.",
			func(f Finding) bool {
				// Only suppress when it's low-impact AND there is no spoof PoC evidence.
				t := text(f)
				return reEmailNoSPF.MatchString(t) && !strings.Contains(t, "spoof") && !strings.Contains(t, "poc")
			}),

		rule("SUP-PORT-INFO",
			"Open-port / service enumeration with no exploitable service.",
			"Port-scan output alone is reconnaissance, not a reportable vulnerability.",
			func(f Finding) bool { return reOpenPortInfo.MatchString(text(f)) }),

		rule("SUP-DIR-LISTING-NO-SECRET",
			"Directory listing enabled but exposing no sensitive/secret content.",
			"Directory listing is only accepted when it exposes sensitive data; empty/static listings are closed.",
			func(f Finding) bool {
				t := text(f)
				return reDirListing.MatchString(t) &&
					!strings.Contains(t, "secret") && !strings.Contains(t, "credential") &&
					!strings.Contains(t, "backup") && !strings.Contains(t, ".env")
			}),

		rule("SUP-LOW-CONF-INFO",
			"Informational-severity finding with confidence below the reporting floor.",
			"Sub-threshold informational findings are noise for a hardened-program submission.",
			func(f Finding) bool {
				return reSoftInfo.MatchString(severity(f)) && confidence(f) < 40
			}),
	}
}

// Suppressor applies a set of rules to findings.
type Suppressor struct {
	rules []SuppressionRule
}

// New returns a Suppressor with the given rules. Pass DefaultRules() for the
// curated GitLab/HackerOne set.
func New(rules []SuppressionRule) *Suppressor {
	return &Suppressor{rules: rules}
}

// NewDefault returns a Suppressor loaded with DefaultRules().
func NewDefault() *Suppressor { return New(DefaultRules()) }

// Rules exposes the configured rules (read-only use).
func (s *Suppressor) Rules() []SuppressionRule { return s.rules }

// Apply partitions findings into kept vs suppressed. The FIRST matching rule
// wins for a given finding (rules are checked in order). A nil/empty finding is
// kept (never crash the pipeline on malformed input).
func (s *Suppressor) Apply(findings []Finding) Result {
	var res Result
	for _, f := range findings {
		d := Decision{Finding: f}
		if f != nil {
			for _, r := range s.rules {
				if r.match != nil && r.match(f) {
					d.Suppressed = true
					d.RuleID = r.ID
					d.Reason = r.Reason
					d.Policy = r.Policy
					break
				}
			}
		}
		res.Decisions = append(res.Decisions, d)
		if d.Suppressed {
			res.Suppressed = append(res.Suppressed, d)
		} else {
			res.Kept = append(res.Kept, f)
		}
	}
	return res
}

// SuppressionLog renders a human-readable audit of what was dropped and why.
// This is written alongside the report so a reviewer can see EXACTLY what the
// tool chose not to submit — suppression is never silent.
func (r Result) SuppressionLog() string {
	var b strings.Builder
	b.WriteString("# MOHAMMED V13 — Suppressed Findings (GitLab/HackerOne known-rejected classes)\n")
	fmt.Fprintf(&b, "# Kept: %d   Suppressed: %d\n\n", r.KeptCount(), r.SuppressedCount())
	if len(r.Suppressed) == 0 {
		b.WriteString("(nothing suppressed — no findings matched a known-rejected class)\n")
		return b.String()
	}
	for i, d := range r.Suppressed {
		title := str(d.Finding, "title")
		if title == "" {
			title = str(d.Finding, "name")
		}
		fmt.Fprintf(&b, "%d. [%s] %s\n", i+1, d.RuleID, title)
		fmt.Fprintf(&b, "   severity : %s\n", str(d.Finding, "severity"))
		fmt.Fprintf(&b, "   url      : %s\n", str(d.Finding, "url"))
		fmt.Fprintf(&b, "   reason   : %s\n", d.Reason)
		fmt.Fprintf(&b, "   policy   : %s\n\n", d.Policy)
	}
	return b.String()
}
