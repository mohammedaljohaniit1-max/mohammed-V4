package filter

// Zero-False-Positive filtering primitives.
//
// This file implements the scope-enforcement, Cloudflare/analytics parameter
// stripping, static-asset detection and behavioural deduplication that the
// vulnerability phases MUST apply before sending any URL to a scanner
// (sqlmap/dalfox/ghauri/nuclei/ffuf). It is dependency-free (stdlib + the
// project's config package) so it can be unit-tested in isolation.
//
// See MOHAMMED_V4_ZERO_FP_PROMPT FIX #1 and FIX #2.

import (
	"net/url"
	"path"
	"sort"
	"strings"

	"github.com/mohammed-v3/core/pkg/config"
)

// ─────────────────────────────────────────────────────────────────────────
// FIX #1 — Cloudflare / analytics parameter stripper
// ─────────────────────────────────────────────────────────────────────────

// cloudflareParams are bot-protection / challenge tokens that expire in
// seconds. Feeding them to sqlmap produces guaranteed false positives because
// the server returns different bodies for valid-vs-expired tokens.
var cloudflareParams = map[string]bool{
	"__cf_chl_rt_tk": true,
	"__cf_chl_tk":    true,
	"__cf_bm":        true,
	"cf_clearance":   true,
	"__cfruid":       true,
	"__cfl_rc":       true,
	"_cf_chl_opt":    true,
	"__cf_chl_f_tk":  true,
}

// analyticsParams are marketing / tracking noise that carry no injectable
// server-side meaning and only inflate the test surface.
var analyticsParams = map[string]bool{
	"utm_source": true, "utm_medium": true, "utm_campaign": true,
	"utm_content": true, "utm_term": true,
	"fbclid": true, "gclid": true, "msclkid": true, "twclid": true, "dclid": true,
	"_ga": true, "_gl": true, "_hsenc": true, "_hsmi": true, "mc_eid": true,
	"ref": true, "source": true, "medium": true, "campaign": true,
}

// authParams are session/CSRF-style tokens. They are NOT injectable but ARE
// interesting for authentication testing, so StripNoisyParams reports them
// separately instead of feeding them to SQLi/XSS scanners.
var authParams = map[string]bool{
	"token": true, "csrf": true, "nonce": true, "state": true,
	"csrf_token": true, "authenticity_token": true, "_token": true,
}

// IsCloudflareChallenge returns true when the URL carries any Cloudflare
// challenge token in its query string. Such URLs are NEVER passed to any
// vulnerability scanner (FIX #1, zero tolerance).
func IsCloudflareChallenge(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		// Fall back to a substring check on the raw string.
		lc := strings.ToLower(rawURL)
		return strings.Contains(lc, "__cf_chl") || strings.Contains(lc, "cf_chl")
	}
	for key := range u.Query() {
		lk := strings.ToLower(key)
		if strings.Contains(lk, "__cf_chl") || strings.Contains(lk, "cf_chl") {
			return true
		}
	}
	// Some challenge URLs put the token in the path fragment too.
	lc := strings.ToLower(rawURL)
	return strings.Contains(lc, "__cf_chl") || strings.Contains(lc, "cf_chl")
}

// StripResult is the outcome of StripNoisyParams.
type StripResult struct {
	// Cleaned is the URL with all Cloudflare/analytics params removed.
	Cleaned string
	// Testable is true when, after stripping, at least one meaningful
	// (non-auth) query parameter remains — i.e. the URL is worth SQLi/XSS.
	Testable bool
	// AuthParams lists any session/CSRF parameters that survived stripping.
	// These should be routed to auth-testing only, never to SQLi.
	AuthParams []string
	// IsChallenge is true if the ORIGINAL url was a Cloudflare challenge.
	IsChallenge bool
}

// StripNoisyParams removes Cloudflare bot-protection tokens and analytics
// parameters from rawURL. It returns the cleaned URL and a boolean reporting
// whether the URL still has a meaningful, injectable parameter worth testing.
//
// Rules (FIX #1):
//   - A URL that is a Cloudflare challenge is never testable.
//   - After stripping, if no meaningful query parameter remains → not testable.
//   - If the only survivors are auth/CSRF tokens → not testable for SQLi, but
//     the tokens are reported in AuthParams for auth testing.
func StripNoisyParams(rawURL string) (string, bool) {
	res := stripNoisyParams(rawURL)
	return res.Cleaned, res.Testable
}

// StripNoisyParamsDetailed is the richer variant used by phases that need the
// auth-param list and challenge flag.
func StripNoisyParamsDetailed(rawURL string) StripResult {
	return stripNoisyParams(rawURL)
}

func stripNoisyParams(rawURL string) StripResult {
	out := StripResult{Cleaned: rawURL}

	if IsCloudflareChallenge(rawURL) {
		out.IsChallenge = true
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		out.Testable = false
		return out
	}

	q := u.Query()
	meaningful := 0
	for key := range q {
		lk := strings.ToLower(key)
		switch {
		case cloudflareParams[lk] || strings.Contains(lk, "__cf_chl") || strings.Contains(lk, "cf_chl"):
			q.Del(key)
		case analyticsParams[lk]:
			q.Del(key)
		case authParams[lk]:
			out.AuthParams = append(out.AuthParams, key)
			q.Del(key)
		default:
			meaningful++
		}
	}

	u.RawQuery = q.Encode()
	out.Cleaned = u.String()

	// A challenge URL is never testable regardless of surviving params.
	if out.IsChallenge {
		out.Testable = false
		return out
	}
	out.Testable = meaningful > 0
	sort.Strings(out.AuthParams)
	return out
}

// ─────────────────────────────────────────────────────────────────────────
// FIX #2 — Strict scope enforcement
// ─────────────────────────────────────────────────────────────────────────

// HostOf extracts the lowercase hostname from a raw URL (or a bare host).
func HostOf(rawURL string) string {
	raw := strings.TrimSpace(rawURL)
	if raw == "" {
		return ""
	}
	// Bare host (no scheme) — url.Parse would put it in Path, so add a scheme.
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// IsInScope reports whether rawURL's hostname belongs to the target scope.
//
// A host is in scope when it EXACTLY matches a scope domain OR is a subdomain
// of a scope apex domain. Out-of-scope third-party CDNs (squarespace.com,
// cloudfront.net, jquery.com) and unrelated domains are rejected. An explicit
// exclude entry (scope "-host") always wins.
func IsInScope(rawURL string, scope *config.Scope) bool {
	if scope == nil {
		return false
	}
	host := HostOf(rawURL)
	if host == "" {
		return false
	}

	// Explicit exclusions take precedence.
	for _, ex := range scope.ExcludeDomains {
		ex = strings.ToLower(strings.TrimSpace(ex))
		if ex == "" {
			continue
		}
		if host == ex || strings.HasSuffix(host, "."+ex) {
			return false
		}
	}

	// Direct IP scope match.
	for _, ip := range scope.IPs {
		if host == strings.ToLower(strings.TrimSpace(ip)) {
			return true
		}
	}

	for _, d := range scope.Domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
		// Also allow matching against the apex of a scope subdomain entry, so
		// scope {api.whatnot.com} still admits www.whatnot.com is NOT desired —
		// we deliberately do NOT widen scope here. Only exact/subdomain of the
		// listed entry is in-scope.
	}
	return false
}

// FilterInScopeURLs returns only the URLs whose hostname is in scope, plus the
// count of URLs that were removed (for logging).
func FilterInScopeURLs(urls []string, scope *config.Scope) ([]string, int) {
	kept := make([]string, 0, len(urls))
	removed := 0
	for _, u := range urls {
		if IsInScope(u, scope) {
			kept = append(kept, u)
		} else {
			removed++
		}
	}
	return kept, removed
}

// OutOfScopeURLs returns the URLs that are NOT in scope (Genius #5 scope-drift
// logging). These are recorded for the researcher but never tested.
func OutOfScopeURLs(urls []string, scope *config.Scope) []string {
	var out []string
	for _, u := range urls {
		if !IsInScope(u, scope) {
			out = append(out, u)
		}
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────────
// Genius #3 — static-asset detection (skip vuln tests on CDN assets)
// ─────────────────────────────────────────────────────────────────────────

var staticExtensions = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".webp": true,
	".svg": true, ".ico": true, ".bmp": true, ".tiff": true,
	".css": true, ".scss": true, ".less": true,
	".woff": true, ".woff2": true, ".ttf": true, ".eot": true, ".otf": true,
	".mp4": true, ".webm": true, ".mp3": true, ".wav": true, ".ogg": true,
	".pdf": true, ".zip": true, ".gz": true, ".tar": true,
	".map": true,
}

// IsStaticAsset reports whether the URL points at a static asset (image, font,
// stylesheet, media) that is never worth active vulnerability testing.
// Note: .js is intentionally NOT here — JS files are scanned for secrets.
func IsStaticAsset(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	ext := strings.ToLower(path.Ext(u.Path))
	return staticExtensions[ext]
}

// ─────────────────────────────────────────────────────────────────────────
// Genius #2 — behavioural deduplication by response body hash
// ─────────────────────────────────────────────────────────────────────────

// DeduplicateByBehavior collapses URLs that share an identical response body
// hash to a single representative. The caller supplies a hash lookup (usually
// backed by a real HTTP GET); URLs with an empty hash are always kept (we
// could not fingerprint them, so we must not silently drop them).
//
// This can reduce a 1000-URL crawl to a handful of behaviourally-unique
// endpoints before any scanner touches them.
func DeduplicateByBehavior(urls []string, hashOf func(string) string) []string {
	seen := make(map[string]bool)
	out := make([]string, 0, len(urls))
	for _, u := range urls {
		h := hashOf(u)
		if h == "" {
			out = append(out, u)
			continue
		}
		if seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, u)
	}
	return out
}

// DeduplicateByParamSignature collapses URLs that differ only in query VALUES
// but share the same host+path+param-NAMES. Purely offline (no HTTP), it is a
// cheap first pass before behavioural dedup. e.g.
//
//	/p?id=1  and  /p?id=2  →  one representative
func DeduplicateByParamSignature(urls []string) []string {
	seen := make(map[string]bool)
	out := make([]string, 0, len(urls))
	for _, raw := range urls {
		sig := ParamSignature(raw)
		if sig == "" {
			out = append(out, raw)
			continue
		}
		if seen[sig] {
			continue
		}
		seen[sig] = true
		out = append(out, raw)
	}
	return out
}

// ParamSignature returns host+path+sorted-param-names, ignoring values.
func ParamSignature(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	var names []string
	for k := range u.Query() {
		names = append(names, strings.ToLower(k))
	}
	sort.Strings(names)
	return strings.ToLower(u.Host) + u.Path + "?" + strings.Join(names, "&")
}
