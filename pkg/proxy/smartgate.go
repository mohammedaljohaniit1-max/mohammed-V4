package proxy

// ═══════════════════════════════════════════════════════════════════════════
// V12.2 §2.6 — Burp SMART PROXY GATE
// ---------------------------------------------------------------------------
// The 8-hour crash flooded Burp with tens of thousands of low-value requests
// (static assets, 404s, CDN error pages, out-of-scope hosts), which is both
// useless and a big contributor to the request storm. The smart gate forwards
// to Burp ONLY high-value traffic and DROPS the noise:
//
//   FORWARD (high value):
//     • URLs carrying query params (?a=1) or fragments that imply logic
//     • API-looking paths (/api/, /v1/, /graphql, .json)
//     • auth / admin / upload endpoints (login, oauth, admin, upload, ...)
//     • non-404 responses (when a status is known)
//     • crawl-sourced URLs (discovered by the spider, not brute-forced noise)
//
//   DROP (noise):
//     • static assets (.js/.css/.png/.woff/.map/… with no params)
//     • 404 / CDN error responses
//     • out-of-scope hosts (never send another program's traffic to Burp)
//
// The gate is rate-limited to 10 req/s, keeps a proxied/filtered counter that
// the engine logs ("Burp: X proxied, Y filtered"), and can export the set of
// forwarded targets to burp_scope.json for import into Burp's scope.
// ═══════════════════════════════════════════════════════════════════════════

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// SmartGateDecision is the outcome of evaluating one candidate request.
type SmartGateDecision struct {
	Forward bool
	Reason  string
}

// GateCandidate describes one request the gate must decide on. Status<=0 means
// "unknown" (the request has not been made yet); Source is where the URL came
// from ("crawl", "wayback", "fuzz", ...); InScope must be pre-computed by the
// caller against the active scope+excludes.
type GateCandidate struct {
	URL     string
	Status  int
	Source  string
	InScope bool
}

// staticAssetExts are extensions we consider low-value static assets.
var staticAssetExts = map[string]bool{
	".js": true, ".css": true, ".png": true, ".jpg": true, ".jpeg": true,
	".gif": true, ".svg": true, ".ico": true, ".woff": true, ".woff2": true,
	".ttf": true, ".eot": true, ".map": true, ".webp": true, ".mp4": true,
	".webm": true, ".avif": true, ".bmp": true, ".pdf": true,
}

// highValuePathMarkers imply security-relevant logic worth proxying.
var highValuePathMarkers = []string{
	"/api", "/api/", "/v1", "/v2", "/v3", "/graphql", "/rest/", "/rpc",
	"login", "logout", "signin", "signup", "register", "auth", "oauth",
	"sso", "saml", "token", "session", "admin", "dashboard", "account",
	"upload", "import", "export", "download", "file", "password", "reset",
	"user", "users", "profile", "settings", "config", "debug", "internal",
	"payment", "billing", "invoice", "webhook", "callback", "redirect",
}

// EvaluateBurpForward implements the §2.6 forward/drop decision. It is pure
// (no I/O, no locking) so it is trivially testable.
func EvaluateBurpForward(c GateCandidate) SmartGateDecision {
	// 1) Never proxy out-of-scope hosts (FAILURE #6 crossover).
	if !c.InScope {
		return SmartGateDecision{false, "out-of-scope"}
	}

	u, err := url.Parse(c.URL)
	if err != nil || u.Host == "" {
		return SmartGateDecision{false, "unparseable-url"}
	}

	// 2) Drop known error / 404 responses (CDN error pages, missing routes).
	if c.Status == 404 || (c.Status >= 500 && c.Status <= 599 && c.Status != 500) {
		return SmartGateDecision{false, "error-status"}
	}

	path := strings.ToLower(u.Path)
	ext := strings.ToLower(filepath.Ext(path))
	hasParams := u.RawQuery != ""

	// 3) High-value path markers (API/auth/admin/upload/etc.) → forward.
	for _, m := range highValuePathMarkers {
		if strings.Contains(path, m) {
			return SmartGateDecision{true, "high-value-path"}
		}
	}

	// 4) JSON / API-ish content → forward.
	if ext == ".json" {
		return SmartGateDecision{true, "json-endpoint"}
	}

	// 5) Query params or fragment logic → forward (even on an asset path,
	//    a parameterized request is worth testing).
	if hasParams {
		return SmartGateDecision{true, "has-params"}
	}

	// 6) Static assets with no params → drop.
	if staticAssetExts[ext] {
		return SmartGateDecision{false, "static-asset"}
	}

	// 7) Crawl-sourced dynamic URLs (no extension, discovered by spider) →
	//    forward: these are real application routes.
	if c.Source == "crawl" && ext == "" {
		return SmartGateDecision{true, "crawl-sourced-route"}
	}

	// 8) A concrete non-404 status on a dynamic path → forward.
	if c.Status > 0 && c.Status != 404 && ext == "" {
		return SmartGateDecision{true, "live-dynamic"}
	}

	// Default: not obviously high value → drop to keep Burp quiet.
	return SmartGateDecision{false, "low-value-default"}
}

// SmartGate is a stateful wrapper around EvaluateBurpForward that adds a
// 10 req/s rate limit, proxied/filtered counters, and a de-duplicated set of
// forwarded targets for burp_scope.json export. Safe for concurrent use.
type SmartGate struct {
	mu        sync.Mutex
	proxied   int
	filtered  int
	forwarded map[string]bool

	// rate limiting: token-bucket-ish minimum interval between forwards.
	rate    int // requests/second (0 = unlimited)
	lastFwd time.Time
	nowFn   func() time.Time // injectable clock for tests
	sleepFn func(time.Duration)
}

// NewSmartGate creates a gate limited to ratePerSec forwarded requests/second.
// A ratePerSec <= 0 disables rate limiting.
func NewSmartGate(ratePerSec int) *SmartGate {
	return &SmartGate{
		forwarded: make(map[string]bool),
		rate:      ratePerSec,
		nowFn:     time.Now,
		sleepFn:   time.Sleep,
	}
}

// Allow evaluates a candidate, updates counters, applies the rate limit for
// forwarded requests, and records the target for scope export. It returns the
// decision so callers can log per-request reasons in debug mode.
func (g *SmartGate) Allow(c GateCandidate) SmartGateDecision {
	d := EvaluateBurpForward(c)

	g.mu.Lock()
	if !d.Forward {
		g.filtered++
		g.mu.Unlock()
		return d
	}
	g.proxied++
	if norm := normalizeTarget(c.URL); norm != "" {
		g.forwarded[norm] = true
	}
	// Compute how long we must sleep to honor the rate limit, while holding
	// the lock so concurrent Allow calls serialize their forwards.
	var wait time.Duration
	if g.rate > 0 {
		minGap := time.Second / time.Duration(g.rate)
		now := g.nowFn()
		if !g.lastFwd.IsZero() {
			if gap := now.Sub(g.lastFwd); gap < minGap {
				wait = minGap - gap
			}
		}
		g.lastFwd = now.Add(wait)
	}
	g.mu.Unlock()

	if wait > 0 {
		g.sleepFn(wait)
	}
	return d
}

// Counts returns (proxied, filtered).
func (g *SmartGate) Counts() (proxied, filtered int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.proxied, g.filtered
}

// CounterLine returns the mandated summary line: "Burp: X proxied, Y filtered".
func (g *SmartGate) CounterLine() string {
	p, f := g.Counts()
	return "Burp: " + itoaGate(p) + " proxied, " + itoaGate(f) + " filtered"
}

// ForwardedTargets returns the sorted, de-duplicated set of scheme://host that
// the gate forwarded — the basis for burp_scope.json.
func (g *SmartGate) ForwardedTargets() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]string, 0, len(g.forwarded))
	for t := range g.forwarded {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// burpScopeFile is the on-disk shape of burp_scope.json (a Burp-importable-ish
// include list). Kept intentionally simple and stable.
type burpScopeFile struct {
	Version  string   `json:"version"`
	Proxied  int      `json:"proxied"`
	Filtered int      `json:"filtered"`
	Targets  []string `json:"targets"`
}

// ExportScope writes burp_scope.json into dir with the forwarded targets.
func (g *SmartGate) ExportScope(dir string) (string, error) {
	p, f := g.Counts()
	payload := burpScopeFile{
		Version:  "V12.2",
		Proxied:  p,
		Filtered: f,
		Targets:  g.ForwardedTargets(),
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "burp_scope.json")
	if err := os.WriteFile(path, data, 0644); err != nil {
		return "", err
	}
	return path, nil
}

// normalizeTarget reduces a URL to scheme://host for scope grouping.
func normalizeTarget(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	scheme := u.Scheme
	if scheme == "" {
		scheme = "https"
	}
	return scheme + "://" + u.Host
}

// itoaGate is a tiny dependency-free int→string (avoids importing strconv into
// hot logging paths and dodges any package-local itoa name collisions).
func itoaGate(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
