package phases

// Zero-false-positive helpers shared across the vulnerability phases.
//
// These implement:
//   FIX #4 — ValidateSensitiveFile (HTTP 200 != real file)
//   FIX #6 — WAF detection + SQLi candidate preparation (CF strip, cap, order)
//   Genius #1 — anti-honeypot detection
//
// All HTTP here goes through a short-lived stdlib client (optionally via the
// Burp proxy) so behaviour can be validated without shelling out.

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/mohammed-v3/core/pkg/config"
	"github.com/mohammed-v3/core/pkg/filter"
	"github.com/mohammed-v3/core/pkg/proxy"
)

// wafFingerprints are body/response markers that prove a Cloudflare/WAF block
// page rather than a real application response (FIX #4/#6).
var wafFingerprints = []string{
	"sorry, you have been blocked",
	"attention required",
	"ray id",
	"cloudflare",
	"access denied",
	"cf-ray",
	"cf-mitigated",
	"just a moment",
	"checking your browser",
	"__cf_chl",
}

// httpClientFor builds a short-timeout HTTP client that routes through Burp
// when the (already tier-resolved) proxy manager is active. TLS verification
// is skipped because self-signed / intercepting proxies are expected.
func httpClientFor(px *proxy.ProxyManager, timeout time.Duration) *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // scanner probes
	}
	if px != nil && px.Active && px.ProxyURL != "" {
		if pu, err := url.Parse(px.ProxyURL); err == nil {
			tr.Proxy = http.ProxyURL(pu)
		}
	}
	return &http.Client{Timeout: timeout, Transport: tr}
}

// fetch performs a GET and returns (status, body, headerBlob). Errors yield
// (0, "", "").
func fetch(ctx context.Context, client *http.Client, rawURL string) (int, string, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, "", ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (MOHAMMED-v4 validator)")
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	var hb strings.Builder
	for k, vs := range resp.Header {
		hb.WriteString(k + ": " + strings.Join(vs, ",") + "\n")
	}
	return resp.StatusCode, string(body), hb.String()
}

// bodyHasWAF reports whether a response body/headers contain a WAF/CF block
// fingerprint.
func bodyHasWAF(body, headers string) bool {
	lc := strings.ToLower(body + "\n" + headers)
	for _, fp := range wafFingerprints {
		if strings.Contains(lc, fp) {
			return true
		}
	}
	return false
}

// ─────────────────────────────────────────────────────────────────────────
// FIX #6 — WAF detection before SQLi
// ─────────────────────────────────────────────────────────────────────────

// DetectWAF sends a harmless probe (adds test=1) and reports whether the
// endpoint is behind a WAF that would make SQLi results untrustworthy.
func DetectWAF(ctx context.Context, px *proxy.ProxyManager, rawURL string) bool {
	client := httpClientFor(px, 12*time.Second)
	probe := rawURL
	if strings.Contains(probe, "?") {
		probe += "&mohammed_waf_probe=1"
	} else {
		probe += "?mohammed_waf_probe=1"
	}
	status, body, headers := fetch(ctx, client, probe)
	if status == 403 && strings.Contains(strings.ToLower(body+headers), "cloudflare") {
		return true
	}
	return bodyHasWAF(body, headers)
}

// sqliParamPriority ranks parameter names most likely to be injectable first.
var sqliParamPriority = []string{
	"id", "user_id", "product_id", "order", "search", "query",
	"filter", "cat", "category", "page", "file", "path",
}

func paramRank(name string) int {
	name = strings.ToLower(name)
	for i, p := range sqliParamPriority {
		if name == p {
			return i
		}
	}
	return len(sqliParamPriority) + 1
}

// bestParamRank returns the priority of the highest-priority parameter in a URL.
func bestParamRank(rawURL string) int {
	u, err := url.Parse(rawURL)
	if err != nil {
		return 999
	}
	best := 999
	for k := range u.Query() {
		if r := paramRank(k); r < best {
			best = r
		}
	}
	return best
}

// SQLiCandidate is a cleaned, testable URL plus its priority.
type SQLiCandidate struct {
	URL  string
	Rank int
}

// PrepareSQLiURLs is the candidate builder for the SQLi phase. It:
//  1. strips Cloudflare/analytics params and drops CF-challenge URLs (FIX #1)
//  2. drops URLs with no meaningful injectable parameter (FIX #6 step 2)
//  3. keeps only in-scope hosts (FIX #2)
//  4. de-dupes by param signature (Genius #2 cheap pass)
//  5. orders by parameter priority and caps the count (FIX #6 step 3)
func PrepareSQLiURLs(rawURLs []string, scope *config.Scope, maxN int) []string {
	seenSig := map[string]bool{}
	var cands []SQLiCandidate
	for _, raw := range rawURLs {
		if filter.IsCloudflareChallenge(raw) {
			continue
		}
		cleaned, testable := filter.StripNoisyParams(raw)
		if !testable {
			continue
		}
		if scope != nil && !filter.IsInScope(cleaned, scope) {
			continue
		}
		sig := filter.ParamSignature(cleaned)
		if sig != "" && seenSig[sig] {
			continue
		}
		seenSig[sig] = true
		cands = append(cands, SQLiCandidate{URL: cleaned, Rank: bestParamRank(cleaned)})
	}
	sort.SliceStable(cands, func(i, j int) bool { return cands[i].Rank < cands[j].Rank })
	out := make([]string, 0, maxN)
	for _, c := range cands {
		if len(out) >= maxN {
			break
		}
		out = append(out, c.URL)
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────────
// FIX #4 — sensitive file validator (HTTP 200 != real file)
// ─────────────────────────────────────────────────────────────────────────

// ValidateSensitiveFile fetches the URL and confirms the response is a REAL
// exposed file, not a Cloudflare/WAF error page that merely returned 200.
// Returns (valid, reason). A false result means the "finding" is a FP.
func ValidateSensitiveFile(ctx context.Context, px *proxy.ProxyManager, rawURL string) (bool, string) {
	client := httpClientFor(px, 12*time.Second)
	status, body, headers := fetch(ctx, client, rawURL)

	if status == 0 {
		return false, "no response"
	}
	if status != 200 {
		return false, "status " + itoa(status)
	}
	if len(strings.TrimSpace(body)) < 100 {
		return false, "body < 100 bytes (too small for a real file)"
	}
	if bodyHasWAF(body, headers) {
		return false, "Cloudflare/WAF block page (not a real file)"
	}

	// File-type-specific content assertions.
	lc := strings.ToLower(rawURL)
	lbody := strings.ToLower(body)
	switch {
	case strings.Contains(lc, ".svn/entries"):
		if !strings.Contains(lbody, "svn:") && !strings.Contains(body, "dir\n") {
			return false, ".svn/entries lacks svn markers"
		}
	case strings.Contains(lc, ".git/config"):
		if !strings.Contains(lbody, "[core]") {
			return false, ".git/config lacks [core] section"
		}
	case strings.Contains(lc, ".ds_store"):
		// Real .DS_Store starts with the Aled magic bytes 00 00 00 01.
		if !strings.HasPrefix(body, "\x00\x00\x00\x01") {
			return false, ".DS_Store lacks 00 00 00 01 magic"
		}
	case strings.Contains(lc, ".env"):
		if !strings.Contains(body, "=") {
			return false, ".env has no KEY=VALUE lines"
		}
	case strings.Contains(lc, "swagger") || strings.Contains(lc, "openapi"):
		if !strings.Contains(lbody, "swagger") && !strings.Contains(lbody, "openapi") {
			return false, "swagger/openapi body missing swagger/openapi key"
		}
	}
	return true, "validated: 200 + real content, no WAF fingerprint"
}

// ─────────────────────────────────────────────────────────────────────────
// Genius #1 — anti-honeypot / non-reflective endpoint detection
// ─────────────────────────────────────────────────────────────────────────

// IsHoneypotOrSink sends three probes (baseline / gibberish / SQL keyword) and
// reports true when all three bodies are byte-identical — meaning the endpoint
// does not reflect input and is not worth injection testing.
func IsHoneypotOrSink(ctx context.Context, px *proxy.ProxyManager, rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	q := u.Query()
	var pname string
	for k := range q {
		pname = k
		break
	}
	if pname == "" {
		return false
	}
	client := httpClientFor(px, 12*time.Second)

	mk := func(val string) string {
		q2 := u.Query()
		q2.Set(pname, val)
		u2 := *u
		u2.RawQuery = q2.Encode()
		return u2.String()
	}
	_, b1, _ := fetch(ctx, client, rawURL)
	_, b2, _ := fetch(ctx, client, mk("AAAAAAAAAAAA"))
	_, b3, _ := fetch(ctx, client, mk("1' OR '1'='1"))
	if b1 == "" && b2 == "" && b3 == "" {
		return false
	}
	h1 := filter.HashBodyString(b1)
	h2 := filter.HashBodyString(b2)
	h3 := filter.HashBodyString(b3)
	return h1 == h2 && h2 == h3
}

// itoa is a tiny int→string without importing strconv here.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
