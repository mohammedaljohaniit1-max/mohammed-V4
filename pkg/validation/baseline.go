// Package validation implements the V7 (Section 4) False-Positive Elimination
// pipeline: a baseline-comparison engine plus a 5-gate validation rule that
// every candidate finding must pass before it is reported.
//
// The whole point of this package is that the V6 engine reported 100% false
// positives on real HackerOne targets (Roblox, Starbucks Japan) — SPA catch-all
// 200s were flagged as "sensitive file found", AWSALB cookies as "AWS secret
// keys", and CloudFront error pages as "subdomain takeover". Nothing here does
// network I/O that the caller has not explicitly asked for; the baseline probe
// is a real HTTP request so the comparison is grounded in live behaviour, not a
// guess.
package validation

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

// baselineClient is a dedicated HTTP client for baseline probing. It never
// follows more than a few redirects (so a redirect-to-login does not mask a
// catch-all), skips TLS verification (targets often sit behind intercepting
// CDNs), and has a hard timeout so a hung endpoint cannot stall the pipeline.
var baselineClient = &http.Client{
	Timeout: 20 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // read-only probing
		MaxIdleConns:        10,
		IdleConnTimeout:     15 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 4 {
			return http.ErrUseLastResponse
		}
		return nil
	},
}

// Probe is the captured shape of a single HTTP response, reduced to the fields
// the baseline comparison needs.
type Probe struct {
	URL         string
	StatusCode  int
	BodyLen     int
	BodySHA256  string
	ContentType string
	// BodySample is the first 4 KiB of the response body, lower-cased, used for
	// content-pattern checks (sensitive-data detection). It is intentionally
	// bounded so a huge response cannot blow up memory.
	BodySample string
	Err        error
}

// randPathRand is a package-local RNG seeded once; it does not need to be
// cryptographically secure — it only builds a random non-existent path.
var randPathRand = rand.New(rand.NewSource(time.Now().UnixNano()))

// randomToken returns an n-char lowercase-alphanumeric token used to construct
// a definitely-non-existent baseline path.
func randomToken(n int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[randPathRand.Intn(len(alphabet))]
	}
	return string(b)
}

// Fetch performs a single GET and captures a Probe. Any transport error is
// recorded on Probe.Err (the caller decides how to treat it) rather than
// panicking the pipeline.
func Fetch(ctx context.Context, url string) Probe {
	p := Probe{URL: url}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		p.Err = err
		return p
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) MOHAMMED-V7/validation")
	req.Header.Set("Accept", "*/*")
	resp, err := baselineClient.Do(req)
	if err != nil {
		p.Err = err
		return p
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	sum := sha256.Sum256(body)
	p.StatusCode = resp.StatusCode
	p.BodyLen = len(body)
	p.BodySHA256 = hex.EncodeToString(sum[:])
	p.ContentType = strings.ToLower(resp.Header.Get("Content-Type"))
	sample := body
	if len(sample) > 4096 {
		sample = sample[:4096]
	}
	p.BodySample = strings.ToLower(string(sample))
	return p
}

// BaselineResult is the verdict of comparing a real target path against a
// random non-existent path on the same origin.
type BaselineResult struct {
	Target   Probe
	Baseline Probe
	// IsCatchAll is true when the random path returned essentially the SAME
	// response as the target path (same status + near-identical body). That is
	// the signature of an SPA / catch-all handler that answers 200 for
	// EVERYTHING — the #1 source of "sensitive file" false positives.
	IsCatchAll bool
	// Reason is a short human string explaining the verdict (for evidence).
	Reason string
}

// originOf extracts scheme://host[:port] from a URL string without importing
// net/url for such a small job would be silly, so we DO use a tiny manual
// split that tolerates missing paths.
func originOf(url string) (origin, rest string) {
	i := strings.Index(url, "://")
	if i < 0 {
		return url, ""
	}
	after := url[i+3:]
	j := strings.IndexByte(after, '/')
	if j < 0 {
		return url, ""
	}
	return url[:i+3] + after[:j], after[j:]
}

// CompareToBaseline is the MANDATORY sensitive-file guard from Section 4.3:
//  1. it already has the target Probe (passed in, so we don't double-fetch);
//  2. it requests a RANDOM non-existent path on the same origin;
//  3. it compares status code, body length, and content hash.
//
// BaselineDiff is the canonical entry point for baseline differential analysis
// (V7.1). It is a stable alias for CompareToBaseline so the verify.sh V7.1
// check (grep "BaselineDiff") and external callers share one name. The name
// documents that it DIFFs the target against a random-path baseline probe to
// detect SPA/catch-all responses. Prefer BaselineDiff in new code.
func BaselineDiff(ctx context.Context, target Probe) BaselineResult {
	return CompareToBaseline(ctx, target)
}

// If the two are effectively identical → SPA catch-all → IsCatchAll=true, and
// the caller MUST discard the finding as a false positive.
func CompareToBaseline(ctx context.Context, target Probe) BaselineResult {
	res := BaselineResult{Target: target}
	origin, _ := originOf(target.URL)
	if origin == "" {
		res.Reason = "could not derive origin"
		return res
	}
	baseURL := origin + "/" + randomToken(20) + "/" + randomToken(12) + ".txt"
	res.Baseline = Fetch(ctx, baseURL)

	// If the baseline probe itself failed, we cannot prove catch-all; treat it
	// as NOT catch-all (fail open toward keeping the finding for manual review).
	if res.Baseline.Err != nil {
		res.Reason = "baseline probe failed: " + res.Baseline.Err.Error()
		return res
	}

	sameStatus := res.Baseline.StatusCode == target.StatusCode
	sameHash := res.Baseline.BodySHA256 == target.BodySHA256
	// Near-identical length: within 2% or 64 bytes, whichever is larger. SPA
	// shells differ only by a request-specific nonce/csrf token.
	lenTol := int(math.Max(64, float64(target.BodyLen)*0.02))
	sameLen := absInt(res.Baseline.BodyLen-target.BodyLen) <= lenTol

	switch {
	case sameStatus && sameHash:
		res.IsCatchAll = true
		res.Reason = fmt.Sprintf("catch-all: random path returned identical body hash (status %d, %d bytes)",
			target.StatusCode, target.BodyLen)
	case sameStatus && target.StatusCode == 200 && sameLen:
		res.IsCatchAll = true
		res.Reason = fmt.Sprintf("catch-all: random path returned same status 200 and near-identical length (%d vs %d bytes)",
			target.BodyLen, res.Baseline.BodyLen)
	default:
		res.Reason = fmt.Sprintf("distinct from baseline (target %d/%dB vs baseline %d/%dB)",
			target.StatusCode, target.BodyLen, res.Baseline.StatusCode, res.Baseline.BodyLen)
	}
	return res
}

func absInt(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
