package osint

import (
	"context"
	"net/http"
	"strings"
	"time"
)

// Checker performs the ONLY network activity in this package: a gentle,
// passive existence probe of already-built candidate URLs. It is completely
// optional and gated behind an explicit operator flag. It NEVER logs in, NEVER
// bypasses rate limits, and honours a per-request pacing delay so it stays
// polite to sensitive targets (idea #2).
type Checker struct {
	Client *http.Client
	// Delay is the minimum gap between probes (politeness / anti-ban).
	Delay time.Duration
	// UserAgent is sent verbatim; operators should set an honest identifying UA.
	UserAgent string
}

// NewChecker returns a Checker with sane, gentle defaults.
func NewChecker(timeout, delay time.Duration, userAgent string) *Checker {
	if userAgent == "" {
		userAgent = "mohammed-osint/1.0 (passive existence check)"
	}
	return &Checker{
		Client:    &http.Client{Timeout: timeout},
		Delay:     delay,
		UserAgent: userAgent,
	}
}

// existenceProber is the injectable seam so tests never hit the network.
type existenceProber interface {
	probe(ctx context.Context, method, url string) (status int, err error)
}

// probe implements existenceProber against a real HTTP client.
func (c *Checker) probe(ctx context.Context, method, u string) (int, error) {
	if method != http.MethodHead {
		method = http.MethodGet // default to GET; many sites 405 on HEAD
	}
	req, err := http.NewRequestWithContext(ctx, method, u, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", c.UserAgent)
	resp, err := c.Client.Do(req)
	if err != nil {
		return 0, err
	}
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}

// Check runs live existence probes over the "account"/"gravatar" candidates
// (never "manual"/"dork" ones — those are for humans). It mutates a COPY and
// returns it; the input is untouched.
//
// A 2xx marks Confirmed=true. 3xx/404/others are recorded via Status but stay
// unconfirmed. Network errors leave the candidate unconfirmed (honest: we
// could not prove existence, so we do not claim it).
func (c *Checker) Check(ctx context.Context, in []Candidate) []Candidate {
	return checkWith(ctx, c, c.Delay, in)
}

// checkWith is the testable core: prober + delay are injected.
func checkWith(ctx context.Context, p existenceProber, delay time.Duration, in []Candidate) []Candidate {
	out := make([]Candidate, len(in))
	copy(out, in)
	for i := range out {
		if !isProbable(out[i]) {
			continue
		}
		if delay > 0 && i > 0 {
			select {
			case <-ctx.Done():
				return out
			case <-time.After(delay):
			}
		}
		status, err := p.probe(ctx, methodFor(out[i]), out[i].URL)
		if err != nil {
			continue // inconclusive; never fabricate a positive
		}
		out[i].Status = status
		if status >= 200 && status < 300 {
			out[i].Confirmed = true
		}
	}
	return out
}

// isProbable reports whether a candidate is safe/meaningful to auto-probe.
func isProbable(c Candidate) bool {
	if strings.TrimSpace(c.URL) == "" {
		return false
	}
	switch c.Kind {
	case "account", "gravatar":
		return c.Method == http.MethodHead || c.Method == http.MethodGet
	default:
		return false // dork/manual/info/breach-check are human-only
	}
}

func methodFor(c Candidate) string {
	if c.Method == http.MethodHead {
		return http.MethodHead
	}
	return http.MethodGet
}
