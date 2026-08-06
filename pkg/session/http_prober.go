package session

import (
	"context"
	"io"
	"net/http"
	"time"
)

// HTTPProber is the production Prober: it performs one real GET against the
// authenticated endpoint carrying the current cookies, follows redirects, and
// reports the final URL + a bounded body slice.
//
// It is intentionally minimal and read-only: it never mutates state on the
// target, it only observes whether we are still logged in.
type HTTPProber struct {
	Client *http.Client
	// UserAgent is sent on the probe; keep it identical to the scan's UA so the
	// target does not treat the heartbeat as a different client (some sites bind
	// the session to the UA).
	UserAgent string
	// MaxBody caps how much of the response body we read for liveness checks.
	MaxBody int64
}

// NewHTTPProber builds a prober with a sane default client. timeout applies to
// the whole probe request.
func NewHTTPProber(timeout time.Duration, userAgent string) *HTTPProber {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &HTTPProber{
		Client:    &http.Client{Timeout: timeout},
		UserAgent: userAgent,
		MaxBody:   64 * 1024,
	}
}

// Probe implements Prober.
func (p *HTTPProber) Probe(ctx context.Context, endpoint, cookies string) ProbeResult {
	if p.MaxBody <= 0 {
		p.MaxBody = 64 * 1024
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return ProbeResult{Err: err}
	}
	if cookies != "" {
		req.Header.Set("Cookie", cookies)
	}
	if p.UserAgent != "" {
		req.Header.Set("User-Agent", p.UserAgent)
	}
	// Prefer HTML/JSON so we get a representative authenticated view.
	req.Header.Set("Accept", "text/html,application/json;q=0.9,*/*;q=0.8")

	resp, err := p.Client.Do(req)
	if err != nil {
		return ProbeResult{Err: err}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, p.MaxBody))
	final := endpoint
	if resp.Request != nil && resp.Request.URL != nil {
		final = resp.Request.URL.String()
	}
	return ProbeResult{
		StatusCode: resp.StatusCode,
		FinalURL:   final,
		Body:       string(body),
	}
}
