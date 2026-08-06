package session

import (
	"context"
	"sync"
	"time"
)

// GentleMode is the safety profile for SENSITIVE / LOW-CAPACITY targets — the
// Saudi-government-style hosts the operator flagged: authorized to test, but
// where even an nmap or aggressive fan-out can overload a small server, and a
// single 429/503 must halt the pressure immediately.
//
// It is NOT a scanner; it is a shared PACER + CIRCUIT BREAKER that the session
// keeper and every request-issuing engine consult:
//
//   - MinInterval enforces a hard floor between requests (serialised, no bursts).
//   - On a 429/503 (or Retry-After), it BACKS OFF exponentially and can trip a
//     circuit breaker that pauses all traffic for a cool-down window.
//   - It exposes a boolean the scan reads to know whether port scanning / active
//     bruteforce / fuzzing are permitted at all (they are not, in gentle mode).
//
// Pure logic + an injectable clock/sleep, so it is fully unit-testable.
type GentleMode struct {
	// MinInterval is the minimum spacing between outgoing requests.
	MinInterval time.Duration
	// AllowPortScan / AllowActiveBrute / AllowFuzzing gate the aggressive phases.
	// In gentle mode these are all false.
	AllowPortScan    bool
	AllowActiveBrute bool
	AllowFuzzing     bool
	// MaxBackoff caps the exponential backoff.
	MaxBackoff time.Duration

	// sleep is injectable for tests (defaults to time.Sleep).
	sleep func(time.Duration)
	// now is injectable for tests (defaults to time.Now).
	now func() time.Time

	mu          sync.Mutex
	last        time.Time
	backoff     time.Duration
	trippedUntil time.Time
}

// NewGentleMode returns the recommended profile for a Class-A-sensitive target:
// slow, serialised, no active scanning, immediate backoff on stress signals.
func NewGentleMode() *GentleMode {
	return &GentleMode{
		MinInterval:      2 * time.Second, // deliberately slow
		AllowPortScan:    false,
		AllowActiveBrute: false,
		AllowFuzzing:     false,
		MaxBackoff:       60 * time.Second,
		sleep:            time.Sleep,
		now:              time.Now,
	}
}

// NewNormalMode returns an unrestricted pacer (for Class C/D targets that can
// take the load). Kept here so callers pick a mode from one place.
func NewNormalMode() *GentleMode {
	return &GentleMode{
		MinInterval:      0,
		AllowPortScan:    true,
		AllowActiveBrute: true,
		AllowFuzzing:     true,
		MaxBackoff:       30 * time.Second,
		sleep:            time.Sleep,
		now:              time.Now,
	}
}

// Wait blocks until it is safe to issue the next request. It respects the
// circuit breaker (if tripped, waits out the cool-down) and the MinInterval
// spacing. Returns early if ctx is cancelled.
func (g *GentleMode) Wait(ctx context.Context) {
	g.mu.Lock()
	now := g.clock()
	var d time.Duration

	if now.Before(g.trippedUntil) {
		d = g.trippedUntil.Sub(now)
	} else {
		gap := now.Sub(g.last)
		need := g.MinInterval + g.backoff
		if gap < need {
			d = need - gap
		}
	}
	g.mu.Unlock()

	if d > 0 {
		select {
		case <-ctx.Done():
		case <-timeAfter(d, g.sleep):
		}
	}

	g.mu.Lock()
	g.last = g.clock()
	g.mu.Unlock()
}

// Observe feeds back the outcome of a request so the pacer can adapt. Pass the
// HTTP status code (0 if the request errored) and any Retry-After seconds (0 if
// none). A 429/503 trips backoff + the circuit breaker; a clean 2xx gradually
// relaxes the backoff.
func (g *GentleMode) Observe(status int, retryAfter time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()

	switch {
	case status == 429 || status == 503:
		// Stress signal: exponential backoff + trip the breaker.
		if g.backoff == 0 {
			g.backoff = g.MinInterval
			if g.backoff == 0 {
				g.backoff = time.Second
			}
		} else {
			g.backoff *= 2
		}
		if g.backoff > g.MaxBackoff {
			g.backoff = g.MaxBackoff
		}
		cool := retryAfter
		if cool <= 0 {
			cool = g.backoff
		}
		g.trippedUntil = g.clock().Add(cool)
	case status >= 200 && status < 400:
		// Healthy: decay the backoff by half (never below zero).
		g.backoff /= 2
	}
}

// Tripped reports whether the circuit breaker is currently open (all traffic
// should pause). Used by the scan loop to log/pause.
func (g *GentleMode) Tripped() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.clock().Before(g.trippedUntil)
}

// CurrentBackoff exposes the current backoff (for telemetry/tests).
func (g *GentleMode) CurrentBackoff() time.Duration {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.backoff
}

func (g *GentleMode) clock() time.Time {
	if g.now != nil {
		return g.now()
	}
	return time.Now()
}

// timeAfter returns a channel that fires after d, using the injected sleeper so
// tests run instantly. When sleep is the real time.Sleep we approximate with a
// goroutine timer.
func timeAfter(d time.Duration, sleep func(time.Duration)) <-chan struct{} {
	ch := make(chan struct{})
	go func() {
		if sleep != nil {
			sleep(d)
		} else {
			time.Sleep(d)
		}
		close(ch)
	}()
	return ch
}
