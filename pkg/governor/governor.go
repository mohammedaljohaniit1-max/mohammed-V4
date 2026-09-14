package governor

import (
	"strings"
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// CircuitState represents the current status of the circuit breaker.
type CircuitState int

const (
	StateClosed CircuitState = iota
	StateHalfOpen
	StateOpen
)

func (s CircuitState) String() string {
	switch s {
	case StateClosed:
		return "CLOSED"
	case StateHalfOpen:
		return "HALF-OPEN"
	case StateOpen:
		return "OPEN"
	default:
		return "UNKNOWN"
	}
}

// Config controls operational limits for the governor.
type Config struct {
	MaxRPS              float64       // Maximum requests per second (e.g. 2.0)
	MaxConcurrency      int           // Maximum concurrent workers (e.g. 2)
	MinJitter           time.Duration // Minimum jitter added to interval (e.g. 200ms)
	MaxJitter           time.Duration // Maximum jitter added to interval (e.g. 400ms)
	ConsecutiveErrors   int           // Threshold of 429/503/504 to trip breaker (e.g. 3)
	CooldownDuration    time.Duration // Initial cooldown when breaker trips (e.g. 5s)
	MaxCooldownDuration time.Duration // Maximum exponential backoff cooldown (e.g. 60s)
}

// DefaultConfig returns safe enterprise / government default settings.
func DefaultConfig() Config {
	return Config{
		MaxRPS:              2.0,
		MaxConcurrency:      2,
		MinJitter:           200 * time.Millisecond,
		MaxJitter:           400 * time.Millisecond,
		ConsecutiveErrors:   3,
		CooldownDuration:    5 * time.Second,
		MaxCooldownDuration: 60 * time.Second,
	}
}

// GovernorOption configures a Governor instance.
type GovernorOption func(*Governor)

// WithMaxRPS sets the maximum requests per second ceiling.
func WithMaxRPS(rps float64) GovernorOption {
	return func(g *Governor) {
		if rps > 0 {
			g.cfg.MaxRPS = rps
			g.baseInterval = time.Duration(float64(time.Second) / rps)
		}
	}
}

// WithConcurrency sets the worker concurrency cap.
func WithConcurrency(concurrency int) GovernorOption {
	return func(g *Governor) {
		if concurrency > 0 {
			g.Concurrency = concurrency
			g.cfg.MaxConcurrency = concurrency
			g.sem = make(chan struct{}, concurrency)
		}
	}
}

// WithJitter sets the jitter range.
func WithJitter(min, max time.Duration) GovernorOption {
	return func(g *Governor) {
		if min >= 0 && max >= min {
			g.cfg.MinJitter = min
			g.cfg.MaxJitter = max
		}
	}
}

// WithCircuitBreaker sets threshold and cooldown for rate/service errors.
func WithCircuitBreaker(threshold int, cooldown time.Duration) GovernorOption {
	return func(g *Governor) {
		if threshold > 0 {
			g.cfg.ConsecutiveErrors = threshold
		}
		if cooldown > 0 {
			g.cfg.CooldownDuration = cooldown
		}
	}
}

// Governor manages network rate-limiting, concurrency, and target protection.
type Governor struct {
	mu           sync.Mutex
	cfg          Config
	Concurrency  int
	CurrentDelay time.Duration
	WAFHits      int
	MaxWAFHits   int

	// Rate Limiting & Jitter
	baseInterval time.Duration
	lastRequest  time.Time
	rng          *rand.Rand

	// Concurrency Semaphore
	sem chan struct{}

	// Circuit Breaker
	circuitMu         sync.RWMutex
	circuitState      CircuitState
	consecutiveErrors int
	lastTripTime      time.Time
	currentCooldown   time.Duration

	// Metrics
	totalRequests atomic.Uint64
	throttledWait atomic.Uint64
}

// NewGovernor constructs a Governor. Compatible with legacy NewGovernor(initialConcurrency)
// and extensible via GovernorOption functional parameters.
func NewGovernor(initialConcurrency int, opts ...GovernorOption) *Governor {
	cfg := DefaultConfig()
	if initialConcurrency > 0 {
		cfg.MaxConcurrency = initialConcurrency
	}

	baseInterval := time.Duration(float64(time.Second) / cfg.MaxRPS)

	g := &Governor{
		cfg:             cfg,
		Concurrency:     cfg.MaxConcurrency,
		CurrentDelay:    50 * time.Millisecond,
		MaxWAFHits:      5,
		baseInterval:    baseInterval,
		lastRequest:     time.Now().Add(-baseInterval),
		rng:             rand.New(rand.NewSource(time.Now().UnixNano())),
		sem:             make(chan struct{}, cfg.MaxConcurrency),
		circuitState:    StateClosed,
		currentCooldown: cfg.CooldownDuration,
	}

	for _, opt := range opts {
		opt(g)
	}

	return g
}

// Acquire reserves a concurrency slot. It blocks until a worker slot is available
// or the context is cancelled. The caller MUST call Release() when done.
func (g *Governor) Acquire(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case g.sem <- struct{}{}:
		return nil
	}
}

// Release frees an acquired concurrency slot.
func (g *Governor) Release() {
	select {
	case <-g.sem:
	default:
	}
}

// Throttle enforces the rate-limit interval, dynamic jitter, and circuit breaker.
// Legacy-compatible with zero parameters.
func (g *Governor) Throttle() {
	_ = g.ThrottleWithContext(context.Background())
}

// ThrottleWithContext enforces rate-limit interval, dynamic jitter, and circuit breaker
// with context cancellation support.
func (g *Governor) ThrottleWithContext(ctx context.Context) error {
	for {
		// 1. Check Circuit Breaker status
		if err := g.checkCircuitBreaker(ctx); err != nil {
			return err
		}

		// 2. Compute pacing delay with jitter
		g.mu.Lock()
		now := time.Now()
		elapsed := now.Sub(g.lastRequest)

		// Base target interval between requests
		targetInterval := g.baseInterval
		if g.CurrentDelay > targetInterval {
			targetInterval = g.CurrentDelay
		}

		// Add dynamic random jitter (e.g. 200ms - 400ms)
		jitter := time.Duration(0)
		if g.cfg.MaxJitter > g.cfg.MinJitter {
			jitterDelta := int64(g.cfg.MaxJitter - g.cfg.MinJitter)
			jitter = g.cfg.MinJitter + time.Duration(g.rng.Int63n(jitterDelta))
		} else if g.cfg.MinJitter > 0 {
			jitter = g.cfg.MinJitter
		}

		neededDelay := time.Duration(0)
		requiredInterval := targetInterval + jitter
		if elapsed < requiredInterval {
			neededDelay = requiredInterval - elapsed
		}

		// Pre-reserve the slot so concurrent callers queue behind each other
		g.lastRequest = now.Add(neededDelay)
		g.mu.Unlock()

		if neededDelay > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(neededDelay):
			}
		}

		g.totalRequests.Add(1)
		return nil
	}
}

// checkCircuitBreaker verifies whether the circuit breaker is OPEN, and blocks
// during cooldown until transition to HALF-OPEN or CLOSED.
func (g *Governor) checkCircuitBreaker(ctx context.Context) error {
	g.circuitMu.Lock()
	if g.circuitState == StateOpen {
		elapsed := time.Since(g.lastTripTime)
		if elapsed < g.currentCooldown {
			remaining := g.currentCooldown - elapsed
			g.circuitMu.Unlock()

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(remaining):
			}

			g.circuitMu.Lock()
		}
		// Transition to Half-Open after cooldown expires
		g.circuitState = StateHalfOpen
	}
	g.circuitMu.Unlock()
	return nil
}

// ReportStatus records an HTTP response status code to feed the Circuit Breaker.
// Codes 429 (Too Many Requests), 503 (Service Unavailable), and 504 (Gateway Timeout)
// trigger backoff and increment consecutive error count.
func (g *Governor) ReportStatus(statusCode int) {
	if statusCode == http.StatusTooManyRequests ||
		statusCode == http.StatusServiceUnavailable ||
		statusCode == http.StatusGatewayTimeout {
		g.tripError(statusCode)
		return
	}

	// Any successful or benign response resets consecutive errors
	if statusCode >= 200 && statusCode < 400 {
		g.circuitMu.Lock()
		g.consecutiveErrors = 0
		if g.circuitState == StateHalfOpen {
			g.circuitState = StateClosed
			g.currentCooldown = g.cfg.CooldownDuration
		}
		g.circuitMu.Unlock()
	}
}

func (g *Governor) tripError(statusCode int) {
	g.circuitMu.Lock()
	defer g.circuitMu.Unlock()

	g.consecutiveErrors++
	if g.consecutiveErrors >= g.cfg.ConsecutiveErrors || g.circuitState == StateHalfOpen {
		g.circuitState = StateOpen
		g.lastTripTime = time.Now()

		// Exponential backoff up to MaxCooldownDuration
		g.currentCooldown = minDuration(g.cfg.MaxCooldownDuration, g.currentCooldown*2)
		if g.currentCooldown < g.cfg.CooldownDuration {
			g.currentCooldown = g.cfg.CooldownDuration
		}
	}

	// Also inform legacy delay scaling
	g.ReportWAF()
}

// ReportWAF is legacy-compatible: halves concurrency and doubles delay on WAF blocks.
func (g *Governor) ReportWAF() {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.WAFHits++
	g.Concurrency = maxInt(1, g.Concurrency/2)
	g.CurrentDelay = minDuration(2*time.Second, g.CurrentDelay*2)
}

// CircuitState returns the current state of the circuit breaker.
func (g *Governor) CircuitState() CircuitState {
	g.circuitMu.RLock()
	defer g.circuitMu.RUnlock()
	return g.circuitState
}

// WrapTransport returns an http.RoundTripper that passes all requests through
// this governor's Acquire/Release concurrency gate, Throttle, and status reporting.
func (g *Governor) WrapTransport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &governedTransport{
		gov:  g,
		base: base,
	}
}

// WrapClient configures an http.Client to execute all requests under this governor.
func (g *Governor) WrapClient(client *http.Client) *http.Client {
	if client == nil {
		client = &http.Client{}
	}
	client.Transport = g.WrapTransport(client.Transport)
	return client
}

type governedTransport struct {
	gov  *Governor
	base http.RoundTripper
}

func (t *governedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()

	if err := t.gov.Acquire(ctx); err != nil {
		return nil, fmt.Errorf("governor acquire cancelled: %w", err)
	}
	defer t.gov.Release()

	if err := t.gov.ThrottleWithContext(ctx); err != nil {
		return nil, fmt.Errorf("governor throttle cancelled: %w", err)
	}

	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	if resp != nil {
		t.gov.ReportStatus(resp.StatusCode)
	}

	return resp, nil
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

// TargetCapacity represents auto-detected pacing and concurrency parameters.
type TargetCapacity struct {
	RateLimit   int           // Requests per second
	Concurrency int           // Maximum concurrent workers
	AvgLatency  time.Duration // Average ping latency
	IsCDN       bool          // Whether target is fronted by Cloudflare/Akamai/etc.
	IPCount     int           // Number of distinct IP addresses resolved
	Rationale   string        // Diagnostic explanation
}

// AutoDetectTargetCapacity probes live target hosts with lightweight baseline pings
// to automatically sense optimal rate-limiting and worker concurrency without manual tuning.
func AutoDetectTargetCapacity(liveHosts []string) (rateLimit int, concurrency int) {
	cap := DetectTargetCapacity(liveHosts)
	return cap.RateLimit, cap.Concurrency
}

// DetectTargetCapacity evaluates network latency, IP multi-homing, and CDN fronting.
func DetectTargetCapacity(liveHosts []string) TargetCapacity {
	if len(liveHosts) == 0 {
		return TargetCapacity{
			RateLimit:   1,
			Concurrency: 1,
			Rationale:   "No live hosts provided; fallback to high-safety minimum (1 req/s, 1 worker)",
		}
	}

	sampleSize := len(liveHosts)
	if sampleSize > 3 {
		sampleSize = 3
	}

	client := &http.Client{
		Timeout: 4 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 2 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	var totalLatency time.Duration
	successfulProbes := 0
	isCDN := false

	for i := 0; i < sampleSize; i++ {
		host := liveHosts[i]
		url := host
		if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
			url = "https://" + host
		}

		start := time.Now()
		req, err := http.NewRequest("HEAD", url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

		resp, err := client.Do(req)
		elapsed := time.Since(start)

		if err != nil {
			// Try HTTP fallback if HTTPS fails
			if strings.HasPrefix(url, "https://") {
				httpURL := "http://" + strings.TrimPrefix(url, "https://")
				start = time.Now()
				if req2, err2 := http.NewRequest("HEAD", httpURL, nil); err2 == nil {
					req2.Header.Set("User-Agent", "Mozilla/5.0")
					if resp2, err3 := client.Do(req2); err3 == nil {
						resp = resp2
						elapsed = time.Since(start)
						err = nil
					}
				}
			}
		}

		if err == nil && resp != nil {
			successfulProbes++
			totalLatency += elapsed

			// Check for CDN headers
			server := strings.ToLower(resp.Header.Get("Server"))
			cfRay := resp.Header.Get("CF-RAY")
			akamai := resp.Header.Get("X-Akamai-Transformed")
			via := strings.ToLower(resp.Header.Get("Via"))
			fastly := resp.Header.Get("X-Fastly-Request-ID")

			if cfRay != "" || akamai != "" || fastly != "" ||
				strings.Contains(server, "cloudflare") ||
				strings.Contains(server, "akamai") ||
				strings.Contains(via, "cloudflare") ||
				strings.Contains(via, "cloudfront") {
				isCDN = true
			}
			_ = resp.Body.Close()
		}
	}

	var avgLatency time.Duration
	if successfulProbes > 0 {
		avgLatency = totalLatency / time.Duration(successfulProbes)
	} else {
		avgLatency = 1200 * time.Millisecond // assume high latency if unresponsive
	}

	// Decision Matrix:
	// 1. High latency (>1000ms) or unresponsive: 1 req/s, concurrency 1
	// 2. CDN / Cloud WAF fronting (low latency < 400ms): 5 req/s, concurrency 3-5
	// 3. Medium Enterprise (300-800ms): 2-3 req/s, concurrency 2
	if avgLatency >= 1000*time.Millisecond {
		return TargetCapacity{
			RateLimit:   1,
			Concurrency: 1,
			AvgLatency:  avgLatency,
			IsCDN:       isCDN,
			Rationale:   fmt.Sprintf("High target latency (%v); locked to 1 req/s and concurrency 1 to prevent server strain", avgLatency),
		}
	}

	if isCDN && avgLatency < 500*time.Millisecond {
		return TargetCapacity{
			RateLimit:   5,
			Concurrency: 4,
			AvgLatency:  avgLatency,
			IsCDN:       true,
			Rationale:   fmt.Sprintf("CDN / Cloud Edge infrastructure detected (%v latency); tuned to 5 req/s and concurrency 4", avgLatency),
		}
	}

	return TargetCapacity{
		RateLimit:   2,
		Concurrency: 2,
		AvgLatency:  avgLatency,
		IsCDN:       isCDN,
		Rationale:   fmt.Sprintf("Enterprise infrastructure (%v latency); set to 2 req/s and concurrency 2", avgLatency),
	}
}
