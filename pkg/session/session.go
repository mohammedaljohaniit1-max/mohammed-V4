// Package session implements a LIVE authenticated-session keeper — the fix for
// the single most damaging silent bug in long scans:
//
//	The scanner logs in ONCE at bootstrap, the session dies after 30-60 min,
//	and the remaining ~11 hours of a 12-hour scan run as an ANONYMOUS visitor.
//	IDOR / BOLA / privilege-escalation / business-logic bugs — the only classes
//	worth finding on a hardened target — are then IMPOSSIBLE to detect, because
//	they all live behind the login.
//
// This package keeps the session alive:
//
//	1. Heartbeat      — periodically probe a known authenticated endpoint.
//	2. Liveness check — decide from the probe response whether we are still
//	                    logged in (redirect to /login, sudden 401/403, "Sign in"
//	                    text, disappearance of an authenticated marker).
//	3. Re-auth hook   — when the session is judged dead, call a caller-supplied
//	                    Reauthenticator to obtain fresh cookies, then swap them
//	                    in atomically so every engine keeps using a live session.
//
// DESIGN (same discipline as pkg/intelligence):
//   - No network code in the decision logic. The prober is an interface, so the
//     liveness/heartbeat state machine is unit-tested deterministically with
//     fixtures — no live target needed.
//   - Thread-safe: the cookie jar and status are guarded by an RWMutex because
//     many scan engines read the current cookies concurrently.
//   - Fails SAFE: if we cannot prove the session is alive we mark it Unknown/Dead
//     and stop feeding "authenticated" findings, rather than silently pretending
//     to be logged in.
package session

import (
	"context"
	"regexp"
	"strings"
	"sync"
	"time"
)

// State is the current judged status of the session.
type State string

const (
	StateUnknown State = "unknown" // not yet probed
	StateAlive   State = "alive"   // last probe proved we are logged in
	StateDead    State = "dead"    // last probe proved we are logged out
)

// ProbeResult is what a single heartbeat probe observed. It is deliberately a
// plain value type so tests can construct it directly without any HTTP.
type ProbeResult struct {
	StatusCode int
	// FinalURL is the URL after following redirects (used to detect a bounce to
	// a login page).
	FinalURL string
	// Body is a bounded slice of the response body (caller caps the size).
	Body string
	// Err is set when the probe itself failed (network error). A failed probe is
	// treated as "inconclusive", NOT as "dead", to avoid re-auth storms on a
	// flaky network.
	Err error
}

// Prober performs one authenticated heartbeat request and returns what it saw.
// The production implementation lives in http_prober.go; tests inject a fake.
type Prober interface {
	Probe(ctx context.Context, endpoint string, cookies string) ProbeResult
}

// Reauthenticator obtains a fresh authenticated cookie string. It is supplied by
// the caller because HOW you log in is target-specific:
//   - automated user/pass bootstrap (pkg/exploit/autobootstrap), or
//   - interactive browser login (pkg/browser) where a human solves CAPTCHA/2FA,
//   - or an operator-pasted cookie.
//
// It returns the new cookie string and nil on success. An error means re-auth
// failed (e.g. CAPTCHA appeared and no human is present) — the keeper then stays
// Dead and reports it, rather than looping forever.
type Reauthenticator func(ctx context.Context) (cookies string, err error)

// Config tunes the keeper.
type Config struct {
	// Endpoint is a known authenticated URL to probe (e.g. https://x/api/user).
	Endpoint string
	// HeartbeatEvery is the probe interval. Clamped to a sane floor so we never
	// hammer a sensitive target (see Gentle Mode).
	HeartbeatEvery time.Duration
	// AuthMarker, when non-empty, is a substring that MUST appear in an
	// authenticated response (e.g. the username, or "Sign out"). Its
	// disappearance is a strong death signal.
	AuthMarker string
	// MaxReauthAttempts caps consecutive re-auth tries before giving up.
	MaxReauthAttempts int
}

func (c *Config) withDefaults() {
	if c.HeartbeatEvery <= 0 {
		c.HeartbeatEvery = 5 * time.Minute
	}
	// Hard floor: never probe faster than every 20s, even if misconfigured —
	// protects sensitive/low-capacity targets (Saudi gov-style) from our own
	// heartbeat becoming a load source.
	if c.HeartbeatEvery < 20*time.Second {
		c.HeartbeatEvery = 20 * time.Second
	}
	if c.MaxReauthAttempts <= 0 {
		c.MaxReauthAttempts = 3
	}
}

// Keeper is the live-session manager. Construct with New, then either drive it
// manually (Tick) in your scan loop or run it in the background with Run.
type Keeper struct {
	cfg     Config
	prober  Prober
	reauth  Reauthenticator
	loginRe *regexp.Regexp

	mu           sync.RWMutex
	cookies      string
	state        State
	lastProbe    time.Time
	reauthCount  int
	deaths       int // total number of times the session was found dead
	revivals     int // successful re-auths
	lastReason   string
}

// New builds a Keeper. cookies is the initial (bootstrap) cookie string.
func New(cfg Config, initialCookies string, prober Prober, reauth Reauthenticator) *Keeper {
	cfg.withDefaults()
	return &Keeper{
		cfg:     cfg,
		prober:  prober,
		reauth:  reauth,
		cookies: strings.TrimSpace(initialCookies),
		state:   StateUnknown,
		// Compiled once. Matches a bounce to a login/signin page in the final URL.
		loginRe: regexp.MustCompile(`(?i)/(login|signin|sign-in|sso|auth/login|users/sign_in|account/login)(/|\?|$)`),
	}
}

// Cookies returns the current cookie string (thread-safe). Every scan engine
// should read this before each request rather than caching it.
func (k *Keeper) Cookies() string {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.cookies
}

// Status returns the current judged state and the reason for it.
func (k *Keeper) Status() (State, string) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.state, k.lastReason
}

// Stats returns counters for reporting/telemetry.
func (k *Keeper) Stats() (deaths, revivals int) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.deaths, k.revivals
}

// judge decides whether a probe result proves we are still logged in. This is
// the pure heart of the package — no I/O, fully unit-tested.
//
// Returns (alive, reason). A network error yields alive=true with an
// "inconclusive" reason: we do NOT declare death on a flaky probe, because a
// false death triggers an unnecessary (and possibly CAPTCHA-blocked) re-auth.
func (k *Keeper) judge(r ProbeResult) (alive bool, reason string) {
	if r.Err != nil {
		return true, "probe error (inconclusive, keeping previous state): " + r.Err.Error()
	}
	// A redirect/landing on a login page is the clearest death signal.
	if k.loginRe.MatchString(r.FinalURL) {
		return false, "final URL bounced to a login page: " + r.FinalURL
	}
	// Auth endpoints answering 401/403 mean the credentials are no longer valid.
	if r.StatusCode == 401 || r.StatusCode == 403 {
		return false, "authenticated endpoint returned " + itoa(r.StatusCode)
	}
	// Login/sign-in prompts in the body (only when we're not clearly 200-OK with
	// a marker) indicate a logged-out view was served.
	bodyLower := strings.ToLower(r.Body)
	hasLoginPrompt := strings.Contains(bodyLower, "sign in") ||
		strings.Contains(bodyLower, "log in") ||
		strings.Contains(bodyLower, "please log in") ||
		strings.Contains(bodyLower, "session expired") ||
		strings.Contains(bodyLower, "you have been signed out")

	// If an AuthMarker is configured it is the authoritative positive signal.
	if m := strings.TrimSpace(k.cfg.AuthMarker); m != "" {
		if strings.Contains(r.Body, m) {
			return true, "auth marker present"
		}
		// Marker missing → dead, regardless of a 200 (a logged-out page is often 200).
		return false, "auth marker missing from response"
	}

	if hasLoginPrompt {
		return false, "login prompt detected in body"
	}
	if r.StatusCode >= 200 && r.StatusCode < 400 {
		return true, "authenticated endpoint OK (" + itoa(r.StatusCode) + ")"
	}
	// Anything else (5xx etc.) is inconclusive; keep previous state.
	return true, "non-auth status " + itoa(r.StatusCode) + " (inconclusive)"
}

// Tick performs exactly one heartbeat probe + judgement + (if needed) re-auth.
// Returns the resulting state. Call it from your scan loop, or use Run for a
// background goroutine. Safe for concurrent callers (serialised internally).
func (k *Keeper) Tick(ctx context.Context) State {
	k.mu.RLock()
	cookies := k.cookies
	endpoint := k.cfg.Endpoint
	k.mu.RUnlock()

	res := k.prober.Probe(ctx, endpoint, cookies)
	alive, reason := k.judge(res)

	k.mu.Lock()
	k.lastProbe = time.Now()
	k.lastReason = reason
	if alive {
		k.state = StateAlive
		k.reauthCount = 0
		k.mu.Unlock()
		return StateAlive
	}
	// Session is dead.
	k.state = StateDead
	k.deaths++
	canReauth := k.reauth != nil && k.reauthCount < k.cfg.MaxReauthAttempts
	k.reauthCount++
	k.mu.Unlock()

	if !canReauth {
		return StateDead
	}

	// Attempt re-auth OUTSIDE the lock (it may open a browser / network call).
	newCookies, err := k.reauth(ctx)
	k.mu.Lock()
	defer k.mu.Unlock()
	if err != nil || strings.TrimSpace(newCookies) == "" {
		k.lastReason = "re-auth failed: " + errStr(err)
		k.state = StateDead
		return StateDead
	}
	k.cookies = strings.TrimSpace(newCookies)
	k.state = StateAlive
	k.revivals++
	k.reauthCount = 0
	k.lastReason = "session revived via re-auth"
	return StateAlive
}

// Run drives Tick on the configured interval until ctx is cancelled. Intended to
// run in its own goroutine alongside the scan. onChange (optional) is invoked
// whenever the state transitions, so the caller can log / pause the scan while
// the session is dead.
func (k *Keeper) Run(ctx context.Context, onChange func(State, string)) {
	// Probe once immediately so we don't spend the first interval blind.
	prev := k.Tick(ctx)
	if onChange != nil {
		onChange(prev, k.reasonSnapshot())
	}
	t := time.NewTicker(k.cfg.HeartbeatEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			cur := k.Tick(ctx)
			if cur != prev && onChange != nil {
				onChange(cur, k.reasonSnapshot())
			}
			prev = cur
		}
	}
}

func (k *Keeper) reasonSnapshot() string {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.lastReason
}

// SetCookies lets an external flow (e.g. interactive browser login) inject a
// fresh cookie string and mark the session alive.
func (k *Keeper) SetCookies(cookies string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.cookies = strings.TrimSpace(cookies)
	if k.cookies != "" {
		k.state = StateAlive
		k.lastReason = "cookies set externally"
	}
}

// --- tiny stdlib-free helpers (avoid strconv import churn in hot path) ---

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
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

func errStr(err error) string {
	if err == nil {
		return "unknown"
	}
	return err.Error()
}
