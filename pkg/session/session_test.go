package session

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// fakeProber returns queued results in order; the last one repeats.
type fakeProber struct {
	mu      sync.Mutex
	results []ProbeResult
	calls   int
	lastCookies []string
}

func (f *fakeProber) Probe(_ context.Context, _ string, cookies string) ProbeResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.lastCookies = append(f.lastCookies, cookies)
	if len(f.results) == 0 {
		return ProbeResult{StatusCode: 200}
	}
	i := f.calls - 1
	if i >= len(f.results) {
		i = len(f.results) - 1
	}
	return f.results[i]
}

func newKeeper(cfg Config, cookies string, p Prober, r Reauthenticator) *Keeper {
	return New(cfg, cookies, p, r)
}

// --- judge() truth table (pure logic, no I/O) ---

func TestJudge_AliveOn200WithMarker(t *testing.T) {
	k := newKeeper(Config{AuthMarker: "mohammed@x"}, "c", &fakeProber{}, nil)
	alive, reason := k.judge(ProbeResult{StatusCode: 200, Body: "hello mohammed@x welcome"})
	if !alive {
		t.Fatalf("expected alive, got dead: %s", reason)
	}
}

func TestJudge_DeadWhenMarkerMissing(t *testing.T) {
	k := newKeeper(Config{AuthMarker: "mohammed@x"}, "c", &fakeProber{}, nil)
	alive, reason := k.judge(ProbeResult{StatusCode: 200, Body: "<html>public homepage</html>"})
	if alive {
		t.Fatalf("expected dead when marker missing, got alive: %s", reason)
	}
}

func TestJudge_DeadOnLoginRedirect(t *testing.T) {
	k := newKeeper(Config{}, "c", &fakeProber{}, nil)
	alive, reason := k.judge(ProbeResult{StatusCode: 200, FinalURL: "https://x.test/users/sign_in?redirect=/api"})
	if alive {
		t.Fatalf("expected dead on login redirect, got alive: %s", reason)
	}
}

func TestJudge_DeadOn401(t *testing.T) {
	k := newKeeper(Config{}, "c", &fakeProber{}, nil)
	if alive, _ := k.judge(ProbeResult{StatusCode: 401}); alive {
		t.Fatal("expected dead on 401")
	}
	if alive, _ := k.judge(ProbeResult{StatusCode: 403}); alive {
		t.Fatal("expected dead on 403")
	}
}

func TestJudge_DeadOnLoginPromptBody(t *testing.T) {
	k := newKeeper(Config{}, "c", &fakeProber{}, nil)
	alive, _ := k.judge(ProbeResult{StatusCode: 200, Body: "Your session expired, please log in again"})
	if alive {
		t.Fatal("expected dead on session-expired body")
	}
}

// CRITICAL: a network error must NOT be judged as death (avoids re-auth storms).
func TestJudge_NetworkErrorIsInconclusiveNotDead(t *testing.T) {
	k := newKeeper(Config{}, "c", &fakeProber{}, nil)
	alive, reason := k.judge(ProbeResult{Err: errors.New("connection reset")})
	if !alive {
		t.Fatalf("network error must be inconclusive (alive), got dead: %s", reason)
	}
}

func TestJudge_AliveOnPlain200NoMarker(t *testing.T) {
	k := newKeeper(Config{}, "c", &fakeProber{}, nil)
	if alive, _ := k.judge(ProbeResult{StatusCode: 200, Body: `{"user":{"id":5}}`}); !alive {
		t.Fatal("expected alive on clean 200 with no login prompt")
	}
}

// --- Tick + re-auth flow ---

func TestTick_ReauthRevivesDeadSession(t *testing.T) {
	fp := &fakeProber{results: []ProbeResult{
		{StatusCode: 401}, // dead on first probe
	}}
	reauthCalled := 0
	reauth := func(_ context.Context) (string, error) {
		reauthCalled++
		return "fresh=cookie123", nil
	}
	k := newKeeper(Config{Endpoint: "https://x/api/user"}, "old=cookie", fp, reauth)

	st := k.Tick(context.Background())
	if st != StateAlive {
		t.Fatalf("expected StateAlive after successful re-auth, got %s", st)
	}
	if reauthCalled != 1 {
		t.Fatalf("expected 1 re-auth call, got %d", reauthCalled)
	}
	if k.Cookies() != "fresh=cookie123" {
		t.Fatalf("cookies not refreshed: %q", k.Cookies())
	}
	deaths, revivals := k.Stats()
	if deaths != 1 || revivals != 1 {
		t.Fatalf("stats deaths=%d revivals=%d, want 1/1", deaths, revivals)
	}
}

func TestTick_ReauthFailureStaysDead(t *testing.T) {
	fp := &fakeProber{results: []ProbeResult{{StatusCode: 401}}}
	reauth := func(_ context.Context) (string, error) {
		return "", errors.New("CAPTCHA appeared, no human present")
	}
	k := newKeeper(Config{}, "old", fp, reauth)
	if st := k.Tick(context.Background()); st != StateDead {
		t.Fatalf("expected StateDead when re-auth fails, got %s", st)
	}
	_, reason := k.Status()
	if reason == "" {
		t.Fatal("expected a failure reason to be recorded")
	}
}

func TestTick_RespectsMaxReauthAttempts(t *testing.T) {
	fp := &fakeProber{results: []ProbeResult{{StatusCode: 401}}} // always dead
	attempts := 0
	reauth := func(_ context.Context) (string, error) {
		attempts++
		return "", errors.New("still failing")
	}
	k := newKeeper(Config{MaxReauthAttempts: 2}, "old", fp, reauth)
	for i := 0; i < 5; i++ {
		k.Tick(context.Background())
	}
	if attempts > 2 {
		t.Fatalf("re-auth attempted %d times, must cap at 2", attempts)
	}
}

func TestSetCookies_MarksAlive(t *testing.T) {
	k := newKeeper(Config{}, "", &fakeProber{}, nil)
	k.SetCookies("browser=session789")
	st, _ := k.Status()
	if st != StateAlive || k.Cookies() != "browser=session789" {
		t.Fatalf("SetCookies did not mark alive with new cookies: state=%s cookies=%q", st, k.Cookies())
	}
}

func TestConfig_HeartbeatFloorEnforced(t *testing.T) {
	c := Config{HeartbeatEvery: 1 * time.Second}
	c.withDefaults()
	if c.HeartbeatEvery < 20*time.Second {
		t.Fatalf("heartbeat floor not enforced: %v", c.HeartbeatEvery)
	}
}

func TestKeeper_ConcurrentCookieReads(t *testing.T) {
	fp := &fakeProber{results: []ProbeResult{{StatusCode: 200}}}
	k := newKeeper(Config{}, "c", fp, nil)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = k.Cookies(); k.Tick(context.Background()) }()
	}
	wg.Wait()
}
