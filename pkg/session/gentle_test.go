package session

import (
	"context"
	"testing"
	"time"
)

// newTestGentle builds a GentleMode with a controllable clock and a no-op sleep
// so timing tests run instantly and deterministically.
func newTestGentle() (*GentleMode, *fakeClock) {
	fc := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	g := NewGentleMode()
	g.now = fc.Now
	g.sleep = func(d time.Duration) { fc.Advance(d) } // "sleeping" advances the clock
	return g, fc
}

type fakeClock struct{ t time.Time }

func (f *fakeClock) Now() time.Time    { return f.t }
func (f *fakeClock) Advance(d time.Duration) { f.t = f.t.Add(d) }

func TestGentle_DefaultsDisableAggressivePhases(t *testing.T) {
	g := NewGentleMode()
	if g.AllowPortScan || g.AllowActiveBrute || g.AllowFuzzing {
		t.Fatal("gentle mode must disable port scan / active brute / fuzzing")
	}
	if g.MinInterval <= 0 {
		t.Fatal("gentle mode must enforce a positive MinInterval")
	}
}

func TestNormal_EnablesAggressivePhases(t *testing.T) {
	g := NewNormalMode()
	if !g.AllowPortScan || !g.AllowActiveBrute || !g.AllowFuzzing {
		t.Fatal("normal mode should allow aggressive phases")
	}
}

func TestGentle_429TripsCircuitBreaker(t *testing.T) {
	g, _ := newTestGentle()
	if g.Tripped() {
		t.Fatal("should not be tripped initially")
	}
	g.Observe(429, 0)
	if !g.Tripped() {
		t.Fatal("429 must trip the circuit breaker")
	}
	if g.CurrentBackoff() <= 0 {
		t.Fatal("429 must introduce a positive backoff")
	}
}

func TestGentle_503AlsoTrips(t *testing.T) {
	g, _ := newTestGentle()
	g.Observe(503, 0)
	if !g.Tripped() {
		t.Fatal("503 must trip the circuit breaker")
	}
}

func TestGentle_BackoffIsExponentialAndCapped(t *testing.T) {
	g, _ := newTestGentle()
	var prev time.Duration
	for i := 0; i < 10; i++ {
		g.Observe(429, 0)
		b := g.CurrentBackoff()
		if b < prev {
			t.Fatalf("backoff decreased under sustained 429: %v -> %v", prev, b)
		}
		prev = b
	}
	if prev > g.MaxBackoff {
		t.Fatalf("backoff %v exceeded cap %v", prev, g.MaxBackoff)
	}
}

func TestGentle_HealthyResponseDecaysBackoff(t *testing.T) {
	g, _ := newTestGentle()
	g.Observe(429, 0)
	high := g.CurrentBackoff()
	g.Observe(200, 0)
	if g.CurrentBackoff() >= high {
		t.Fatalf("healthy 200 must decay backoff: was %v, now %v", high, g.CurrentBackoff())
	}
}

func TestGentle_RetryAfterHonored(t *testing.T) {
	g, fc := newTestGentle()
	g.Observe(429, 30*time.Second)
	if !g.Tripped() {
		t.Fatal("expected tripped")
	}
	fc.Advance(29 * time.Second)
	if !g.Tripped() {
		t.Fatal("should still be tripped before Retry-After elapses")
	}
	fc.Advance(2 * time.Second)
	if g.Tripped() {
		t.Fatal("should be untripped after Retry-After elapses")
	}
}

func TestGentle_WaitEnforcesMinInterval(t *testing.T) {
	g, fc := newTestGentle()
	g.MinInterval = 2 * time.Second
	start := fc.Now()
	g.Wait(context.Background()) // first call: last is zero, may not wait much
	g.Wait(context.Background()) // second call must space by >= MinInterval
	elapsed := fc.Now().Sub(start)
	if elapsed < 2*time.Second {
		t.Fatalf("Wait did not enforce MinInterval spacing, elapsed=%v", elapsed)
	}
}

func TestGentle_WaitRespectsContextCancel(t *testing.T) {
	g := NewGentleMode()
	g.MinInterval = time.Hour // would block a long time
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled
	done := make(chan struct{})
	go func() { g.Wait(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Wait did not return promptly on cancelled context")
	}
}
