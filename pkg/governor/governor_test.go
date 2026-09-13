package governor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestGovernorLegacyCompatibility(t *testing.T) {
	gov := NewGovernor(4)
	if gov.Concurrency != 4 {
		t.Fatalf("expected concurrency 4, got %d", gov.Concurrency)
	}

	// Throttle with zero args should work
	gov.Throttle()

	// ReportWAF should halve concurrency
	gov.ReportWAF()
	if gov.Concurrency != 2 {
		t.Fatalf("expected concurrency 2 after ReportWAF, got %d", gov.Concurrency)
	}
}

func TestGovernorRateLimiterAndJitter(t *testing.T) {
	// 5 RPS = 200ms interval, Jitter = 50ms - 100ms
	gov := NewGovernor(2,
		WithMaxRPS(5.0),
		WithJitter(50*time.Millisecond, 100*time.Millisecond),
	)

	start := time.Now()
	for i := 0; i < 3; i++ {
		gov.Throttle()
	}
	elapsed := time.Since(start)

	// 2 throttled gaps should take at least ~500ms (2 * (200ms + 50ms))
	if elapsed < 400*time.Millisecond {
		t.Fatalf("expected throttling delay >= 400ms, took %v", elapsed)
	}
}

func TestGovernorConcurrencyGate(t *testing.T) {
	gov := NewGovernor(2, WithConcurrency(2), WithMaxRPS(100.0), WithJitter(0, 0))

	var active atomic.Int32
	var maxActive atomic.Int32
	var wg sync.WaitGroup

	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx := context.Background()
			if err := gov.Acquire(ctx); err != nil {
				t.Errorf("acquire failed: %v", err)
				return
			}
			cur := active.Add(1)
			for {
				old := maxActive.Load()
				if cur <= old || maxActive.CompareAndSwap(old, cur) {
					break
				}
			}

			time.Sleep(20 * time.Millisecond)
			active.Add(-1)
			gov.Release()
		}()
	}

	wg.Wait()
	if maxActive.Load() > 2 {
		t.Fatalf("concurrency exceeded limit 2: got %d", maxActive.Load())
	}
}

func TestGovernorCircuitBreaker(t *testing.T) {
	gov := NewGovernor(1,
		WithMaxRPS(100.0),
		WithJitter(0, 0),
		WithCircuitBreaker(2, 200*time.Millisecond),
	)

	// Simulate 2 consecutive 429s
	gov.ReportStatus(http.StatusTooManyRequests)
	if gov.CircuitState() != StateClosed {
		t.Fatalf("expected closed after 1 error, got %v", gov.CircuitState())
	}

	gov.ReportStatus(http.StatusTooManyRequests)
	if gov.CircuitState() != StateOpen {
		t.Fatalf("expected open after 2 errors, got %v", gov.CircuitState())
	}

	// A throttle request should wait for cooldown
	start := time.Now()
	gov.Throttle()
	if time.Since(start) < 180*time.Millisecond {
		t.Fatalf("expected cooldown pause, elapsed %v", time.Since(start))
	}

	// Half-open transition after cooldown
	if gov.CircuitState() != StateHalfOpen {
		t.Fatalf("expected half-open, got %v", gov.CircuitState())
	}

	// Success resets it to closed
	gov.ReportStatus(http.StatusOK)
	if gov.CircuitState() != StateClosed {
		t.Fatalf("expected closed after 200 OK, got %v", gov.CircuitState())
	}
}

func TestGovernorWrapClient(t *testing.T) {
	var requestCount atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	gov := NewGovernor(2, WithMaxRPS(50.0), WithJitter(10*time.Millisecond, 20*time.Millisecond))
	client := gov.WrapClient(ts.Client())

	resp, err := client.Get(ts.URL)
	if err != nil {
		t.Fatalf("client.Get failed: %v", err)
	}
	resp.Body.Close()

	if requestCount.Load() != 1 {
		t.Fatalf("expected 1 request, got %d", requestCount.Load())
	}
}
