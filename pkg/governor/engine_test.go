package governor

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestTargetTelemetryMonitor(t *testing.T) {
	mon := NewTargetTelemetryMonitor(10)

	// Baseline healthy response
	backoff, pause := mon.RecordResponse(50*time.Millisecond, http.StatusOK, nil)
	if backoff || pause > 0 {
		t.Fatalf("expected healthy response, got backoff=%v pause=%v", backoff, pause)
	}

	snap := mon.Snapshot()
	if snap.TotalRequests != 1 || snap.TotalErrors != 0 {
		t.Fatalf("unexpected snapshot: %+v", snap)
	}

	// Inject successive errors to trigger error-rate threshold (>5%)
	for i := 0; i < 5; i++ {
		mon.RecordResponse(60*time.Millisecond, http.StatusTooManyRequests, nil)
	}

	snap = mon.Snapshot()
	if snap.ErrorRate <= 0.05 {
		t.Fatalf("expected error rate > 0.05, got %f", snap.ErrorRate)
	}

	if !mon.IsPaused() {
		t.Fatalf("expected monitor to be paused after repeated 429s")
	}

	// Verify WaitUntilHealthy with context cancellation
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	err := mon.WaitUntilHealthy(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline exceeded, got %v", err)
	}
}
