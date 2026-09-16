package governor

import (
	"context"
	"math"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// TargetHealthMetrics captures real-time target responsiveness and error trends.
type TargetHealthMetrics struct {
	TotalRequests    uint64        `json:"total_requests"`
	TotalErrors      uint64        `json:"total_errors"`
	ErrorRate        float64       `json:"error_rate"`
	AverageRTT       time.Duration `json:"average_rtt"`
	LastRTT          time.Duration `json:"last_rtt"`
	CircuitTrips     uint64        `json:"circuit_trips"`
	IsPaused         bool          `json:"is_paused"`
	ActiveWorkers    int           `json:"active_workers"`
	MaxConcurrency   int           `json:"max_concurrency"`
	CurrentRPS       float64       `json:"current_rps"`
}

// TargetTelemetryMonitor continuously computes EWMA latency, tracks error ratios,
// and directs the adaptive load governor.
type TargetTelemetryMonitor struct {
	mu sync.RWMutex

	// EWMA Latency tracking
	ewmaRTT    float64 // in milliseconds
	baselineRTT float64 // calibrated baseline RTT
	sampleCount uint64

	// Sliding window error tracking
	windowSize      int
	windowErrors    []bool
	windowIdx       int
	windowCount     int

	// Health state
	errorRate float64
	circuitBreakerTripped atomic.Bool
	pauseUntil            time.Time

	// Stats
	totalRequests atomic.Uint64
	totalErrors   atomic.Uint64
	circuitTrips  atomic.Uint64
}

// NewTargetTelemetryMonitor constructs a real-time monitor with a sliding sample window.
func NewTargetTelemetryMonitor(windowSize int) *TargetTelemetryMonitor {
	if windowSize <= 0 {
		windowSize = 50
	}
	return &TargetTelemetryMonitor{
		windowSize:   windowSize,
		windowErrors: make([]bool, windowSize),
	}
}

// RecordResponse updates EWMA RTT, tracks error responses, and determines backoff conditions.
// Returns (needsBackoff bool, pauseDuration time.Duration).
func (m *TargetTelemetryMonitor) RecordResponse(rtt time.Duration, statusCode int, netErr error) (bool, time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.totalRequests.Add(1)
	rttMs := float64(rtt.Milliseconds())
	if rttMs < 1.0 {
		rttMs = 1.0
	}

	// Update EWMA RTT with alpha = 0.2
	const alpha = 0.2
	if m.sampleCount == 0 {
		m.ewmaRTT = rttMs
		m.baselineRTT = rttMs
	} else {
		m.ewmaRTT = (alpha * rttMs) + ((1.0 - alpha) * m.ewmaRTT)
	}
	m.sampleCount++

	// Determine if this response signifies target stress or rate-limiting
	isError := false
	if netErr != nil {
		isError = true
	} else if statusCode == http.StatusTooManyRequests || // 429
		statusCode == http.StatusBadGateway || // 502
		statusCode == http.StatusServiceUnavailable || // 503
		statusCode == http.StatusGatewayTimeout { // 504
		isError = true
	}

	if isError {
		m.totalErrors.Add(1)
	}

	// Update sliding window
	if m.windowCount < m.windowSize {
		m.windowCount++
	}
	m.windowErrors[m.windowIdx] = isError
	m.windowIdx = (m.windowIdx + 1) % m.windowSize

	// Compute current error rate in window
	errSum := 0
	for i := 0; i < m.windowCount; i++ {
		if m.windowErrors[i] {
			errSum++
		}
	}
	if m.windowCount > 0 {
		m.errorRate = float64(errSum) / float64(m.windowCount)
	} else {
		m.errorRate = 0.0
	}

	// Adaptive Backoff Logic:
	// 1. Error rate > 5% (0.05)
	// 2. Latency spike: EWMA > 3x baseline RTT (provided baseline is established with >= 5 samples)
	latencySpike := m.sampleCount >= 5 && m.baselineRTT > 0 && (m.ewmaRTT >= 3.0*m.baselineRTT)
	highErrors := m.windowCount >= 5 && m.errorRate > 0.05

	if highErrors || latencySpike {
		// Calculate backoff pause
		pause := 3 * time.Second
		if m.errorRate > 0.20 {
			pause = 10 * time.Second
		}
		m.circuitBreakerTripped.Store(true)
		m.circuitTrips.Add(1)
		m.pauseUntil = time.Now().Add(pause)
		return true, pause
	}

	return false, 0
}

// IsPaused reports if the circuit breaker is currently holding requests to allow target recovery.
func (m *TargetTelemetryMonitor) IsPaused() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if time.Now().Before(m.pauseUntil) {
		return true
	}
	return false
}

// WaitUntilHealthy pauses execution if target health has degraded past safe thresholds.
func (m *TargetTelemetryMonitor) WaitUntilHealthy(ctx context.Context) error {
	m.mu.RLock()
	pause := m.pauseUntil
	m.mu.RUnlock()

	now := time.Now()
	if now.Before(pause) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(pause.Sub(now)):
			return nil
		}
	}
	return nil
}

// Snapshot returns a copy of current target metrics for telemetry dashboards.
func (m *TargetTelemetryMonitor) Snapshot() TargetHealthMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return TargetHealthMetrics{
		TotalRequests: m.totalRequests.Load(),
		TotalErrors:   m.totalErrors.Load(),
		ErrorRate:     math.Round(m.errorRate*1000) / 1000,
		AverageRTT:    time.Duration(m.ewmaRTT) * time.Millisecond,
		CircuitTrips:  m.circuitTrips.Load(),
		IsPaused:      time.Now().Before(m.pauseUntil),
	}
}
