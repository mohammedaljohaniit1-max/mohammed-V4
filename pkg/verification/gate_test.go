package verification

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mohammed-v3/core/pkg/governor"
)

func TestZeroNoiseGate_BaselineAndDifferential(t *testing.T) {
	// Setup test server that returns 200 OK with specific signature for verified path,
	// and generic soft-404 for random paths.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/actuator/health":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"UP","components":{"db":{"status":"UP"}}}`))
		default:
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`<html><body>404 Not Found</body></html>`))
		}
	}))
	defer ts.Close()

	gov := governor.NewGovernor(2)
	tempDir := t.TempDir()
	gate := NewZeroNoiseGate(tempDir, gov)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Verify verified endpoint with signature
	cand := FindingRecord{
		ID:         "TEST-01",
		Title:      "Spring Actuator Health",
		URL:        ts.URL + "/actuator/health",
		Confidence: 85,
	}

	valid := gate.VerifyDifferential(ctx, cand, "/actuator/health", `"status":"UP"`)
	if !valid {
		t.Fatalf("expected finding to be valid across differential probes")
	}

	cand.IsConfirmed = true
	gate.IngestFinding(cand)

	if err := gate.ExportArtifacts(); err != nil {
		t.Fatalf("failed to export artifacts: %v", err)
	}
}
