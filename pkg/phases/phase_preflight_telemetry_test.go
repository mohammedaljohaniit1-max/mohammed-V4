package phases

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mohammed-v3/core/pkg/config"
	"github.com/mohammed-v3/core/pkg/engine"
)

func TestPreFlightTelemetryPhase_Execute(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "preflight_phase_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.22-preflight")
		w.Header().Set("Cache-Control", "no-store, private")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer mockServer.Close()

	cfg := &config.Config{
		OutputDir: tempDir,
		Threads:   5,
		RateLimit: 100,
	}

	scope := &config.Scope{
		Domains: []string{mockServer.Listener.Addr().String()},
	}

	state := engine.NewState(cfg, scope)
	state.OutputFolder = tempDir

	phase := &PreFlightTelemetryPhase{}

	if phase.Name() != "Phase 0: Pre-Flight Telemetry & Asset Enrichment" {
		t.Errorf("unexpected phase name: %s", phase.Name())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := phase.Execute(ctx, state); err != nil {
		t.Fatalf("phase execution failed: %v", err)
	}

	// Verify audit_telemetry.json exists
	telemetryFile := filepath.Join(tempDir, "audit_telemetry.json")
	if _, err := os.Stat(telemetryFile); os.IsNotExist(err) {
		t.Errorf("expected audit_telemetry.json to be created")
	}

	// Verify ActiveCorrelator is active
	correlator := ActiveCorrelator()
	if correlator == nil {
		t.Errorf("expected active correlator instance")
	}
}
