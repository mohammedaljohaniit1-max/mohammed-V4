package collector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestUnifiedAuditEngine_ExecuteAudit(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "collector_audit_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.22-test")
		if r.URL.Path == "/api/v1/users" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"bad_request"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer mockServer.Close()

	engine := NewUnifiedAuditEngine(2*time.Second, tempDir)

	jsBundles := []string{
		`const endpoint = "/api/v1/users"; fetch(endpoint);`,
		`const health = "/health";`,
	}

	ctx := context.Background()
	report, err := engine.ExecuteAudit(ctx, mockServer.URL, jsBundles)
	if err != nil {
		t.Fatalf("unexpected error during audit: %v", err)
	}

	if report == nil {
		t.Fatalf("expected non-nil audit report")
	}

	if !report.ExecutionSuccess {
		t.Errorf("expected execution to be marked successful")
	}

	if len(report.DiscoveredRoutes) != 1 {
		t.Errorf("expected 1 api route extracted (/api/v1/users), got %d: %v", len(report.DiscoveredRoutes), report.DiscoveredRoutes)
	}

	if len(report.ContractResults) != 1 {
		t.Errorf("expected 1 contract test executed, got %d", len(report.ContractResults))
	} else {
		if !report.ContractResults[0].Passed {
			t.Errorf("expected contract test to pass on 400 rejection, failed: %s", report.ContractResults[0].FailureNotes)
		}
	}

	// Verify routes.json output was created
	routesFile := tempDir + "/routes.json"
	if _, err := os.Stat(routesFile); os.IsNotExist(err) {
		t.Errorf("expected output/routes.json to be written")
	}
}
