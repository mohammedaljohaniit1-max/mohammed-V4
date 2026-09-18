package ingress

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestIngressMonitor_CheckEndpoint(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "test-nginx/1.22")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer ts.Close()

	monitor := NewIngressMonitor(2 * time.Second)
	ctx := context.Background()

	health := monitor.CheckEndpoint(ctx, ts.URL)
	if health == nil {
		t.Fatalf("expected non-nil EndpointHealth")
	}

	if !health.Healthy {
		t.Errorf("expected endpoint to be healthy, got: %s", health.ErrorMessage)
	}

	if health.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", health.StatusCode)
	}

	if health.ServerHeader != "test-nginx/1.22" {
		t.Errorf("expected Server header 'test-nginx/1.22', got '%s'", health.ServerHeader)
	}
}

func TestIngressMonitor_CompareEndpoints(t *testing.T) {
	ts1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts1.Close()

	ts2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer ts2.Close()

	monitor := NewIngressMonitor(2 * time.Second)
	ctx := context.Background()

	results := monitor.CompareEndpoints(ctx, []string{ts1.URL, ts2.URL})
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
}
