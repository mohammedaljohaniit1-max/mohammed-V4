package phases

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mohammed-v3/core/pkg/config"
	"github.com/mohammed-v3/core/pkg/engine"
)

func TestAPISchemaAuditor(t *testing.T) {
	// Setup test server returning an OpenAPI v3 schema with an unprotected admin endpoint
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v3/api-docs":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{
				"openapi": "3.0.0",
				"paths": {
					"/api/v1/admin/export": {
						"get": {
							"summary": "Export Admin Config",
							"responses": {"200": {"description": "OK"}}
						}
					},
					"/api/v1/users/{uimUserId}/details": {
						"get": {
							"summary": "User Details",
							"parameters": [{"name": "uimUserId", "in": "path"}]
						}
					}
				}
			}`))
		case "/api/v1/admin/export":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"admin_config": "secret_data", "users_count": 42}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	cfg := &config.Config{OutputDir: t.TempDir()}
	scope := &config.Scope{Domains: []string{"127.0.0.1"}}
	state := engine.NewState(cfg, scope)
	state.LiveHosts = []string{ts.URL}

	phase := &APISchemaAuditorPhase{}
	err := phase.Execute(context.Background(), state)
	if err != nil {
		t.Fatalf("APISchemaAuditorPhase failed: %v", err)
	}

	foundBOLA := false
	foundUnprotected := false
	for _, f := range state.Findings {
		title, _ := f["title"].(string)
		if title == "API Object-Level Identifier Parameter (Potential BOLA/IDOR)" {
			foundBOLA = true
		}
		if title == "Broken Authentication / Unprotected Management Endpoint: /api/v1/admin/export" {
			foundUnprotected = true
		}
	}

	if !foundBOLA {
		t.Errorf("Expected BOLA parameter finding, got none")
	}
	if !foundUnprotected {
		t.Errorf("Expected Unprotected Management Endpoint finding, got none")
	}
}

func TestJSHarvester(t *testing.T) {
	// Setup test server serving a landing page and a JS bundle with hardcoded credentials and an endpoint
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html><head><script src="/static/bundle.js"></script></head><body>Hello</body></html>`))
		case "/static/bundle.js":
			w.Header().Set("Content-Type", "application/javascript")
			w.WriteHeader(http.StatusOK)
			// High-entropy AWS Key + Internal route
			_, _ = w.Write([]byte(`
				const awsKey = "AKIAIOSFODNN7EXAMPLE";
				const hiddenAPI = "/api/v2/internal/secrets";
			`))
		case "/static/bundle.js.map":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"version":3,"sources":["bundle.ts"]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	cfg := &config.Config{OutputDir: t.TempDir()}
	scope := &config.Scope{Domains: []string{"127.0.0.1"}}
	state := engine.NewState(cfg, scope)
	state.LiveHosts = []string{ts.URL}

	phase := &JSHarvesterPhase{}
	err := phase.Execute(context.Background(), state)
	if err != nil {
		t.Fatalf("JSHarvesterPhase failed: %v", err)
	}

	foundSecret := false
	foundSourceMap := false
	for _, f := range state.Findings {
		title, _ := f["title"].(string)
		if title == "Exposed AWS Access Key ID in JavaScript Bundle" {
			foundSecret = true
		}
		if title == "Exposed JavaScript Source Map (.js.map)" {
			foundSourceMap = true
		}
	}

	if !foundSecret {
		t.Errorf("Expected Exposed AWS Access Key ID finding, got none")
	}
	if !foundSourceMap {
		t.Errorf("Expected Exposed Source Map finding, got none")
	}

	// Verify internal route was extracted into state.URLs
	foundURL := false
	for _, u := range state.URLs {
		if u == ts.URL+"/api/v2/internal/secrets" {
			foundURL = true
			break
		}
	}
	if !foundURL {
		t.Errorf("Expected extracted URL %s/api/v2/internal/secrets, got %v", ts.URL, state.URLs)
	}
}

func TestSurgicalProbesCatchAll(t *testing.T) {
	// Setup test server returning 200 OK for everything (wildcard/catch-all site)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><body>404 Page Not Found - Custom Soft Catch-All</body></html>`))
	}))
	defer ts.Close()

	cfg := &config.Config{OutputDir: t.TempDir()}
	scope := &config.Scope{Domains: []string{"127.0.0.1"}}
	state := engine.NewState(cfg, scope)
	state.LiveHosts = []string{ts.URL}

	phase := &SurgicalProbesPhase{}
	err := phase.Execute(context.Background(), state)
	if err != nil {
		t.Fatalf("SurgicalProbesPhase failed: %v", err)
	}

	// Catch-all MUST be discarded: 0 findings expected
	if len(state.Findings) > 0 {
		t.Errorf("Expected 0 findings on catch-all server, got %d: %v", len(state.Findings), state.Findings)
	}
}
