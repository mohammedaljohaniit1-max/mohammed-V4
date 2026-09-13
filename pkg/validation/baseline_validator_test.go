package validation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBaselineValidator_CalibrateAndCatchAll(t *testing.T) {
	// Simulate an SPA / Wildcard server that responds 200 OK with "Welcome" to ANY URL
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><head><title>CatchAll App</title></head><body>Welcome to the SPA</body></html>"))
	}))
	defer ts.Close()

	bv := NewBaselineValidator()
	profile, err := bv.Calibrate(context.Background(), ts.URL+"/login", ts.Client())
	if err != nil {
		t.Fatalf("Calibrate failed: %v", err)
	}

	if !profile.IsCatchAll {
		t.Fatalf("expected profile.IsCatchAll to be true for wildcard 200 server")
	}

	// 1. Probe to a fake /.env on this server returning the same catch-all body
	fakeEnvBody := []byte("<html><head><title>CatchAll App</title></head><body>Welcome to the SPA</body></html>")
	if !bv.IsSoft404(http.StatusOK, fakeEnvBody, ts.URL+"/.env") {
		t.Fatalf("expected fakeEnvBody to be identified as Soft-404 false positive")
	}

	// 2. Response with slight whitespace / nonce variation within ±64 bytes
	slightVariation := []byte("<html><head><title>CatchAll App</title></head><body>Welcome to the SPA   </body></html>")
	if !bv.IsSoft404(http.StatusOK, slightVariation, ts.URL+"/.git/config") {
		t.Fatalf("expected slightVariation within tolerance to be identified as Soft-404")
	}
}

func TestExactTokenCheck(t *testing.T) {
	// Case 1: .env returns 200 OK HTML login/WAF page -> must reject
	htmlEnv := []byte("<html><body>Please log in to your account</body></html>")
	ok, reason := ExactTokenCheck("Sensitive File: .env", "https://example.com/.env", 200, htmlEnv, "text/html; charset=utf-8")
	if ok {
		t.Fatalf("expected HTML .env response to be rejected, reason: %s", reason)
	}

	// Case 2: .env returns genuine credentials -> must pass
	realEnv := []byte("APP_NAME=Laravel\nAPP_ENV=production\nAPP_KEY=base64:AbCdEf123456=\nDB_PASSWORD=secret")
	ok, reason = ExactTokenCheck("Sensitive File: .env", "https://example.com/.env", 200, realEnv, "text/plain")
	if !ok {
		t.Fatalf("expected genuine .env to pass, rejected with: %s", reason)
	}

	// Case 3: .git/config returns genuine repo config -> must pass
	realGit := []byte("[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n[remote \"origin\"]\n\turl = git@github.com:org/repo.git")
	ok, reason = ExactTokenCheck("Exposed Repository", "https://example.com/.git/config", 200, realGit, "text/plain")
	if !ok {
		t.Fatalf("expected genuine .git/config to pass, rejected with: %s", reason)
	}

	// Case 4: .git endpoint returns generic 200 without git tokens -> must reject
	fakeGit := []byte("Nothing to see here")
	ok, reason = ExactTokenCheck("Exposed Repository", "https://example.com/.git/HEAD", 200, fakeGit, "text/plain")
	if ok {
		t.Fatalf("expected fake .git response to be rejected")
	}

	// Case 5: Spring Actuator genuine JSON -> must pass
	realActuator := []byte(`{"status":"UP","components":{"diskSpace":{"status":"UP"}}}`)
	ok, reason = ExactTokenCheck("Diagnostic: Actuator", "https://example.com/actuator/health", 200, realActuator, "application/json")
	if !ok {
		t.Fatalf("expected genuine actuator health to pass, rejected with: %s", reason)
	}
}
