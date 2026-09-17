package verification

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mohammed-v3/core/pkg/governor"
)

func TestZeroNoiseGate_SimHashAndDifferential(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/user/profile":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"user_id": "usr-12345", "role": "admin", "email": "admin@example.com", "token": "secret-jwt-token-987654321"}`))
		case "/catalog/product":
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html><body><h1>Product View</h1><p>Public item description</p></body></html>`))
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

	// 1. Test BOLA public path exclusion: /catalog/product MUST fail BOLA validation
	isPublicBOLA := gate.ValidateBOLA(ts.URL+"/catalog/product?productId=17", []byte(`<html><body>Product 17</body></html>`), false)
	if isPublicBOLA {
		t.Fatalf("expected /catalog/product to be rejected by PublicRouteExclusionRegex")
	}

	// 2. Test BOLA private API validation: /api/user/profile with sensitive data MUST pass
	isPrivateBOLA := gate.ValidateBOLA(ts.URL+"/api/user/profile", []byte(`{"email": "test@example.com", "token": "secret-token-12345"}`), true)
	if !isPrivateBOLA {
		t.Fatalf("expected /api/user/profile to pass BOLA sensitivity validation")
	}

	// 3. Test CORS validation on unauthenticated public route without credentials
	headers := make(http.Header)
	headers.Set("Access-Control-Allow-Origin", "https://evil.com")
	isBadCORS := gate.ValidateCORS(headers, []byte(`<html><body>Public</body></html>`), false)
	if isBadCORS {
		t.Fatalf("expected unauthenticated CORS reflection to be discarded")
	}

	// 4. Test Differential Verification on valid private endpoint
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cand := FindingRecord{
		ID:         "BOLA-01",
		Title:      "BOLA User Profile",
		URL:        ts.URL + "/api/user/profile",
		Tool:       "api_security",
		Confidence: 85,
	}

	valid := gate.VerifyDifferential(ctx, cand, "/api/user/profile", "admin@example.com")
	if !valid {
		t.Fatalf("expected private API differential finding to pass verification")
	}
}
