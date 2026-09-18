package beacon

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCorrelator_RegisterAndResolve(t *testing.T) {
	correlator := NewCorrelator()

	token, err := correlator.Register("/api/v1/jobs/async")
	if err != nil {
		t.Fatalf("failed to register token: %v", err)
	}

	if token.Resolved {
		t.Errorf("token should not be resolved initially")
	}

	resolved, ok := correlator.Resolve(token.ID)
	if !ok || !resolved.Resolved {
		t.Fatalf("expected token to be resolved")
	}

	if resolved.ResolvedAt.Before(resolved.CreatedAt) {
		t.Errorf("resolved timestamp should be after created timestamp")
	}
}

func TestCallbackHandler_ServeHTTP(t *testing.T) {
	correlator := NewCorrelator()
	token, _ := correlator.Register("/webhooks/event")

	handler := NewCallbackHandler(correlator)

	// Test missing header
	reqMissing := httptest.NewRequest(http.MethodPost, "/callback", nil)
	rrMissing := httptest.NewRecorder()
	handler.ServeHTTP(rrMissing, reqMissing)
	if rrMissing.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing trace ID, got %d", rrMissing.Code)
	}

	// Test successful correlation via X-Correlation-ID
	reqValid := httptest.NewRequest(http.MethodPost, "/callback", nil)
	reqValid.Header.Set("X-Correlation-ID", token.ID)
	rrValid := httptest.NewRecorder()
	handler.ServeHTTP(rrValid, reqValid)

	if rrValid.Code != http.StatusOK {
		t.Errorf("expected 200 for valid correlation, got %d", rrValid.Code)
	}

	// Verify status in correlator
	status, ok := correlator.Get(token.ID)
	if !ok || !status.Resolved {
		t.Errorf("expected token state to be marked as resolved")
	}
}
