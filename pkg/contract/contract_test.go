package contract

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestContractClient_RunTest(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/orders" {
			if r.Method == http.MethodPost {
				// Simulating boundary validation: reject invalid payload
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"invalid_amount"}`))
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer mockServer.Close()

	client := NewContractClient(mockServer.URL, 2*time.Second)
	ctx := context.Background()

	// Test boundary case: invalid amount should trigger 400 Bad Request
	tc := TestCase{
		Name:             "boundary_negative_amount",
		Method:           http.MethodPost,
		Path:             "/api/v1/orders",
		Payload:          map[string]interface{}{"amount": -50},
		ExpectedStatuses: []int{http.StatusBadRequest, http.StatusUnprocessableEntity},
	}

	res := client.RunTest(ctx, tc)
	if !res.Passed {
		t.Fatalf("expected test case to pass, failed: %s", res.FailureNotes)
	}
	if res.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", res.StatusCode)
	}

	// Test suite execution
	suite := []TestCase{
		tc,
		{
			Name:             "valid_health_check",
			Method:           http.MethodGet,
			Path:             "/health",
			ExpectedStatuses: []int{http.StatusOK},
		},
	}
	results := client.RunSuite(ctx, suite)
	if len(results) != 2 {
		t.Fatalf("expected 2 test results, got %d", len(results))
	}
	for _, r := range results {
		if !r.Passed {
			t.Errorf("test %s failed: %s", r.TestCase.Name, r.FailureNotes)
		}
	}
}
