package contract

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// TestCase represents an individual boundary test case for API contract validation.
type TestCase struct {
	Name             string            `json:"name"`
	Method           string            `json:"method"`
	Path             string            `json:"path"`
	Headers          map[string]string `json:"headers,omitempty"`
	Payload          interface{}       `json:"payload,omitempty"`
	ExpectedStatuses []int             `json:"expected_statuses"` // E.g., [400, 422] for invalid inputs
}

// TestResult records the execution outcome of an API contract boundary test.
type TestResult struct {
	TestCase     TestCase      `json:"test_case"`
	StatusCode   int           `json:"status_code"`
	ResponseBody string        `json:"response_body"`
	Duration     time.Duration `json:"duration"`
	Passed       bool          `json:"passed"`
	FailureNotes string        `json:"failure_notes,omitempty"`
}

// ContractClient executes automated API integration boundary tests against endpoints.
type ContractClient struct {
	baseURL    string
	httpClient *http.Client
	timeout    time.Duration
}

// NewContractClient creates a new ContractClient.
func NewContractClient(baseURL string, timeout time.Duration) *ContractClient {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &ContractClient{
		baseURL: baseURL,
		timeout: timeout,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

// RunTest executes a single boundary test case and validates the response status against expected codes.
func (c *ContractClient) RunTest(ctx context.Context, tc TestCase) *TestResult {
	result := &TestResult{
		TestCase: tc,
	}

	callCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	var bodyReader io.Reader
	if tc.Payload != nil {
		data, err := json.Marshal(tc.Payload)
		if err != nil {
			result.Passed = false
			result.FailureNotes = fmt.Sprintf("failed to serialize payload: %v", err)
			return result
		}
		bodyReader = bytes.NewReader(data)
	}

	reqURL := c.baseURL + tc.Path
	req, err := http.NewRequestWithContext(callCtx, tc.Method, reqURL, bodyReader)
	if err != nil {
		result.Passed = false
		result.FailureNotes = fmt.Sprintf("failed to create request: %v", err)
		return result
	}

	req.Header.Set("Content-Type", "application/json")
	for k, v := range tc.Headers {
		req.Header.Set(k, v)
	}

	start := time.Now()
	resp, err := c.httpClient.Do(req)
	result.Duration = time.Since(start)

	if err != nil {
		result.Passed = false
		result.FailureNotes = fmt.Sprintf("request execution error: %v", err)
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	result.ResponseBody = string(bodyBytes)

	// Verify if actual status matches any of the expected statuses
	matched := false
	for _, expected := range tc.ExpectedStatuses {
		if resp.StatusCode == expected {
			matched = true
			break
		}
	}

	result.Passed = matched
	if !matched {
		result.FailureNotes = fmt.Sprintf("received status %d, expected one of %v", resp.StatusCode, tc.ExpectedStatuses)
	}

	return result
}

// RunSuite runs a collection of contract boundary test cases sequentially.
func (c *ContractClient) RunSuite(ctx context.Context, suite []TestCase) []*TestResult {
	results := make([]*TestResult, 0, len(suite))
	for _, tc := range suite {
		results = append(results, c.RunTest(ctx, tc))
	}
	return results
}
