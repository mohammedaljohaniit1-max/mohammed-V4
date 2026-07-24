// Package ai provides local LLM triage of security findings via Ollama.
//
// It is intentionally dependency-free (stdlib only) and fails OPEN: if Ollama
// is unreachable or disabled, TriageFinding returns (true, "ollama_offline")
// so the scan never loses a finding because the AI layer was down. The point
// of triage is to DEMOTE confirmed false positives, never to silently drop
// real findings.
package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Client talks to a local Ollama server.
type Client struct {
	Enabled  bool
	Endpoint string
	Model    string
	Timeout  time.Duration
	http     *http.Client
}

// NewClient builds a triage client. endpoint/model default to sensible local
// values when empty. A non-enabled client short-circuits every call to
// "fail open" (returns REAL) without touching the network.
func NewClient(enabled bool, endpoint, model string, timeoutSecs int) *Client {
	if endpoint == "" {
		endpoint = "http://127.0.0.1:11434"
	}
	if model == "" {
		model = "gemma:2b"
	}
	if timeoutSecs <= 0 {
		timeoutSecs = 15
	}
	to := time.Duration(timeoutSecs) * time.Second
	return &Client{
		Enabled:  enabled,
		Endpoint: strings.TrimRight(endpoint, "/"),
		Model:    model,
		Timeout:  to,
		http:     &http.Client{Timeout: to},
	}
}

// Ping performs a ONE-TIME connectivity check against the Ollama server
// (FIX #7). It hits /api/tags with a short timeout. Returns true only if the
// server is enabled AND reachable AND answers 200. Used at startup so the whole
// run knows whether AI confirmation is available; when offline, unconfirmed
// Critical findings are downgraded to Unverified-Critical Info by the
// confidence policy rather than reported as confirmed.
func (c *Client) Ping(ctx context.Context) bool {
	if c == nil || !c.Enabled {
		return false
	}
	to := c.Timeout
	if to > 5*time.Second {
		to = 5 * time.Second
	}
	callCtx, cancel := context.WithTimeout(ctx, to)
	defer cancel()
	req, err := http.NewRequestWithContext(callCtx, http.MethodGet, c.Endpoint+"/api/tags", nil)
	if err != nil {
		return false
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// ollamaRequest is the /api/generate request body.
type ollamaRequest struct {
	Model   string                 `json:"model"`
	Prompt  string                 `json:"prompt"`
	Stream  bool                   `json:"stream"`
	Options map[string]interface{} `json:"options,omitempty"`
}

// ollamaResponse is the /api/generate response body (stream=false).
type ollamaResponse struct {
	Response string `json:"response"`
	Done     bool   `json:"done"`
	Error    string `json:"error,omitempty"`
}

// promptTemplate is intentionally rigid — small models (gemma:2b) need a strict
// structure or they ramble. Two clearly-delimited answer lines are requested.
const promptTemplate = `SYSTEM: You are a strict cybersecurity auditor. Be concise and direct.
TASK: Is the following security finding a real vulnerability or a false positive? Read the evidence carefully.
FINDING TYPE: %s
TARGET: %s
EVIDENCE: %s
ANSWER FORMAT (one line only): REAL or FALSE_POSITIVE
REASON FORMAT (one line only): brief reason under 20 words`

// TriageFinding asks the local model whether a finding is real.
//
// Returns (isConfirmed, reason).
//   - Ollama disabled/unreachable/errored → (true, "ollama_offline"): fail OPEN.
//   - Model answers FALSE_POSITIVE         → (false, reason).
//   - Model answers REAL / anything else   → (true, reason).
//
// ctx lets a cancelled scan abort the HTTP call promptly.
func (c *Client) TriageFinding(ctx context.Context, findingType, target, evidence string) (bool, string) {
	if c == nil || !c.Enabled {
		return true, "ollama_offline"
	}

	// Cap evidence size so we never send a multi-megabyte JS body to a 2B model.
	if len(evidence) > 4000 {
		evidence = evidence[:4000]
	}

	prompt := fmt.Sprintf(promptTemplate, findingType, target, evidence)
	reqBody := ollamaRequest{
		Model:  c.Model,
		Prompt: prompt,
		Stream: false,
		Options: map[string]interface{}{
			"temperature": 0.2,
			"num_predict": 80,
		},
	}
	payload, err := json.Marshal(reqBody)
	if err != nil {
		return true, "ollama_offline"
	}

	callCtx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(callCtx, http.MethodPost,
		c.Endpoint+"/api/generate", bytes.NewReader(payload))
	if err != nil {
		return true, "ollama_offline"
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return true, "ollama_offline"
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return true, "ollama_offline"
	}

	var out ollamaResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return true, "ollama_offline"
	}
	if out.Error != "" {
		return true, "ollama_offline"
	}

	return parseVerdict(out.Response)
}

// parseVerdict interprets the model's free-text answer. Default is REAL
// (fail open) unless the model clearly says FALSE_POSITIVE.
func parseVerdict(raw string) (bool, string) {
	text := strings.TrimSpace(raw)
	if text == "" {
		return true, "ollama_empty_response"
	}
	upper := strings.ToUpper(text)

	// Extract a short reason: first non-empty line that is not the verdict token.
	reason := ""
	for _, line := range strings.Split(text, "\n") {
		l := strings.TrimSpace(line)
		lu := strings.ToUpper(l)
		if l == "" || lu == "REAL" || lu == "FALSE_POSITIVE" {
			continue
		}
		// Strip a leading "REASON:" label if present.
		if idx := strings.Index(lu, "REASON"); idx == 0 {
			if c := strings.Index(l, ":"); c != -1 {
				l = strings.TrimSpace(l[c+1:])
			}
		}
		reason = l
		break
	}
	if len(reason) > 160 {
		reason = reason[:160]
	}

	// A model that mentions FALSE_POSITIVE (and does not also assert REAL first)
	// is treated as a false positive.
	if strings.Contains(upper, "FALSE_POSITIVE") || strings.Contains(upper, "FALSE POSITIVE") {
		if reason == "" {
			reason = "model flagged false positive"
		}
		return false, reason
	}
	if reason == "" {
		reason = "model confirmed real"
	}
	return true, reason
}
