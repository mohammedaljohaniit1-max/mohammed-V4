// Package ai provides local LLM triage of security findings via Ollama.
package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
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

// NewClient builds a triage client.
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

type ollamaRequest struct {
	Model   string                 `json:"model"`
	Prompt  string                 `json:"prompt"`
	Stream  bool                   `json:"stream"`
	Options map[string]interface{} `json:"options,omitempty"`
}

type ollamaResponse struct {
	Response string `json:"response"`
	Done     bool   `json:"done"`
	Error    string `json:"error,omitempty"`
}

const promptTemplate = `SYSTEM: You are a strict cybersecurity auditor. Be concise and direct.
TASK: Is the following security finding a real vulnerability or a false positive? Read the evidence carefully.
FINDING TYPE: %s
TARGET: %s
EVIDENCE: %s
ANSWER FORMAT (one line only): REAL or FALSE_POSITIVE
REASON FORMAT (one line only): brief reason under 20 words`

func (c *Client) TriageFinding(ctx context.Context, findingType, target, evidence string) (bool, string) {
	if c == nil || !c.Enabled {
		return true, "ollama_offline"
	}

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
		return true, "ollama_marshal_error"
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint+"/api/generate", bytes.NewReader(payload))
	if err != nil {
		return true, "ollama_request_error"
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if geminiKey := os.Getenv("GEMINI_API_KEY"); geminiKey != "" {
			return c.triageViaGemini(ctx, geminiKey, prompt)
		}
		if err != nil {
			return true, "ollama_offline"
		}
		resp.Body.Close()
		return true, fmt.Sprintf("ollama_status_%d", resp.StatusCode)
	}
	defer resp.Body.Close()

	var ores ollamaResponse
	if err := json.NewDecoder(resp.Body).Decode(&ores); err != nil {
		return true, "ollama_decode_error"
	}
	if ores.Error != "" {
		return true, "ollama_error: " + ores.Error
	}

	ans := strings.ToLower(ores.Response)
	if strings.Contains(ans, "false_positive") || strings.Contains(ans, "false positive") {
		return false, strings.TrimSpace(ores.Response)
	}
	return true, strings.TrimSpace(ores.Response)
}

type geminiRequest struct {
	Contents []struct {
		Parts []struct {
			Text string `json:"text"`
		} `json:"parts"`
	} `json:"contents"`
}

type geminiResponse struct {
	Candidates []struct {
		Content struct {
			Parts []struct {
				Text string `json:"text"`
			} `json:"parts"`
		} `json:"content"`
	} `json:"candidates"`
}

func (c *Client) triageViaGemini(ctx context.Context, apiKey, prompt string) (bool, string) {
	apiURL := "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=" + apiKey
	reqPayload := geminiRequest{
		Contents: []struct {
			Parts []struct {
				Text string `json:"text"`
			} `json:"parts"`
		}{
			{
				Parts: []struct {
					Text string `json:"text"`
				}{
					{Text: prompt},
				},
			},
		},
	}
	bodyData, err := json.Marshal(reqPayload)
	if err != nil {
		return true, "gemini_marshal_error"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(bodyData))
	if err != nil {
		return true, "gemini_req_error"
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return true, "gemini_offline"
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return true, fmt.Sprintf("gemini_status_%d", resp.StatusCode)
	}
	var gResp geminiResponse
	if err := json.NewDecoder(resp.Body).Decode(&gResp); err != nil || len(gResp.Candidates) == 0 {
		return true, "gemini_empty_response"
	}
	text := ""
	if len(gResp.Candidates[0].Content.Parts) > 0 {
		text = gResp.Candidates[0].Content.Parts[0].Text
	}
	lower := strings.ToLower(text)
	if strings.Contains(lower, "false_positive") || strings.Contains(lower, "false positive") {
		return false, "gemini: " + strings.TrimSpace(text)
	}
	return true, "gemini: " + strings.TrimSpace(text)
}
