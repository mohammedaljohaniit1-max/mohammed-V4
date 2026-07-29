// brain.go — MOHAMMED V10.0 SOVEREIGN — Local Ollama AI Cognitive Brain.
//
// Section 2 of the V10 mandate: a zero-cost, 100%-local cognitive engine on top
// of the existing triage Client. Where triage.go answers the single question
// "is this finding real?", the Brain adds the three higher-order cognitive
// responsibilities the mandate demands:
//
//  1. Semantic Response Triage  — reason over an ambiguous HTTP response to tell
//     a genuine DB error / stack trace apart from a sanitized, echoed string.
//  2. Dynamic Payload Mutation  — when a WAF/filter blocks a payload (403/406),
//     feed the block response back to the model and get mutated, bypass-oriented
//     variants in real time.
//  3. Business-Logic Decision Gate — read an API/JSON schema and rank the
//     endpoints/parameters most likely to hide IDOR / BOLA / privilege
//     escalation, so the stateful engines attack the highest-signal targets.
//
// Design rules (identical spirit to triage.go):
//   - stdlib-only, NO paid APIs, NO network beyond the local Ollama server.
//   - Fails OPEN and SAFE: if Ollama is unreachable/disabled every method returns
//     a conservative, deterministic fallback so the scan never blocks on the AI
//     layer and never loses a finding because the brain was offline.
//   - Model auto-fallback: tries a priority list (qwen2.5-coder → gemma → llama3.2)
//     and remembers the first model that answers, so a box with only gemma:2b
//     still works with zero configuration.
package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// DefaultModelPriority is the auto-fallback order from the mandate (Section 2.1):
// qwen2.5-coder for code/payload work, gemma for fast response analysis, and
// llama3.2 as the final fallback. The Brain probes /api/tags once and keeps the
// first installed model that matches this order.
var DefaultModelPriority = []string{
	"qwen2.5-coder:latest",
	"qwen2.5-coder",
	"gemma:7b",
	"gemma:2b",
	"gemma",
	"llama3.2:latest",
	"llama3.2",
}

// Brain is the V10 cognitive engine. It embeds a triage Client (reusing its
// endpoint, timeout and fail-open generate path) and layers model auto-fallback
// plus the three cognitive methods on top.
type Brain struct {
	// Client is the underlying Ollama connection (endpoint/timeout/http).
	Client *Client
	// Online reflects the last connectivity probe. When false every method
	// returns its deterministic fallback without touching the network.
	Online bool
	// available is the auto-fallback model list actually installed on the server
	// (intersection of DefaultModelPriority and /api/tags), resolved by Probe.
	available []string
}

// NewBrain builds a cognitive brain around an Ollama endpoint. enabled=false (or
// an empty endpoint that turns out unreachable) yields a brain whose methods all
// fail open. The primary model, when non-empty, is tried before the default
// priority list so an operator override is always honoured.
func NewBrain(enabled bool, endpoint, primaryModel string, timeoutSecs int) *Brain {
	c := NewClient(enabled, endpoint, primaryModel, timeoutSecs)
	return &Brain{Client: c}
}

// tagsResponse is the /api/tags listing body.
type tagsResponse struct {
	Models []struct {
		Name string `json:"name"`
	} `json:"models"`
}

// Probe performs the one-time startup connectivity + model-discovery check. It
// hits /api/tags, records every installed model, and computes the auto-fallback
// order: the configured primary model first (if installed), then the default
// priority list restricted to what is actually installed. Returns whether the
// brain is usable (enabled AND reachable AND at least one model present).
func (b *Brain) Probe(ctx context.Context) bool {
	if b == nil || b.Client == nil || !b.Client.Enabled {
		return false
	}
	to := b.Client.Timeout
	if to > 5*time.Second {
		to = 5 * time.Second
	}
	callCtx, cancel := context.WithTimeout(ctx, to)
	defer cancel()

	req, err := http.NewRequestWithContext(callCtx, http.MethodGet, b.Client.Endpoint+"/api/tags", nil)
	if err != nil {
		b.Online = false
		return false
	}
	resp, err := b.Client.http.Do(req)
	if err != nil {
		b.Online = false
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b.Online = false
		return false
	}
	var tags tagsResponse
	if err := json.NewDecoder(resp.Body).Decode(&tags); err != nil {
		b.Online = false
		return false
	}

	installed := make(map[string]bool, len(tags.Models))
	for _, m := range tags.Models {
		installed[strings.ToLower(strings.TrimSpace(m.Name))] = true
	}
	b.available = resolveModelOrder(b.Client.Model, installed)
	b.Online = len(b.available) > 0
	// Pin the underlying triage client to the best available model so legacy
	// TriageFinding calls also use a model that is actually installed.
	if b.Online {
		b.Client.Model = b.available[0]
	}
	return b.Online
}

// resolveModelOrder computes the auto-fallback list: the operator's primary
// model first (if installed), then DefaultModelPriority filtered to installed
// models, de-duplicated. When /api/tags returned nothing recognizable we keep
// the primary model as a last resort so a custom-named model still works.
func resolveModelOrder(primary string, installed map[string]bool) []string {
	var out []string
	seen := map[string]bool{}
	push := func(name string) {
		key := strings.ToLower(strings.TrimSpace(name))
		if key == "" || seen[key] {
			return
		}
		if installed[key] {
			seen[key] = true
			out = append(out, name)
		}
	}
	push(primary)
	for _, m := range DefaultModelPriority {
		push(m)
	}
	// If nothing matched but a primary was configured and the server listed
	// models we simply did not recognize, still allow the primary through.
	if len(out) == 0 && strings.TrimSpace(primary) != "" && len(installed) > 0 {
		out = append(out, primary)
	}
	return out
}

// ActiveModel returns the model the brain will use for its next call (best
// available after Probe, else the configured primary). Useful for banners/logs.
func (b *Brain) ActiveModel() string {
	if b == nil {
		return ""
	}
	if len(b.available) > 0 {
		return b.available[0]
	}
	if b.Client != nil {
		return b.Client.Model
	}
	return ""
}

// generate runs a single, non-streaming completion against the first working
// model in the fallback list. It walks b.available so a transient model error
// (e.g. model still loading) transparently drops to the next candidate. Returns
// ("", false) when the brain is offline or every model failed — callers then use
// their deterministic fallback.
func (b *Brain) generate(ctx context.Context, prompt string, numPredict int) (string, bool) {
	if b == nil || b.Client == nil || !b.Client.Enabled || !b.Online {
		return "", false
	}
	models := b.available
	if len(models) == 0 {
		models = []string{b.Client.Model}
	}
	for _, model := range models {
		if out, ok := b.generateWith(ctx, model, prompt, numPredict); ok {
			return out, true
		}
	}
	return "", false
}

// generateWith runs one completion against a specific model.
func (b *Brain) generateWith(ctx context.Context, model, prompt string, numPredict int) (string, bool) {
	if numPredict <= 0 {
		numPredict = 200
	}
	reqBody := ollamaRequest{
		Model:  model,
		Prompt: prompt,
		Stream: false,
		Options: map[string]interface{}{
			"temperature": 0.2,
			"num_predict": numPredict,
		},
	}
	payload, err := json.Marshal(reqBody)
	if err != nil {
		return "", false
	}
	callCtx, cancel := context.WithTimeout(ctx, b.Client.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(callCtx, http.MethodPost,
		b.Client.Endpoint+"/api/generate", bytes.NewReader(payload))
	if err != nil {
		return "", false
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := b.Client.http.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", false
	}
	var out ollamaResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", false
	}
	if out.Error != "" {
		return "", false
	}
	return strings.TrimSpace(out.Response), true
}

// ─────────────────────────────────────────────────────────────────────────
// 2.1 Semantic Response Triage
// ─────────────────────────────────────────────────────────────────────────

// SemanticVerdict is the structured result of reasoning over an ambiguous
// response. Vulnerable is the model's confirmation; Confidence is a coarse
// 0-100 self-assessment; Reason is a short human explanation.
type SemanticVerdict struct {
	Vulnerable bool
	Confidence int
	Reason     string
	// Offline is true when the brain could not be reached and a deterministic
	// heuristic fallback was used instead of the model.
	Offline bool
}

const semanticTriagePrompt = `SYSTEM: You are a strict application-security triage engine. Reason about CONTEXT.
Distinguish a genuine vulnerability signal (raw SQL/stack error, reflected+executed input, leaked secret, cross-user data) from a benign one (sanitized echo, generic 404, WAF block page, framework boilerplate).
FINDING TYPE: %s
REQUEST CONTEXT: %s
RESPONSE EVIDENCE: %s
Answer with EXACTLY three lines:
VERDICT: VULNERABLE or SAFE
CONFIDENCE: an integer 0-100
REASON: one short line under 20 words`

// SemanticTriage reasons over an ambiguous HTTP response and returns a
// structured verdict. When the brain is offline it falls back to a deterministic
// keyword heuristic (fail SAFE-toward-real: it never silently marks a finding
// safe when offline — Offline=true and Vulnerable defaults to the heuristic).
func (b *Brain) SemanticTriage(ctx context.Context, findingType, reqContext, evidence string) SemanticVerdict {
	if len(evidence) > 4000 {
		evidence = evidence[:4000]
	}
	if b == nil || !b.Online {
		return heuristicSemantic(findingType, evidence)
	}
	prompt := formatPrompt(semanticTriagePrompt, findingType, reqContext, evidence)
	raw, ok := b.generate(ctx, prompt, 96)
	if !ok {
		return heuristicSemantic(findingType, evidence)
	}
	return parseSemanticVerdict(raw)
}

// heuristicSemantic is the offline deterministic fallback: it looks for
// high-signal error/leak markers so an offline brain still gives a useful,
// conservative verdict without ever fabricating a model answer.
func heuristicSemantic(findingType, evidence string) SemanticVerdict {
	lower := strings.ToLower(evidence)
	markers := []string{
		"sql syntax", "syntax error", "unclosed quotation", "odbc", "psql:",
		"you have an error in your sql", "warning: mysqli", "stack trace",
		"traceback (most recent call last)", "java.lang.", "at org.springframework",
		"fatal error:", "exception in thread", "undefined index", "root:x:0:0",
	}
	for _, m := range markers {
		if strings.Contains(lower, m) {
			return SemanticVerdict{Vulnerable: true, Confidence: 60, Reason: "offline heuristic matched error/leak marker: " + m, Offline: true}
		}
	}
	// Benign markers that strongly indicate a false positive.
	benign := []string{"just a moment", "attention required", "access denied", "request blocked", "captcha"}
	for _, m := range benign {
		if strings.Contains(lower, m) {
			return SemanticVerdict{Vulnerable: false, Confidence: 20, Reason: "offline heuristic matched WAF/challenge page: " + m, Offline: true}
		}
	}
	_ = findingType
	return SemanticVerdict{Vulnerable: false, Confidence: 0, Reason: "brain offline, no deterministic marker", Offline: true}
}

// parseSemanticVerdict extracts VERDICT/CONFIDENCE/REASON from the model reply.
func parseSemanticVerdict(raw string) SemanticVerdict {
	v := SemanticVerdict{}
	for _, line := range strings.Split(raw, "\n") {
		l := strings.TrimSpace(line)
		u := strings.ToUpper(l)
		switch {
		case strings.HasPrefix(u, "VERDICT"):
			v.Vulnerable = strings.Contains(u, "VULNERABLE") && !strings.Contains(u, "NOT VULNERABLE")
		case strings.HasPrefix(u, "CONFIDENCE"):
			v.Confidence = extractInt(l)
		case strings.HasPrefix(u, "REASON"):
			if c := strings.Index(l, ":"); c != -1 {
				v.Reason = strings.TrimSpace(l[c+1:])
			}
		}
	}
	if v.Reason == "" {
		v.Reason = firstNonEmptyLine(raw)
	}
	if len(v.Reason) > 160 {
		v.Reason = v.Reason[:160]
	}
	// A bare answer with no explicit VERDICT line but containing VULNERABLE.
	if !v.Vulnerable && strings.Contains(strings.ToUpper(raw), "VULNERABLE") && !strings.Contains(strings.ToUpper(raw), "SAFE") {
		v.Vulnerable = true
	}
	if v.Confidence == 0 && v.Vulnerable {
		v.Confidence = 50
	}
	return v
}

// ─────────────────────────────────────────────────────────────────────────
// 2.2 Dynamic Payload Mutation
// ─────────────────────────────────────────────────────────────────────────

const payloadMutationPrompt = `SYSTEM: You are an offensive-security payload engineer for AUTHORIZED testing.
A payload was blocked by a WAF/filter. Produce mutated, semantically-equivalent bypass variants using encoding, case, comments, whitespace, and alternate syntax.
VULNERABILITY CLASS: %s
BLOCKED PAYLOAD: %s
WAF/BLOCK RESPONSE SNIPPET: %s
Output ONLY the mutated payloads, one per line, no prose, no numbering. Max 8 lines.`

// MutatePayload asks the model for WAF-bypass variants of a blocked payload.
// When the brain is offline it returns a deterministic set of classic encoding
// mutations so payload evasion still degrades gracefully to zero-cost local
// transforms. It never returns an empty slice (the caller always gets variants).
func (b *Brain) MutatePayload(ctx context.Context, vulnClass, blocked, wafResponse string) []string {
	blocked = strings.TrimSpace(blocked)
	if blocked == "" {
		return nil
	}
	if len(wafResponse) > 1500 {
		wafResponse = wafResponse[:1500]
	}
	if b != nil && b.Online {
		prompt := formatPrompt(payloadMutationPrompt, vulnClass, blocked, wafResponse)
		if raw, ok := b.generate(ctx, prompt, 220); ok {
			if muts := parsePayloadLines(raw, blocked); len(muts) > 0 {
				return muts
			}
		}
	}
	return deterministicMutations(blocked)
}

// parsePayloadLines turns the model's line-per-payload reply into a clean,
// de-duplicated slice, dropping prose/markdown and the original payload.
func parsePayloadLines(raw, original string) []string {
	var out []string
	seen := map[string]bool{strings.TrimSpace(original): true}
	for _, line := range strings.Split(raw, "\n") {
		l := strings.TrimSpace(line)
		l = strings.TrimPrefix(l, "- ")
		l = strings.Trim(l, "`")
		// Drop obvious prose lines (sentences ending in a period, no payload chars).
		if l == "" || seen[l] {
			continue
		}
		if len(l) > 400 {
			continue
		}
		// Skip lines that look like explanations rather than payloads.
		lower := strings.ToLower(l)
		if strings.HasPrefix(lower, "here") || strings.HasPrefix(lower, "these") ||
			strings.HasPrefix(lower, "note") || strings.HasPrefix(lower, "the ") {
			continue
		}
		seen[l] = true
		out = append(out, l)
		if len(out) >= 8 {
			break
		}
	}
	return out
}

// deterministicMutations is the offline fallback: classic zero-cost transforms
// that frequently slip past naive signature filters. Purely local, no network.
func deterministicMutations(p string) []string {
	muts := []string{
		strings.ToUpper(p),
		caseFlip(p),
		strings.ReplaceAll(p, " ", "/**/"),
		strings.ReplaceAll(p, " ", "%20"),
		strings.ReplaceAll(p, "<", "%3C"),
		urlEncodeAll(p),
		doubleURLEncode(p),
	}
	// De-duplicate and drop the identity mutation.
	seen := map[string]bool{p: true}
	var out []string
	for _, m := range muts {
		if m == "" || seen[m] {
			continue
		}
		seen[m] = true
		out = append(out, m)
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────────
// 2.3 Business-Logic Decision Gate
// ─────────────────────────────────────────────────────────────────────────

const bizLogicPrompt = `SYSTEM: You are an API authorization analyst. Given a list of API endpoints/params, identify which are most likely to hide IDOR, BOLA, or privilege-escalation flaws.
Prioritize object-id parameters (id, uuid, user_id, account, order), admin/role functions, and cross-tenant resources.
ENDPOINTS:
%s
Output ONLY the highest-risk endpoints, one per line, most-suspicious first. Max 10 lines. No prose.`

// RankIDORCandidates asks the model to rank endpoints by IDOR/BOLA likelihood.
// Offline it falls back to a deterministic scorer (object-id/admin heuristics).
// The result is always a subset/reordering of the input (never fabricated URLs).
func (b *Brain) RankIDORCandidates(ctx context.Context, endpoints []string) []string {
	if len(endpoints) == 0 {
		return nil
	}
	// Cap the prompt size — feed at most 60 endpoints to a small model.
	feed := endpoints
	if len(feed) > 60 {
		feed = feed[:60]
	}
	valid := make(map[string]bool, len(endpoints))
	for _, e := range endpoints {
		valid[strings.TrimSpace(e)] = true
	}
	if b != nil && b.Online {
		prompt := formatPrompt(bizLogicPrompt, strings.Join(feed, "\n"))
		if raw, ok := b.generate(ctx, prompt, 300); ok {
			var out []string
			seen := map[string]bool{}
			for _, line := range strings.Split(raw, "\n") {
				l := strings.TrimSpace(line)
				l = strings.TrimPrefix(l, "- ")
				l = strings.Trim(l, "`")
				// Only accept lines the model echoed back from the real input
				// (prevents hallucinated endpoints reaching the attack engines).
				if l != "" && valid[l] && !seen[l] {
					seen[l] = true
					out = append(out, l)
				}
			}
			if len(out) > 0 {
				return out
			}
		}
	}
	return HeuristicIDORRank(endpoints)
}

// HeuristicIDORRank is the deterministic, offline IDOR/BOLA prioritizer. Exposed
// so the stateful/BOLA engines can rank targets even with the brain disabled.
func HeuristicIDORRank(endpoints []string) []string {
	type scored struct {
		url   string
		score int
	}
	idSignals := []string{"id=", "/id/", "uuid", "user_id", "account", "order", "/users/", "/api/", "/v1/", "profile", "invoice", "document", "file_id", "customer"}
	adminSignals := []string{"admin", "role", "privilege", "internal", "manage", "owner", "delete", "grant"}
	var list []scored
	for _, e := range endpoints {
		lower := strings.ToLower(e)
		sc := 0
		for _, s := range idSignals {
			if strings.Contains(lower, s) {
				sc += 2
			}
		}
		for _, s := range adminSignals {
			if strings.Contains(lower, s) {
				sc += 3
			}
		}
		list = append(list, scored{e, sc})
	}
	// Stable insertion sort by descending score (keeps original order on ties).
	for i := 1; i < len(list); i++ {
		for j := i; j > 0 && list[j].score > list[j-1].score; j-- {
			list[j], list[j-1] = list[j-1], list[j]
		}
	}
	out := make([]string, 0, len(list))
	for _, s := range list {
		out = append(out, s.url)
	}
	return out
}
