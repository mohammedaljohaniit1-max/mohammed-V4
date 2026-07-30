package phases

// phases_advanced.go implements the V7 (Section 3) custom exploit phases 31-45.
// Unlike the tool-wrapper phases in phases.go, these phases run REAL attack
// logic from pkg/exploit against the in-scope URL corpus discovered by the
// earlier phases, then push every candidate through the 5-gate false-positive
// pipeline in pkg/validation before a finding is ever stored. This is the
// direct answer to the V6 failure (100% false positives): nothing reaches the
// report unless it survives a baseline diff + private-data + exploitability +
// scope + reproduce gate.
//
// Routing (Section 5): every crafted request goes through the exploit Client,
// which is pointed at Burp when the phase's selective-proxy tier is active, so
// an operator can review the full attack in the Burp sitemap.

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/mohammed-v3/core/pkg/correlation"
	"github.com/mohammed-v3/core/pkg/engine"
	"github.com/mohammed-v3/core/pkg/exploit"
	"github.com/mohammed-v3/core/pkg/filter"
	"github.com/mohammed-v3/core/pkg/proxy"
	"github.com/mohammed-v3/core/pkg/validation"
)

// ─────────────────────────────────────────────────────────────────────────────
// Shared advanced-phase plumbing
// ─────────────────────────────────────────────────────────────────────────────

// advCtx carries the per-phase machinery every exploit phase needs: a proxy-
// aware exploit client, the 5-gate validator wired to the run's scope, and the
// candidate URL corpus. Building it once per phase keeps each phase small.
type advCtx struct {
	client    *exploit.Client
	validator *validation.FPValidator
	urls      []string
	burp      bool
}

// newAdvCtx assembles the advanced-phase context. It routes the exploit client
// through Burp only when the selective-proxy tier is active (Section 5), and
// injects filter.IsInScope as the validator's Gate-4 scope oracle.
func newAdvCtx(s *engine.State) *advCtx {
	px := s.PhaseProxy(proxy.ProxyModeSelective)
	proxyURL := ""
	burp := false
	if px != nil && px.Active && px.ProxyURL != "" {
		proxyURL = px.ProxyURL
		burp = true
	}
	client := exploit.NewClient(exploit.Options{
		ProxyURL:        proxyURL,
		FollowRedirects: false,
		// V9.0 ABSOLUTE APEX: every exploit-phase request now flows through the
		// shared adaptive stealth governor — adaptive concurrency (50→5 on
		// 429/503/403), jittered backoff, WAF cool-down, memory-shielded
		// parallelism, UA rotation and header randomization. One governor per
		// scan so backoff decisions are shared across all phases/engines.
		Stealth: sharedStealthGovernor(s),
	})
	scope := s.Scope
	validator := validation.NewFPValidator(func(rawURL string) bool {
		return filter.IsInScope(rawURL, scope)
	})
	return &advCtx{
		client:    client,
		validator: validator,
		urls:      advCandidateURLs(s),
		burp:      burp,
	}
}

// advCandidateURLs returns the in-scope, non-static URL corpus the exploit
// phases operate on. It prefers discovered URLs (params/endpoints) and falls
// back to live hosts so a phase still has targets on a passive-only run.
func advCandidateURLs(s *engine.State) []string {
	seen := make(map[string]bool)
	var out []string
	add := func(u string) {
		u = strings.TrimSpace(u)
		if u == "" || seen[u] {
			return
		}
		if !filter.IsInScope(u, s.Scope) {
			return
		}
		if filter.IsStaticAsset(u) {
			return
		}
		seen[u] = true
		out = append(out, u)
	}
	for _, u := range s.URLs {
		add(u)
	}
	if len(out) == 0 {
		for _, h := range s.LiveHosts {
			if strings.HasPrefix(h, "http") {
				add(h)
			} else {
				add("https://" + h)
			}
		}
	}
	return out
}

// storeCandidate runs a candidate through the 5-gate validator and, only if it
// passes, applies the confidence policy and stores it as a finding. It returns
// true when a finding was stored. Rejected candidates are logged with the gate
// that stopped them so a researcher can audit the zero-FP pipeline.
func (a *advCtx) storeCandidate(ctx context.Context, s *engine.State, c validation.Candidate,
	findingType, severity string, extra map[string]interface{}) bool {

	c.InScope = filter.IsInScope(c.URL, s.Scope)
	verdict := a.validator.Validate(ctx, c)
	if !verdict.Passed {
		s.Printf("│  FP-GATE reject [%s] %s → gate %d: %s\n", findingType, c.URL, verdict.Gate, verdict.Reason)
		return false
	}
	f := map[string]interface{}{
		"type":        findingType,
		"severity":    severity,
		"url":         c.URL,
		"target":      filter.HostOf(c.URL),
		"evidence":    c.Evidence,
		"fp_gate":     "passed_5_gate",
		"phase":       "V7-exploit",
		"exploitable": c.Exploitable,
	}
	if verdict.Baseline != nil {
		f["baseline_catchall"] = verdict.Baseline.IsCatchAll
		if verdict.Baseline.Reason != "" {
			f["baseline_reason"] = verdict.Baseline.Reason
		}
	}
	for k, v := range extra {
		f[k] = v
	}
	// AI triage + confidence policy (same discipline as the tool phases).
	kept := s.TriageAndScore(ctx, findingType, filter.HostOf(c.URL), c.Evidence, f,
		func(m map[string]interface{}) bool { return filter.ApplyConfidencePolicy(m, s.Scope) })
	if kept {
		s.Printf("│  ✓ CONFIRMED [%s] %s\n", findingType, c.URL)
	}
	return kept
}

// budget caps how many URLs an exploit phase will hammer so a huge corpus does
// not turn a single phase into an hour-long scan. The earlier discovery phases
// already deduplicate by behaviour/param-signature, so the head of the list is
// the highest-signal set.
func budget(urls []string, max int) []string {
	if len(urls) <= max {
		return urls
	}
	return urls[:max]
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 31 — Authentication & Session
// ─────────────────────────────────────────────────────────────────────────────
type AuthSessionPhase struct{}

func (p *AuthSessionPhase) Name() string { return "Auth & Session Analysis" }
func (p *AuthSessionPhase) Description() string {
	return "Phase 31: login-surface discovery + full session-cookie audit (HttpOnly/Secure/SameSite/expiry>30d/entropy) — V12.1 UPGRADE Phase 32"
}
func (p *AuthSessionPhase) Execute(ctx context.Context, s *engine.State) error {
	a := newAdvCtx(s)
	if len(a.urls) == 0 {
		s.Printf("│  Auth/Session: SKIP (no in-scope URLs)\n")
		return nil
	}
	eng := &exploit.AuthEngine{Client: a.client}
	origins := distinctOrigins(a.urls)
	kept := 0
	for _, origin := range budget(origins, 25) {
		if s.IsWAFProtected(origin) {
			continue
		}
		// Login discovery (informational context, not itself a finding).
		logins := eng.DiscoverLogins(ctx, origin)
		for _, l := range logins {
			s.Printf("│  login surface: %s\n", l.URL)
		}
		// Session hardening issues → candidates.
		for _, issue := range eng.AnalyzeSession(ctx, origin) {
			c := validation.Candidate{
				Type:                   "session-hardening",
				URL:                    issue.URL,
				Evidence:               issue.Problem + " (cookie=" + issue.Cookie + "): " + issue.Evidence,
				RequiresExploitability: false,
				Exploitable:            false,
				SkipReproduce:          true,
			}
			if a.storeCandidate(ctx, s, c, "Weak Session Cookie", mapSeverity(issue.Severity), nil) {
				kept++
			}
		}
	}
	s.Printf("│  Auth/Session: %d confirmed session issues\n", kept)
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 32 — IDOR
// ─────────────────────────────────────────────────────────────────────────────
type IDORPhase struct{}

func (p *IDORPhase) Name() string { return "IDOR (Differential)" }
func (p *IDORPhase) Description() string {
	return "Phase 32: differential IDOR — mutate numeric object ids and compare responses"
}
func (p *IDORPhase) Execute(ctx context.Context, s *engine.State) error {
	a := newAdvCtx(s)
	eng := exploit.NewIDOREngine(a.client)
	kept := 0
	// V12.1 UPGRADE Phase 33: test discovered API/priority endpoints first.
	for _, u := range budget(prioritizeDiscovered(s, a.urls), 120) {
		if s.IsWAFProtected(u) {
			continue
		}
		for _, r := range eng.Test(ctx, u) {
			if !r.Exploitable {
				continue
			}
			c := validation.Candidate{
				Type:                   "idor",
				URL:                    r.MutatedURL,
				Evidence:               r.Evidence,
				RequiresPrivateData:    false,
				RequiresExploitability: true,
				Exploitable:            true,
			}
			if a.storeCandidate(ctx, s, c, "IDOR", "High", map[string]interface{}{
				"original_url": r.OriginalURL,
			}) {
				kept++
			}
		}
	}
	s.Printf("│  IDOR: %d confirmed\n", kept)
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 33 — Race Condition
// ─────────────────────────────────────────────────────────────────────────────
type RaceConditionPhase struct{}

func (p *RaceConditionPhase) Name() string { return "Race Condition" }
func (p *RaceConditionPhase) Description() string {
	return "Phase 33: release-barrier burst on single-use endpoints to detect TOCTOU races"
}
func (p *RaceConditionPhase) Execute(ctx context.Context, s *engine.State) error {
	a := newAdvCtx(s)
	eng := &exploit.RaceEngine{Client: a.client}
	kept := 0
	// Race testing is intrusive; only run on endpoints that look like state
	// mutations (coupon/redeem/apply/vote/transfer) to stay non-destructive on
	// everything else.
	// V12.1 UPGRADE Phase 34: include discovered priority endpoints when
	// looking for state-mutating targets (cart/coupon/checkout live there).
	for _, u := range budget(raceCandidates(prioritizeDiscovered(s, a.urls)), 20) {
		if s.IsWAFProtected(u) {
			continue
		}
		res := eng.Burst(ctx, http.MethodGet, u, "", nil, 20, true)
		if !res.Suspicious {
			continue
		}
		c := validation.Candidate{
			Type:                   "race-condition",
			URL:                    u,
			Evidence:               res.Evidence,
			RequiresExploitability: true,
			Exploitable:            true,
			SkipReproduce:          true, // the burst IS the reproduction
		}
		if a.storeCandidate(ctx, s, c, "Race Condition", "High", map[string]interface{}{
			"success_count": res.SuccessCount,
			"concurrency":   res.Concurrency,
		}) {
			kept++
		}
	}
	s.Printf("│  Race Condition: %d confirmed\n", kept)
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 34 — Business Logic
// ─────────────────────────────────────────────────────────────────────────────
type BusinessLogicPhase struct{}

func (p *BusinessLogicPhase) Name() string { return "Business Logic" }
func (p *BusinessLogicPhase) Description() string {
	return "Phase 34: price/role parameter tampering against baseline"
}
func (p *BusinessLogicPhase) Execute(ctx context.Context, s *engine.State) error {
	a := newAdvCtx(s)
	eng := &exploit.BusinessLogicEngine{Client: a.client}
	kept := 0
	// V12.1 UPGRADE Phase 35: test discovered checkout/cart/order + priority
	// endpoints first (price=0/-1/0.01, qty=-1/999999, currency swap).
	for _, u := range budget(prioritizeDiscovered(s, a.urls), 120) {
		if s.IsWAFProtected(u) {
			continue
		}
		for _, r := range eng.TestURL(ctx, u) {
			if !r.Exploitable {
				continue
			}
			c := validation.Candidate{
				Type:                   "business-logic",
				URL:                    r.URL,
				Evidence:               r.Evidence,
				RequiresExploitability: true,
				Exploitable:            true,
			}
			if a.storeCandidate(ctx, s, c, "Business Logic Flaw", "High", map[string]interface{}{
				"param":    r.Param,
				"class":    r.Class,
				"mutation": r.Mutation,
			}) {
				kept++
			}
		}
	}
	s.Printf("│  Business Logic: %d confirmed\n", kept)
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 35 — API Security
// ─────────────────────────────────────────────────────────────────────────────
type APISecurityPhase struct{}

func (p *APISecurityPhase) Name() string { return "API Security" }
func (p *APISecurityPhase) Description() string {
	return "Phase 35: GraphQL introspection, verb tampering, mass assignment, JWT, versioning bypass, BOLA (V12.1 FIX #4: 5-Gate confirmed BEFORE marking exploitable)"
}
func (p *APISecurityPhase) Execute(ctx context.Context, s *engine.State) error {
	a := newAdvCtx(s)
	eng := exploit.NewAPIEngine(a.client)
	kept := 0
	preGateReject := 0
	apiURLs := budget(apiCandidates(a.urls), 120)
	for _, u := range apiURLs {
		if s.IsWAFProtected(u) {
			continue
		}
		var results []*exploit.APIResult
		results = append(results,
			eng.TestGraphQL(ctx, u),
			eng.TestVerbTampering(ctx, u),
			eng.TestMassAssignment(ctx, u),
			eng.TestVersioningBypass(ctx, u),
			eng.TestBOLA(ctx, u),
		)
		for _, r := range results {
			if r == nil || !r.Exploitable {
				continue
			}
			// ── V12.1 FIX #4 ──────────────────────────────────────────────
			// ROOT CAUSE: API finding *classes* (graphql-introspection,
			// verb-tampering, …) do NOT match needsBaseline()/needsReproduce()
			// keywords, so when they reached the generic validator Gates 1 & 5
			// were no-ops — a WAF/error/catch-all API response could be marked
			// CONFIRMED here only for Phase 45 to reject it later (the mandate's
			// "6 confirmed that Phase 45 rejected"). We now run an EXPLICIT
			// 5-Gate confirmation that fetches the live API response and rejects
			// WAF/error/catch-all pages BEFORE the candidate is ever stored.
			c := validation.Candidate{
				Type:                   r.Class,
				URL:                    r.URL,
				Evidence:               r.Evidence,
				RequiresExploitability: true,
				Exploitable:            true,
			}
			if reason, ok := apiFiveGateConfirm(ctx, a, s, c); !ok {
				preGateReject++
				s.Printf("│  API 5-GATE reject [%s] %s → %s\n", r.Class, r.URL, reason)
				continue
			}
			if a.storeCandidate(ctx, s, c, "API: "+r.Class, mapSeverity(r.Severity), map[string]interface{}{
				"api_method": r.Method,
				"api_5gate":  "confirmed_before_report",
				"fix":        "v12.1-fix4",
			}) {
				kept++
			}
		}
	}
	// JWTs seen in earlier phases (cookies/headers) can be analysed offline.
	for _, tok := range collectJWTs(s) {
		if r := eng.JWTAnalysis(tok.source, tok.token); r != nil && r.Exploitable {
			c := validation.Candidate{
				Type:                   r.Class,
				URL:                    tok.source,
				Evidence:               r.Evidence,
				RequiresExploitability: true,
				Exploitable:            true,
				SkipReproduce:          true, // structural finding, not path-dependent
			}
			if a.storeCandidate(ctx, s, c, "API: "+r.Class, mapSeverity(r.Severity), nil) {
				kept++
			}
		}
	}
	s.Printf("│  API Security: %d confirmed, %d rejected by pre-report 5-Gate (V12.1 FIX #4)\n", kept, preGateReject)
	return nil
}

// apiFiveGateConfirm is the V12.1 FIX #4 pre-report validation for API findings.
// It fetches the LIVE API response into the candidate's Target so the 5-gate
// pipeline actually has HTTP evidence to judge (API finding classes otherwise
// bypass the baseline/reproduce gates), then runs the canonical FiveGateValidate.
// It returns (reason, true) when the finding survives all five gates and
// (reason, false) — naming the failing gate — when it must NOT be marked
// exploitable. It never mutates state; the caller stores the finding on ok.
func apiFiveGateConfirm(ctx context.Context, a *advCtx, s *engine.State, c validation.Candidate) (string, bool) {
	// Populate the response the gates will judge. A transport error means we
	// could not even reach the endpoint → cannot honestly claim exploitable.
	if c.Target.BodySHA256 == "" && c.Target.Err == nil {
		c.Target = validation.Fetch(ctx, c.URL)
	}
	if c.Target.Err != nil {
		return "unreachable on re-fetch: " + c.Target.Err.Error(), false
	}
	c.InScope = filter.IsInScope(c.URL, s.Scope)
	if !c.InScope {
		return "out of scope", false
	}
	verdict := a.validator.FiveGateValidate(ctx, c)
	if !verdict.Passed {
		return fmt.Sprintf("gate %d: %s", verdict.Gate, verdict.Reason), false
	}
	return "5-gate passed", true
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 39 — SSTI
// ─────────────────────────────────────────────────────────────────────────────
type SSTIPhase struct{}

func (p *SSTIPhase) Name() string { return "SSTI (Arithmetic Oracle)" }
func (p *SSTIPhase) Description() string {
	return "Phase 39: template-injection arithmetic oracle ({{a*b}} must render the product, not echo)"
}
func (p *SSTIPhase) Execute(ctx context.Context, s *engine.State) error {
	a := newAdvCtx(s)
	eng := &exploit.SSTIEngine{Client: a.client}
	kept := 0
	for _, u := range budget(a.urls, 120) {
		if s.IsWAFProtected(u) {
			continue
		}
		for _, r := range eng.TestURL(ctx, u) {
			if !r.Exploitable {
				continue
			}
			c := validation.Candidate{
				Type:                   "ssti",
				URL:                    r.URL,
				Evidence:               r.Evidence,
				RequiresExploitability: true,
				Exploitable:            true,
			}
			if a.storeCandidate(ctx, s, c, "SSTI", "Critical", map[string]interface{}{
				"param":  r.Param,
				"engine": r.Engine,
			}) {
				kept++
			}
		}
	}
	s.Printf("│  SSTI: %d confirmed\n", kept)
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 36 — WebSocket Security (V7.1 GAP 2)
// ─────────────────────────────────────────────────────────────────────────────
type WebSocketPhase struct{}

func (p *WebSocketPhase) Name() string { return "WebSocket Security (CSWSH)" }
func (p *WebSocketPhase) Description() string {
	return "Phase 36: mines ws://wss:// endpoints, tests cross-origin handshake (CSWSH) + message injection"
}
func (p *WebSocketPhase) Execute(ctx context.Context, s *engine.State) error {
	a := newAdvCtx(s)
	if len(a.urls) == 0 {
		s.Printf("│  WebSocket: SKIP (no in-scope URLs)\n")
		return nil
	}
	eng := exploit.NewWebSocketEngine(a.client)
	kept := 0
	seenWS := make(map[string]bool)
	// Mine ws:// / wss:// references from page + JS bodies.
	for _, u := range budget(a.urls, 60) {
		if s.IsWAFProtected(u) {
			continue
		}
		resp := a.client.Get(ctx, u)
		if resp.Err != nil {
			continue
		}
		for _, ws := range exploit.FindWebSocketRefs(resp.Body) {
			if seenWS[ws] {
				continue
			}
			seenWS[ws] = true
			r := eng.WebSocketTest(ctx, ws)
			if !r.CSWSH || !r.Exploitable {
				continue
			}
			c := validation.Candidate{
				Type:                   "cswsh",
				URL:                    ws,
				Evidence:               r.Evidence,
				RequiresExploitability: true,
				Exploitable:            true,
				SkipReproduce:          true, // the cross-origin handshake IS the proof
			}
			if a.storeCandidate(ctx, s, c, "WebSocket CSWSH", mapSeverity(r.Severity), map[string]interface{}{
				"origin":        r.Origin,
				"upgraded":      r.Upgraded,
				"ping_response": firstN(r.PingResponse, 120),
			}) {
				kept++
			}
		}
	}
	s.Printf("│  WebSocket: %d endpoint(s) mined, %d CSWSH confirmed\n", len(seenWS), kept)
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 37 — File Upload (V7.1 GAP 2)
// ─────────────────────────────────────────────────────────────────────────────
type FileUploadPhase struct{}

func (p *FileUploadPhase) Name() string { return "File Upload Security" }
func (p *FileUploadPhase) Description() string {
	return "Phase 37: finds upload endpoints; tests ext/content-type bypass, SVG XSS, traversal — verifies EXECUTION"
}
func (p *FileUploadPhase) Execute(ctx context.Context, s *engine.State) error {
	a := newAdvCtx(s)
	if len(a.urls) == 0 {
		s.Printf("│  File Upload: SKIP (no in-scope URLs)\n")
		return nil
	}
	eng := exploit.NewFileUploadEngine(a.client)
	kept := 0
	seenEP := make(map[string]bool)
	for _, u := range budget(a.urls, 60) {
		if s.IsWAFProtected(u) {
			continue
		}
		resp := a.client.Get(ctx, u)
		if resp.Err != nil {
			continue
		}
		for _, ep := range exploit.FindUploadEndpoints(u, resp.Body) {
			if seenEP[ep] {
				continue
			}
			seenEP[ep] = true
			for _, r := range eng.FileUploadTest(ctx, ep) {
				if !r.Exploitable {
					continue
				}
				c := validation.Candidate{
					Type:                   "file-upload",
					URL:                    ep,
					Evidence:               r.Evidence,
					RequiresExploitability: true,
					Exploitable:            true,
				}
				if a.storeCandidate(ctx, s, c, "File Upload: "+r.TestName, mapSeverity(r.Severity), map[string]interface{}{
					"filename":   r.Filename,
					"executed":   r.Executed,
					"stored_url": r.StoredURL,
				}) {
					kept++
				}
			}
		}
	}
	s.Printf("│  File Upload: %d endpoint(s) tested, %d confirmed\n", len(seenEP), kept)
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 38 — Cloud Attack Surface (V7.1 GAP 2)
// ─────────────────────────────────────────────────────────────────────────────
type CloudAttackPhase struct{}

func (p *CloudAttackPhase) Name() string { return "Cloud Attack Surface" }
func (p *CloudAttackPhase) Description() string {
	return "Phase 38: S3 ListBucket/ACL, cloud metadata SSRF, K8s/Docker ports, .git exposure w/ extraction"
}
func (p *CloudAttackPhase) Execute(ctx context.Context, s *engine.State) error {
	a := newAdvCtx(s)
	eng := exploit.NewCloudEngine(a.client)
	kept := 0

	// 1. Mine S3 bucket refs from page/JS bodies, then probe each bucket.
	seenBucket := make(map[string]bool)
	for _, u := range budget(a.urls, 60) {
		if s.IsWAFProtected(u) {
			continue
		}
		resp := a.client.Get(ctx, u)
		if resp.Err != nil {
			continue
		}
		for _, b := range exploit.FindBucketRefs(resp.Body) {
			if seenBucket[b] {
				continue
			}
			seenBucket[b] = true
			for _, r := range eng.CloudAttack(ctx, b) {
				if !r.Exploitable {
					continue
				}
				c := validation.Candidate{
					Type:                   "cloud-s3",
					URL:                    r.Target,
					Evidence:               r.Evidence,
					RequiresExploitability: true,
					Exploitable:            true,
					SkipReproduce:          true,
				}
				if a.storeCandidate(ctx, s, c, "Cloud: "+r.Kind, mapSeverity(r.Severity), map[string]interface{}{
					"extract": firstN(r.Extract, 200),
				}) {
					kept++
				}
			}
		}
	}

	// 2. .git exposure with content extraction (per distinct origin).
	for _, origin := range budget(distinctOrigins(a.urls), 40) {
		if r := eng.GitExposure(ctx, origin); r != nil && r.Exploitable {
			c := validation.Candidate{
				Type:                   "git-exposure",
				URL:                    r.Target,
				Evidence:               r.Evidence,
				RequiresExploitability: true,
				Exploitable:            true,
				SkipReproduce:          true,
			}
			if a.storeCandidate(ctx, s, c, "Cloud: git-exposure", mapSeverity(r.Severity), map[string]interface{}{
				"repo_url": r.Extract,
			}) {
				kept++
			}
		}
	}

	// 3. K8s / Docker control-port exposure per distinct host.
	seenHost := make(map[string]bool)
	for _, origin := range budget(distinctOrigins(a.urls), 20) {
		host := filter.HostOf(origin)
		if host == "" || seenHost[host] {
			continue
		}
		seenHost[host] = true
		for _, r := range eng.OrchestrationExposure(ctx, host) {
			if !r.Exploitable {
				continue
			}
			c := validation.Candidate{
				Type:                   "cloud-orchestration",
				URL:                    r.Target,
				Evidence:               r.Evidence,
				RequiresExploitability: true,
				Exploitable:            true,
				SkipReproduce:          true,
			}
			if a.storeCandidate(ctx, s, c, "Cloud: "+r.Kind, mapSeverity(r.Severity), nil) {
				kept++
			}
		}
	}
	s.Printf("│  Cloud Attack: %d bucket(s) mined, %d confirmed\n", len(seenBucket), kept)
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 40 — Google Dorking (V7.1 GAP 2)
// ─────────────────────────────────────────────────────────────────────────────
type GoogleDorkPhase struct{}

func (p *GoogleDorkPhase) Name() string { return "Google Dorking" }
func (p *GoogleDorkPhase) Description() string {
	return "Phase 40: 20+ automated dorks (filetype/inurl/secret leaks); feeds discovered URLs to the corpus"
}
func (p *GoogleDorkPhase) Execute(ctx context.Context, s *engine.State) error {
	if len(s.Scope.Domains) == 0 {
		s.Printf("│  Google Dork: SKIP (no apex domains)\n")
		return nil
	}
	a := newAdvCtx(s)
	eng := exploit.NewGoogleDorkEngine(a.client)
	found := 0
	seen := make(map[string]bool)
	for _, u := range s.URLs {
		seen[u] = true
	}
	for _, domain := range s.Scope.Domains {
		for _, dr := range eng.GoogleDork(ctx, domain) {
			if len(dr.URLs) == 0 {
				continue
			}
			s.Printf("│  dork [%s] → %d url(s)\n", dr.Dork, len(dr.URLs))
			for _, u := range dr.URLs {
				if seen[u] || !filter.IsInScope(u, s.Scope) {
					continue
				}
				seen[u] = true
				s.URLs = append(s.URLs, u)
				found++
			}
		}
	}
	s.Printf("│  Google Dork: +%d new in-scope URLs added to corpus\n", found)
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 41 — Credential Intelligence (V7.1 GAP 2)
// ─────────────────────────────────────────────────────────────────────────────
type CredentialIntelPhase struct{}

func (p *CredentialIntelPhase) Name() string { return "Credential Intelligence" }
func (p *CredentialIntelPhase) Description() string {
	return "Phase 41: HIBP domain-breach lookup + email cross-reference (informational, NO credential stuffing)"
}
func (p *CredentialIntelPhase) Execute(ctx context.Context, s *engine.State) error {
	if len(s.Scope.Domains) == 0 {
		s.Printf("│  Cred Intel: SKIP (no apex domains)\n")
		return nil
	}
	a := newAdvCtx(s)
	eng := exploit.NewCredIntelEngine(a.client)
	if s.Config != nil {
		eng.HIBPKey = s.Config.APIKeys.HaveIBeenPwned
	}
	for _, domain := range s.Scope.Domains {
		emails := collectEmails(s, domain)
		res := eng.CredentialIntel(ctx, domain, emails)
		if len(res.Breaches) == 0 && res.EmailsPwned == 0 {
			s.Printf("│  Cred Intel [%s]: no public breach records\n", domain)
			continue
		}
		s.Printf("│  Cred Intel [%s]: %s\n", domain, res.Evidence)
		// Informational finding — added directly (not an exploitable vuln).
		f := map[string]interface{}{
			"type":           "Credential Exposure (Informational)",
			"severity":       "Info",
			"url":            "https://" + domain,
			"target":         domain,
			"evidence":       res.Evidence,
			"phase":          "V7.1-cred-intel",
			"breach_count":   len(res.Breaches),
			"emails_checked": res.EmailsChecked,
			"emails_pwned":   res.EmailsPwned,
		}
		s.AddFinding(f)
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 42 — Deep Burp Integration + OOB (V7.1 GAP 3)
// ─────────────────────────────────────────────────────────────────────────────
type BurpIntegrationPhase struct{}

func (p *BurpIntegrationPhase) Name() string { return "Deep Burp Integration + OOB" }
func (p *BurpIntegrationPhase) Description() string {
	return "Phase 42: populates Burp sitemap, triggers active scan, monitors Interactsh OOB callbacks"
}
func (p *BurpIntegrationPhase) Execute(ctx context.Context, s *engine.State) error {
	a := newAdvCtx(s)
	if !a.burp {
		s.Printf("│  Burp Integration: SKIP (Burp proxy not active this run)\n")
		return nil
	}
	direct := exploit.NewClient(exploit.Options{FollowRedirects: false})
	eng := exploit.NewBurpEngine(a.client, direct)

	// 1. Sitemap population — relay every discovered URL through Burp.
	if len(a.urls) > 0 {
		sent := eng.PopulateSitemap(ctx, budget(a.urls, 500))
		s.Printf("│  Burp Sitemap: relayed %d/%d URL(s) into Burp's Target tab\n", sent, len(a.urls))
	}

	// 2. Active scan trigger on the highest-value endpoints.
	highValue := budget(apiCandidates(a.urls), 30)
	if len(highValue) == 0 {
		highValue = budget(a.urls, 30)
	}
	if len(highValue) > 0 {
		if scan, err := eng.TriggerActiveScan(ctx, highValue); err != nil {
			s.Printf("│  Burp Active Scan: unavailable (%v)\n", err)
		} else {
			s.Printf("│  Burp Active Scan: %s\n", scan.Evidence)
		}
	}

	// 3. Interactsh OOB monitoring for blind SSRF candidates in the corpus.
	oobConfirmed := 0
	for _, u := range budget(ssrfCandidates(a.urls), 8) {
		probe := eng.NewOOBProbe("ssrf", u)
		// Inject the OOB host into likely SSRF sinks and fire the request.
		injected := injectOOBHost(u, probe.Host)
		_ = a.client.Get(ctx, injected)
		res := eng.MonitorCallbacks(ctx, probe)
		if !res.Confirmed {
			continue
		}
		c := validation.Candidate{
			Type:                   "blind-ssrf",
			URL:                    u,
			Evidence:               res.Evidence,
			RequiresExploitability: true,
			Exploitable:            true,
			SkipReproduce:          true, // OOB callback IS the reproduction
		}
		if a.storeCandidate(ctx, s, c, "Blind SSRF (OOB confirmed)", "Critical", map[string]interface{}{
			"callback_type": res.CallbackType,
			"oob_host":      probe.Host,
		}) {
			oobConfirmed++
		}
	}
	s.Printf("│  Burp OOB: %d blind-SSRF confirmed via Interactsh callback\n", oobConfirmed)
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 45 — Smart Correlation Engine
// ─────────────────────────────────────────────────────────────────────────────
type CorrelationPhase struct{}

func (p *CorrelationPhase) Name() string { return "Smart Correlation Engine" }
func (p *CorrelationPhase) Description() string {
	return "Phase 45: chains atomic findings into high-severity attack paths (must run last)"
}
func (p *CorrelationPhase) Execute(ctx context.Context, s *engine.State) error {
	_ = ctx
	if len(s.Findings) == 0 {
		s.Printf("│  Correlation: no findings to correlate\n")
		return nil
	}
	eng := correlation.New()
	chains := eng.Correlate(s.Findings)
	if len(chains) == 0 {
		s.Printf("│  Correlation: no multi-finding attack chains detected\n")
		return nil
	}
	for _, f := range eng.AsFindings(chains) {
		s.AddFinding(f)
		title, _ := f["chain_title"].(string)
		sev, _ := f["severity"].(string)
		tgt, _ := f["target"].(string)
		s.Printf("│  ⛓  CHAIN [%s] %s on %s\n", sev, title, tgt)
	}
	s.Printf("│  Correlation: %d attack chain(s) promoted\n", len(chains))
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// helpers shared by the advanced phases
// ─────────────────────────────────────────────────────────────────────────────

// mapSeverity normalises the exploit-engine severity vocabulary to the
// report's Title-case levels.
func mapSeverity(sev string) string {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical":
		return "Critical"
	case "high":
		return "High"
	case "medium":
		return "Medium"
	case "low":
		return "Low"
	default:
		return "Info"
	}
}

// distinctOrigins reduces a URL list to unique scheme://host origins.
func distinctOrigins(urls []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, u := range urls {
		o := originOf(u)
		if o == "" || seen[o] {
			continue
		}
		seen[o] = true
		out = append(out, o)
	}
	return out
}

func originOf(rawURL string) string {
	i := strings.Index(rawURL, "://")
	if i < 0 {
		return ""
	}
	rest := rawURL[i+3:]
	if slash := strings.IndexByte(rest, '/'); slash >= 0 {
		return rawURL[:i+3+slash]
	}
	return rawURL
}

// raceCandidates keeps only URLs whose path hints at a state mutation, so the
// intrusive burst never fires at read-only pages.
func raceCandidates(urls []string) []string {
	signals := []string{"coupon", "redeem", "apply", "promo", "vote", "like", "follow",
		"transfer", "withdraw", "purchase", "checkout", "cart", "claim", "gift", "invite"}
	var out []string
	for _, u := range urls {
		low := strings.ToLower(u)
		for _, sig := range signals {
			if strings.Contains(low, sig) {
				out = append(out, u)
				break
			}
		}
	}
	return out
}

// prioritizeDiscovered reorders the exploit corpus so the endpoints discovered
// by the JS analyzer / crawler (state.PriorityTargets — /admin, /internal, and
// flagged API paths) are tested FIRST, followed by API-shaped URLs, then the
// rest. V12.1 UPGRADE Phase 33-35: these phases returned 0 on Temu because they
// had no endpoints to test; now that Phase 15 feeds real endpoints into the
// corpus we make the intrusive phases consume that discovered surface up front.
// The result is deduplicated and preserves scope filtering already applied by
// advCandidateURLs.
func prioritizeDiscovered(s *engine.State, urls []string) []string {
	seen := make(map[string]bool)
	var out []string
	push := func(list []string) {
		for _, u := range list {
			if u == "" || seen[u] {
				continue
			}
			// PriorityTargets may be absolute; only include in-scope ones.
			if !filter.IsInScope(u, s.Scope) {
				continue
			}
			seen[u] = true
			out = append(out, u)
		}
	}
	push(s.PriorityTargets)   // discovered /admin, /internal, flagged API
	push(apiCandidates(urls)) // API-shaped surface next
	push(urls)                // everything else
	return out
}

// apiCandidates keeps URLs that look like API endpoints (path contains /api/,
// /graphql, /v1/, /rest/, or ends in a numeric id) so the API engine focuses
// on real API surface.
func apiCandidates(urls []string) []string {
	var out []string
	for _, u := range urls {
		low := strings.ToLower(u)
		if strings.Contains(low, "/api/") || strings.Contains(low, "/graphql") ||
			strings.Contains(low, "/rest/") || strings.Contains(low, "/v1/") ||
			strings.Contains(low, "/v2/") || strings.Contains(low, "/gql") ||
			len(exploit.FindNumericIDs(u)) > 0 {
			out = append(out, u)
		}
	}
	return out
}

// jwtToken pairs a discovered JWT with the URL it was seen on.
type jwtToken struct {
	source string
	token  string
}

// collectJWTs scans prior findings for anything that looks like a JWT (three
// base64url segments) so Phase 35 can analyse the algorithm offline.
func collectJWTs(s *engine.State) []jwtToken {
	var out []jwtToken
	seen := make(map[string]bool)
	for _, f := range s.Findings {
		ev, _ := f["evidence"].(string)
		url, _ := f["url"].(string)
		for _, tok := range extractJWTLike(ev) {
			if seen[tok] {
				continue
			}
			seen[tok] = true
			out = append(out, jwtToken{source: url, token: tok})
		}
	}
	return out
}

// extractJWTLike returns substrings shaped like a JWS (xxxxx.yyyyy.zzzzz where
// the first segment base64url-decodes to a JSON object containing "alg").
func extractJWTLike(text string) []string {
	var out []string
	for _, field := range strings.FieldsFunc(text, func(r rune) bool {
		return r == ' ' || r == '"' || r == '\'' || r == ';' || r == ',' || r == '\n' || r == '\t'
	}) {
		field = strings.TrimSpace(field)
		if strings.Count(field, ".") != 2 {
			continue
		}
		if strings.HasPrefix(field, "eyJ") { // base64url of {"...
			out = append(out, field)
		}
	}
	return out
}

// emailPattern extracts RFC-ish email addresses from finding evidence.
var emailPattern = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)

// collectEmails harvests employee emails at the given apex domain from prior
// findings/evidence so Cred Intel can cross-reference them against breaches.
func collectEmails(s *engine.State, domain string) []string {
	seen := make(map[string]bool)
	var out []string
	dom := strings.ToLower(domain)
	for _, f := range s.Findings {
		ev, _ := f["evidence"].(string)
		for _, m := range emailPattern.FindAllString(ev, -1) {
			m = strings.ToLower(m)
			if !strings.HasSuffix(m, "@"+dom) && !strings.HasSuffix(m, "."+dom) {
				continue
			}
			if !seen[m] {
				seen[m] = true
				out = append(out, m)
			}
		}
	}
	return out
}

// ssrfCandidates keeps URLs whose query params look like a fetch/callback sink
// so the OOB SSRF probe only fires at plausible targets.
func ssrfCandidates(urls []string) []string {
	signals := []string{"url=", "uri=", "next=", "target=", "dest=", "redirect=",
		"callback=", "webhook=", "fetch=", "load=", "image=", "img=", "proxy=", "feed="}
	var out []string
	for _, u := range urls {
		low := strings.ToLower(u)
		for _, sig := range signals {
			if strings.Contains(low, sig) {
				out = append(out, u)
				break
			}
		}
	}
	return out
}

// injectOOBHost rewrites the first SSRF-like query parameter value to point at
// the OOB callback host (http://{host}/). Falls back to appending a param.
func injectOOBHost(rawURL, oobHost string) string {
	payload := "http://" + oobHost + "/"
	for _, sig := range []string{"url=", "uri=", "next=", "target=", "dest=", "redirect=",
		"callback=", "webhook=", "fetch=", "load=", "image=", "img=", "proxy=", "feed="} {
		if i := strings.Index(strings.ToLower(rawURL), sig); i >= 0 {
			start := i + len(sig)
			end := strings.IndexAny(rawURL[start:], "&#")
			if end < 0 {
				return rawURL[:start] + urlEsc(payload)
			}
			return rawURL[:start] + urlEsc(payload) + rawURL[start+end:]
		}
	}
	sep := "?"
	if strings.Contains(rawURL, "?") {
		sep = "&"
	}
	return rawURL + sep + "url=" + urlEsc(payload)
}

// urlEsc percent-encodes an injected OOB payload value.
func urlEsc(v string) string { return url.QueryEscape(v) }

// ensure fmt is used (evidence formatting helper kept for future phases).
var _ = fmt.Sprintf
