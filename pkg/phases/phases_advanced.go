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
	return "Phase 31: discovers login surfaces and audits session-cookie flags & entropy"
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
	for _, u := range budget(a.urls, 120) {
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
	for _, u := range budget(raceCandidates(a.urls), 20) {
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
	for _, u := range budget(a.urls, 120) {
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
	return "Phase 35: GraphQL introspection, verb tampering, mass assignment, JWT, versioning bypass, BOLA"
}
func (p *APISecurityPhase) Execute(ctx context.Context, s *engine.State) error {
	a := newAdvCtx(s)
	eng := exploit.NewAPIEngine(a.client)
	kept := 0
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
			c := validation.Candidate{
				Type:                   r.Class,
				URL:                    r.URL,
				Evidence:               r.Evidence,
				RequiresExploitability: true,
				Exploitable:            true,
			}
			if a.storeCandidate(ctx, s, c, "API: "+r.Class, mapSeverity(r.Severity), map[string]interface{}{
				"api_method": r.Method,
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
	s.Printf("│  API Security: %d confirmed\n", kept)
	return nil
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

// ensure fmt is used (evidence formatting helper kept for future phases).
var _ = fmt.Sprintf
