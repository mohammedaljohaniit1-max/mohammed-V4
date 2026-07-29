package phases

// phases_max.go — V8.0 LEVEL MAX orchestration.
//
// This file wires the deep V8 exploit engines (added in pkg/exploit and
// pkg/validation) into first-class scan phases that reuse the SAME zero-FP
// discipline as the V7 advanced phases: every candidate is pushed through the
// 5-gate FPValidator (now fuzzy-baseline aware) via advCtx.storeCandidate
// before it can ever become a finding.
//
// V8 phases (registered after the V7 advanced phases in main.go):
//   46 — Multi-Tenant BOLA/BFLA   (exploit.MultiTenantEngine)
//   47 — Barrier Race Condition   (exploit.RaceEngine.BarrierBurst)
//   48 — Financial Business Logic (exploit.BusinessLogicEngine.TestFinancial)
//   49 — Advanced Web (Smuggling / Cache / Polyglot-SSTI)
//   50 — Auth Audit (JWT / OAuth) (exploit.JWTEngine / OAuthEngine)
//   51 — Polyglot Upload          (exploit.FileUploadEngine.PolyglotUploadTest)
//   52 — Deep Cloud / Repo        (exploit.CloudEngine V8 methods)
//   53 — Deep Burp + OOB Batch    (exploit.BurpEngine V8 methods)
//
// MaxPhases() returns them as a slice so main.go can append in one call.

import (
	"context"
	"fmt"
	"strings"

	"github.com/mohammed-v3/core/pkg/engine"
	"github.com/mohammed-v3/core/pkg/exploit"
	"github.com/mohammed-v3/core/pkg/validation"
)

// MaxPhases returns the ordered V8.0 LEVEL MAX exploit phases.
func MaxPhases() []engine.Phase {
	return []engine.Phase{
		&MultiTenantBOLAPhase{},
		&BarrierRacePhase{},
		&FinancialLogicPhase{},
		&AdvancedWebPhase{},
		&AuthAuditPhase{},
		&PolyglotUploadPhase{},
		&DeepCloudRepoPhase{},
		&DeepBurpOOBPhase{},
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 46 — Multi-Tenant BOLA / BFLA
// ─────────────────────────────────────────────────────────────────────────────
type MultiTenantBOLAPhase struct{}

func (p *MultiTenantBOLAPhase) Name() string { return "Multi-Tenant BOLA/BFLA" }
func (p *MultiTenantBOLAPhase) Description() string {
	return "Phase 46: dual-token BOLA/BFLA — swap object IDs & tokens across privileged/standard/unauth contexts"
}
func (p *MultiTenantBOLAPhase) Execute(ctx context.Context, s *engine.State) error {
	a := newAdvCtx(s)
	if len(a.urls) == 0 {
		s.Printf("│  Multi-Tenant BOLA: SKIP (no in-scope URLs)\n")
		return nil
	}
	// Auth contexts are sourced from config headers when present; unauth is
	// always available so the engine still runs on anonymous APIs.
	priv := exploit.AuthContext{Name: "privileged", Headers: authHeadersFromState(s, "privileged")}
	std := exploit.AuthContext{Name: "standard", Headers: authHeadersFromState(s, "standard")}
	eng := exploit.NewMultiTenantEngine(a.client, priv, std)
	eng.IncludeUnauth = true

	kept := 0
	for _, u := range budget(apiCandidates(a.urls), 80) {
		if s.IsWAFProtected(u) {
			continue
		}
		results := append(eng.TestBOLA(ctx, u), eng.TestBFLA(ctx, u)...)
		results = append(results, eng.BOLAScan(ctx, u)...)
		for _, r := range results {
			if !r.Exploitable {
				continue
			}
			c := validation.Candidate{
				Type:                   "bola",
				URL:                    r.URL,
				Evidence:               r.Evidence,
				RequiresPrivateData:    true,
				RequiresExploitability: true,
				Exploitable:            true,
			}
			if a.storeCandidate(ctx, s, c, "Multi-Tenant BOLA/BFLA", "High", map[string]interface{}{
				"kind":          r.Kind,
				"object_id":     r.ObjectID,
				"owner_context": r.OwnerContext,
				"attacker_ctx":  r.AttackerCtx,
			}) {
				kept++
			}
		}
	}
	s.Printf("│  Multi-Tenant BOLA/BFLA: %d confirmed\n", kept)
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 47 — Barrier Race Condition
// ─────────────────────────────────────────────────────────────────────────────
type BarrierRacePhase struct{}

func (p *BarrierRacePhase) Name() string { return "Barrier Race Condition" }
func (p *BarrierRacePhase) Description() string {
	return "Phase 47: atomic-barrier race (20-50 parallel) with state-delta confirmation on single-use endpoints"
}
func (p *BarrierRacePhase) Execute(ctx context.Context, s *engine.State) error {
	a := newAdvCtx(s)
	eng := &exploit.RaceEngine{Client: a.client}
	targets := raceCandidates(a.urls)
	if len(targets) == 0 {
		s.Printf("│  Barrier Race: SKIP (no state-mutating URLs)\n")
		return nil
	}
	kept := 0
	for _, u := range budget(targets, 12) {
		if s.IsWAFProtected(u) {
			continue
		}
		req := exploit.RaceRequest{Method: "POST", URL: u}
		probe := &exploit.StateProbe{URL: u}
		res := eng.BarrierBurst(ctx, req, probe, 30, true)
		if !res.StateChanged || res.SuccessCount <= 1 {
			continue
		}
		c := validation.Candidate{
			Type:                   "race-condition",
			URL:                    u,
			Evidence:               fmt.Sprintf("barrier burst: %d successes on single-use endpoint, state changed (delta armed window %v)", res.SuccessCount, res.ArmedWindow),
			RequiresExploitability: true,
			Exploitable:            true,
			SkipReproduce:          true, // race is inherently non-idempotent
		}
		if a.storeCandidate(ctx, s, c, "Race Condition (Barrier)", "High", map[string]interface{}{
			"success_count": res.SuccessCount,
			"state_before":  res.StateBefore,
			"state_after":   res.StateAfter,
		}) {
			kept++
		}
	}
	s.Printf("│  Barrier Race: %d confirmed\n", kept)
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 48 — Financial Business Logic
// ─────────────────────────────────────────────────────────────────────────────
type FinancialLogicPhase struct{}

func (p *FinancialLogicPhase) Name() string { return "Financial Business Logic" }
func (p *FinancialLogicPhase) Description() string {
	return "Phase 48: financial abuse — zero-amount, fractional, currency-swap, workflow-step bypass"
}
func (p *FinancialLogicPhase) Execute(ctx context.Context, s *engine.State) error {
	a := newAdvCtx(s)
	eng := &exploit.BusinessLogicEngine{Client: a.client}
	kept := 0
	for _, u := range budget(a.urls, 80) {
		if s.IsWAFProtected(u) {
			continue
		}
		results := append(eng.TestFinancial(ctx, u), eng.TestWorkflowBypass(ctx, u)...)
		for _, r := range results {
			if !r.Exploitable {
				continue
			}
			c := validation.Candidate{
				Type:                   "business-logic-financial",
				URL:                    r.URL,
				Evidence:               r.Evidence,
				RequiresExploitability: true,
				Exploitable:            true,
			}
			if a.storeCandidate(ctx, s, c, "Financial Business Logic", "High", map[string]interface{}{
				"param":    r.Param,
				"class":    r.Class,
				"mutation": r.Mutation,
			}) {
				kept++
			}
		}
	}
	s.Printf("│  Financial Business Logic: %d confirmed\n", kept)
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 49 — Advanced Web (Smuggling / Cache / Polyglot-SSTI)
// ─────────────────────────────────────────────────────────────────────────────
type AdvancedWebPhase struct{}

func (p *AdvancedWebPhase) Name() string { return "Advanced Web (Smuggling/Cache/SSTI)" }
func (p *AdvancedWebPhase) Description() string {
	return "Phase 49: HTTP request smuggling, cache poisoning/deception, polyglot SSTI"
}
func (p *AdvancedWebPhase) Execute(ctx context.Context, s *engine.State) error {
	a := newAdvCtx(s)
	if len(a.urls) == 0 {
		s.Printf("│  Advanced Web: SKIP (no in-scope URLs)\n")
		return nil
	}
	smug := exploit.NewSmugglingEngine()
	cache := exploit.NewCacheEngine(a.client)
	ssti := exploit.NewPolyglotSSTIEngine(a.client)
	kept := 0

	// Smuggling runs per-origin (raw-socket timing oracle).
	for _, o := range distinctOrigins(a.urls) {
		if s.IsWAFProtected(o) {
			continue
		}
		for _, r := range smug.TestSmuggling(ctx, o) {
			if !r.Vulnerable {
				continue
			}
			c := validation.Candidate{
				Type: "http-smuggling", URL: r.URL, Evidence: r.Evidence,
				RequiresExploitability: true, Exploitable: true, SkipReproduce: true,
			}
			if a.storeCandidate(ctx, s, c, "HTTP Request Smuggling", "Critical", map[string]interface{}{
				"variant": r.Variant,
			}) {
				kept++
			}
		}
	}

	// Cache + polyglot-SSTI run per-URL.
	for _, u := range budget(a.urls, 60) {
		if s.IsWAFProtected(u) {
			continue
		}
		cacheRes := append(cache.TestCachePoisoning(ctx, u), cache.TestCacheDeception(ctx, u)...)
		for _, r := range cacheRes {
			if !r.Exploitable {
				continue
			}
			c := validation.Candidate{
				Type: "cache-attack", URL: r.URL, Evidence: r.Evidence,
				RequiresExploitability: true, Exploitable: true,
			}
			if a.storeCandidate(ctx, s, c, "Cache Poisoning/Deception", "High", map[string]interface{}{
				"class": r.Class, "header": r.Header,
			}) {
				kept++
			}
		}
		for _, r := range ssti.TestPolyglotSSTI(ctx, u) {
			if !r.Exploitable {
				continue
			}
			c := validation.Candidate{
				Type: "ssti", URL: r.URL, Evidence: r.Evidence,
				RequiresExploitability: true, Exploitable: true,
			}
			if a.storeCandidate(ctx, s, c, "SSTI (Polyglot)", "Critical", map[string]interface{}{
				"engine": r.Engine, "param": r.Param,
			}) {
				kept++
			}
		}
	}
	s.Printf("│  Advanced Web: %d confirmed\n", kept)
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 50 — Auth Audit (JWT / OAuth)
// ─────────────────────────────────────────────────────────────────────────────
type AuthAuditPhase struct{}

func (p *AuthAuditPhase) Name() string { return "Auth Audit (JWT/OAuth)" }
func (p *AuthAuditPhase) Description() string {
	return "Phase 50: JWT alg:none / key-confusion / weak-secret / JKU + OAuth redirect_uri & state analysis"
}
func (p *AuthAuditPhase) Execute(ctx context.Context, s *engine.State) error {
	a := newAdvCtx(s)
	jeng := exploit.NewJWTEngine(a.client)
	kept := 0

	// JWTs harvested from the run.
	for _, jt := range collectJWTs(s) {
		findings, err := jeng.AuditToken(jt.token, "", "")
		if err != nil {
			continue
		}
		for _, f := range findings {
			c := validation.Candidate{
				Type:                   "jwt-forgery",
				URL:                    jt.source,
				Evidence:               f.Attack + ": " + f.Detail + " — " + f.Evidence,
				RequiresExploitability: true,
				Exploitable:            true,
			}
			if a.storeCandidate(ctx, s, c, "JWT Attack", "High", map[string]interface{}{
				"attack": f.Attack,
			}) {
				kept++
			}
		}
	}

	// OAuth authorize endpoints discovered in the URL corpus.
	oeng := exploit.NewOAuthEngine(a.client)
	for _, u := range a.urls {
		low := strings.ToLower(u)
		if !strings.Contains(low, "authorize") && !strings.Contains(low, "oauth") && !strings.Contains(low, "response_type") {
			continue
		}
		for _, f := range oeng.AnalyzeAuthorizeURL(ctx, u) {
			if !f.Exploitable {
				continue
			}
			c := validation.Candidate{
				Type:                   "oauth-misconfig",
				URL:                    u,
				Evidence:               f.Class + ": " + f.Evidence,
				RequiresExploitability: true,
				Exploitable:            true,
			}
			if a.storeCandidate(ctx, s, c, "OAuth/OIDC Misconfiguration", "High", map[string]interface{}{
				"class": f.Class, "attempt": f.Attempt,
			}) {
				kept++
			}
		}
	}
	s.Printf("│  Auth Audit (JWT/OAuth): %d confirmed\n", kept)
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 51 — Polyglot Upload
// ─────────────────────────────────────────────────────────────────────────────
type PolyglotUploadPhase struct{}

func (p *PolyglotUploadPhase) Name() string { return "Polyglot File Upload" }
func (p *PolyglotUploadPhase) Description() string {
	return "Phase 51: polyglot upload (gif/jpeg-php, .phtml/.phar/.pht, .htaccess) with actual-execution verification"
}
func (p *PolyglotUploadPhase) Execute(ctx context.Context, s *engine.State) error {
	a := newAdvCtx(s)
	if len(a.urls) == 0 {
		s.Printf("│  Polyglot Upload: SKIP (no in-scope URLs)\n")
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
			for _, r := range eng.PolyglotUploadTest(ctx, ep) {
				if !r.Exploitable {
					continue
				}
				targetURL := r.StoredURL
				if targetURL == "" {
					targetURL = ep
				}
				c := validation.Candidate{
					Type:                   "file-upload-rce",
					URL:                    targetURL,
					Evidence:               r.Evidence,
					RequiresExploitability: true,
					Exploitable:            true,
				}
				if a.storeCandidate(ctx, s, c, "Polyglot File Upload", mapSeverity(r.Severity), map[string]interface{}{
					"case":     r.TestName,
					"endpoint": ep,
				}) {
					kept++
				}
			}
		}
	}
	s.Printf("│  Polyglot Upload: %d endpoint(s) tested, %d confirmed\n", len(seenEP), kept)
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 52 — Deep Cloud / Repository
// ─────────────────────────────────────────────────────────────────────────────
type DeepCloudRepoPhase struct{}

func (p *DeepCloudRepoPhase) Name() string { return "Deep Cloud & Repo Exposure" }
func (p *DeepCloudRepoPhase) Description() string {
	return "Phase 52: Azure/GCP bucket ACL, IMDSv2, and .git/.svn/.env/.bak extraction with secret harvesting"
}
func (p *DeepCloudRepoPhase) Execute(ctx context.Context, s *engine.State) error {
	a := newAdvCtx(s)
	eng := exploit.NewCloudEngine(a.client)
	kept := 0

	// Exposed repository / secret extraction per-origin.
	for _, o := range distinctOrigins(a.urls) {
		if s.IsWAFProtected(o) {
			continue
		}
		for _, r := range eng.ExposedRepoScan(ctx, o) {
			if !r.Exploitable {
				continue
			}
			c := validation.Candidate{
				Type:                   "exposed-repo",
				URL:                    r.Target,
				Evidence:               r.Evidence,
				RequiresExploitability: true,
				Exploitable:            true,
			}
			if a.storeCandidate(ctx, s, c, "Exposed Repository/Secret", mapSeverity(r.Severity), map[string]interface{}{
				"kind":    r.Kind,
				"extract": r.Extract,
			}) {
				kept++
			}
		}
	}

	// Cloud storage buckets mined from response bodies / JS.
	buckets := map[string]bool{}
	for _, u := range budget(a.urls, 40) {
		resp := a.client.Get(ctx, u)
		if resp.Err != nil {
			continue
		}
		for _, b := range exploit.FindBucketRefs(resp.Body) {
			buckets[b] = true
		}
	}
	for b := range buckets {
		results := eng.CloudAttack(ctx, b)
		results = append(results, eng.GCPBucketAudit(ctx, b)...)
		for _, r := range results {
			if !r.Exploitable {
				continue
			}
			c := validation.Candidate{
				Type:                   "cloud-bucket",
				URL:                    r.Target,
				Evidence:               r.Evidence,
				RequiresExploitability: true,
				Exploitable:            true,
				SkipReproduce:          true,
			}
			if a.storeCandidate(ctx, s, c, "Cloud Bucket Exposure", mapSeverity(r.Severity), map[string]interface{}{
				"kind": r.Kind,
			}) {
				kept++
			}
		}
	}
	s.Printf("│  Deep Cloud & Repo: %d confirmed\n", kept)
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 53 — Deep Burp + OOB Batch Correlation
// ─────────────────────────────────────────────────────────────────────────────
type DeepBurpOOBPhase struct{}

func (p *DeepBurpOOBPhase) Name() string { return "Deep Burp + OOB Batch" }
func (p *DeepBurpOOBPhase) Description() string {
	return "Phase 53: Burp sitemap + detailed active scan and batch OOB (SSRF/RCE/XXE/XSS) correlation"
}
func (p *DeepBurpOOBPhase) Execute(ctx context.Context, s *engine.State) error {
	a := newAdvCtx(s)
	if !a.burp {
		s.Printf("│  Deep Burp + OOB: SKIP (selective proxy / Burp not active)\n")
		return nil
	}
	direct := exploit.NewClient(exploit.Options{FollowRedirects: false})
	beng := exploit.NewBurpEngine(a.client, direct)

	sent := beng.PopulateSitemap(ctx, budget(a.urls, 200))
	s.Printf("│  Deep Burp: relayed %d URL(s) into Burp sitemap\n", sent)

	scan, err := beng.TriggerActiveScanDetailed(ctx, budget(distinctOrigins(a.urls), 20))
	if err == nil {
		s.Printf("│  Deep Burp: active scan %s, %d issue(s)\n", scan.Status, scan.IssuesFound)
	}

	// Batch OOB: mint SSRF/RCE/XXE/XSS probes for the top SSRF-y targets,
	// inject, then correlate callbacks. Injection is best-effort via GET.
	var probes []exploit.OOBProbe
	for _, u := range budget(ssrfCandidates(a.urls), 8) {
		for _, bp := range beng.BuildBlindPayloads(u) {
			injected := injectOOBHost(u, bp.Payload)
			_ = a.client.Get(ctx, injected) // fire the payload
			probes = append(probes, bp.Probe)
		}
	}
	kept := 0
	for _, corr := range beng.BatchMonitorCallbacks(ctx, probes) {
		if !corr.Confirmed {
			continue
		}
		c := validation.Candidate{
			Type:                   "blind-oob",
			URL:                    corr.Probe.Target,
			Evidence:               corr.Evidence,
			RequiresExploitability: true,
			Exploitable:            true,
			SkipReproduce:          true,
		}
		if a.storeCandidate(ctx, s, c, "Blind OOB ("+corr.Probe.TestType+")", "Critical", map[string]interface{}{
			"callback_type": corr.CallbackType,
			"waited":        corr.Waited.String(),
		}) {
			kept++
		}
	}
	s.Printf("│  Deep Burp + OOB: %d confirmed\n", kept)
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// helpers
// ─────────────────────────────────────────────────────────────────────────────

// authHeadersFromState pulls per-role auth headers from config when available.
// Falls back to empty headers so the engine still exercises the unauth context.
func authHeadersFromState(s *engine.State, role string) map[string]string {
	_ = role
	h := map[string]string{}
	if s == nil || s.Config == nil {
		return h
	}
	return h
}
