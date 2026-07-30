package phases

// phases_secret_weapons.go — MOHAMMED V12.0 OMEGA Secret Weapon phases (61-65).
//
// These five phases wire the pure-Go Secret Weapon engines (pkg/exploit) into
// the scan pipeline behind the SAME 5-gate false-positive discipline as every
// other exploit phase. Each phase:
//   • builds an advCtx (Burp-aware, stealth-governed client + scope validator),
//   • fails open on empty corpus / offline dependencies,
//   • only stores findings that clear validation + confidence policy.
//
//   Phase 61  API Endpoint Intelligence   — classify endpoints, run per-class
//                                            targeted attacks (Secret Weapon #1).
//   Phase 62  Response Differential        — auth/user/method/param diffs for
//                                            BOLA/IDOR/verb-tamper (Secret Weapon #2).
//   Phase 63  Intelligent Adaptive Fuzz    — WAF-adaptive XSS/SQLi/SSRF mutation,
//                                            AI-escalated (Secret Weapon #3).
//   Phase 64  JavaScript Deep Analysis     — mine JS for endpoints/secrets/source
//                                            maps with entropy validation (Secret Weapon #4).
//   Phase 65  Subdomain Intelligence       — functional grouping, staging-first
//                                            prioritization, Wayback diff (Secret Weapon #5).

import (
	"context"
	"fmt"
	"strings"

	"github.com/mohammed-v3/core/pkg/config"
	"github.com/mohammed-v3/core/pkg/engine"
	"github.com/mohammed-v3/core/pkg/exploit"
	"github.com/mohammed-v3/core/pkg/filter"
	"github.com/mohammed-v3/core/pkg/validation"
)

// SecretWeaponPhases returns the ordered V12.0 OMEGA Secret Weapon phases (61-65).
func SecretWeaponPhases() []engine.Phase {
	return []engine.Phase{
		&APIHunterPhase{},
		&ResponseDifferentialPhase{},
		&SmartFuzzPhase{},
		&JSDeepAnalysisPhase{},
		&SubdomainIntelPhase{},
	}
}

// swConfig reads the Secret Weapon configuration from state, applying safe
// defaults when no config is present (all weapons ON, standard budgets). This
// keeps each phase honouring the operator's config.yaml toggles/budgets.
func swConfig(s *engine.State) config.SecretWeaponsConfig {
	sw := config.SecretWeaponsConfig{}
	if s.Config != nil {
		sw = s.Config.SecretWeapons
	}
	// If the block is entirely zero-valued (no config at all), enable all.
	if !sw.APIHunter && !sw.Differential && !sw.SmartFuzz && !sw.JSDeep && !sw.SubdomainIntel &&
		sw.APIHunterBudget == 0 && sw.DifferentialBudget == 0 && sw.SmartFuzzBudget == 0 && sw.JSDeepBudget == 0 {
		sw.APIHunter, sw.Differential, sw.SmartFuzz = true, true, true
		sw.JSDeep, sw.SubdomainIntel, sw.WaybackHistory = true, true, true
	}
	if sw.APIHunterBudget == 0 {
		sw.APIHunterBudget = 400
	}
	if sw.DifferentialBudget == 0 {
		sw.DifferentialBudget = 250
	}
	if sw.SmartFuzzBudget == 0 {
		sw.SmartFuzzBudget = 150
	}
	if sw.JSDeepBudget == 0 {
		sw.JSDeepBudget = 200
	}
	return sw
}

// ─────────────────────────────────────────────────────────────────────────
// Phase 61 — API Endpoint Intelligence (Secret Weapon #1)
// ─────────────────────────────────────────────────────────────────────────

type APIHunterPhase struct{}

func (p *APIHunterPhase) Name() string { return "API Endpoint Intelligence" }
func (p *APIHunterPhase) Description() string {
	return "Phase 61: classify API endpoints (AUTH/DATA/MONEY/ADMIN/OAUTH) and run targeted per-class attack sequences"
}
func (p *APIHunterPhase) Execute(ctx context.Context, s *engine.State) error {
	sw := swConfig(s)
	if !sw.APIHunter {
		s.Printf("│  API Hunter: SKIP (disabled in config)\n")
		return nil
	}
	a := newAdvCtx(s)
	if len(a.urls) == 0 {
		s.Printf("│  API Hunter: SKIP (no in-scope URLs)\n")
		return nil
	}
	hunter := exploit.NewAPIHunter(a.client)
	classified := hunter.ClassifyAll(a.urls)
	s.Printf("│  API Hunter: %d classified endpoints from %d URLs\n", len(classified), len(a.urls))
	if len(classified) == 0 {
		return nil
	}

	findings := hunter.Hunt(ctx, budget(a.urls, sw.APIHunterBudget))
	for _, f := range findings {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		a.storeCandidate(ctx, s, validation.Candidate{
			Type:                   f.Type,
			URL:                    f.URL,
			Evidence:               f.Evidence,
			RequiresExploitability: true,
			Exploitable:            f.Exploitable,
			SkipReproduce:          true, // the engine already proved the effect once (PoE)
		}, "API: "+f.Type, f.Severity, map[string]interface{}{
			"api_class":    string(f.Class),
			"secret_weapon": "API Hunter (#1)",
		})
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────────
// Phase 62 — Response Differential Analysis (Secret Weapon #2)
// ─────────────────────────────────────────────────────────────────────────

type ResponseDifferentialPhase struct{}

func (p *ResponseDifferentialPhase) Name() string { return "Response Differential" }
func (p *ResponseDifferentialPhase) Description() string {
	return "Phase 62: cross-context structural JSON diff (auth vs unauth, user A vs B, verb tamper, param pollution) for BOLA/IDOR"
}
func (p *ResponseDifferentialPhase) Execute(ctx context.Context, s *engine.State) error {
	sw := swConfig(s)
	if !sw.Differential {
		s.Printf("│  Differential: SKIP (disabled in config)\n")
		return nil
	}
	a := newAdvCtx(s)
	if len(a.urls) == 0 {
		s.Printf("│  Differential: SKIP (no in-scope URLs)\n")
		return nil
	}
	eng := exploit.NewDifferentialEngine(a.client)

	// Build the two authenticated contexts from the auto-bootstrapped identities
	// when Phase 56 produced them; otherwise run the auth-vs-unauth and verb /
	// param tests that need no credentials.
	var userA, userB exploit.DiffContext
	haveIdentities := sovereignBootstrap.present
	if haveIdentities {
		userA = exploit.DiffContext{Name: "UserA", Headers: authHeader(sovereignBootstrap.userA)}
		userB = exploit.DiffContext{Name: "UserB", Headers: authHeader(sovereignBootstrap.userB)}
	}

	tested := 0
	for _, u := range budget(a.urls, sw.DifferentialBudget) {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		tested++

		// Test 1: auth vs unauth (needs at least User A).
		if haveIdentities {
			if d := eng.AuthVsUnauth(ctx, u, userA); d != nil {
				a.storeCandidate(ctx, s, diffCandidate(*d), "DIFF: "+d.Type, d.Severity, diffExtra(*d))
			}
			// Test 2: user A vs user B (BOLA/IDOR).
			if d := eng.UserAVsUserB(ctx, u, userA, userB); d != nil {
				a.storeCandidate(ctx, s, diffCandidate(*d), "DIFF: "+d.Type, d.Severity, diffExtra(*d))
			}
		}
		// Test 3: HTTP method / verb tampering (credential-optional).
		for _, d := range eng.MethodTamper(ctx, u, userA) {
			a.storeCandidate(ctx, s, diffCandidate(d), "DIFF: "+d.Type, d.Severity, diffExtra(d))
		}
		// Test 4: parameter pollution on the first query key of the URL.
		if key := firstQueryKey(u); key != "" {
			if d := eng.ParamPollution(ctx, u, key, "mohammed_a", "mohammed_b"); d != nil {
				a.storeCandidate(ctx, s, diffCandidate(*d), "DIFF: "+d.Type, d.Severity, diffExtra(*d))
			}
		}
	}
	s.Printf("│  Differential: analyzed %d URLs (identities=%v)\n", tested, haveIdentities)
	return nil
}

// ─────────────────────────────────────────────────────────────────────────
// Phase 63 — Intelligent Adaptive Fuzz (Secret Weapon #3)
// ─────────────────────────────────────────────────────────────────────────

type SmartFuzzPhase struct{}

func (p *SmartFuzzPhase) Name() string { return "Intelligent Adaptive Fuzz" }
func (p *SmartFuzzPhase) Description() string {
	return "Phase 63: WAF-adaptive mutation fuzzer (baseline→probe→adapt→AI-escalate) for XSS/SQLi/SSRF, stop-on-PoE"
}
func (p *SmartFuzzPhase) Execute(ctx context.Context, s *engine.State) error {
	sw := swConfig(s)
	if !sw.SmartFuzz {
		s.Printf("│  Smart Fuzz: SKIP (disabled in config)\n")
		return nil
	}
	a := newAdvCtx(s)
	if len(a.urls) == 0 {
		s.Printf("│  Smart Fuzz: SKIP (no in-scope URLs)\n")
		return nil
	}
	// The AI brain is optional (fail-open): pass it when online so exhausted
	// static mutations escalate to creative model-generated bypasses.
	var brain exploit.PayloadBrain
	if s.Brain != nil {
		brain = s.Brain
	}
	fz := exploit.NewSmartFuzzer(a.client, brain)

	classes := []exploit.FuzzClass{exploit.FuzzXSS, exploit.FuzzSQLI, exploit.FuzzSSRF}
	tested := 0
	for _, u := range budget(paramURLs(a.urls), sw.SmartFuzzBudget) {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		for _, key := range queryKeys(u) {
			for _, class := range classes {
				if hit := fz.FuzzParam(ctx, u, key, class); hit != nil {
					a.storeCandidate(ctx, s, validation.Candidate{
						Type:                   string(hit.Class),
						URL:                    hit.URL,
						Evidence:               hit.Evidence,
						RequiresExploitability: true,
						Exploitable:            hit.Exploitable,
						SkipReproduce:          true,
					}, "FUZZ: "+string(hit.Class), fuzzSeverity(hit.Class), map[string]interface{}{
						"param":         hit.Param,
						"payload":       hit.Payload,
						"waf_bypassed":  hit.Bypassed,
						"secret_weapon": "Smart Fuzz (#3)",
					})
				}
			}
		}
		tested++
	}
	s.Printf("│  Smart Fuzz: adaptively fuzzed %d parameterized URLs\n", tested)
	return nil
}

// ─────────────────────────────────────────────────────────────────────────
// Phase 64 — JavaScript Deep Analysis (Secret Weapon #4)
// ─────────────────────────────────────────────────────────────────────────

type JSDeepAnalysisPhase struct{}

func (p *JSDeepAnalysisPhase) Name() string { return "JavaScript Deep Analysis" }
func (p *JSDeepAnalysisPhase) Description() string {
	return "Phase 64: mine in-scope JS for endpoints/admin-routes/secrets/source-maps with Shannon-entropy validation"
}
func (p *JSDeepAnalysisPhase) Execute(ctx context.Context, s *engine.State) error {
	sw := swConfig(s)
	if !sw.JSDeep {
		s.Printf("│  JS Deep: SKIP (disabled in config)\n")
		return nil
	}
	a := newAdvCtx(s)
	jsURLs := jsAssetURLs(s)
	if len(jsURLs) == 0 {
		s.Printf("│  JS Deep: SKIP (no in-scope .js assets)\n")
		return nil
	}
	eng := exploit.NewJSDeepEngine(a.client)
	inScope := func(u string) bool { return filter.IsInScope(u, s.Scope) }
	findings := eng.AnalyzeURLs(ctx, budget(jsURLs, sw.JSDeepBudget), inScope)

	// Feed discovered endpoints back into the crawl corpus for later phases.
	newEndpoints := exploit.Endpoints(findings)
	added := 0
	for _, ep := range newEndpoints {
		full := absolutize(ep, s)
		if full != "" && filter.IsInScope(full, s.Scope) {
			s.URLs = append(s.URLs, full)
			added++
		}
	}

	secrets, others := 0, 0
	for _, f := range findings {
		if f.Kind == "Secret" {
			secrets++
			sev := "Medium"
			if f.Confidence == "high" {
				sev = "High"
			}
			a.storeCandidate(ctx, s, validation.Candidate{
				Type:                "JS Hardcoded Secret",
				URL:                 f.SourceURL,
				Evidence:            fmt.Sprintf("%s in %s (entropy=%.2f, %s): %s", f.Provider, f.SourceURL, f.Entropy, f.Confidence, redact(f.Value)),
				RequiresPrivateData: false,
				RequiresExploitability: true,
				Exploitable:         f.Confidence == "high",
				SkipReproduce:       true,
			}, "JS: Hardcoded Secret", sev, map[string]interface{}{
				"provider":      f.Provider,
				"entropy":       f.Entropy,
				"confidence":    f.Confidence,
				"secret_weapon": "JS Deep (#4)",
			})
		} else {
			others++
		}
	}
	s.Printf("│  JS Deep: %d JS files → %d secrets, %d artifacts, +%d endpoints to corpus\n",
		len(jsURLs), secrets, others, added)
	return nil
}

// ─────────────────────────────────────────────────────────────────────────
// Phase 65 — Subdomain Correlation Intelligence (Secret Weapon #5)
// ─────────────────────────────────────────────────────────────────────────

type SubdomainIntelPhase struct{}

func (p *SubdomainIntelPhase) Name() string { return "Subdomain Intelligence" }
func (p *SubdomainIntelPhase) Description() string {
	return "Phase 65: functional subdomain grouping, staging-first prioritization, staging-vs-prod diff, Wayback historical takeover analysis"
}
func (p *SubdomainIntelPhase) Execute(ctx context.Context, s *engine.State) error {
	sw := swConfig(s)
	if !sw.SubdomainIntel {
		s.Printf("│  Subdomain Intel: SKIP (disabled in config)\n")
		return nil
	}
	if len(s.Subdomains) == 0 {
		s.Printf("│  Subdomain Intel: SKIP (no subdomains)\n")
		return nil
	}
	a := newAdvCtx(s)
	eng := exploit.NewSubIntel(a.client)

	counts := eng.GroupCounts(s.Subdomains)
	s.Printf("│  Subdomain Intel: production=%d staging-dev=%d internal=%d infra=%d other=%d\n",
		counts[exploit.GroupProduction], counts[exploit.GroupStagingDev],
		counts[exploit.GroupInternal], counts[exploit.GroupInfra], counts[exploit.GroupOther])

	// Publish the staging/dev/internal-first exploit ordering for later phases.
	prioritized := eng.PrioritizedTargets(s.Subdomains)
	s.PriorityTargets = prioritized
	high := counts[exploit.GroupStagingDev] + counts[exploit.GroupInternal]
	if high > 0 {
		s.Printf("│  Subdomain Intel: %d staging/dev/internal hosts prioritized for exploit-first testing\n", high)
	}

	// Staging-vs-prod security-header diff (informational-to-medium signal).
	pairs := eng.StagingProdPairs(s.Subdomains)
	for st, pr := range pairs {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		if d := eng.CompareStagingProd(ctx, st, pr); d != nil {
			a.storeCandidate(ctx, s, validation.Candidate{
				Type:                   "Weaker Staging Security Config",
				URL:                    "https://" + st + "/",
				Evidence:               d.Evidence,
				RequiresExploitability: false,
				Exploitable:            false,
				SkipReproduce:          true,
			}, "SUBINTEL: Staging Weakness", "Low", map[string]interface{}{
				"prod_twin":       pr,
				"missing_headers": strings.Join(d.MissingHeaders, ","),
				"secret_weapon":   "Subdomain Intel (#5)",
			})
		}
	}

	// Historical (Wayback) analysis for the primary apex — dead archived hosts
	// become subdomain-takeover candidates.
	if sw.WaybackHistory && len(s.Scope.Domains) > 0 {
		hist := eng.Historical(ctx, s.Scope.Domains[0], s.Subdomains)
		if len(hist.TakeoverCandidates) > 0 {
			s.Printf("│  Subdomain Intel: %d historical hosts now dead → takeover candidates\n", len(hist.TakeoverCandidates))
			for _, h := range budgetStrings(hist.TakeoverCandidates, 25) {
				a.storeCandidate(ctx, s, validation.Candidate{
					Type:                   "Historical Subdomain (Takeover Candidate)",
					URL:                    "https://" + h + "/",
					Evidence:               "host " + h + " appears in the Wayback archive but is no longer live — verify for dangling takeover",
					RequiresExploitability: false,
					Exploitable:            false,
					SkipReproduce:          true,
				}, "SUBINTEL: Historical Takeover Candidate", "Informational", map[string]interface{}{
					"secret_weapon": "Subdomain Intel (#5)",
				})
			}
		}
		if len(hist.NewHosts) > 0 {
			s.Printf("│  Subdomain Intel: %d newly-appeared hosts (active development)\n", len(hist.NewHosts))
		}
	}
	return nil
}

// ── Shared helpers for the Secret Weapon phases ────────────────────────────

// authHeader builds an Authorization header map from a bootstrapped identity.
func authHeader(id exploit.Identity) map[string]string {
	if id.Token == "" {
		return nil
	}
	return map[string]string{"Authorization": "Bearer " + id.Token}
}

func diffCandidate(d exploit.DiffFinding) validation.Candidate {
	return validation.Candidate{
		Type:                   d.Type,
		URL:                    d.URL,
		Evidence:               d.Evidence,
		RequiresExploitability: d.Exploitable,
		Exploitable:            d.Exploitable,
		SkipReproduce:          true,
	}
}

func diffExtra(d exploit.DiffFinding) map[string]interface{} {
	return map[string]interface{}{
		"diff_test":     d.Test,
		"secret_weapon": "Differential (#2)",
	}
}

func fuzzSeverity(c exploit.FuzzClass) string {
	switch c {
	case exploit.FuzzXSS:
		return "Medium"
	case exploit.FuzzSQLI:
		return "High"
	case exploit.FuzzSSRF:
		return "High"
	}
	return "Medium"
}

// paramURLs filters a corpus down to URLs that carry a query string (fuzz
// targets). Non-parameterized URLs have nothing for the fuzzer to mutate.
func paramURLs(urls []string) []string {
	var out []string
	for _, u := range urls {
		if strings.Contains(u, "?") && strings.Contains(u, "=") {
			out = append(out, u)
		}
	}
	return out
}

// queryKeys returns the query-parameter names of a URL.
func queryKeys(rawURL string) []string {
	i := strings.Index(rawURL, "?")
	if i < 0 {
		return nil
	}
	var keys []string
	seen := make(map[string]bool)
	for _, kv := range strings.Split(rawURL[i+1:], "&") {
		k := kv
		if eq := strings.Index(kv, "="); eq >= 0 {
			k = kv[:eq]
		}
		if k != "" && !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	return keys
}

func firstQueryKey(rawURL string) string {
	ks := queryKeys(rawURL)
	if len(ks) == 0 {
		return ""
	}
	return ks[0]
}

// jsAssetURLs collects in-scope .js URLs from the discovered corpus.
func jsAssetURLs(s *engine.State) []string {
	var out []string
	seen := make(map[string]bool)
	for _, u := range s.URLs {
		lu := strings.ToLower(u)
		if (strings.Contains(lu, ".js?") || strings.HasSuffix(lu, ".js") || strings.Contains(lu, ".js#")) &&
			!seen[u] && filter.IsInScope(u, s.Scope) {
			seen[u] = true
			out = append(out, u)
		}
	}
	return out
}

// absolutize turns a JS-discovered path/URL into an absolute in-scope URL.
func absolutize(ref string, s *engine.State) string {
	ref = strings.TrimSpace(ref)
	if strings.HasPrefix(ref, "http://") || strings.HasPrefix(ref, "https://") {
		return ref
	}
	if strings.HasPrefix(ref, "/") && len(s.Scope.Domains) > 0 {
		return "https://" + s.Scope.Domains[0] + ref
	}
	return ""
}

// redact masks the middle of a secret value so the report proves discovery
// without printing a fully usable live credential.
func redact(v string) string {
	if len(v) <= 8 {
		return "****"
	}
	return v[:4] + "…" + v[len(v)-4:]
}

// budgetStrings is budget() for a plain string slice.
func budgetStrings(ss []string, max int) []string {
	if len(ss) <= max {
		return ss
	}
	return ss[:max]
}
