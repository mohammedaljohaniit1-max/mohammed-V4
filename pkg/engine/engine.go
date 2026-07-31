package engine

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mohammed-v3/core/pkg/ai"
	"github.com/mohammed-v3/core/pkg/browser"
	"github.com/mohammed-v3/core/pkg/config"
	"github.com/mohammed-v3/core/pkg/governor"
	"github.com/mohammed-v3/core/pkg/proxy"
	"github.com/mohammed-v3/core/pkg/runner"
)

// ─────────────────────────────────────────
// Phase interface
// ─────────────────────────────────────────
type Phase interface {
	Name() string
	Description() string
	Execute(ctx context.Context, state *State) error
}

// ─────────────────────────────────────────
// State: shared data across all phases
// ─────────────────────────────────────────
type State struct {
	Config   *config.Config
	Scope    *config.Scope
	Governor *governor.Governor
	Proxy    *proxy.ProxyManager
	AI       *ai.Client
	// Brain is the V10.0 SOVEREIGN local Ollama cognitive engine (semantic
	// triage, payload mutation, business-logic ranking). Layered on the same
	// Ollama endpoint as AI; nil-safe and fails open when offline.
	Brain *ai.Brain
	// Browser is the V10.0 SOVEREIGN headless-Chrome CDP engine (Go-Rod). It is
	// lazily launched on first use and shared across the client-side phases;
	// when Chromium is unavailable every capability degrades to the HTTP path.
	Browser *browser.Engine
	// BrowserSem is the resource governor for headless-Chrome pages. Each page
	// costs real memory, so client-side phases Acquire()/Release() a slot before
	// opening a page. Sized small so a SPA-heavy scan can never spawn dozens of
	// Chromium tabs and OOM the host.
	BrowserSem chan struct{}
	// BrowserOnline records whether the one-time startup CDP probe found a
	// usable Chromium; when false client-side phases skip cleanly.
	BrowserOnline bool
	Subdomains    []string
	LiveHosts     []string
	URLs          []string
	// PriorityTargets is the staging/dev/internal-first exploit ordering
	// produced by the Subdomain Intelligence engine (Secret Weapon #5, Phase
	// 65). Later exploit phases may consume it to test weaker-security hosts
	// before hardened production. Empty until Phase 65 runs.
	PriorityTargets []string
	Parameters      map[string][]string
	Findings        []map[string]interface{}
	OutputFolder    string
	StartTime       time.Time

	// WAFProtected records hosts flagged as WAF/Captcha/challenge protected
	// during Phase 07 (HTTP probing). EXPANSION 3: such hosts are excluded from
	// heavy fuzzing (XSS/SQLi) so a WAF block page can never masquerade as a
	// vulnerability (zero-false-positive). Keyed by bare host (no scheme).
	WAFProtected map[string]bool

	// AIOnline records the result of the one-time startup Ollama connectivity
	// probe (FIX #7). When false, findings that require AI confirmation are
	// downgraded by the confidence policy rather than reported as confirmed.
	AIOnline bool

	// CompletedPhases records the Name() of every phase that finished
	// successfully. It is serialized into checkpoint.json after each phase so
	// an interrupted scan can be resumed with --resume (FLAW #2).
	CompletedPhases []string

	// completedSet mirrors CompletedPhases for O(1) skip lookups when resuming.
	// It is populated from a loaded checkpoint; nil means "resume disabled".
	completedSet map[string]bool

	// V12.2 · FAILURE #5: --skip / --only phase selection (1-based phase
	// numbers). SkipPhases lists phases to NOT run; OnlyPhases, when non-empty,
	// restricts the run to EXACTLY those phases. Consulted by ShouldRunPhase.
	SkipPhases map[int]bool
	OnlyPhases map[int]bool

	// PrintMu protects all fmt.Printf calls so the live timer line and
	// phase output lines do not interleave and corrupt each other.
	PrintMu sync.Mutex

	// findingsMu protects concurrent AddFinding calls (phases may fan out).
	findingsMu sync.Mutex
}

// MarkComplete records a finished phase (thread-safe) for checkpointing.
func (s *State) MarkComplete(name string) {
	s.findingsMu.Lock()
	defer s.findingsMu.Unlock()
	for _, n := range s.CompletedPhases {
		if n == name {
			return
		}
	}
	s.CompletedPhases = append(s.CompletedPhases, name)
}

// IsComplete reports whether a phase was already completed in a resumed scan.
func (s *State) IsComplete(name string) bool {
	if s.completedSet == nil {
		return false
	}
	return s.completedSet[name]
}

// IsResumed reports whether this run was restored from a checkpoint. A nil
// completedSet means no checkpoint was loaded (a fresh scan).
func (s *State) IsResumed() bool {
	return s.completedSet != nil
}

// CleanStaleResults deletes result .txt/report artifacts left over from a
// PREVIOUS scan into the same output folder (BUG #10 audit). It runs ONLY on a
// fresh scan (never on --resume, which must keep prior-phase artifacts intact).
// The checkpoint.json itself is preserved so an accidental fresh run can still
// be recovered.
func (s *State) CleanStaleResults() int {
	if s.IsResumed() {
		return 0 // never wipe artifacts we are resuming from
	}
	entries, err := os.ReadDir(s.OutputFolder)
	if err != nil {
		return 0
	}
	removed := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if name == "checkpoint.json" {
			continue // keep the recovery point
		}
		if strings.HasSuffix(name, ".txt") ||
			strings.HasSuffix(name, ".json") ||
			strings.HasSuffix(name, ".md") {
			if os.Remove(filepath.Join(s.OutputFolder, name)) == nil {
				removed++
			}
		}
	}
	return removed
}

func NewState(cfg *config.Config, scope *config.Scope) *State {
	target := "target"
	if len(scope.Domains) > 0 {
		target = scope.Domains[0]
	}
	outDir := config.GetOutputFolder(target)
	config.EnsureDir(outDir)

	pm := proxy.NewProxyManager(cfg.BurpProxy)
	// FIX #5: enable the two-tier (direct vs Burp) routing model.
	pm.Selective = cfg.SelectiveProxyRouting

	return &State{
		Config:   cfg,
		Scope:    scope,
		Governor: governor.NewGovernor(cfg.Threads),
		Proxy:    pm,
		AI: ai.NewClient(
			cfg.Ollama.Enabled,
			cfg.Ollama.Endpoint,
			cfg.Ollama.Model,
			cfg.Ollama.Timeout,
		),
		// V11.0 FINAL SOVEREIGN cognitive brain — 3-tier model cascade
		// (llama3.2:3b fast triage → qwen2.5:7b deep analysis → deepseek-r1:7b
		// reasoning). Missing tier models are auto-pulled at startup by
		// Brain.Probe when AutoPull is enabled; each tier falls back to
		// heuristics when Ollama is offline (FLAW #2 fix).
		Brain: ai.NewCascadeBrain(
			cfg.Ollama.Enabled,
			cfg.Ollama.Endpoint,
			cfg.Ollama.Model,
			cfg.Ollama.Timeout,
			ai.CascadeConfig{
				FastModel:      cfg.Ollama.FastModel,
				DeepModel:      cfg.Ollama.DeepModel,
				ReasoningModel: cfg.Ollama.ReasoningModel,
				AutoPull:       cfg.Ollama.AutoPull,
				TimeoutFast:    cfg.Ollama.TimeoutFast,
				TimeoutDeep:    cfg.Ollama.TimeoutDeep,
				TimeoutReason:  cfg.Ollama.TimeoutReason,
			},
		),
		// V10.0 SOVEREIGN headless-Chrome engine (lazy launch) + its page
		// resource governor. Cap browser pages hard (min(threads,4)) so the
		// memory shield and Chromium never fight over the host.
		Browser:      browser.NewEngine(browser.Options{}),
		BrowserSem:   make(chan struct{}, browserSlots(cfg.Threads)),
		Subdomains:   make([]string, 0),
		LiveHosts:    make([]string, 0),
		URLs:         make([]string, 0),
		Parameters:   make(map[string][]string),
		Findings:     make([]map[string]interface{}, 0),
		WAFProtected: make(map[string]bool),
		OutputFolder: outDir,
		StartTime:    time.Now(),
	}
}

// MarkWAFProtected records that a host is behind a WAF/challenge (thread-safe).
// EXPANSION 3: consumed by the fuzzing/injection phases to skip heavy scanning.
func (s *State) MarkWAFProtected(host string) {
	if host == "" {
		return
	}
	s.findingsMu.Lock()
	defer s.findingsMu.Unlock()
	if s.WAFProtected == nil {
		s.WAFProtected = make(map[string]bool)
	}
	s.WAFProtected[strings.ToLower(host)] = true
}

// IsWAFProtected reports whether a host (or the host component of a URL) was
// flagged WAF-protected during probing.
func (s *State) IsWAFProtected(hostOrURL string) bool {
	if s.WAFProtected == nil || hostOrURL == "" {
		return false
	}
	h := strings.ToLower(hostOrURL)
	// Strip scheme + path if a full URL was passed.
	if i := strings.Index(h, "://"); i != -1 {
		h = h[i+3:]
	}
	if i := strings.IndexAny(h, "/:?"); i != -1 {
		h = h[:i]
	}
	s.findingsMu.Lock()
	defer s.findingsMu.Unlock()
	return s.WAFProtected[h]
}

// ─────────────────────────────────────────────────────────────────────────
// V9.0 ABSOLUTE APEX — System Resource Shield (Section 1.1)
//
// MemoryPressure reads live heap statistics via runtime.ReadMemStats and reports
// whether the process heap-in-use has crossed the soft ceiling (default 80% of
// a 2 GiB budget). The orchestrator and fan-out phases consult it to throttle
// parallel tasks so a huge target can never OOM-crash the host the scanner runs
// on. It is cheap (a single ReadMemStats) and safe to call in hot loops.
// ─────────────────────────────────────────────────────────────────────────

// memBudgetBytes is the assumed usable memory budget for the shield.
var memBudgetBytes uint64 = 2 * 1024 * 1024 * 1024 // 2 GiB

// memSoftLimitPct is the heap-in-use percentage of the budget above which the
// shield reports pressure.
var memSoftLimitPct = 80

// MemoryPressure reports whether the process is over the soft memory ceiling.
func MemoryPressure() bool {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	limit := memBudgetBytes / 100 * uint64(memSoftLimitPct)
	return m.HeapInuse >= limit
}

// AdaptiveThreads returns a safe worker count derived from the configured
// thread budget and the current memory pressure. When the host is over the soft
// ceiling it clamps to a floor (5) so parallel work cannot crash the machine.
func AdaptiveThreads(configured int) int {
	if configured <= 0 {
		configured = 20
	}
	if MemoryPressure() {
		const floor = 5
		if configured > floor {
			return floor
		}
	}
	return configured
}

// ─────────────────────────────────────────────────────────────────────────
// V10.0 SOVEREIGN — Headless-Chrome resource governor (Section 5.3)
//
// Each Chromium page costs real memory; browserSlots caps how many can be open
// at once, derived from the thread budget but hard-limited so a SPA-heavy scan
// can never spawn a swarm of tabs and OOM the host the scanner runs on.
// V12.1 FIX #6: the hard cap is 3 concurrent tabs (was 4) to keep Chrome's RSS
// under the ~500 MB recycle threshold the DOM-XSS recovery governor enforces.
// ─────────────────────────────────────────────────────────────────────────

func browserSlots(threads int) int {
	const maxSlots = 3 // FIX #6: max 3 concurrent CDP tabs
	if threads <= 0 {
		return 2
	}
	if threads < maxSlots {
		return threads
	}
	return maxSlots
}

// AcquireBrowserSlot blocks until a headless-Chrome page slot is free (or ctx is
// cancelled), returning a release func. Client-side phases call this before
// opening a page so browser memory stays bounded. Nil-safe.
func (s *State) AcquireBrowserSlot(ctx context.Context) (release func(), ok bool) {
	if s == nil || s.BrowserSem == nil {
		return func() {}, true
	}
	select {
	case s.BrowserSem <- struct{}{}:
		return func() { <-s.BrowserSem }, true
	case <-ctx.Done():
		return func() {}, false
	}
}

// ProbeSovereign runs the one-time V10 startup checks for the cognitive brain
// (Ollama model discovery + auto-fallback) and the headless-Chrome engine, and
// records their availability on state. It reports a short posture string for the
// banner. Safe to call once from Run().
func (s *State) ProbeSovereign(ctx context.Context) string {
	brainStatus := "disabled"
	if s.Brain != nil && s.Brain.Client != nil && s.Brain.Client.Enabled {
		if s.Brain.Probe(ctx) {
			brainStatus = "ONLINE (" + s.Brain.ActiveModel() + ")"
		} else {
			brainStatus = "offline (fail-open heuristics)"
		}
	}
	browserStatus := "unavailable (HTTP-only fallback)"
	if s.Browser != nil && s.Browser.Available() {
		s.BrowserOnline = true
		browserStatus = "ONLINE (headless Chromium)"
	}
	return "AI-Brain=" + brainStatus + " | CDP-Browser=" + browserStatus
}

// FingerprintAndMarkWAF classifies a captured response with the V9 WAF/CDN
// evasion engine and, when a WAF/challenge is detected, records the host as
// WAF-protected on state (so heavy fuzzing is skipped unless --waf-bypass).
// It returns the fingerprint for the caller's evidence trail.
func (s *State) FingerprintAndMarkWAF(host string, status int, headers http.Header, body string) WAFFingerprint {
	fp := FingerprintWAFResponse(status, headers, body)
	if fp.Detected && host != "" {
		s.MarkWAFProtected(host)
	}
	return fp
}

// SkipHeavyFuzzing reports whether heavy injection fuzzing should be skipped for
// a host given the WAF verdict and the --waf-bypass flag (Section 1.2 routing).
func (s *State) SkipHeavyFuzzing(hostOrURL string) bool {
	bypass := s.Config != nil && s.Config.WAFBypass
	return ShouldSkipHeavyFuzzing(s.IsWAFProtected(hostOrURL), bypass)
}

// AddFinding appends a finding in a thread-safe manner.
func (s *State) AddFinding(f map[string]interface{}) {
	s.findingsMu.Lock()
	defer s.findingsMu.Unlock()
	s.Findings = append(s.Findings, f)
}

// PhaseProxy returns the proxy manager appropriate for a phase's routing tier
// (FIX #5). Tier-1 (noisy discovery) phases call PhaseProxy(ProxyModeDirect)
// and get an inert manager so they never flood Burp; Tier-2 (confirmed
// security verification) phases call PhaseProxy(ProxyModeSelective).
func (s *State) PhaseProxy(mode proxy.ProxyMode) *proxy.ProxyManager {
	return s.Proxy.For(mode)
}

// Triage runs AI triage on a candidate finding and adds it with the verdict
// recorded. When the model marks it a false positive, the severity is demoted
// to "Info" (never dropped — we keep the evidence for the report) and an
// "ai_verdict" field records the reason. Fails open when Ollama is offline.
//
// NOTE: this is the legacy always-store path. New zero-FP phases should prefer
// TriageAndScore, which additionally applies the confidence policy and can
// DISCARD a finding that cannot clear the confidence floor (FIX #3).
func (s *State) Triage(ctx context.Context, findingType, target, evidence string, f map[string]interface{}) {
	s.TriageVerdict(ctx, findingType, target, evidence, f)
	s.AddFinding(f)
}

// TriageVerdict runs AI triage and records the verdict fields on f WITHOUT
// storing it. When Ollama reports offline, ai_offline is set so the confidence
// scorer can apply the FIX #7 penalty. Returns whether the model confirmed.
func (s *State) TriageVerdict(ctx context.Context, findingType, target, evidence string, f map[string]interface{}) bool {
	// FIX #7: if the startup probe found Ollama offline, skip the per-finding
	// network round-trip entirely and treat it as offline (fail open).
	if s.AI == nil || !s.AI.Enabled || !s.AIOnline {
		f["ai_verdict"] = "ollama_offline"
		f["ai_offline"] = true
		return true
	}
	confirmed, reason := s.AI.TriageFinding(ctx, findingType, target, evidence)
	f["ai_verdict"] = reason
	offline := reason == "ollama_offline"
	if offline {
		f["ai_offline"] = true
	}
	if !confirmed {
		f["ai_confirmed"] = false
		if _, ok := f["original_severity"]; !ok {
			f["original_severity"] = f["severity"]
		}
		// A model that explicitly says FALSE_POSITIVE demotes to Info.
		if !offline {
			f["severity"] = "Info"
		}
	} else if !offline {
		f["ai_confirmed"] = true
	}
	// When the model explicitly rejected the finding, log it (FIX #7).
	if !confirmed && !offline {
		s.Printf("│  AI: REJECTED [%s] on %s — %s\n", findingType, target, reason)
	}
	return confirmed
}

// TriageAndScore triages a candidate finding, applies the confidence policy,
// and stores it ONLY if the policy says keep. Returns true when the finding
// was kept (possibly downgraded), false when it was discarded (FIX #3/#7).
// scoreFn is the package-level filter.ApplyConfidencePolicy, injected to avoid
// an import cycle (engine → filter → config, filter must not import engine).
func (s *State) TriageAndScore(ctx context.Context, findingType, target, evidence string,
	f map[string]interface{}, scoreFn func(map[string]interface{}) bool) bool {
	s.TriageVerdict(ctx, findingType, target, evidence, f)
	if scoreFn != nil && !scoreFn(f) {
		return false // discarded — never stored
	}
	s.AddFinding(f)
	return true
}

// ─────────────────────────────────────────
// Printf: thread-safe print helper used by phases
// ─────────────────────────────────────────
func (s *State) Printf(format string, a ...interface{}) {
	s.PrintMu.Lock()
	defer s.PrintMu.Unlock()
	fmt.Printf(format, a...)
}

// ─────────────────────────────────────────
// Orchestrator: manages phase registration and execution
// ─────────────────────────────────────────
type Orchestrator struct {
	State  *State
	Phases []Phase
}

func NewOrchestrator(state *State) *Orchestrator {
	return &Orchestrator{
		State:  state,
		Phases: make([]Phase, 0),
	}
}

func (o *Orchestrator) RegisterPhase(p Phase) {
	o.Phases = append(o.Phases, p)
}

// ─────────────────────────────────────────
// checkBurp: verify Burp Suite is reachable before scan starts
// ─────────────────────────────────────────
func checkBurp(proxyURL string) bool {
	if proxyURL == "" {
		return false
	}
	pu, err := url.Parse(proxyURL)
	if err != nil {
		return false
	}
	// CRITICAL: the request must actually be routed THROUGH the proxy, so we
	// configure the transport with http.ProxyURL. The previous implementation
	// used a plain client and never touched the proxy at all.
	client := &http.Client{
		Timeout: 4 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(pu),
		},
	}
	req, err := http.NewRequest("GET", "http://detectportal.firefox.com/success.txt", nil)
	if err != nil {
		return false
	}
	req.Header.Set("X-MOHAMMED-CHECK", "1")
	resp, err := client.Do(req)
	if err != nil {
		// "connection refused" against the proxy address itself → Burp is down.
		errStr := strings.ToLower(err.Error())
		if strings.Contains(errStr, "connection refused") ||
			strings.Contains(errStr, "no such host") ||
			strings.Contains(errStr, "timeout") ||
			strings.Contains(errStr, "deadline exceeded") {
			return false
		}
		// Any other transport error means the proxy accepted the connection but
		// the target misbehaved — Burp itself is alive.
		return true
	}
	defer resp.Body.Close()
	return true
}

// ─────────────────────────────────────────
// Run: executes all registered phases with live timer
// ─────────────────────────────────────────
func (o *Orchestrator) Run(ctx context.Context) error {
	o.State.StartTime = time.Now()

	// ── Print initial header ──────────────────────────────
	fmt.Printf("\n[+] MOHAMMED V12.2 PROCESS-CRISIS Engine Started | Output: %s\n", o.State.OutputFolder)
	fmt.Printf("⏱  SCAN STARTED: %s\n", o.State.StartTime.Format("2006-01-02 15:04:05 MST"))

	// V9.0 System Resource Shield: report the adaptive concurrency posture up
	// front. AdaptiveThreads clamps parallelism to a safe floor whenever the
	// process heap crosses the soft memory ceiling (runtime.ReadMemStats), so a
	// large target can never OOM-crash the host running the scan.
	if o.State.Config != nil {
		eff := AdaptiveThreads(o.State.Config.Threads)
		shield := "nominal"
		if MemoryPressure() {
			shield = "THROTTLED (memory pressure)"
		}
		fmt.Printf("[+] Adaptive Stealth Shield: threads=%d (configured %d) | memory=%s | 429/503/403 backoff=ON | WAF cool-down=30s\n",
			eff, o.State.Config.Threads, shield)
	}

	// BUG #10 (audit) FIX: on a FRESH scan, purge stale result files from a
	// previous scan into the same folder so no old .txt/.json/.md data (e.g.
	// last week's sqli_results.txt with __cf_chl URLs) pollutes this run. This
	// is a no-op on --resume (IsResumed guard) so we never delete data we are
	// restoring from.
	if !o.State.IsResumed() {
		if n := o.State.CleanStaleResults(); n > 0 {
			fmt.Printf("[+] Fresh scan: cleared %d stale result file(s) from %s\n", n, o.State.OutputFolder)
		}
	}

	// ── Burp Suite connectivity check ────────────────────
	//
	// BUG #1 (CATASTROPHIC) FIX: the old code printed "Not reachable" but NEVER
	// changed o.State.Proxy.Active. Every downstream phase (httpx, katana,
	// gospider, ffuf, nuclei…) then kept routing through the dead proxy and got
	// connection-refused → 0 results, silently breaking Phases 07 and 11-27.
	// We now HARD-DISABLE the proxy in shared State the moment Burp is proven
	// unreachable, so the whole pipeline falls back to direct networking.
	if o.State.Proxy != nil && o.State.Proxy.Active {
		fmt.Printf("[*] Checking Burp Suite connectivity at %s ... ", o.State.Proxy.ProxyURL)
		if checkBurp(o.State.Proxy.ProxyURL) {
			fmt.Printf("✅ Connected — traffic will be intercepted\n")
		} else {
			fmt.Printf("⚠️  Not reachable — DISABLING proxy, scanning DIRECT (no Burp)\n")
			o.State.Proxy.Active = false
			o.State.Proxy.ProxyURL = ""
		}
	}

	// ── Ollama (AI triage) connectivity check — ONCE at startup ──────────
	//
	// FIX #7: probe Ollama a single time here instead of discovering it is
	// offline mid-scan on every finding. When AI is offline, the confidence
	// policy downgrades unconfirmed Critical findings to Unverified-Critical
	// Info and High JS secrets to Info — nothing is reported as AI-confirmed
	// without a REAL verdict from the model.
	if o.State.AI != nil && o.State.AI.Enabled {
		fmt.Printf("[*] Checking Ollama (%s) at %s ... ", o.State.AI.Model, o.State.AI.Endpoint)
		if o.State.AI.Ping(ctx) {
			o.State.AIOnline = true
			fmt.Printf("✅ Online — AI confirmation active\n")
		} else {
			o.State.AIOnline = false
			fmt.Printf("⚠️  Offline — unconfirmed Critical/High findings will be downgraded (zero-FP)\n")
		}
	} else {
		o.State.AIOnline = false
		fmt.Printf("[*] Ollama: disabled — AI confirmation OFF (findings needing AI will be downgraded)\n")
	}

	// ── V10.0 SOVEREIGN subsystems: local AI cognitive brain + headless-Chrome
	// CDP engine. Probed ONCE here so every downstream phase knows whether
	// semantic reasoning and real DOM execution proofs are available. Both fail
	// open: the scan continues on the deterministic/HTTP path if either is down.
	fmt.Printf("[*] Sovereign subsystems: probing local AI brain + headless-Chrome CDP ... ")
	posture := o.State.ProbeSovereign(ctx)
	fmt.Printf("\n[+] %s\n", posture)
	// Ensure the headless browser is torn down when the scan ends (frees the
	// Chromium process + leakless guard). No-op when it was never launched.
	if o.State.Browser != nil {
		defer o.State.Browser.Close()
	}

	// ── V11.0 FINAL SOVEREIGN pre-scan READINESS check (FLAW #7) ─────────
	//
	// Before the scan proper, audit the engine's own dependencies: Ollama +
	// the 3-tier cascade models (auto-pulled when missing), the Go-Rod
	// Chromium launch, and the 38 recon tools on $PATH. The report makes any
	// degradation explicit instead of silently dropping to the HTTP path. It
	// never aborts the scan — readiness is advisory.
	readiness := o.State.CheckReadiness(ctx)
	o.State.PrintReadinessReport(readiness)

	fmt.Println()

	// ── Live timer goroutine (every 1 second, single line with \r) ──
	tickerCtx, cancelTicker := context.WithCancel(context.Background())
	defer cancelTicker()

	// currentTool stores the currently running tool name for display
	var currentTool atomic.Value
	currentTool.Store("engine")

	// timerLine tracks whether we printed a timer line (so we can clear it)
	timerRunning := make(chan struct{})

	go func() {
		close(timerRunning)
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-tickerCtx.Done():
				// Clear the timer line on exit
				o.State.PrintMu.Lock()
				fmt.Printf("\r%s\r", strings.Repeat(" ", 80))
				o.State.PrintMu.Unlock()
				return
			case <-ticker.C:
				elapsed := time.Since(o.State.StartTime)
				h := int(elapsed.Hours())
				m := int(elapsed.Minutes()) % 60
				s := int(elapsed.Seconds()) % 60
				tool := currentTool.Load().(string)

				o.State.PrintMu.Lock()
				// \r goes back to start of line, overwriting the previous timer
				fmt.Printf("\r\033[K  ⏱  %02d:%02d:%02d | %s ", h, m, s, tool)
				o.State.PrintMu.Unlock()
			}
		}
	}()

	// Wait for goroutine to start
	<-timerRunning

	// ── Execute phases ───────────────────────────────────
	for i, phase := range o.Phases {
		select {
		case <-ctx.Done():
			cancelTicker()
			// Persist progress so --resume can continue from here (FLAW #2):
			// this is what makes the SIGINT "Saving progress..." message true.
			if cpErr := o.State.SaveCheckpoint(); cpErr == nil {
				fmt.Printf("\n[+] Progress saved to %s — resume with --resume\n", o.State.checkpointPath())
			}
			elapsed := time.Since(o.State.StartTime)
			fmt.Printf("\n[!] Scan cancelled. Total elapsed: %v\n", elapsed.Round(time.Second))
			return fmt.Errorf("scan cancelled by user")
		default:
		}

		// ── V12.2 · FAILURE #5: honor --skip / --only phase selection ──────
		// phaseNum is 1-based to match the "Phase NN/MM" labels the operator
		// sees, so `--skip 12` skips the 12th phase in the run order.
		phaseNum := i + 1
		if !o.State.ShouldRunPhase(phaseNum) {
			o.State.PrintMu.Lock()
			fmt.Printf("\r\033[K\n┌─ Phase %02d/%02d  %-35s  [SKIPPED by user]\n", phaseNum, len(o.Phases), phase.Name())
			fmt.Printf("└─ ⏭ Skipped (--skip/--only)\n")
			o.State.PrintMu.Unlock()
			continue
		}

		// ── RESUME: skip phases already completed in a loaded checkpoint ──
		if o.State.IsComplete(phase.Name()) {
			o.State.PrintMu.Lock()
			fmt.Printf("\r\033[K\n┌─ Phase %02d/%02d  %-35s  [RESUME]\n", i+1, len(o.Phases), phase.Name())
			fmt.Printf("│  ⏭  already completed in checkpoint — skipping\n")
			fmt.Printf("└─ ✔ Restored from checkpoint\n")
			o.State.PrintMu.Unlock()
			continue
		}

		phaseStart := time.Now()
		elapsed := time.Since(o.State.StartTime)
		h := int(elapsed.Hours())
		m := int(elapsed.Minutes()) % 60
		s := int(elapsed.Seconds()) % 60

		// Update tool indicator so timer shows phase name
		pLabel := fmt.Sprintf("Phase %02d/%02d: %s", i+1, len(o.Phases), phase.Name())
		currentTool.Store(pLabel)

		// ── V12.2 · FAILURE #3: per-phase hard wall-clock timeout ──────────
		// Derive a child context bounded by this phase's cap. When it fires,
		// the phase's ctx is Done → every runner.RunTool call it launched sees
		// the cancellation and SIGKILLs its process group, and we additionally
		// force-reap any surviving groups so a wedged naabu/amass can never run
		// for hours (the 4h38m Port Scanning bug).
		phaseTO := PhaseTimeout(phase.Name())
		phaseCtx, phaseCancel := context.WithTimeout(ctx, phaseTO)

		// Print phase header (with newline BEFORE to clear timer line)
		o.State.PrintMu.Lock()
		fmt.Printf("\r\033[K\n┌─ Phase %02d/%02d  %-35s  [Elapsed: %02d:%02d:%02d | cap %s]\n", i+1, len(o.Phases), phase.Name(), h, m, s, fmtDur(phaseTO))
		fmt.Printf("│  %s\n", phase.Description())
		o.State.PrintMu.Unlock()

		// Run the phase in a goroutine so we can observe the timeout deadline
		// independently and log a clear "TIMEOUT" line + reap children even if
		// the phase itself is blocked inside a syscall.
		phaseErrCh := make(chan error, 1)
		go func() {
			phaseErrCh <- phase.Execute(phaseCtx, o.State)
		}()

		var err error
		select {
		case err = <-phaseErrCh:
			// Phase returned on its own (success, error, or it honored ctx).
		case <-phaseCtx.Done():
			if ctx.Err() != nil {
				// Parent scan cancelled (Ctrl+C) — fall through to the outer
				// ctx.Done() handling on the next loop iteration; wait for the
				// phase goroutine to unwind so we don't leak it.
				err = <-phaseErrCh
			} else {
				// The PHASE hit its own hard cap. Force-reap children so no
				// tool outlives the phase, then proceed with partial results.
				killed := runner.KillAllChildren()
				o.State.PrintMu.Lock()
				fmt.Printf("\r\033[K│  ⏱  TIMEOUT after %s — killed %d child process group(s), proceeding with partial results\n", fmtDur(phaseTO), killed)
				o.State.PrintMu.Unlock()
				// Give the goroutine a moment to unwind after cancellation.
				<-phaseErrCh
				err = nil // partial results are acceptable; do not fail the scan
			}
		}
		phaseCancel()

		// REPAIR #5: after every phase, close any idle Burp keep-alive
		// connections so a socket left over from this phase's tool handoff
		// cannot emit "Unsolicited response on idle HTTP channel" spam while
		// the next phase runs.
		if o.State.Proxy != nil {
			o.State.Proxy.CloseIdleConnections()
		}

		phaseDur := time.Since(phaseStart)
		totalElapsed := time.Since(o.State.StartTime)

		// ── CHECKPOINT: record completion + persist state after EVERY phase ──
		// Only mark complete on success so a failed/partial phase re-runs on
		// resume. A checkpoint-write failure is logged but never aborts the scan.
		if err == nil {
			o.State.MarkComplete(phase.Name())
		}
		if cpErr := o.State.SaveCheckpoint(); cpErr != nil {
			o.State.PrintMu.Lock()
			fmt.Printf("\r\033[K│  ⚠️  checkpoint save failed: %v\n", cpErr)
			o.State.PrintMu.Unlock()
		}

		o.State.PrintMu.Lock()
		if err != nil {
			fmt.Printf("\r\033[K└─ ✖ Failed in %s: %v\n", fmtDur(phaseDur), err)
		} else {
			fmt.Printf("\r\033[K└─ ✔ Phase done in %s | Total: %s\n", fmtDur(phaseDur), fmtDur(totalElapsed))
		}
		o.State.PrintMu.Unlock()
	}

	// ── Final summary ────────────────────────────────────
	cancelTicker()
	time.Sleep(100 * time.Millisecond) // let ticker goroutine clean up

	total := time.Since(o.State.StartTime)
	fmt.Printf("\n\n╔═══════════════════════════════════════════════╗\n")
	fmt.Printf("║  🎉 ALL PHASES COMPLETE                       ║\n")
	fmt.Printf("║  Total Execution Time: %-22s ║\n", fmtDur(total))
	fmt.Printf("║  Subdomains: %-32d ║\n", len(o.State.Subdomains))
	fmt.Printf("║  Live Hosts: %-32d ║\n", len(o.State.LiveHosts))
	fmt.Printf("║  URLs:       %-32d ║\n", len(o.State.URLs))
	fmt.Printf("║  Findings:   %-32d ║\n", len(o.State.Findings))
	fmt.Printf("╚═══════════════════════════════════════════════╝\n\n")

	return nil
}

// fmtDur formats duration as Xm Ys or Xs depending on size
func fmtDur(d time.Duration) string {
	d = d.Round(time.Second)
	if d >= time.Minute {
		m := int(d.Minutes())
		s := int(d.Seconds()) % 60
		return fmt.Sprintf("%dm%02ds", m, s)
	}
	return fmt.Sprintf("%.0fs", d.Seconds())
}
