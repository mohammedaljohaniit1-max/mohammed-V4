package engine

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mohammed-v3/core/pkg/ai"
	"github.com/mohammed-v3/core/pkg/config"
	"github.com/mohammed-v3/core/pkg/governor"
	"github.com/mohammed-v3/core/pkg/proxy"
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
	Config       *config.Config
	Scope        *config.Scope
	Governor     *governor.Governor
	Proxy        *proxy.ProxyManager
	AI           *ai.Client
	Subdomains   []string
	LiveHosts    []string
	URLs         []string
	Parameters   map[string][]string
	Findings     []map[string]interface{}
	OutputFolder string
	StartTime    time.Time

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
		Subdomains:   make([]string, 0),
		LiveHosts:    make([]string, 0),
		URLs:         make([]string, 0),
		Parameters:   make(map[string][]string),
		Findings:     make([]map[string]interface{}, 0),
		OutputFolder: outDir,
		StartTime:    time.Now(),
	}
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
	fmt.Printf("\n[+] MOHAMMED v3 Engine Started | Output: %s\n", o.State.OutputFolder)
	fmt.Printf("⏱  SCAN STARTED: %s\n", o.State.StartTime.Format("2006-01-02 15:04:05 MST"))

	// ── Burp Suite connectivity check ────────────────────
	//
	// BUG #1 (CATASTROPHIC) FIX: the old code printed "Not reachable" but NEVER
	// changed o.State.Proxy.Active. Every downstream phase (httpx, katana,
	// gospider, ffuf, nuclei…) then kept routing through the dead proxy and got
	// connection-refused → 0 results, silently breaking Phases 07 and 11-27.
	// We now HARD-DISABLE the proxy in shared State the moment Burp is proven
	// unreachable, so the whole pipeline falls back to direct networking.
	if o.State.Proxy.Active {
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

		// Print phase header (with newline BEFORE to clear timer line)
		o.State.PrintMu.Lock()
		fmt.Printf("\r\033[K\n┌─ Phase %02d/%02d  %-35s  [Elapsed: %02d:%02d:%02d]\n", i+1, len(o.Phases), phase.Name(), h, m, s)
		fmt.Printf("│  %s\n", phase.Description())
		o.State.PrintMu.Unlock()

		err := phase.Execute(ctx, o.State)

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
