package engine

// readiness.go — MOHAMMED V11.0 FINAL SOVEREIGN — FLAW #7 fix.
//
// V10.0 could START a scan while its cognitive/CDP engines were only
// half-installed: Ollama running but the cascade models not pulled, Chromium
// missing, or recon binaries absent from $PATH. That silently degraded the
// scan to the HTTP path without telling the operator WHY.
//
// This module runs a PRE-SCAN readiness check that:
//   1. Verifies the Ollama endpoint and AUTO-PULLS the missing cascade models
//      (llama3.2:3b / qwen2.5:7b / deepseek-r1:7b) when auto-pull is enabled.
//   2. Launch-tests Go-Rod Chromium (bounded) and reports whether CDP is live.
//   3. Probes the 38 recon tools on $PATH and prints which are missing (with the
//      one-line install hint) so the operator can fix them.
//   4. Prints a single READINESS REPORT block and returns a structured result
//      the orchestrator surfaces in the banner.
//
// It NEVER aborts the scan: readiness is advisory. A degraded engine still runs
// on its fallback path; the report just makes the degradation explicit.

import (
	"context"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// ToolStatus is the readiness of a single external recon binary.
type ToolStatus struct {
	Name       string
	Present    bool
	Path       string
	InstallCmd string // one-line install hint printed when absent
}

// ReadinessReport is the structured outcome of the pre-scan check.
type ReadinessReport struct {
	// AIEndpoint reachable + per-tier model availability.
	OllamaReachable bool
	CascadeSummary  string
	ModelsPulled    []string // models auto-pulled during the check
	// Chromium/CDP.
	BrowserAvailable bool
	BrowserReason    string
	// Recon tools.
	Tools        []ToolStatus
	ToolsPresent int
	ToolsTotal   int
	// Overall is a coarse posture: "READY", "DEGRADED" or "MINIMAL".
	Overall string
}

// reconTools is the canonical 45-tool recon inventory MOHAMMED wraps, each with
// a copy-paste install hint. Kept sorted for a stable readiness report. V12.1
// added 7 modern tools (chaos, alterx, cdncheck, uncover, cariddi, trufflehog,
// ppmap) per Section 3 of the ZERO-TOLERANCE mandate.
var reconTools = []ToolStatus{
	{Name: "subfinder", InstallCmd: "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"},
	{Name: "amass", InstallCmd: "go install github.com/owasp-amass/amass/v4/...@master"},
	{Name: "assetfinder", InstallCmd: "go install github.com/tomnomnom/assetfinder@latest"},
	{Name: "findomain", InstallCmd: "curl -L https://github.com/findomain/findomain/releases/latest/download/findomain-linux -o /usr/local/bin/findomain && chmod +x /usr/local/bin/findomain"},
	{Name: "dnsx", InstallCmd: "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest"},
	{Name: "puredns", InstallCmd: "go install github.com/d3mondev/puredns/v2@latest"},
	{Name: "massdns", InstallCmd: "apt-get install -y massdns || (git clone https://github.com/blechschmidt/massdns && make -C massdns)"},
	{Name: "shuffledns", InstallCmd: "go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"},
	{Name: "httpx", InstallCmd: "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"},
	{Name: "httprobe", InstallCmd: "go install github.com/tomnomnom/httprobe@latest"},
	{Name: "naabu", InstallCmd: "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"},
	{Name: "nmap", InstallCmd: "apt-get install -y nmap"},
	{Name: "masscan", InstallCmd: "apt-get install -y masscan"},
	{Name: "katana", InstallCmd: "go install github.com/projectdiscovery/katana/cmd/katana@latest"},
	{Name: "gau", InstallCmd: "go install github.com/lc/gau/v2/cmd/gau@latest"},
	{Name: "waybackurls", InstallCmd: "go install github.com/tomnomnom/waybackurls@latest"},
	{Name: "hakrawler", InstallCmd: "go install github.com/hakluke/hakrawler@latest"},
	{Name: "gospider", InstallCmd: "go install github.com/jaeles-project/gospider@latest"},
	{Name: "gauplus", InstallCmd: "go install github.com/bp0lr/gauplus@latest"},
	{Name: "ffuf", InstallCmd: "go install github.com/ffuf/ffuf/v2@latest"},
	{Name: "feroxbuster", InstallCmd: "apt-get install -y feroxbuster || cargo install feroxbuster"},
	{Name: "gobuster", InstallCmd: "go install github.com/OJ/gobuster/v3@latest"},
	{Name: "dirsearch", InstallCmd: "pipx install dirsearch"},
	{Name: "nuclei", InstallCmd: "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"},
	{Name: "dalfox", InstallCmd: "go install github.com/hahwul/dalfox/v2@latest"},
	{Name: "sqlmap", InstallCmd: "pipx install sqlmap"},
	{Name: "gf", InstallCmd: "go install github.com/tomnomnom/gf@latest"},
	{Name: "qsreplace", InstallCmd: "go install github.com/tomnomnom/qsreplace@latest"},
	{Name: "unfurl", InstallCmd: "go install github.com/tomnomnom/unfurl@latest"},
	{Name: "anew", InstallCmd: "go install github.com/tomnomnom/anew@latest"},
	{Name: "notify", InstallCmd: "go install github.com/projectdiscovery/notify/cmd/notify@latest"},
	{Name: "interactsh-client", InstallCmd: "go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"},
	{Name: "subjs", InstallCmd: "go install github.com/lc/subjs@latest"},
	{Name: "getJS", InstallCmd: "go install github.com/003random/getJS@latest"},
	{Name: "wafw00f", InstallCmd: "pipx install wafw00f"},
	{Name: "nikto", InstallCmd: "apt-get install -y nikto"},
	{Name: "whatweb", InstallCmd: "apt-get install -y whatweb"},
	{Name: "cero", InstallCmd: "go install github.com/glebarez/cero@latest"},
	// ── V12.1 modern tooling (Section 3) ────────────────────────────────
	// chaos-client: ProjectDiscovery Chaos passive subdomain DB — amass backup.
	{Name: "chaos", InstallCmd: "go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest"},
	// alterx: pattern-based subdomain permutation wordlist generator.
	{Name: "alterx", InstallCmd: "go install github.com/projectdiscovery/alterx/cmd/alterx@latest"},
	// cdncheck: accurate CDN/WAF/cloud detection (beats header heuristics).
	{Name: "cdncheck", InstallCmd: "go install github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest"},
	// uncover: unified Shodan/Censys/FOFA/Hunter exposed-host search.
	{Name: "uncover", InstallCmd: "go install github.com/projectdiscovery/uncover/cmd/uncover@latest"},
	// cariddi: crawl + extract endpoints/secrets/errors from HTTP responses.
	{Name: "cariddi", InstallCmd: "go install github.com/edoardottt/cariddi/cmd/cariddi@latest"},
	// trufflehog: deep verified-secret scanning across code/commits/files.
	{Name: "trufflehog", InstallCmd: "go install github.com/trufflesecurity/trufflehog/v3@latest"},
	// ppmap: prototype-pollution detection (replaces generic nuclei probe).
	{Name: "ppmap", InstallCmd: "git clone https://github.com/kleiton0x00/ppmap /opt/ppmap && go build -C /opt/ppmap -o /usr/local/bin/ppmap"},
}

// CheckReadiness runs the full pre-scan readiness audit and returns a report.
// It is bounded: model pulls are gated by the brain's own 10-minute pull
// timeout, and the Chromium launch test is capped at ~8s.
func (s *State) CheckReadiness(ctx context.Context) ReadinessReport {
	rep := ReadinessReport{ToolsTotal: len(reconTools)}

	// ── 1. Ollama + cascade models ──────────────────────────────────────
	if s.Brain != nil && s.Brain.Client != nil && s.Brain.Client.Enabled {
		before := s.Brain.CascadeSummary()
		// Probe() reaches /api/tags, auto-pulls missing tier models (when the
		// cascade AutoPull flag is set) and resolves the per-tier best model.
		rep.OllamaReachable = s.Brain.Probe(ctx)
		rep.CascadeSummary = s.Brain.CascadeSummary()
		// Detect which models became available after the probe (auto-pulled).
		if rep.OllamaReachable && before != rep.CascadeSummary {
			rep.ModelsPulled = diffCascade(before, rep.CascadeSummary)
		}
	} else {
		rep.CascadeSummary = "AI disabled (deterministic heuristics only)"
	}

	// ── 2. Chromium / CDP launch test ───────────────────────────────────
	if s.Browser != nil {
		lctx, cancel := context.WithTimeout(ctx, 8*time.Second)
		ok, reason := probeBrowser(lctx, s.Browser)
		cancel()
		rep.BrowserAvailable = ok
		rep.BrowserReason = reason
	} else {
		rep.BrowserReason = "CDP engine not constructed (HTTP-only mode)"
	}

	// ── 3. Recon tool inventory ─────────────────────────────────────────
	rep.Tools = probeReconTools()
	for _, t := range rep.Tools {
		if t.Present {
			rep.ToolsPresent++
		}
	}

	// ── Overall posture ─────────────────────────────────────────────────
	rep.Overall = overallPosture(rep)
	return rep
}

// probeBrowser launch-tests Chromium within the caller's timeout. Returns
// (available, reason). Never panics: browser.Available() already recovers
// go-rod panics internally.
func probeBrowser(ctx context.Context, b interface{ Available() bool }) (bool, string) {
	done := make(chan bool, 1)
	go func() {
		done <- b.Available()
	}()
	select {
	case ok := <-done:
		if ok {
			return true, "headless Chromium launched OK"
		}
		return false, "Chromium unavailable — run: `npx @puppeteer/browsers install chrome` or set CHROME_BIN"
	case <-ctx.Done():
		return false, "Chromium launch timed out (>8s) — HTTP-only fallback active"
	}
}

// probeReconTools resolves each recon binary on $PATH, filling Present/Path.
func probeReconTools() []ToolStatus {
	out := make([]ToolStatus, len(reconTools))
	copy(out, reconTools)
	for i := range out {
		if p, err := exec.LookPath(out[i].Name); err == nil {
			out[i].Present = true
			out[i].Path = p
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Name < out[b].Name })
	return out
}

// overallPosture summarizes readiness into a coarse label.
func overallPosture(rep ReadinessReport) string {
	toolFrac := 0.0
	if rep.ToolsTotal > 0 {
		toolFrac = float64(rep.ToolsPresent) / float64(rep.ToolsTotal)
	}
	switch {
	case rep.OllamaReachable && rep.BrowserAvailable && toolFrac >= 0.8:
		return "READY"
	case toolFrac >= 0.5:
		return "DEGRADED"
	default:
		return "MINIMAL"
	}
}

// diffCascade returns the tier models present in after but not before (the
// models that were auto-pulled during the readiness probe).
func diffCascade(before, after string) []string {
	beforeSet := map[string]bool{}
	for _, tok := range strings.Fields(before) {
		beforeSet[tok] = true
	}
	var pulled []string
	for _, tok := range strings.Fields(after) {
		if !beforeSet[tok] && strings.Contains(tok, "=") {
			pulled = append(pulled, strings.SplitN(tok, "=", 2)[1])
		}
	}
	return pulled
}

// PrintReadinessReport writes the human-readable READINESS REPORT block to the
// state's output. Called once by the orchestrator before the scan proper.
func (s *State) PrintReadinessReport(rep ReadinessReport) {
	s.Printf("╭─ V12.0 OMEGA PRE-SCAN READINESS REPORT ──────────────────────────────\n")
	// AI.
	if rep.OllamaReachable {
		s.Printf("│  AI Cascade : ONLINE  [%s]\n", rep.CascadeSummary)
	} else {
		s.Printf("│  AI Cascade : offline [%s] — deterministic fail-open heuristics active\n", rep.CascadeSummary)
	}
	if len(rep.ModelsPulled) > 0 {
		s.Printf("│              auto-pulled: %s\n", strings.Join(rep.ModelsPulled, ", "))
	}
	// Browser.
	if rep.BrowserAvailable {
		s.Printf("│  CDP Browser: ONLINE  [%s]\n", rep.BrowserReason)
	} else {
		s.Printf("│  CDP Browser: offline [%s]\n", rep.BrowserReason)
	}
	// Tools.
	s.Printf("│  Recon Tools: %d/%d present\n", rep.ToolsPresent, rep.ToolsTotal)
	var missing []string
	for _, t := range rep.Tools {
		if !t.Present {
			missing = append(missing, t.Name)
		}
	}
	if len(missing) > 0 {
		s.Printf("│  Missing    : %s\n", strings.Join(missing, ", "))
		s.Printf("│  (install hints printed below — the scan continues on available tools)\n")
		for _, t := range rep.Tools {
			if !t.Present {
				s.Printf("│    • %-18s %s\n", t.Name, t.InstallCmd)
			}
		}
	}
	s.Printf("│  Overall    : %s\n", rep.Overall)
	s.Printf("╰────────────────────────────────────────────────────────────────\n")
}
