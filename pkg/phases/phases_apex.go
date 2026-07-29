package phases

// phases_apex.go — V9.0 ABSOLUTE APEX master orchestration.
//
// V8 delivered the deep exploit engines (phases 46-53). V9 adds the ADAPTIVE
// INTELLIGENCE layer that governs how every one of those phases talks to the
// target:
//
//   • a single shared StealthGovernor per scan — adaptive concurrency (50→5 on
//     429/503/403), jittered backoff, a 30s WAF cool-down and a
//     runtime.ReadMemStats memory shield — injected into the exploit client
//     used by ALL advanced/max phases (see newAdvCtx);
//   • WAF/CDN fingerprinting of every live host up front, so heavy injection
//     fuzzing is skipped on protected endpoints unless --waf-bypass;
//   • the high-signal Burp filter, so only APIs / state-changing endpoints /
//     high-confidence vulns ever reach the operator's Burp history.
//
// ApexOrchestrationPhase (Phase 54) is the umbrella phase that primes the
// governor, fingerprints hosts, and reports the apex posture. It runs BEFORE
// the exploit phases so the governor and WAF map are populated when they start.

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/mohammed-v3/core/pkg/engine"
	"github.com/mohammed-v3/core/pkg/exploit"
	"github.com/mohammed-v3/core/pkg/filter"
)

// ─────────────────────────────────────────────────────────────────────────
// Shared adaptive stealth governor (one per scan)
// ─────────────────────────────────────────────────────────────────────────

var (
	stealthOnce sync.Once
	stealthGov  *exploit.StealthGovernor
)

// sharedStealthGovernor lazily builds the one StealthGovernor for the whole
// scan, sized from the configured thread budget. Every exploit-phase client
// (newAdvCtx) shares it, so a 429/WAF backoff triggered by one phase throttles
// them all — the single source of adaptive-concurrency truth.
func sharedStealthGovernor(s *engine.State) *exploit.StealthGovernor {
	stealthOnce.Do(func() {
		max := 50
		if s != nil && s.Config != nil && s.Config.Threads > 0 {
			max = s.Config.Threads
		}
		min := max / 10
		if min < 5 {
			min = 5
		}
		if min > max {
			min = max
		}
		stealthGov = exploit.NewStealthGovernor(exploit.StealthConfig{
			MaxConcurrency:  max,
			MinConcurrency:  min,
			BlockThreshold:  5,
			MemSoftLimitPct: 80,
		})
	})
	return stealthGov
}

// ─────────────────────────────────────────────────────────────────────────
// Phase 54 — Apex Orchestration (stealth prime + WAF fingerprint + Burp signal)
// ─────────────────────────────────────────────────────────────────────────

// ApexPhases returns the ordered V9.0 apex orchestration phases. It is a single
// umbrella phase that primes the adaptive subsystems for the exploit phases.
func ApexPhases() []engine.Phase {
	return []engine.Phase{
		&ApexOrchestrationPhase{},
	}
}

// ApexOrchestrationPhase primes the adaptive stealth governor, fingerprints
// every live host for WAF/CDN protection, and reports the high-signal Burp
// surface. It never itself reports a vulnerability — it configures the engine.
type ApexOrchestrationPhase struct{}

func (p *ApexOrchestrationPhase) Name() string { return "Apex Orchestration" }
func (p *ApexOrchestrationPhase) Description() string {
	return "Phase 54: prime adaptive stealth governor, WAF/CDN fingerprint live hosts, compute high-signal Burp surface"
}

func (p *ApexOrchestrationPhase) Execute(ctx context.Context, s *engine.State) error {
	// 1. Prime the shared governor so its posture is reported before exploits.
	gov := sharedStealthGovernor(s)
	s.Printf("│  Adaptive Stealth Governor: max=%d effective=%d | 429/503/403 backoff, jitter 200ms-1500ms, WAF cool-down 30s\n",
		func() int {
			if s.Config != nil && s.Config.Threads > 0 {
				return s.Config.Threads
			}
			return 50
		}(), gov.CurrentLimit())
	if engine.MemoryPressure() {
		s.Printf("│  ⚠ Memory shield ACTIVE: parallel tasks throttled to floor to protect host\n")
	}

	// 2. WAF/CDN fingerprint each unique live host (Section 1.2). Marks
	//    WAF-protected hosts on state so heavy fuzzing is skipped downstream.
	client := exploit.NewClient(exploit.Options{FollowRedirects: true, Stealth: gov})
	hosts := apexLiveOrigins(s)
	wafCount := 0
	for _, origin := range budget(hosts, 60) {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		resp := client.Get(ctx, origin)
		if resp.Err != nil {
			continue
		}
		fp := s.FingerprintAndMarkWAF(hostOnly(origin), resp.Status, resp.Headers, resp.Body)
		if fp.Detected {
			wafCount++
			kind := "passthrough CDN"
			if fp.Challenge {
				kind = "ACTIVE challenge/block"
			}
			s.Printf("│  WAF/CDN: %s → %s (%s) [%s]\n", hostOnly(origin), fp.Vendor, kind, strings.Join(fp.Signals, ", "))
		}
	}
	if wafCount > 0 {
		bypass := s.Config != nil && s.Config.WAFBypass
		mode := "SKIP heavy fuzzing on protected hosts (use --waf-bypass to override)"
		if bypass {
			mode = "--waf-bypass ON: heavy fuzzing WILL run on protected hosts"
		}
		s.Printf("│  WAF-protected hosts: %d | routing: %s\n", wafCount, mode)
	} else {
		s.Printf("│  WAF/CDN: no protected hosts detected among %d live origins\n", len(hosts))
	}

	// 3. High-signal Burp surface (Section 3.1): report how much crawl noise
	//    the Zero-Noise filter removes before anything reaches Burp.
	high := exploit.FilterHighSignal(s.URLs)
	s.Printf("│  High-signal Burp filter: %d/%d URLs are API/state-changing (%d static/noise dropped)\n",
		len(high), len(s.URLs), len(s.URLs)-len(high))

	return nil
}

// apexLiveOrigins returns unique in-scope scheme://host origins from the live
// hosts / URL corpus for WAF fingerprinting.
func apexLiveOrigins(s *engine.State) []string {
	seen := make(map[string]bool)
	var out []string
	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		if !strings.HasPrefix(raw, "http") {
			raw = "https://" + raw
		}
		o := originString(raw)
		if o == "" || seen[o] || !filter.IsInScope(o, s.Scope) {
			return
		}
		seen[o] = true
		out = append(out, o)
	}
	for _, h := range s.LiveHosts {
		add(h)
	}
	for _, u := range s.URLs {
		add(u)
	}
	return out
}

// originString extracts scheme://host[:port] from a URL string.
func originString(raw string) string {
	i := strings.Index(raw, "://")
	if i < 0 {
		return ""
	}
	after := raw[i+3:]
	if j := strings.IndexByte(after, '/'); j >= 0 {
		return raw[:i+3] + after[:j]
	}
	return raw
}

// hostOnly returns the bare host (no scheme, no path/port) of a URL.
func hostOnly(raw string) string {
	h := raw
	if i := strings.Index(h, "://"); i != -1 {
		h = h[i+3:]
	}
	if i := strings.IndexAny(h, "/:?"); i != -1 {
		h = h[:i]
	}
	return h
}

// apexPosture returns a one-line human summary of the apex configuration, used
// by the banner/report. Exposed for tests.
func apexPosture(s *engine.State) string {
	threads := 50
	if s != nil && s.Config != nil && s.Config.Threads > 0 {
		threads = s.Config.Threads
	}
	return fmt.Sprintf("adaptive-concurrency=%d→5 backoff=429/503/403 cooldown=30s ua-pool=%d 5-gate=simhash+levenshtein",
		threads, exploit.UserAgentPoolSize())
}
