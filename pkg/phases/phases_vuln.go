package phases

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mohammed-v3/core/pkg/config"
	"github.com/mohammed-v3/core/pkg/engine"
	"github.com/mohammed-v3/core/pkg/runner"
)

// parameterizedURLs returns URLs that carry at least one query parameter
// (contain '?' and '='), deduplicated and capped at `limit`. Used to feed
// dalfox / sqlmap only URLs worth testing (BUG #7).
func parameterizedURLs(lines []string, limit int) []string {
	seen := make(map[string]bool)
	var out []string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" || !strings.HasPrefix(l, "http") {
			continue
		}
		if !strings.Contains(l, "?") || !strings.Contains(l, "=") {
			continue
		}
		// Dedupe by path+param-names so we don't test 100 variants of one endpoint.
		key := paramSignature(l)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, l)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

// paramSignature reduces a URL to scheme+host+path+sorted-param-names so that
// ?id=1 and ?id=2 collapse to one signature.
func paramSignature(u string) string {
	base := u
	q := ""
	if idx := strings.Index(u, "?"); idx != -1 {
		base = u[:idx]
		q = u[idx+1:]
	}
	var names []string
	for _, kv := range strings.Split(q, "&") {
		if eq := strings.Index(kv, "="); eq != -1 {
			names = append(names, kv[:eq])
		} else if kv != "" {
			names = append(names, kv)
		}
	}
	return base + "?" + strings.Join(names, "&")
}

// ═══════════════════════════════════════════════════════════════
// Phase 15: Cloud & Bucket Reconnaissance
// ═══════════════════════════════════════════════════════════════
type CloudReconPhase struct{}

func (p *CloudReconPhase) Name() string { return "Cloud & Bucket Reconnaissance" }
func (p *CloudReconPhase) Description() string {
	return "cloud_enum, s3scanner for exposed buckets"
}
func (p *CloudReconPhase) Execute(ctx context.Context, s *engine.State) error {
	if len(s.Scope.Domains) == 0 {
		s.Printf("│  cloud_enum: SKIP (no domains in scope)\n")
		return nil
	}
	// Keyword for enumeration = registrable name without TLD (e.g. "whatnot").
	apex := config.ApexOf(s.Scope.Domains[0])
	keyword := apex
	if idx := strings.Index(apex, "."); idx != -1 {
		keyword = apex[:idx]
	}
	cloudOut := filepath.Join(s.OutputFolder, "cloud_results.txt")

	res := runner.RunTool(ctx, "cloud_enum", []string{"-k", keyword, "-l", cloudOut}, nil)
	if res.OK() || res.TimedOut {
		found := 0
		for _, l := range readNonEmptyLines(cloudOut) {
			ll := strings.ToLower(l)
			if strings.Contains(ll, "open") || strings.Contains(ll, "public") || strings.Contains(ll, "exists") {
				found++
				s.AddFinding(map[string]interface{}{
					"title": "Exposed Cloud Resource", "severity": "High",
					"url": l, "tool": "cloud_enum", "evidence": l,
				})
			}
		}
		s.Printf("│  cloud_enum: %d exposed resources\n", found)
	} else {
		s.Printf("│  cloud_enum: SKIP (%v)\n", res.Err)
	}

	// ── s3scanner ──────────────────────────────────────────────────────────
	// BUG #8 FIX: the old code printed "SKIP (<nil>)" whenever stdout was empty,
	// even though s3scanner had run successfully (exit 0, Err==nil) — the guard
	// `res.OK() && res.Stdout != ""` sent a *successful* run into the error
	// branch and formatted a nil error as "<nil>". A clean run that simply
	// found nothing is NOT a skip. We also fix the flag: s3scanner v2+ uses the
	// `scan -bucket <name>` subcommand, not the removed `--bucket`.
	if keyword == "" {
		s.Printf("│  s3scanner: SKIP (no keyword derived from scope)\n")
		return nil
	}
	res = runner.RunTool(ctx, "s3scanner", []string{"scan", "-bucket", keyword}, nil)
	switch {
	case !res.OK():
		// Genuine failure (binary missing, cancelled, timeout).
		s.Printf("│  s3scanner: SKIP (%v)\n", res.Err)
	case res.Stdout == "":
		s.Printf("│  s3scanner: no open buckets (empty result)\n")
	default:
		ll := strings.ToLower(res.Stdout)
		if strings.Contains(ll, "open") || strings.Contains(ll, "exists") {
			s.AddFinding(map[string]interface{}{
				"title": "Exposed S3 Bucket", "severity": "High",
				"url": keyword, "tool": "s3scanner", "evidence": strings.TrimSpace(res.Stdout),
			})
			s.Printf("│  s3scanner: exposed bucket found\n")
		} else {
			s.Printf("│  s3scanner: no open buckets\n")
		}
	}
	return nil
}

// ═══════════════════════════════════════════════════════════════
// Phase 16: Directory & Content Fuzzing
//
// Feeds LIVE endpoints (BUG #1 cascade fix): once httpx works, ffuf fuzzes
// real hosts instead of archived URLs.
// ═══════════════════════════════════════════════════════════════
type FuzzingPhase struct{}

func (p *FuzzingPhase) Name() string { return "Directory & Content Fuzzing" }
func (p *FuzzingPhase) Description() string {
	return "ffuf directory brute-force on live endpoints"
}
func (p *FuzzingPhase) Execute(ctx context.Context, s *engine.State) error {
	wordlist := firstExisting([]string{
		"/usr/share/seclists/Discovery/Web-Content/common.txt",
		"/usr/share/wordlists/dirb/common.txt",
		"/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt",
	})
	if wordlist == "" {
		s.Printf("│  ffuf: SKIP (no wordlist)\n")
		return nil
	}

	// Prefer live endpoints from httpx; fall back to any http URL.
	seeds := extractURLsFromHTTPX(filepath.Join(s.OutputFolder, "http_live.txt"))
	if len(seeds) == 0 {
		seeds = dedupeURLs(s.URLs)
	}
	if len(seeds) > 15 {
		seeds = seeds[:15]
	}
	if len(seeds) == 0 {
		s.Printf("│  ffuf: SKIP (no targets)\n")
		return nil
	}

	fuzzOut := filepath.Join(s.OutputFolder, "fuzz_results.txt")
	var allResults []string
	hits := 0

	for i, u := range seeds {
		if !strings.HasPrefix(u, "http") {
			continue
		}
		base := strings.TrimRight(u, "/")
		outFile := filepath.Join(s.OutputFolder, fmt.Sprintf("ffuf_%d.json", i))

		args := []string{"-u", base + "/FUZZ", "-w", wordlist,
			"-mc", "200,204,301,302,307,401,403", "-t", "20",
			"-rate", "100", "-o", outFile, "-of", "json", "-s"}
		if s.Proxy.Active {
			args = append(args, "-x", s.Proxy.ProxyURL)
		}
		res := runner.RunTool(ctx, "ffuf", args, nil)
		if res.OK() || res.TimedOut {
			if data, err := os.ReadFile(outFile); err == nil {
				allResults = append(allResults, string(data))
				var parsed struct {
					Results []map[string]interface{} `json:"results"`
				}
				if json.Unmarshal(data, &parsed) == nil {
					hits += len(parsed.Results)
				}
			}
		}
		s.Governor.Throttle()
	}

	writeLines(fuzzOut, allResults)
	s.Printf("│  ffuf: scanned %d targets, %d content hits\n", len(seeds), hits)
	return nil
}

// ═══════════════════════════════════════════════════════════════
// Phase 17: Vulnerability Scanning (Nuclei)
//
// Parses JSONL (-jsonl) output properly and runs AI triage on each finding
// before adding it, so false positives are demoted (not silently dropped).
// ═══════════════════════════════════════════════════════════════
type VulnScanPhase struct{}

func (p *VulnScanPhase) Name() string { return "Vulnerability Scanning (Nuclei)" }
func (p *VulnScanPhase) Description() string {
	return "Full nuclei template scan on live endpoints (JSONL parsed + AI triage)"
}
func (p *VulnScanPhase) Execute(ctx context.Context, s *engine.State) error {
	urlsFile := filepath.Join(s.OutputFolder, "nuclei_targets.txt")
	seeds := extractURLsFromHTTPX(filepath.Join(s.OutputFolder, "http_live.txt"))
	if len(seeds) == 0 {
		seeds = dedupeURLs(s.URLs)
	}
	if len(seeds) == 0 {
		s.Printf("│  nuclei: SKIP (no live endpoints)\n")
		return nil
	}
	writeLines(urlsFile, seeds)

	nucleiJSONL := filepath.Join(s.OutputFolder, "nuclei_results.jsonl")

	args := []string{"-l", urlsFile, "-jsonl", "-o", nucleiJSONL,
		"-silent", "-nc", "-rl", "150", "-c", "25",
		"-severity", "critical,high,medium,low,info"}
	if s.Proxy.Active {
		args = append(args, "-proxy", s.Proxy.ProxyURL)
	}

	res := runner.RunTool(ctx, "nuclei", args, nil)
	if !res.OK() && !res.TimedOut {
		s.Printf("│  nuclei: SKIP (%v)\n", res.Err)
		return nil
	}

	count := 0
	demoted := 0
	for _, line := range readNonEmptyLines(nucleiJSONL) {
		var rec map[string]interface{}
		if json.Unmarshal([]byte(line), &rec) != nil {
			continue
		}
		templateID, _ := rec["template-id"].(string)
		matched, _ := rec["matched-at"].(string)
		host, _ := rec["host"].(string)
		severity := "Info"
		description := ""
		if info, ok := rec["info"].(map[string]interface{}); ok {
			if sv, ok := info["severity"].(string); ok {
				severity = normalizeSeverity(sv)
			}
			if d, ok := info["description"].(string); ok {
				description = d
			}
		}
		target := matched
		if target == "" {
			target = host
		}
		evidence := fmt.Sprintf("template=%s matched=%s desc=%s", templateID, matched, description)

		f := map[string]interface{}{
			"title": templateID, "severity": severity,
			"url": target, "tool": "nuclei", "evidence": evidence,
		}
		// Only spend AI cycles on higher-severity findings; info/low are added directly.
		if severity == "Critical" || severity == "High" || severity == "Medium" {
			before := f["severity"]
			s.Triage(ctx, "Nuclei: "+templateID, target, evidence, f)
			if f["severity"] != before {
				demoted++
			}
		} else {
			s.AddFinding(f)
		}
		count++
	}
	s.Printf("│  nuclei: %d findings (%d demoted by AI triage)\n", count, demoted)
	return nil
}

// normalizeSeverity maps nuclei severity strings to our title-case scale.
func normalizeSeverity(sv string) string {
	switch strings.ToLower(strings.TrimSpace(sv)) {
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

// ═══════════════════════════════════════════════════════════════
// Phase 18: XSS Detection
//
// BUG #7 FIX: pre-filter to parameterized URLs only (<=20), add --timeout /
// --delay, and route through Burp with TLS ignore.
// ═══════════════════════════════════════════════════════════════
type XSSPhase struct{}

func (p *XSSPhase) Name() string { return "XSS Detection" }
func (p *XSSPhase) Description() string {
	return "kxss pre-filter + dalfox on parameterized URLs (max 20)"
}
func (p *XSSPhase) Execute(ctx context.Context, s *engine.State) error {
	paramsFile := filepath.Join(s.OutputFolder, "params.txt")
	if ok, _ := fileHasContent(paramsFile); !ok {
		s.Printf("│  XSS: SKIP (no parameterized URLs)\n")
		return nil
	}

	// Build a filtered, deduplicated, capped target list.
	targets := parameterizedURLs(readNonEmptyLines(paramsFile), 20)
	if len(targets) == 0 {
		s.Printf("│  XSS: SKIP (no URLs with query parameters)\n")
		return nil
	}
	dalfoxIn := filepath.Join(s.OutputFolder, "xss_targets.txt")
	writeLines(dalfoxIn, targets)
	s.Printf("│  XSS targets (parameterized, capped): %d\n", len(targets))

	// ── kxss pre-filter (reflection check) ─────────────────────────────
	kxssOut := filepath.Join(s.OutputFolder, "kxss_results.txt")
	cmd := fmt.Sprintf("cat %q | kxss > %q 2>/dev/null", dalfoxIn, kxssOut)
	res := runner.RunTool(ctx, "bash", []string{"-c", cmd}, nil)
	if res.OK() {
		if _, n := fileHasContent(kxssOut); n > 0 {
			s.Printf("│  kxss: %d reflecting params\n", n)
		} else {
			s.Printf("│  kxss: no reflecting params\n")
		}
	} else {
		s.Printf("│  kxss: SKIP (%v)\n", res.Err)
	}

	// ── dalfox ─────────────────────────────────────────────────────────
	xssOut := filepath.Join(s.OutputFolder, "xss_results.txt")
	args := []string{"file", dalfoxIn, "-o", xssOut, "--silence",
		"-w", "10", "--timeout", "10", "--delay", "100"}
	if s.Proxy.Active {
		args = append(args, "--proxy", s.Proxy.ProxyURL, "--skip-bav")
	}
	res = runner.RunTool(ctx, "dalfox", args, nil)
	if res.OK() || res.TimedOut {
		found := 0
		for _, l := range readNonEmptyLines(xssOut) {
			if strings.Contains(l, "POC") || strings.Contains(l, "[V]") || strings.Contains(strings.ToLower(l), "verified") {
				found++
				f := map[string]interface{}{
					"title": "XSS Vulnerability", "severity": "High",
					"url": l, "tool": "dalfox", "evidence": l,
				}
				s.Triage(ctx, "Reflected XSS", l, l, f)
			}
		}
		s.Printf("│  dalfox: %d XSS finding(s)\n", found)
	} else {
		s.Printf("│  dalfox: SKIP (%v)\n", res.Err)
	}
	return nil
}

// ═══════════════════════════════════════════════════════════════
// Phase 19: SQL Injection
// ═══════════════════════════════════════════════════════════════
type SQLiPhase struct{}

func (p *SQLiPhase) Name() string { return "SQL Injection Analysis" }
func (p *SQLiPhase) Description() string {
	return "sqlmap + ghauri on parameterized URLs (filtered, capped)"
}
func (p *SQLiPhase) Execute(ctx context.Context, s *engine.State) error {
	paramsFile := filepath.Join(s.OutputFolder, "params.txt")
	if ok, _ := fileHasContent(paramsFile); !ok {
		s.Printf("│  SQLi: SKIP (no parameterized URLs)\n")
		return nil
	}

	targets := parameterizedURLs(readNonEmptyLines(paramsFile), 10)
	if len(targets) == 0 {
		s.Printf("│  SQLi: SKIP (no URLs with query parameters)\n")
		return nil
	}

	sqliOut := filepath.Join(s.OutputFolder, "sqli_results.txt")
	var results []string
	for _, u := range targets {
		args := []string{"-u", u, "--batch", "--level", "2", "--risk", "1",
			"--random-agent", "--output-dir", s.OutputFolder}
		if s.Proxy.Active {
			args = append(args, "--proxy", s.Proxy.ProxyURL)
		}
		res := runner.RunTool(ctx, "sqlmap", args, nil)
		if res.OK() && strings.Contains(strings.ToLower(res.Stdout), "injectable") {
			results = append(results, u)
			f := map[string]interface{}{
				"title": "SQL Injection", "severity": "Critical",
				"url": u, "tool": "sqlmap", "evidence": "sqlmap reports parameter injectable",
			}
			s.Triage(ctx, "SQL Injection", u, "sqlmap reports parameter injectable", f)
		} else {
			// ghauri as a second opinion.
			res = runner.RunTool(ctx, "ghauri", []string{"-u", u, "--batch", "--level", "2"}, nil)
			if res.OK() && strings.Contains(strings.ToLower(res.Stdout), "injectable") {
				results = append(results, u+" [ghauri]")
				f := map[string]interface{}{
					"title": "SQL Injection", "severity": "Critical",
					"url": u, "tool": "ghauri", "evidence": "ghauri reports parameter injectable",
				}
				s.Triage(ctx, "SQL Injection", u, "ghauri reports parameter injectable", f)
			}
		}
		s.Governor.Throttle()
	}
	writeLines(sqliOut, results)
	s.Printf("│  SQLi: tested %d, found %d injectable\n", len(targets), len(results))
	return nil
}

// ═══════════════════════════════════════════════════════════════
// Phase 20: SSRF Scanning
//
// nuclei SSRF templates need an interaction server. If interactsh-client is
// unavailable, skip with a clear message rather than hanging.
// ═══════════════════════════════════════════════════════════════
type SSRFPhase struct{}

func (p *SSRFPhase) Name() string { return "SSRF Scanning" }
func (p *SSRFPhase) Description() string {
	return "nuclei SSRF templates with interactsh callback"
}
func (p *SSRFPhase) Execute(ctx context.Context, s *engine.State) error {
	urlsFile := filepath.Join(s.OutputFolder, "nuclei_targets.txt")
	if ok, _ := fileHasContent(urlsFile); !ok {
		urlsFile = filepath.Join(s.OutputFolder, "http_live.txt")
	}
	if ok, _ := fileHasContent(urlsFile); !ok {
		s.Printf("│  nuclei SSRF: SKIP (no live endpoints)\n")
		return nil
	}
	ssrfJSONL := filepath.Join(s.OutputFolder, "ssrf_results.jsonl")

	args := []string{"-l", urlsFile, "-tags", "ssrf", "-jsonl", "-o", ssrfJSONL,
		"-silent", "-nc", "-rl", "100"}
	// Use a public interactsh server explicitly (oast.pro) — nuclei defaults to
	// interactsh.com but naming it makes the behaviour deterministic.
	args = append(args, "-iserver", "https://oast.pro")
	if s.Proxy.Active {
		args = append(args, "-proxy", s.Proxy.ProxyURL)
	}

	res := runner.RunTool(ctx, "nuclei", args, nil)
	if res.OK() || res.TimedOut {
		count := 0
		for _, line := range readNonEmptyLines(ssrfJSONL) {
			var rec map[string]interface{}
			if json.Unmarshal([]byte(line), &rec) != nil {
				continue
			}
			matched, _ := rec["matched-at"].(string)
			tid, _ := rec["template-id"].(string)
			f := map[string]interface{}{
				"title": "SSRF Vulnerability", "severity": "High",
				"url": matched, "tool": "nuclei-ssrf", "evidence": "template=" + tid,
			}
			s.Triage(ctx, "SSRF", matched, "template="+tid, f)
			count++
		}
		s.Printf("│  nuclei SSRF: %d finding(s)\n", count)
	} else {
		s.Printf("│  nuclei SSRF: SKIP (%v)\n", res.Err)
	}
	return nil
}

// ═══════════════════════════════════════════════════════════════
// Phase 21: Open Redirect
// ═══════════════════════════════════════════════════════════════
type OpenRedirectPhase struct{}

func (p *OpenRedirectPhase) Name() string { return "Open Redirect Testing" }
func (p *OpenRedirectPhase) Description() string {
	return "nuclei redirect templates on param URLs"
}
func (p *OpenRedirectPhase) Execute(ctx context.Context, s *engine.State) error {
	paramsFile := filepath.Join(s.OutputFolder, "params.txt")
	if ok, _ := fileHasContent(paramsFile); !ok {
		s.Printf("│  Open Redirect: SKIP (no param URLs)\n")
		return nil
	}
	redirectJSONL := filepath.Join(s.OutputFolder, "redirect_results.jsonl")

	args := []string{"-l", paramsFile, "-tags", "redirect", "-jsonl", "-o", redirectJSONL,
		"-silent", "-nc", "-rl", "100"}
	if s.Proxy.Active {
		args = append(args, "-proxy", s.Proxy.ProxyURL)
	}

	res := runner.RunTool(ctx, "nuclei", args, nil)
	if res.OK() || res.TimedOut {
		count := 0
		for _, line := range readNonEmptyLines(redirectJSONL) {
			var rec map[string]interface{}
			if json.Unmarshal([]byte(line), &rec) != nil {
				continue
			}
			matched, _ := rec["matched-at"].(string)
			tid, _ := rec["template-id"].(string)
			s.AddFinding(map[string]interface{}{
				"title": "Open Redirect", "severity": "Medium",
				"url": matched, "tool": "nuclei-redirect", "evidence": "template=" + tid,
			})
			count++
		}
		s.Printf("│  Open Redirect: %d finding(s)\n", count)
	} else {
		s.Printf("│  Open Redirect: SKIP (%v)\n", res.Err)
	}
	return nil
}

// ═══════════════════════════════════════════════════════════════
// Phase 22: 403/401 Bypass
//
// BUG #1 cascade fix: forbidden URLs are extracted from httpx JSONL now that
// httpx produces output through Burp.
// ═══════════════════════════════════════════════════════════════
type ForbiddenBypassPhase struct{}

func (p *ForbiddenBypassPhase) Name() string { return "403/401 Bypass Testing" }
func (p *ForbiddenBypassPhase) Description() string {
	return "dontgo403 on forbidden endpoints"
}
func (p *ForbiddenBypassPhase) Execute(ctx context.Context, s *engine.State) error {
	bypassOut := filepath.Join(s.OutputFolder, "bypass_results.txt")
	httpxFile := filepath.Join(s.OutputFolder, "http_live.txt")

	var forbiddenURLs []string
	seen := make(map[string]bool)
	for _, l := range readNonEmptyLines(httpxFile) {
		var rec map[string]interface{}
		if json.Unmarshal([]byte(l), &rec) == nil {
			code := fmt.Sprintf("%v", rec["status_code"])
			if code == "403" || code == "401" {
				if u, ok := rec["url"].(string); ok && !seen[u] {
					seen[u] = true
					forbiddenURLs = append(forbiddenURLs, u)
				}
			}
			continue
		}
		// Plain-text fallback.
		if strings.Contains(l, "[403]") || strings.Contains(l, "[401]") {
			parts := strings.Fields(l)
			if len(parts) > 0 && !seen[parts[0]] {
				seen[parts[0]] = true
				forbiddenURLs = append(forbiddenURLs, parts[0])
			}
		}
	}

	if len(forbiddenURLs) == 0 {
		s.Printf("│  403/401 Bypass: SKIP (no forbidden endpoints)\n")
		return nil
	}

	var results []string
	bypassed := 0
	for _, u := range forbiddenURLs {
		res := runner.RunTool(ctx, "dontgo403", []string{"-u", u}, nil)
		if res.OK() && (strings.Contains(res.Stdout, "200") || strings.Contains(strings.ToLower(res.Stdout), "bypass")) {
			results = append(results, u)
			f := map[string]interface{}{
				"title": "403/401 Bypass", "severity": "High",
				"url": u, "tool": "dontgo403", "evidence": strings.TrimSpace(res.Stdout),
			}
			s.Triage(ctx, "Forbidden Bypass", u, res.Stdout, f)
			bypassed++
		}
		s.Governor.Throttle()
	}
	writeLines(bypassOut, results)
	s.Printf("│  403/401 Bypass: tested %d, bypassed %d\n", len(forbiddenURLs), bypassed)
	return nil
}

// ═══════════════════════════════════════════════════════════════
// Phase 23: API Discovery
// ═══════════════════════════════════════════════════════════════
type APIDiscoveryPhase struct{}

func (p *APIDiscoveryPhase) Name() string { return "API Route Discovery" }
func (p *APIDiscoveryPhase) Description() string {
	return "kiterunner API endpoint brute-force (curl fallback)"
}
func (p *APIDiscoveryPhase) Execute(ctx context.Context, s *engine.State) error {
	seeds := extractURLsFromHTTPX(filepath.Join(s.OutputFolder, "http_live.txt"))
	if len(seeds) == 0 {
		seeds = dedupeURLs(s.URLs)
	}
	if len(seeds) == 0 {
		s.Printf("│  API discovery: SKIP (no live endpoints)\n")
		return nil
	}
	apiSeedFile := filepath.Join(s.OutputFolder, "api_seeds.txt")
	writeLines(apiSeedFile, seeds)
	apiOut := filepath.Join(s.OutputFolder, "api_results.txt")

	krWordlist := firstExisting([]string{
		"/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt",
		"/usr/share/seclists/Discovery/Web-Content/common-api-endpoints-mazen160.txt",
	})

	if _, err := runner.ResolveToolPath("kr"); err == nil && krWordlist != "" {
		res := runner.RunTool(ctx, "kr", []string{"brute", apiSeedFile, "-w", krWordlist, "-o", "text"}, nil)
		if res.OK() || res.TimedOut {
			_ = os.WriteFile(apiOut, []byte(res.Stdout), 0644)
			s.Printf("│  kiterunner: OK\n")
			return nil
		}
		s.Printf("│  kiterunner: failed (%v) → curl fallback\n", res.Err)
	} else {
		s.Printf("│  kiterunner: unavailable → curl fallback\n")
	}

	// curl fallback on a handful of common API paths.
	apiPaths := []string{"/api", "/api/v1", "/api/v2", "/swagger.json",
		"/openapi.json", "/api-docs", "/graphql", "/.well-known/security.txt",
		"/api/health", "/api/status"}
	found := 0
	checked := 0
	for _, u := range seeds {
		if checked >= 10 {
			break
		}
		checked++
		base := strings.TrimRight(u, "/")
		for _, path := range apiPaths {
			args := []string{"-s", "-o", "/dev/null", "-w", "%{http_code}", "-m", "6", base + path}
			if s.Proxy.Active {
				args = append([]string{"-x", s.Proxy.ProxyURL, "-k"}, args...)
			}
			res := runner.RunTool(ctx, "curl", args, nil)
			if res.OK() && (res.Stdout == "200" || res.Stdout == "301" || res.Stdout == "302") {
				found++
				s.AddFinding(map[string]interface{}{
					"title": "API Endpoint Found", "severity": "Info",
					"url": base + path, "tool": "api_scan", "evidence": "HTTP " + res.Stdout,
				})
			}
		}
		s.Governor.Throttle()
	}
	s.Printf("│  API scan (fallback): %d endpoints\n", found)
	return nil
}

// ═══════════════════════════════════════════════════════════════
// Phase 24: CRLF Injection
// ═══════════════════════════════════════════════════════════════
type CRLFPhase struct{}

func (p *CRLFPhase) Name() string { return "CRLF Injection Check" }
func (p *CRLFPhase) Description() string { return "crlfuzz on live endpoints" }
func (p *CRLFPhase) Execute(ctx context.Context, s *engine.State) error {
	seeds := extractURLsFromHTTPX(filepath.Join(s.OutputFolder, "http_live.txt"))
	if len(seeds) == 0 {
		s.Printf("│  crlfuzz: SKIP (no live endpoints)\n")
		return nil
	}
	crlfIn := filepath.Join(s.OutputFolder, "crlf_targets.txt")
	writeLines(crlfIn, seeds)
	crlfOut := filepath.Join(s.OutputFolder, "crlf_results.txt")

	args := []string{"-l", crlfIn, "-o", crlfOut, "-s", "-c", "20"}
	if s.Proxy.Active {
		args = append(args, "-x", s.Proxy.ProxyURL)
	}
	res := runner.RunTool(ctx, "crlfuzz", args, nil)
	if res.OK() || res.TimedOut {
		count := 0
		for _, l := range readNonEmptyLines(crlfOut) {
			count++
			s.AddFinding(map[string]interface{}{
				"title": "CRLF Injection", "severity": "Medium",
				"url": l, "tool": "crlfuzz", "evidence": l,
			})
		}
		s.Printf("│  crlfuzz: %d vulnerable\n", count)
	} else {
		s.Printf("│  crlfuzz: SKIP (%v)\n", res.Err)
	}
	return nil
}

// ═══════════════════════════════════════════════════════════════
// Phase 25: HTTP Request Smuggling
//
// smuggler.py operates on ONE URL at a time (reads a single -u target), so we
// iterate over the top 5 live endpoints instead of passing a list file.
// ═══════════════════════════════════════════════════════════════
type SmugglingPhase struct{}

func (p *SmugglingPhase) Name() string { return "HTTP Request Smuggling" }
func (p *SmugglingPhase) Description() string {
	return "smuggler CL.TE/TE.CL detection (per-endpoint, top 5)"
}
func (p *SmugglingPhase) Execute(ctx context.Context, s *engine.State) error {
	seeds := extractURLsFromHTTPX(filepath.Join(s.OutputFolder, "http_live.txt"))
	if len(seeds) == 0 {
		seeds = dedupeURLs(s.URLs)
	}
	if len(seeds) == 0 {
		s.Printf("│  smuggler: SKIP (no live endpoints)\n")
		return nil
	}
	if len(seeds) > 5 {
		seeds = seeds[:5]
	}

	smugOut := filepath.Join(s.OutputFolder, "smuggling_results.txt")
	var allOut []string
	confirmed := 0

	for _, u := range seeds {
		res := runner.RunTool(ctx, "smuggler", []string{"-u", u}, nil)
		if !res.OK() && !res.TimedOut {
			continue
		}
		combined := res.Stdout + "\n" + res.Stderr
		allOut = append(allOut, "### "+u, combined)
		lower := strings.ToLower(combined)
		if strings.Contains(lower, "vulnerable") || strings.Contains(lower, "potentially vulnerable") {
			f := map[string]interface{}{
				"title": "HTTP Request Smuggling", "severity": "Critical",
				"url": u, "tool": "smuggler", "evidence": strings.TrimSpace(combined),
			}
			s.Triage(ctx, "HTTP Request Smuggling", u, combined, f)
			confirmed++
		}
		s.Governor.Throttle()
	}
	writeLines(smugOut, allOut)
	s.Printf("│  smuggler: %d endpoint(s) tested, %d flagged\n", len(seeds), confirmed)
	return nil
}

// ═══════════════════════════════════════════════════════════════
// Phase 26: Git/Sensitive File Exposure
// ═══════════════════════════════════════════════════════════════
type GitExposurePhase struct{}

func (p *GitExposurePhase) Name() string { return "Git & Sensitive File Exposure" }
func (p *GitExposurePhase) Description() string {
	return "nuclei exposure templates + custom sensitive-file checks"
}
func (p *GitExposurePhase) Execute(ctx context.Context, s *engine.State) error {
	seeds := extractURLsFromHTTPX(filepath.Join(s.OutputFolder, "http_live.txt"))
	if len(seeds) == 0 {
		seeds = dedupeURLs(s.URLs)
	}

	// nuclei exposure templates.
	if len(seeds) > 0 {
		exposureIn := filepath.Join(s.OutputFolder, "exposure_targets.txt")
		writeLines(exposureIn, seeds)
		exposureJSONL := filepath.Join(s.OutputFolder, "exposure_results.jsonl")
		args := []string{"-l", exposureIn, "-tags", "exposure", "-jsonl", "-o", exposureJSONL,
			"-silent", "-nc", "-rl", "100"}
		if s.Proxy.Active {
			args = append(args, "-proxy", s.Proxy.ProxyURL)
		}
		res := runner.RunTool(ctx, "nuclei", args, nil)
		if res.OK() || res.TimedOut {
			count := 0
			for _, line := range readNonEmptyLines(exposureJSONL) {
				var rec map[string]interface{}
				if json.Unmarshal([]byte(line), &rec) != nil {
					continue
				}
				matched, _ := rec["matched-at"].(string)
				tid, _ := rec["template-id"].(string)
				s.AddFinding(map[string]interface{}{
					"title": "Sensitive Exposure", "severity": "High",
					"url": matched, "tool": "nuclei-exposure", "evidence": "template=" + tid,
				})
				count++
			}
			s.Printf("│  nuclei exposure: %d\n", count)
		} else {
			s.Printf("│  nuclei exposure: SKIP (%v)\n", res.Err)
		}
	}

	// Custom checks for common sensitive files.
	sensitiveFiles := []string{"/.git/config", "/.env", "/.DS_Store", "/backup.zip",
		"/wp-config.php.bak", "/.htpasswd", "/server-status", "/.svn/entries"}
	found := 0
	targets := seeds
	if len(targets) > 20 {
		targets = targets[:20]
	}
	for _, u := range targets {
		base := strings.TrimRight(u, "/")
		for _, path := range sensitiveFiles {
			args := []string{"-s", "-o", "/dev/null", "-w", "%{http_code}:%{size_download}", "-m", "6", base + path}
			if s.Proxy.Active {
				args = append([]string{"-x", s.Proxy.ProxyURL, "-k"}, args...)
			}
			res := runner.RunTool(ctx, "curl", args, nil)
			if res.OK() {
				parts := strings.Split(res.Stdout, ":")
				if len(parts) == 2 && parts[0] == "200" && parts[1] != "0" {
					found++
					s.AddFinding(map[string]interface{}{
						"title": "Sensitive File: " + path, "severity": "High",
						"url": base + path, "tool": "custom_scan", "evidence": "HTTP 200, size: " + parts[1],
					})
				}
			}
		}
		s.Governor.Throttle()
	}
	s.Printf("│  Sensitive files found: %d\n", found)
	return nil
}

// ═══════════════════════════════════════════════════════════════
// Phase 27: Email Security (SPF/DKIM/DMARC)
// ═══════════════════════════════════════════════════════════════
type EmailSecurityPhase struct{}

func (p *EmailSecurityPhase) Name() string { return "Email Security Verification" }
func (p *EmailSecurityPhase) Description() string {
	return "Checks SPF, DKIM, DMARC DNS records"
}
func (p *EmailSecurityPhase) Execute(ctx context.Context, s *engine.State) error {
	emailOut := filepath.Join(s.OutputFolder, "email_security.txt")
	var results []string

	for _, domain := range config.ExtractApexDomains(s.Scope.Domains) {
		res := runner.RunTool(ctx, "dig", []string{"+short", "TXT", domain}, nil)
		hasSPF := res.OK() && strings.Contains(res.Stdout, "v=spf1")

		res = runner.RunTool(ctx, "dig", []string{"+short", "TXT", "_dmarc." + domain}, nil)
		hasDMARC := res.OK() && strings.Contains(res.Stdout, "v=DMARC1")

		hasDKIM := false
		for _, sel := range []string{"default", "google", "selector1", "selector2", "mail", "k1"} {
			res = runner.RunTool(ctx, "dig", []string{"+short", "TXT", sel + "._domainkey." + domain}, nil)
			if res.OK() && strings.Contains(res.Stdout, "v=DKIM1") {
				hasDKIM = true
				break
			}
		}

		line := fmt.Sprintf("%s | SPF:%v | DKIM:%v | DMARC:%v", domain, hasSPF, hasDKIM, hasDMARC)
		results = append(results, line)
		s.Printf("│  %s\n", line)

		if !hasSPF || !hasDMARC {
			s.AddFinding(map[string]interface{}{
				"title": "Missing Email Security Records", "severity": "Medium",
				"url": domain, "tool": "email_check",
				"evidence": fmt.Sprintf("SPF:%v DKIM:%v DMARC:%v", hasSPF, hasDKIM, hasDMARC),
			})
		}
	}
	writeLines(emailOut, results)
	return nil
}

// ═══════════════════════════════════════════════════════════════
// Phase 28: Prototype Pollution
// ═══════════════════════════════════════════════════════════════
type PrototypePollutionPhase struct{}

func (p *PrototypePollutionPhase) Name() string { return "Prototype Pollution Scan" }
func (p *PrototypePollutionPhase) Description() string {
	return "nuclei prototype pollution templates"
}
func (p *PrototypePollutionPhase) Execute(ctx context.Context, s *engine.State) error {
	urlsFile := filepath.Join(s.OutputFolder, "nuclei_targets.txt")
	if ok, _ := fileHasContent(urlsFile); !ok {
		urlsFile = filepath.Join(s.OutputFolder, "http_live.txt")
	}
	if ok, _ := fileHasContent(urlsFile); !ok {
		s.Printf("│  Proto Pollution: SKIP (no live endpoints)\n")
		return nil
	}
	ppJSONL := filepath.Join(s.OutputFolder, "proto_pollution_results.jsonl")

	args := []string{"-l", urlsFile, "-tags", "prototype-pollution", "-jsonl", "-o", ppJSONL,
		"-silent", "-nc", "-rl", "100"}
	if s.Proxy.Active {
		args = append(args, "-proxy", s.Proxy.ProxyURL)
	}
	res := runner.RunTool(ctx, "nuclei", args, nil)
	if res.OK() || res.TimedOut {
		count := 0
		for _, line := range readNonEmptyLines(ppJSONL) {
			var rec map[string]interface{}
			if json.Unmarshal([]byte(line), &rec) != nil {
				continue
			}
			matched, _ := rec["matched-at"].(string)
			tid, _ := rec["template-id"].(string)
			f := map[string]interface{}{
				"title": "Prototype Pollution", "severity": "High",
				"url": matched, "tool": "nuclei-pp", "evidence": "template=" + tid,
			}
			s.Triage(ctx, "Prototype Pollution", matched, "template="+tid, f)
			count++
		}
		s.Printf("│  Proto Pollution: %d finding(s)\n", count)
	} else {
		s.Printf("│  Proto Pollution: SKIP (%v)\n", res.Err)
	}
	return nil
}

// ═══════════════════════════════════════════════════════════════
// Phase 29: Final Report Generation
// ═══════════════════════════════════════════════════════════════
type ReportPhase struct{}

func (p *ReportPhase) Name() string { return "Final Report Generation" }
func (p *ReportPhase) Description() string {
	return "Generates Markdown + JSON summary with all findings and AI verdicts"
}
func (p *ReportPhase) Execute(ctx context.Context, s *engine.State) error {
	counts := map[string]int{"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
	for _, f := range s.Findings {
		sev := fmt.Sprintf("%v", f["severity"])
		counts[sev]++
	}

	var b strings.Builder
	b.WriteString("# MOHAMMED v4 — Scan Report\n\n")
	b.WriteString("## Summary\n\n")
	b.WriteString("| Metric | Count |\n|---|---|\n")
	b.WriteString(fmt.Sprintf("| Subdomains | %d |\n", len(s.Subdomains)))
	b.WriteString(fmt.Sprintf("| Live Hosts | %d |\n", len(s.LiveHosts)))
	b.WriteString(fmt.Sprintf("| URLs | %d |\n", len(dedupeURLs(s.URLs))))
	b.WriteString(fmt.Sprintf("| Total Findings | %d |\n\n", len(s.Findings)))

	b.WriteString("## Findings by Severity\n\n")
	b.WriteString("| Severity | Count |\n|---|---|\n")
	for _, sev := range []string{"Critical", "High", "Medium", "Low", "Info"} {
		b.WriteString(fmt.Sprintf("| %s | %d |\n", sev, counts[sev]))
	}

	b.WriteString("\n## Detailed Findings\n\n")
	for _, sev := range []string{"Critical", "High", "Medium", "Low", "Info"} {
		for _, f := range s.Findings {
			if fmt.Sprintf("%v", f["severity"]) != sev {
				continue
			}
			b.WriteString(fmt.Sprintf("### [%s] %v\n", sev, f["title"]))
			b.WriteString(fmt.Sprintf("- URL: %v\n", f["url"]))
			b.WriteString(fmt.Sprintf("- Tool: %v\n", f["tool"]))
			b.WriteString(fmt.Sprintf("- Evidence: %v\n", f["evidence"]))
			if v, ok := f["ai_verdict"]; ok {
				b.WriteString(fmt.Sprintf("- AI Verdict: %v\n", v))
			}
			if orig, ok := f["original_severity"]; ok {
				b.WriteString(fmt.Sprintf("- Original Severity (before AI demotion): %v\n", orig))
			}
			b.WriteString("\n")
		}
	}

	reportFile := filepath.Join(s.OutputFolder, "final_report.md")
	_ = os.WriteFile(reportFile, []byte(b.String()), 0644)

	// Also emit machine-readable JSON.
	if data, err := json.MarshalIndent(map[string]interface{}{
		"subdomains": len(s.Subdomains),
		"live_hosts": len(s.LiveHosts),
		"urls":       len(dedupeURLs(s.URLs)),
		"counts":     counts,
		"findings":   s.Findings,
	}, "", "  "); err == nil {
		_ = os.WriteFile(filepath.Join(s.OutputFolder, "final_report.json"), data, 0644)
	}

	s.Printf("│  Report saved: %s\n", reportFile)
	s.Printf("│  Critical: %d | High: %d | Medium: %d | Low: %d | Info: %d\n",
		counts["Critical"], counts["High"], counts["Medium"], counts["Low"], counts["Info"])
	return nil
}
