package phases

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mohammed-v3/core/pkg/engine"
	"github.com/mohammed-v3/core/pkg/runner"
)

// ═══════════════════════════════════════════════════════════════
// Phase 15: Cloud & Bucket Reconnaissance
// ═══════════════════════════════════════════════════════════════
type CloudReconPhase struct{}

func (p *CloudReconPhase) Name() string        { return "Cloud & Bucket Reconnaissance" }
func (p *CloudReconPhase) Description() string { return "cloud_enum, s3scanner for exposed buckets" }
func (p *CloudReconPhase) Execute(ctx context.Context, s *engine.State) error {
	if len(s.Scope.Domains) == 0 {
		s.Printf("│  cloud_enum: SKIP (no domains in scope)\n")
		return nil
	}
	domain := s.Scope.Domains[0]
	cloudOut := filepath.Join(s.OutputFolder, "cloud_results.txt")

	res := runner.RunTool(ctx, "cloud_enum", []string{"-k", domain, "-l", cloudOut}, nil)
	if res.Err == nil {
		s.Printf("│  cloud_enum: OK\n")
	} else {
		s.Printf("│  cloud_enum: SKIP\n")
	}

	// s3scanner
	res = runner.RunTool(ctx, "s3scanner", []string{"--bucket", domain}, nil)
	if res.Err == nil && res.Stdout != "" {
		if strings.Contains(res.Stdout, "open") || strings.Contains(res.Stdout, "exists") {
			s.Findings = append(s.Findings, map[string]interface{}{
				"title": "Exposed S3 Bucket", "severity": "High",
				"url": domain, "tool": "s3scanner", "evidence": res.Stdout,
			})
		}
		s.Printf("│  s3scanner: OK\n")
	} else {
		s.Printf("│  s3scanner: SKIP\n")
	}
	return nil
}

// ═══════════════════════════════════════════════════════════════
// Phase 16: Directory & Content Fuzzing
// ═══════════════════════════════════════════════════════════════
type FuzzingPhase struct{}

func (p *FuzzingPhase) Name() string        { return "Directory & Content Fuzzing" }
func (p *FuzzingPhase) Description() string { return "ffuf directory brute-force on live endpoints" }
func (p *FuzzingPhase) Execute(ctx context.Context, s *engine.State) error {
	wordlist := "/usr/share/seclists/Discovery/Web-Content/common.txt"
	if _, err := os.Stat(wordlist); err != nil {
		wordlist = "/usr/share/wordlists/dirb/common.txt"
		if _, err := os.Stat(wordlist); err != nil {
			s.Printf("│  ffuf: SKIP (no wordlist)\n")
			return nil
		}
	}

	targets := s.URLs
	if len(targets) > 15 { targets = targets[:15] }

	fuzzOut := filepath.Join(s.OutputFolder, "fuzz_results.txt")
	var allResults []string

	for i, u := range targets {
		if !strings.HasPrefix(u, "http") { continue }
		base := strings.TrimRight(u, "/")
		outFile := filepath.Join(s.OutputFolder, fmt.Sprintf("ffuf_%d.json", i))

		args := []string{"-u", base + "/FUZZ", "-w", wordlist, "-mc", "200,301,302,403",
			"-fc", "404", "-t", "20", "-rate", "100", "-o", outFile, "-of", "json", "-s"}
		if s.Proxy.Active { args = append(args, "-x", s.Proxy.ProxyURL) }

		res := runner.RunTool(ctx, "ffuf", args, s.Proxy.GetEnv())
		if res.Err == nil {
			if data, err := os.ReadFile(outFile); err == nil {
				allResults = append(allResults, string(data))
			}
		}
		s.Governor.Throttle()
	}

	os.WriteFile(fuzzOut, []byte(strings.Join(allResults, "\n")), 0644)
	s.Printf("│  ffuf: scanned %d targets\n", len(targets))
	return nil
}

// ═══════════════════════════════════════════════════════════════
// Phase 17: Vulnerability Scanning (Nuclei)
// ═══════════════════════════════════════════════════════════════
type VulnScanPhase struct{}

func (p *VulnScanPhase) Name() string        { return "Vulnerability Scanning (Nuclei)" }
func (p *VulnScanPhase) Description() string { return "Full nuclei template scan on all live endpoints" }
func (p *VulnScanPhase) Execute(ctx context.Context, s *engine.State) error {
	urlsFile := filepath.Join(s.OutputFolder, "http_live.txt")
	if _, err := os.Stat(urlsFile); err != nil {
		// Create from s.URLs
		content := strings.Join(s.URLs, "\n")
		os.WriteFile(urlsFile, []byte(content), 0644)
	}

	nucleiOut := filepath.Join(s.OutputFolder, "nuclei_results.txt")
	nucleiJSON := filepath.Join(s.OutputFolder, "nuclei_results.json")

	args := []string{"-l", urlsFile, "-o", nucleiOut, "-jsonl", nucleiJSON,
		"-silent", "-rl", "150", "-c", "25",
		"-severity", "critical,high,medium,low,info"}
	if s.Proxy.Active { args = append(args, "-proxy", s.Proxy.ProxyURL) }

	res := runner.RunTool(ctx, "nuclei", args, s.Proxy.GetEnv())
	if res.Err == nil {
		data, _ := os.ReadFile(nucleiOut)
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		for _, l := range lines {
			if l == "" { continue }
			severity := "Info"
			lower := strings.ToLower(l)
			if strings.Contains(lower, "[critical]") { severity = "Critical" }
			if strings.Contains(lower, "[high]") { severity = "High" }
			if strings.Contains(lower, "[medium]") { severity = "Medium" }
			if strings.Contains(lower, "[low]") { severity = "Low" }

			s.Findings = append(s.Findings, map[string]interface{}{
				"title": l, "severity": severity, "url": l, "tool": "nuclei", "evidence": l,
			})
		}
		s.Printf("│  nuclei: %d findings\n", len(lines))
	} else {
		s.Printf("│  nuclei: SKIP (%v)\n", res.Err)
	}
	return nil
}

// ═══════════════════════════════════════════════════════════════
// Phase 18: XSS Detection
// ═══════════════════════════════════════════════════════════════
type XSSPhase struct{}

func (p *XSSPhase) Name() string        { return "XSS Detection" }
func (p *XSSPhase) Description() string { return "dalfox + kxss reflected/stored XSS scanning" }
func (p *XSSPhase) Execute(ctx context.Context, s *engine.State) error {
	paramsFile := filepath.Join(s.OutputFolder, "params.txt")
	xssOut := filepath.Join(s.OutputFolder, "xss_results.txt")

	// kxss pre-filter
	kxssOut := filepath.Join(s.OutputFolder, "kxss_results.txt")
	if _, err := os.Stat(paramsFile); err == nil {
		cmd := fmt.Sprintf("cat %s | kxss > %s 2>/dev/null", paramsFile, kxssOut)
		res := runner.RunTool(ctx, "bash", []string{"-c", cmd}, nil)
		if res.Err == nil {
			s.Printf("│  kxss: OK\n")
		} else {
			s.Printf("│  kxss: SKIP\n")
		}
	}

	// dalfox
	if _, err := os.Stat(paramsFile); err == nil {
		args := []string{"file", paramsFile, "-o", xssOut, "--silence", "-w", "10"}
		if s.Proxy.Active { args = append(args, "--proxy", s.Proxy.ProxyURL) }

		res := runner.RunTool(ctx, "dalfox", args, s.Proxy.GetEnv())
		if res.Err == nil {
			data, _ := os.ReadFile(xssOut)
			lines := strings.Split(strings.TrimSpace(string(data)), "\n")
			for _, l := range lines {
				if l != "" && (strings.Contains(l, "POC") || strings.Contains(l, "Verified")) {
					s.Findings = append(s.Findings, map[string]interface{}{
						"title": "XSS Vulnerability", "severity": "High",
						"url": l, "tool": "dalfox", "evidence": l,
					})
				}
			}
			s.Printf("│  dalfox: %d results\n", len(lines))
		} else {
			s.Printf("│  dalfox: SKIP\n")
		}
	}
	return nil
}

// ═══════════════════════════════════════════════════════════════
// Phase 19: SQL Injection
// ═══════════════════════════════════════════════════════════════
type SQLiPhase struct{}

func (p *SQLiPhase) Name() string        { return "SQL Injection Analysis" }
func (p *SQLiPhase) Description() string { return "sqlmap + ghauri on parameterized URLs" }
func (p *SQLiPhase) Execute(ctx context.Context, s *engine.State) error {
	paramsFile := filepath.Join(s.OutputFolder, "params.txt")
	sqliOut := filepath.Join(s.OutputFolder, "sqli_results.txt")

	if _, err := os.Stat(paramsFile); err != nil {
		s.Printf("│  No param URLs for SQLi\n")
		return nil
	}

	data, _ := os.ReadFile(paramsFile)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	targets := lines
	if len(targets) > 10 { targets = targets[:10] }

	var results []string
	for _, u := range targets {
		if !strings.Contains(u, "=") { continue }

		args := []string{"-u", u, "--batch", "--level", "2", "--risk", "1", "--random-agent", "--output-dir", s.OutputFolder}
		if s.Proxy.Active { args = append(args, "--proxy", s.Proxy.ProxyURL) }

		res := runner.RunTool(ctx, "sqlmap", args, nil)
		if res.Err == nil && strings.Contains(res.Stdout, "injectable") {
			results = append(results, u)
			s.Findings = append(s.Findings, map[string]interface{}{
				"title": "SQL Injection", "severity": "Critical",
				"url": u, "tool": "sqlmap", "evidence": "Parameter injectable",
			})
		}

		// ghauri as alternative
		res = runner.RunTool(ctx, "ghauri", []string{"-u", u, "--batch", "--level", "2"}, nil)
		if res.Err == nil && strings.Contains(res.Stdout, "injectable") {
			results = append(results, u+" [ghauri]")
			s.Findings = append(s.Findings, map[string]interface{}{
				"title": "SQL Injection", "severity": "Critical",
				"url": u, "tool": "ghauri", "evidence": "Parameter injectable",
			})
		}
		s.Governor.Throttle()
	}

	os.WriteFile(sqliOut, []byte(strings.Join(results, "\n")), 0644)
	s.Printf("│  SQLi: tested %d, found %d injectable\n", len(targets), len(results))
	return nil
}

// ═══════════════════════════════════════════════════════════════
// Phase 20: SSRF Scanning
// ═══════════════════════════════════════════════════════════════
type SSRFPhase struct{}

func (p *SSRFPhase) Name() string        { return "SSRF Scanning" }
func (p *SSRFPhase) Description() string { return "nuclei SSRF templates with interactsh callback" }
func (p *SSRFPhase) Execute(ctx context.Context, s *engine.State) error {
	urlsFile := filepath.Join(s.OutputFolder, "http_live.txt")
	ssrfOut := filepath.Join(s.OutputFolder, "ssrf_results.txt")

	args := []string{"-l", urlsFile, "-t", "ssrf", "-o", ssrfOut, "-silent", "-rl", "100", "-iserver", "interact.sh"}
	if s.Proxy.Active { args = append(args, "-proxy", s.Proxy.ProxyURL) }

	res := runner.RunTool(ctx, "nuclei", args, s.Proxy.GetEnv())
	if res.Err == nil {
		data, _ := os.ReadFile(ssrfOut)
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		for _, l := range lines {
			if l != "" {
				s.Findings = append(s.Findings, map[string]interface{}{
					"title": "SSRF Vulnerability", "severity": "High",
					"url": l, "tool": "nuclei-ssrf", "evidence": l,
				})
			}
		}
		s.Printf("│  nuclei SSRF: %d findings\n", len(lines))
	} else { s.Printf("│  nuclei SSRF: SKIP\n") }
	return nil
}

// ═══════════════════════════════════════════════════════════════
// Phase 21: Open Redirect
// ═══════════════════════════════════════════════════════════════
type OpenRedirectPhase struct{}

func (p *OpenRedirectPhase) Name() string        { return "Open Redirect Testing" }
func (p *OpenRedirectPhase) Description() string { return "nuclei redirect templates on param URLs" }
func (p *OpenRedirectPhase) Execute(ctx context.Context, s *engine.State) error {
	paramsFile := filepath.Join(s.OutputFolder, "params.txt")
	redirectOut := filepath.Join(s.OutputFolder, "redirect_results.txt")

	args := []string{"-l", paramsFile, "-tags", "redirect", "-o", redirectOut, "-silent", "-rl", "100"}
	if s.Proxy.Active { args = append(args, "-proxy", s.Proxy.ProxyURL) }

	res := runner.RunTool(ctx, "nuclei", args, nil)
	if res.Err == nil {
		data, _ := os.ReadFile(redirectOut)
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		for _, l := range lines {
			if l != "" {
				s.Findings = append(s.Findings, map[string]interface{}{
					"title": "Open Redirect", "severity": "Medium",
					"url": l, "tool": "nuclei-redirect", "evidence": l,
				})
			}
		}
		s.Printf("│  Open Redirect: %d findings\n", len(lines))
	} else { s.Printf("│  Open Redirect: SKIP\n") }
	return nil
}

// ═══════════════════════════════════════════════════════════════
// Phase 22: 403/401 Bypass
// ═══════════════════════════════════════════════════════════════
type ForbiddenBypassPhase struct{}

func (p *ForbiddenBypassPhase) Name() string        { return "403/401 Bypass Testing" }
func (p *ForbiddenBypassPhase) Description() string { return "dontgo403 on forbidden endpoints" }
func (p *ForbiddenBypassPhase) Execute(ctx context.Context, s *engine.State) error {
	bypassOut := filepath.Join(s.OutputFolder, "bypass_results.txt")
	// Extract 403 URLs from httpx output
	httpxFile := filepath.Join(s.OutputFolder, "http_live.txt")
	var forbiddenURLs []string
	if data, err := os.ReadFile(httpxFile); err == nil {
		for _, l := range strings.Split(string(data), "\n") {
			if strings.Contains(l, "[403]") || strings.Contains(l, " 403 ") {
				parts := strings.Fields(l)
				if len(parts) > 0 { forbiddenURLs = append(forbiddenURLs, parts[0]) }
			}
		}
	}

	if len(forbiddenURLs) == 0 {
		s.Printf("│  No 403 endpoints found\n")
		return nil
	}

	var results []string
	for _, u := range forbiddenURLs {
		res := runner.RunTool(ctx, "dontgo403", []string{"-u", u}, nil)
		if res.Err == nil && (strings.Contains(res.Stdout, "200") || strings.Contains(res.Stdout, "bypass")) {
			results = append(results, u)
			s.Findings = append(s.Findings, map[string]interface{}{
				"title": "403 Bypass", "severity": "High",
				"url": u, "tool": "dontgo403", "evidence": res.Stdout,
			})
		}
		s.Governor.Throttle()
	}

	os.WriteFile(bypassOut, []byte(strings.Join(results, "\n")), 0644)
	s.Printf("│  403 Bypass: tested %d, bypassed %d\n", len(forbiddenURLs), len(results))
	return nil
}

// ═══════════════════════════════════════════════════════════════
// Phase 23: API Discovery
// ═══════════════════════════════════════════════════════════════
type APIDiscoveryPhase struct{}

func (p *APIDiscoveryPhase) Name() string        { return "API Route Discovery" }
func (p *APIDiscoveryPhase) Description() string { return "kiterunner API endpoint brute-force" }
func (p *APIDiscoveryPhase) Execute(ctx context.Context, s *engine.State) error {
	urlsFile := filepath.Join(s.OutputFolder, "http_live.txt")
	apiOut := filepath.Join(s.OutputFolder, "api_results.txt")

	res := runner.RunTool(ctx, "kr", []string{"brute", urlsFile, "-w", "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt", "-o", apiOut}, nil)
	if res.Err == nil {
		s.Printf("│  kiterunner: OK\n")
	} else {
		// Fallback: check common API paths manually
		apiPaths := []string{"/api", "/api/v1", "/api/v2", "/swagger.json", "/openapi.json",
			"/api-docs", "/graphql", "/.well-known", "/api/health", "/api/status"}
		found := 0
		for _, u := range s.URLs {
			if len(s.URLs) > 10 { break }
			for _, path := range apiPaths {
				base := strings.TrimRight(u, "/")
				res := runner.RunTool(ctx, "curl", []string{"-s", "-o", "/dev/null", "-w", "%{http_code}", "-m", "5", base + path}, nil)
				if res.Err == nil && (res.Stdout == "200" || res.Stdout == "301" || res.Stdout == "302") {
					found++
					s.Findings = append(s.Findings, map[string]interface{}{
						"title": "API Endpoint Found", "severity": "Info",
						"url": base + path, "tool": "api_scan", "evidence": "HTTP " + res.Stdout,
					})
				}
			}
			s.Governor.Throttle()
		}
		s.Printf("│  API scan (fallback): %d endpoints\n", found)
	}
	return nil
}

// ═══════════════════════════════════════════════════════════════
// Phase 24: CRLF Injection
// ═══════════════════════════════════════════════════════════════
type CRLFPhase struct{}

func (p *CRLFPhase) Name() string        { return "CRLF Injection Check" }
func (p *CRLFPhase) Description() string { return "crlfuzz on live endpoints" }
func (p *CRLFPhase) Execute(ctx context.Context, s *engine.State) error {
	urlsFile := filepath.Join(s.OutputFolder, "http_live.txt")
	crlfOut := filepath.Join(s.OutputFolder, "crlf_results.txt")

	res := runner.RunTool(ctx, "crlfuzz", []string{"-l", urlsFile, "-o", crlfOut, "-s", "-c", "20"}, nil)
	if res.Err == nil {
		data, _ := os.ReadFile(crlfOut)
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		for _, l := range lines {
			if l != "" {
				s.Findings = append(s.Findings, map[string]interface{}{
					"title": "CRLF Injection", "severity": "Medium",
					"url": l, "tool": "crlfuzz", "evidence": l,
				})
			}
		}
		s.Printf("│  crlfuzz: %d vulnerable\n", len(lines))
	} else { s.Printf("│  crlfuzz: SKIP\n") }
	return nil
}

// ═══════════════════════════════════════════════════════════════
// Phase 25: HTTP Request Smuggling
// ═══════════════════════════════════════════════════════════════
type SmugglingPhase struct{}

func (p *SmugglingPhase) Name() string        { return "HTTP Request Smuggling" }
func (p *SmugglingPhase) Description() string { return "smuggler CL.TE/TE.CL detection" }
func (p *SmugglingPhase) Execute(ctx context.Context, s *engine.State) error {
	urlsFile := filepath.Join(s.OutputFolder, "http_live.txt")
	smugOut := filepath.Join(s.OutputFolder, "smuggling_results.txt")

	res := runner.RunTool(ctx, "smuggler", []string{"-u", urlsFile, "-l", smugOut}, nil)
	if res.Err == nil {
		if data, err := os.ReadFile(smugOut); err == nil {
			lines := strings.Split(strings.TrimSpace(string(data)), "\n")
			for _, l := range lines {
				if strings.Contains(strings.ToLower(l), "vulnerable") {
					s.Findings = append(s.Findings, map[string]interface{}{
						"title": "HTTP Smuggling", "severity": "Critical",
						"url": l, "tool": "smuggler", "evidence": l,
					})
				}
			}
			s.Printf("│  smuggler: %d results\n", len(lines))
		}
	} else { s.Printf("│  smuggler: SKIP\n") }
	return nil
}

// ═══════════════════════════════════════════════════════════════
// Phase 26: Git/Sensitive File Exposure
// ═══════════════════════════════════════════════════════════════
type GitExposurePhase struct{}

func (p *GitExposurePhase) Name() string        { return "Git & Sensitive File Exposure" }
func (p *GitExposurePhase) Description() string { return "nuclei exposure templates + custom checks" }
func (p *GitExposurePhase) Execute(ctx context.Context, s *engine.State) error {
	urlsFile := filepath.Join(s.OutputFolder, "http_live.txt")
	exposureOut := filepath.Join(s.OutputFolder, "exposure_results.txt")

	// Nuclei exposure templates
	args := []string{"-l", urlsFile, "-tags", "exposure", "-o", exposureOut, "-silent", "-rl", "100"}
	if s.Proxy.Active { args = append(args, "-proxy", s.Proxy.ProxyURL) }
	res := runner.RunTool(ctx, "nuclei", args, nil)
	if res.Err == nil {
		data, _ := os.ReadFile(exposureOut)
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		for _, l := range lines {
			if l != "" {
				s.Findings = append(s.Findings, map[string]interface{}{
					"title": "Sensitive Exposure", "severity": "High",
					"url": l, "tool": "nuclei-exposure", "evidence": l,
				})
			}
		}
		s.Printf("│  nuclei exposure: %d\n", len(lines))
	}

	// Custom checks for common sensitive files
	sensitiveFiles := []string{"/.git/config", "/.env", "/.DS_Store", "/backup.zip",
		"/wp-config.php.bak", "/.htpasswd", "/server-status", "/.svn/entries"}
	found := 0
	targets := s.URLs
	if len(targets) > 20 { targets = targets[:20] }
	for _, u := range targets {
		base := strings.TrimRight(u, "/")
		for _, path := range sensitiveFiles {
			res := runner.RunTool(ctx, "curl", []string{"-s", "-o", "/dev/null", "-w", "%{http_code}:%{size_download}", "-m", "5", base + path}, nil)
			if res.Err == nil {
				parts := strings.Split(res.Stdout, ":")
				if len(parts) == 2 && parts[0] == "200" && parts[1] != "0" {
					found++
					s.Findings = append(s.Findings, map[string]interface{}{
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

func (p *EmailSecurityPhase) Name() string        { return "Email Security Verification" }
func (p *EmailSecurityPhase) Description() string { return "Checks SPF, DKIM, DMARC DNS records" }
func (p *EmailSecurityPhase) Execute(ctx context.Context, s *engine.State) error {
	emailOut := filepath.Join(s.OutputFolder, "email_security.txt")
	var results []string

	for _, domain := range s.Scope.Domains {
		// SPF
		res := runner.RunTool(ctx, "dig", []string{"+short", "TXT", domain}, nil)
		hasSPF := false
		if res.Err == nil {
			if strings.Contains(res.Stdout, "v=spf1") { hasSPF = true }
		}

		// DMARC
		res = runner.RunTool(ctx, "dig", []string{"+short", "TXT", "_dmarc." + domain}, nil)
		hasDMARC := false
		if res.Err == nil {
			if strings.Contains(res.Stdout, "v=DMARC1") { hasDMARC = true }
		}

		// DKIM (common selectors)
		hasDKIM := false
		for _, sel := range []string{"default", "google", "selector1", "selector2", "mail", "k1"} {
			res = runner.RunTool(ctx, "dig", []string{"+short", "TXT", sel + "._domainkey." + domain}, nil)
			if res.Err == nil && strings.Contains(res.Stdout, "v=DKIM1") {
				hasDKIM = true
				break
			}
		}

		line := fmt.Sprintf("%s | SPF:%v | DKIM:%v | DMARC:%v", domain, hasSPF, hasDKIM, hasDMARC)
		results = append(results, line)
		s.Printf("│  %s\n", line)

		if !hasSPF || !hasDMARC {
			s.Findings = append(s.Findings, map[string]interface{}{
				"title": "Missing Email Security Records", "severity": "Medium",
				"url": domain, "tool": "email_check",
				"evidence": fmt.Sprintf("SPF:%v DKIM:%v DMARC:%v", hasSPF, hasDKIM, hasDMARC),
			})
		}
	}

	os.WriteFile(emailOut, []byte(strings.Join(results, "\n")), 0644)
	return nil
}

// ═══════════════════════════════════════════════════════════════
// Phase 28: Prototype Pollution
// ═══════════════════════════════════════════════════════════════
type PrototypePollutionPhase struct{}

func (p *PrototypePollutionPhase) Name() string        { return "Prototype Pollution Scan" }
func (p *PrototypePollutionPhase) Description() string { return "nuclei prototype pollution templates" }
func (p *PrototypePollutionPhase) Execute(ctx context.Context, s *engine.State) error {
	urlsFile := filepath.Join(s.OutputFolder, "http_live.txt")
	ppOut := filepath.Join(s.OutputFolder, "proto_pollution_results.txt")

	args := []string{"-l", urlsFile, "-tags", "prototype-pollution", "-o", ppOut, "-silent", "-rl", "100"}
	if s.Proxy.Active { args = append(args, "-proxy", s.Proxy.ProxyURL) }

	res := runner.RunTool(ctx, "nuclei", args, nil)
	if res.Err == nil {
		data, _ := os.ReadFile(ppOut)
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		for _, l := range lines {
			if l != "" {
				s.Findings = append(s.Findings, map[string]interface{}{
					"title": "Prototype Pollution", "severity": "High",
					"url": l, "tool": "nuclei-pp", "evidence": l,
				})
			}
		}
		s.Printf("│  Proto Pollution: %d findings\n", len(lines))
	} else { s.Printf("│  Proto Pollution: SKIP\n") }
	return nil
}

// ═══════════════════════════════════════════════════════════════
// Phase 29: Final Report Generation
// ═══════════════════════════════════════════════════════════════
type ReportPhase struct{}

func (p *ReportPhase) Name() string        { return "Final Report Generation" }
func (p *ReportPhase) Description() string { return "Generates HTML/Markdown summary with all findings" }
func (p *ReportPhase) Execute(ctx context.Context, s *engine.State) error {
	// Count by severity
	counts := map[string]int{"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
	for _, f := range s.Findings {
		sev := fmt.Sprintf("%v", f["severity"])
		counts[sev]++
	}

	report := "# MOHAMMED v3 — Scan Report\n\n"
	report += "## Summary\n\n"
	report += fmt.Sprintf("| Metric | Count |\n|---|---|\n")
	report += fmt.Sprintf("| Subdomains | %d |\n", len(s.Subdomains))
	report += fmt.Sprintf("| Live Hosts | %d |\n", len(s.LiveHosts))
	report += fmt.Sprintf("| URLs | %d |\n", len(s.URLs))
	report += fmt.Sprintf("| Total Findings | %d |\n\n", len(s.Findings))

	report += "## Findings by Severity\n\n"
	report += fmt.Sprintf("| Severity | Count |\n|---|---|\n")
	for _, sev := range []string{"Critical", "High", "Medium", "Low", "Info"} {
		report += fmt.Sprintf("| %s | %d |\n", sev, counts[sev])
	}

	report += "\n## Detailed Findings\n\n"
	for _, sev := range []string{"Critical", "High", "Medium", "Low", "Info"} {
		for _, f := range s.Findings {
			if fmt.Sprintf("%v", f["severity"]) == sev {
				report += fmt.Sprintf("### [%s] %v\n- URL: %v\n- Tool: %v\n- Evidence: %v\n\n",
					sev, f["title"], f["url"], f["tool"], f["evidence"])
			}
		}
	}

	reportFile := filepath.Join(s.OutputFolder, "final_report.md")
	os.WriteFile(reportFile, []byte(report), 0644)

	s.Printf("│  Report saved: %s\n", reportFile)
	s.Printf("│  Critical: %d | High: %d | Medium: %d | Low: %d | Info: %d\n",
		counts["Critical"], counts["High"], counts["Medium"], counts["Low"], counts["Info"])
	return nil
}
