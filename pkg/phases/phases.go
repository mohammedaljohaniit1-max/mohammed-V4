package phases

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mohammed-v3/core/pkg/engine"
	"github.com/mohammed-v3/core/pkg/runner"
)

// ═══════════════════════════════════════════════════════════════
// Phase 01: Scope Validation
// ═══════════════════════════════════════════════════════════════
type ScopeValidationPhase struct{}

func (p *ScopeValidationPhase) Name() string        { return "Scope Validation" }
func (p *ScopeValidationPhase) Description() string { return "Validates target domains, IPs, and scope rules" }
func (p *ScopeValidationPhase) Execute(ctx context.Context, s *engine.State) error {
	s.Printf("│  Domains: %d | IPs: %d | CIDRs: %d\n", len(s.Scope.Domains), len(s.Scope.IPs), len(s.Scope.CIDRs))
	for _, d := range s.Scope.Domains {
		s.Printf("│    ✔ Target Scope: %s\n", d)
	}
	return nil
}

// ═══════════════════════════════════════════════════════════════
// Phase 02: OSINT Intelligence Gathering (With API Keys Support)
// ═══════════════════════════════════════════════════════════════
type OSINTPhase struct{}

func (p *OSINTPhase) Name() string        { return "OSINT Intelligence Gathering" }
func (p *OSINTPhase) Description() string { return "Queries Shodan, VirusTotal, SecurityTrails, AlienVault, GitHub & crt.sh APIs" }
func (p *OSINTPhase) Execute(ctx context.Context, s *engine.State) error {
	allSubs := make(map[string]bool)
	keys := s.Config.APIKeys

	for _, domain := range s.Scope.Domains {
		// 1. Shodan API
		if keys.Shodan != "" {
			url := fmt.Sprintf("https://api.shodan.io/dns/domain/%s?key=%s", domain, keys.Shodan)
			res := runner.RunTool(ctx, "curl", []string{"-s", "-m", "15", url}, nil)
			if res.Err == nil && res.Stdout != "" {
				var shodanRes map[string]interface{}
				if json.Unmarshal([]byte(res.Stdout), &shodanRes) == nil {
					if subs, ok := shodanRes["subdomains"].([]interface{}); ok {
						for _, sub := range subs {
							allSubs[fmt.Sprintf("%s.%s", sub, domain)] = true
						}
						s.Printf("│  Shodan API [%s]: %d subdomains\n", domain, len(subs))
					}
				}
			}
		}

		// 2. VirusTotal API
		if keys.VirusTotal != "" {
			url := fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s/subdomains?limit=40", domain)
			res := runner.RunTool(ctx, "curl", []string{"-s", "-m", "15", "-H", "x-apikey: " + keys.VirusTotal, url}, nil)
			if res.Err == nil && res.Stdout != "" {
				var vtRes map[string]interface{}
				if json.Unmarshal([]byte(res.Stdout), &vtRes) == nil {
					if data, ok := vtRes["data"].([]interface{}); ok {
						for _, item := range data {
							if itemMap, ok := item.(map[string]interface{}); ok {
								if id, ok := itemMap["id"].(string); ok {
									allSubs[id] = true
								}
							}
						}
						s.Printf("│  VirusTotal API [%s]: %d subdomains\n", domain, len(data))
					}
				}
			}
		}

		// 3. SecurityTrails API
		if keys.SecurityTrails != "" {
			url := fmt.Sprintf("https://api.securitytrails.com/v1/domain/%s/subdomains?children_only=false", domain)
			res := runner.RunTool(ctx, "curl", []string{"-s", "-m", "15", "-H", "APIKEY: " + keys.SecurityTrails, url}, nil)
			if res.Err == nil && res.Stdout != "" {
				var stRes map[string]interface{}
				if json.Unmarshal([]byte(res.Stdout), &stRes) == nil {
					if subs, ok := stRes["subdomains"].([]interface{}); ok {
						for _, sub := range subs {
							allSubs[fmt.Sprintf("%s.%s", sub, domain)] = true
						}
						s.Printf("│  SecurityTrails [%s]: %d subdomains\n", domain, len(subs))
					}
				}
			}
		}

		// 4. AlienVault OTX
		url := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", domain)
		headers := []string{"-s", "-m", "15", url}
		if keys.AlienVault != "" {
			headers = append([]string{"-H", "X-OTX-API-KEY: " + keys.AlienVault}, headers...)
		}
		res := runner.RunTool(ctx, "curl", headers, nil)
		if res.Err == nil && res.Stdout != "" {
			var otxData map[string]interface{}
			if json.Unmarshal([]byte(res.Stdout), &otxData) == nil {
				if records, ok := otxData["passive_dns"].([]interface{}); ok {
					for _, r := range records {
						if rec, ok := r.(map[string]interface{}); ok {
							if hostname, ok := rec["hostname"].(string); ok {
								if strings.HasSuffix(hostname, domain) {
									allSubs[hostname] = true
								}
							}
						}
					}
					s.Printf("│  AlienVault OTX [%s]: %d records\n", domain, len(records))
				}
			}
		}

		// 5. crt.sh
		res = runner.RunTool(ctx, "curl", []string{"-s", "-m", "30", fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)}, nil)
		if res.Err == nil && res.Stdout != "" {
			var certs []map[string]interface{}
			if json.Unmarshal([]byte(res.Stdout), &certs) == nil {
				for _, c := range certs {
					if name, ok := c["name_value"].(string); ok {
						for _, n := range strings.Split(name, "\n") {
							n = strings.TrimSpace(strings.TrimPrefix(n, "*."))
							if n != "" && strings.HasSuffix(n, domain) {
								allSubs[n] = true
							}
						}
					}
				}
				s.Printf("│  crt.sh [%s]: %d certificates\n", domain, len(certs))
			}
		}

		// 6. HackerTarget
		res = runner.RunTool(ctx, "curl", []string{"-s", "-m", "30", fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain)}, nil)
		if res.Err == nil && res.Stdout != "" {
			count := 0
			for _, line := range strings.Split(res.Stdout, "\n") {
				parts := strings.Split(line, ",")
				if len(parts) >= 1 {
					h := strings.TrimSpace(parts[0])
					if h != "" && strings.HasSuffix(h, domain) {
						allSubs[h] = true
						count++
					}
				}
			}
			s.Printf("│  HackerTarget [%s]: %d hosts\n", domain, count)
		}
	}

	osintFile := filepath.Join(s.OutputFolder, "osint_subdomains.txt")
	var lines []string
	for sub := range allSubs {
		lines = append(lines, sub)
	}
	os.WriteFile(osintFile, []byte(strings.Join(lines, "\n")), 0644)
	s.Printf("│  OSINT Total Unique: %d\n", len(allSubs))
	return nil
}

// ═══════════════════════════════════════════════════════════════
// Phase 03: Passive Subdomain Enumeration
// Runs all tools across ALL domains in scope (not just Domains[0])
// Each tool shows exact count, not just "OK"
// ═══════════════════════════════════════════════════════════════
type SubdomainPassivePhase struct{}

func (p *SubdomainPassivePhase) Name() string        { return "Passive Subdomain Enumeration" }
func (p *SubdomainPassivePhase) Description() string { return "subfinder, amass, bbot, findomain, assetfinder + OSINT merge" }
func (p *SubdomainPassivePhase) Execute(ctx context.Context, s *engine.State) error {
	if len(s.Scope.Domains) == 0 {
		return fmt.Errorf("no domains in scope")
	}

	found := make(map[string]bool)

	// Run for each domain in scope (not just Domains[0])
	for _, domain := range s.Scope.Domains {
		found[domain] = true
		s.Printf("│  [Domain: %s]\n", domain)
		keys := s.Config.APIKeys

		// ── 1. Subfinder ──────────────────────────────────────
		sfOut := filepath.Join(s.OutputFolder, fmt.Sprintf("subfinder_%s.txt", sanitizeName(domain)))
		env := make(map[string]string)
		if keys.Shodan != "" {
			env["SHODAN_API_KEY"] = keys.Shodan
		}
		sfCount := 0
		res := runner.RunTool(ctx, "subfinder", []string{"-d", domain, "-all", "-o", sfOut, "-silent"}, env)
		if res.Err == nil {
			data, _ := os.ReadFile(sfOut)
			for _, l := range strings.Split(string(data), "\n") {
				l = strings.TrimSpace(strings.ToLower(l))
				if l != "" && !found[l] {
					found[l] = true
					sfCount++
				}
			}
			s.Printf("│    subfinder: %d subdomains\n", sfCount)
		} else {
			s.Printf("│    subfinder: SKIP (%v)\n", res.Err)
		}

		// ── 2. Amass passive (timeout: 4 minutes via runner) ──
		amOut := filepath.Join(s.OutputFolder, fmt.Sprintf("amass_%s.txt", sanitizeName(domain)))
		amCount := 0
		res = runner.RunTool(ctx, "amass", []string{"enum", "-passive", "-d", domain, "-o", amOut, "-timeout", "3"}, nil)
		if res.Err == nil {
			data, _ := os.ReadFile(amOut)
			for _, l := range strings.Split(string(data), "\n") {
				l = strings.TrimSpace(strings.ToLower(l))
				if l != "" && strings.HasSuffix(l, domain) && !found[l] {
					found[l] = true
					amCount++
				}
			}
			s.Printf("│    amass: %d subdomains\n", amCount)
		} else {
			s.Printf("│    amass: SKIP (%v)\n", res.Err)
		}

		// ── 3. BBOT (timeout: 3 minutes via runner) ───────────
		bbotOutDir := filepath.Join(s.OutputFolder, fmt.Sprintf("bbot_%s", sanitizeName(domain)))
		res = runner.RunTool(ctx, "bbot", []string{
			"-t", domain, "-p", "subdomain-enum", "-f", "passive",
			"-o", bbotOutDir, "-y", "--force",
		}, nil)
		if res.Err == nil {
			bbotCount := 0
			filepath.Walk(bbotOutDir, func(path string, info os.FileInfo, err error) error {
				if err == nil && !info.IsDir() && strings.HasSuffix(path, ".txt") {
					if data, err := os.ReadFile(path); err == nil {
						for _, l := range strings.Split(string(data), "\n") {
							l = strings.TrimSpace(strings.ToLower(l))
							if l != "" && strings.HasSuffix(l, domain) && len(l) < 255 && !found[l] {
								found[l] = true
								bbotCount++
							}
						}
					}
				}
				return nil
			})
			s.Printf("│    bbot: %d subdomains\n", bbotCount)
		} else {
			s.Printf("│    bbot: SKIP (%v)\n", res.Err)
		}

		// ── 4. Assetfinder ────────────────────────────────────
		afCount := 0
		res = runner.RunTool(ctx, "assetfinder", []string{"--subs-only", domain}, nil)
		if res.Err == nil {
			for _, l := range strings.Split(res.Stdout, "\n") {
				l = strings.TrimSpace(strings.ToLower(l))
				if l != "" && strings.HasSuffix(l, domain) && !found[l] {
					found[l] = true
					afCount++
				}
			}
			s.Printf("│    assetfinder: %d subdomains\n", afCount)
		} else {
			s.Printf("│    assetfinder: SKIP (%v)\n", res.Err)
		}

		// ── 5. Findomain ─────────────────────────────────────
		fdOut := filepath.Join(s.OutputFolder, fmt.Sprintf("findomain_%s.txt", sanitizeName(domain)))
		fdCount := 0
		res = runner.RunTool(ctx, "findomain", []string{"-t", domain, "-u", fdOut, "-q"}, nil)
		if res.Err == nil {
			data, _ := os.ReadFile(fdOut)
			for _, l := range strings.Split(string(data), "\n") {
				l = strings.TrimSpace(strings.ToLower(l))
				if l != "" && strings.HasSuffix(l, domain) && !found[l] {
					found[l] = true
					fdCount++
				}
			}
			s.Printf("│    findomain: %d subdomains\n", fdCount)
		} else {
			s.Printf("│    findomain: SKIP (%v)\n", res.Err)
		}
	}

	// ── Merge OSINT results from Phase 02 ─────────────────
	osintFile := filepath.Join(s.OutputFolder, "osint_subdomains.txt")
	osintCount := 0
	if data, err := os.ReadFile(osintFile); err == nil {
		for _, l := range strings.Split(string(data), "\n") {
			l = strings.TrimSpace(strings.ToLower(l))
			if l != "" && !found[l] {
				found[l] = true
				osintCount++
			}
		}
		s.Printf("│  OSINT merge: +%d unique subdomains\n", osintCount)
	}

	// ── Write final merged subdomains.txt ─────────────────
	for sub := range found {
		s.Subdomains = append(s.Subdomains, sub)
	}
	subFile := filepath.Join(s.OutputFolder, "subdomains.txt")
	os.WriteFile(subFile, []byte(strings.Join(s.Subdomains, "\n")), 0644)
	s.Printf("│  Total Passive Subdomains: %d\n", len(s.Subdomains))
	return nil
}

// sanitizeName converts domain.com → domain_com for use in filenames
func sanitizeName(s string) string {
	r := strings.NewReplacer(".", "_", "-", "_", "/", "_", ":", "_")
	return r.Replace(s)
}

// ═══════════════════════════════════════════════════════════════
// Phase 04: Active Subdomain Bruteforce
// ═══════════════════════════════════════════════════════════════
type SubdomainActivePhase struct{}

func (p *SubdomainActivePhase) Name() string        { return "Active Subdomain Bruteforce" }
func (p *SubdomainActivePhase) Description() string { return "puredns bruteforce + dnsgen permutations" }
func (p *SubdomainActivePhase) Execute(ctx context.Context, s *engine.State) error {
	if len(s.Scope.Domains) == 0 {
		return nil
	}
	domain := s.Scope.Domains[0]
	subFile := filepath.Join(s.OutputFolder, "subdomains.txt")
	activeOut := filepath.Join(s.OutputFolder, "subdomains_brute.txt")

	// puredns bruteforce — wordlist paths in priority order
	wordlist := ""
	for _, wl := range []string{
		"/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
		"/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
		"/usr/share/wordlists/dnsmap.txt",
	} {
		if _, err := os.Stat(wl); err == nil {
			wordlist = wl
			break
		}
	}

	if wordlist != "" {
		res := runner.RunTool(ctx, "puredns", []string{"bruteforce", wordlist, domain, "-w", activeOut, "--rate-limit", "150"}, nil)
		if res.Err == nil {
			data, _ := os.ReadFile(activeOut)
			added := 0
			existing := make(map[string]bool)
			for _, sub := range s.Subdomains {
				existing[sub] = true
			}
			for _, l := range strings.Split(string(data), "\n") {
				l = strings.TrimSpace(strings.ToLower(l))
				if l != "" && !existing[l] {
					s.Subdomains = append(s.Subdomains, l)
					added++
				}
			}
			s.Printf("│  puredns bruteforce: +%d new subdomains\n", added)
		} else {
			s.Printf("│  puredns: SKIP (%v)\n", res.Err)
		}
	} else {
		s.Printf("│  puredns: SKIP (no wordlist found)\n")
	}

	// dnsgen permutations
	dnsgenOut := filepath.Join(s.OutputFolder, "dnsgen_perms.txt")
	res := runner.RunTool(ctx, "dnsgen", []string{subFile}, nil)
	if res.Err == nil && res.Stdout != "" {
		os.WriteFile(dnsgenOut, []byte(res.Stdout), 0644)
		lines := strings.Split(strings.TrimSpace(res.Stdout), "\n")
		s.Printf("│  dnsgen: %d permutations generated\n", len(lines))
	} else {
		s.Printf("│  dnsgen: SKIP\n")
	}

	os.WriteFile(subFile, []byte(strings.Join(s.Subdomains, "\n")), 0644)
	s.Printf("│  Total After Active Bruteforce: %d\n", len(s.Subdomains))
	return nil
}

// ═══════════════════════════════════════════════════════════════
// Phase 05: DNS Resolution & Enrichment
// ═══════════════════════════════════════════════════════════════
type DNSResolvePhase struct{}

func (p *DNSResolvePhase) Name() string        { return "DNS Resolution & Enrichment" }
func (p *DNSResolvePhase) Description() string { return "Resolves live hosts via dnsx, filters wildcards" }
func (p *DNSResolvePhase) Execute(ctx context.Context, s *engine.State) error {
	subFile := filepath.Join(s.OutputFolder, "subdomains.txt")
	dnsxOut := filepath.Join(s.OutputFolder, "live_dns.txt")

	res := runner.RunTool(ctx, "dnsx", []string{"-l", subFile, "-o", dnsxOut, "-silent", "-rl", "150", "-resp"}, nil)
	if res.Err == nil {
		data, _ := os.ReadFile(dnsxOut)
		for _, l := range strings.Split(string(data), "\n") {
			l = strings.TrimSpace(l)
			if l != "" {
				parts := strings.Fields(l)
				s.LiveHosts = append(s.LiveHosts, parts[0])
			}
		}
		s.Printf("│  dnsx: %d live hosts resolved\n", len(s.LiveHosts))
	} else {
		// Fallback: use subdomains as-is
		s.LiveHosts = s.Subdomains
		s.Printf("│  dnsx: SKIP — fallback to %d subdomains\n", len(s.LiveHosts))
	}
	return nil
}

// ═══════════════════════════════════════════════════════════════
// Phase 06: Subdomain Takeover Check
// ═══════════════════════════════════════════════════════════════
type TakeoverPhase struct{}

func (p *TakeoverPhase) Name() string        { return "Subdomain Takeover Check" }
func (p *TakeoverPhase) Description() string { return "Checks dangling CNAMEs via subzy" }
func (p *TakeoverPhase) Execute(ctx context.Context, s *engine.State) error {
	subFile := filepath.Join(s.OutputFolder, "subdomains.txt")
	takeoverOut := filepath.Join(s.OutputFolder, "takeover_results.txt")

	res := runner.RunTool(ctx, "subzy", []string{"run", "--targets", subFile, "--output", takeoverOut, "--concurrency", "20"}, nil)
	if res.Err == nil {
		if data, err := os.ReadFile(takeoverOut); err == nil {
			count := 0
			for _, l := range strings.Split(string(data), "\n") {
				if strings.Contains(l, "VULNERABLE") || strings.Contains(l, "vulnerable") {
					count++
					s.Findings = append(s.Findings, map[string]interface{}{
						"title": "Subdomain Takeover", "severity": "Critical",
						"url": l, "tool": "subzy", "evidence": l,
					})
				}
			}
			s.Printf("│  subzy: %d vulnerable subdomains\n", count)
		}
	} else {
		s.Printf("│  subzy: SKIP (%v)\n", res.Err)
	}
	return nil
}

// ═══════════════════════════════════════════════════════════════
// Phase 07: HTTP Probing & Tech Fingerprinting
// ═══════════════════════════════════════════════════════════════
type HTTPProbePhase struct{}

func (p *HTTPProbePhase) Name() string        { return "HTTP Probing & Tech Fingerprinting" }
func (p *HTTPProbePhase) Description() string { return "httpx: status codes, titles, tech detect, CDN" }
func (p *HTTPProbePhase) Execute(ctx context.Context, s *engine.State) error {
	hostsFile := filepath.Join(s.OutputFolder, "live_dns.txt")
	if _, err := os.Stat(hostsFile); err != nil {
		hostsFile = filepath.Join(s.OutputFolder, "subdomains.txt")
	}
	httpxOut := filepath.Join(s.OutputFolder, "http_live.txt")

	args := []string{"-l", hostsFile, "-o", httpxOut, "-silent", "-rl", "150",
		"-sc", "-title", "-tech-detect", "-cdn", "-follow-redirects",
		"-threads", fmt.Sprintf("%d", s.Config.Threads)}
	if s.Proxy.Active {
		args = append(args, "-http-proxy", s.Proxy.ProxyURL)
	}

	res := runner.RunTool(ctx, "httpx", args, s.Proxy.GetEnv())
	if res.Err == nil {
		data, _ := os.ReadFile(httpxOut)
		for _, l := range strings.Split(string(data), "\n") {
			l = strings.TrimSpace(l)
			if l != "" {
				parts := strings.Fields(l)
				if len(parts) > 0 {
					s.URLs = append(s.URLs, parts[0])
				}
			}
		}
		s.Printf("│  httpx: %d live endpoints\n", len(s.URLs))
	} else {
		s.Printf("│  httpx: SKIP (%v)\n", res.Err)
	}
	return nil
}

// ═══════════════════════════════════════════════════════════════
// Phase 08: TLS/SSL Analysis
// ═══════════════════════════════════════════════════════════════
type TLSAnalysisPhase struct{}

func (p *TLSAnalysisPhase) Name() string        { return "TLS/SSL Analysis" }
func (p *TLSAnalysisPhase) Description() string { return "Certificate analysis via tlsx — expired, self-signed, mismatched" }
func (p *TLSAnalysisPhase) Execute(ctx context.Context, s *engine.State) error {
	hostsFile := filepath.Join(s.OutputFolder, "live_dns.txt")
	tlsOut := filepath.Join(s.OutputFolder, "tls_results.txt")

	res := runner.RunTool(ctx, "tlsx", []string{"-l", hostsFile, "-o", tlsOut, "-silent", "-expired", "-self-signed", "-mismatched"}, nil)
	if res.Err == nil {
		data, _ := os.ReadFile(tlsOut)
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		issues := 0
		for _, l := range lines {
			if strings.Contains(l, "expired") || strings.Contains(l, "self-signed") || strings.Contains(l, "mismatched") {
				issues++
				s.Findings = append(s.Findings, map[string]interface{}{
					"title": "TLS Issue", "severity": "Medium", "url": l, "tool": "tlsx", "evidence": l,
				})
			}
		}
		s.Printf("│  tlsx: %d hosts analyzed, %d TLS issues\n", len(lines), issues)
	} else {
		s.Printf("│  tlsx: SKIP (%v)\n", res.Err)
	}
	return nil
}

// ═══════════════════════════════════════════════════════════════
// Phase 09: Port Scanning
// ═══════════════════════════════════════════════════════════════
type PortScanPhase struct{}

func (p *PortScanPhase) Name() string        { return "Port Scanning" }
func (p *PortScanPhase) Description() string { return "naabu top-1000 ports on live hosts (connect scan, no sudo needed)" }
func (p *PortScanPhase) Execute(ctx context.Context, s *engine.State) error {
	hostsFile := filepath.Join(s.OutputFolder, "live_dns.txt")
	portsOut := filepath.Join(s.OutputFolder, "ports.txt")

	// -connect-scan avoids need for sudo/root (no SYN scan)
	res := runner.RunTool(ctx, "naabu", []string{"-l", hostsFile, "-o", portsOut, "-silent",
		"-top-ports", "1000", "-rate", "150", "-c", "25", "-connect-scan"}, nil)
	if res.Err == nil {
		data, _ := os.ReadFile(portsOut)
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		s.Printf("│  naabu: %d open port entries\n", len(lines))
	} else {
		s.Printf("│  naabu: SKIP (%v)\n", res.Err)
	}
	return nil
}

// ═══════════════════════════════════════════════════════════════
// Phase 10: Wayback & Historical URL Mining
// ═══════════════════════════════════════════════════════════════
type WaybackPhase struct{}

func (p *WaybackPhase) Name() string        { return "Wayback & Historical URL Mining" }
func (p *WaybackPhase) Description() string { return "gau + waybackurls for historical URL discovery" }
func (p *WaybackPhase) Execute(ctx context.Context, s *engine.State) error {
	allURLs := make(map[string]bool)

	for _, domain := range s.Scope.Domains {
		res := runner.RunTool(ctx, "gau", []string{domain, "--threads", "5", "--subs"}, s.Proxy.GetEnv())
		if res.Err == nil {
			gauCount := 0
			for _, l := range strings.Split(res.Stdout, "\n") {
				l = strings.TrimSpace(l)
				if l != "" {
					allURLs[l] = true
					gauCount++
				}
			}
			s.Printf("│  gau [%s]: %d URLs\n", domain, gauCount)
		}

		res = runner.RunTool(ctx, "waybackurls", []string{domain}, s.Proxy.GetEnv())
		if res.Err == nil {
			wbCount := 0
			for _, l := range strings.Split(res.Stdout, "\n") {
				l = strings.TrimSpace(l)
				if l != "" {
					allURLs[l] = true
					wbCount++
				}
			}
			s.Printf("│  waybackurls [%s]: %d URLs\n", domain, wbCount)
		}
	}

	var lines []string
	for u := range allURLs {
		lines = append(lines, u)
	}
	archiveFile := filepath.Join(s.OutputFolder, "urls_archive.txt")
	os.WriteFile(archiveFile, []byte(strings.Join(lines, "\n")), 0644)
	s.URLs = append(s.URLs, lines...)
	s.Printf("│  Total Archive URLs: %d\n", len(allURLs))
	return nil
}

// ═══════════════════════════════════════════════════════════════
// Phase 11: Web Crawling & Spidering
// ═══════════════════════════════════════════════════════════════
type CrawlPhase struct{}

func (p *CrawlPhase) Name() string        { return "Web Crawling & Spidering" }
func (p *CrawlPhase) Description() string { return "katana + gospider deep crawl on live endpoints" }
func (p *CrawlPhase) Execute(ctx context.Context, s *engine.State) error {
	urlsFile := filepath.Join(s.OutputFolder, "http_live.txt")
	if _, err := os.Stat(urlsFile); err != nil {
		s.Printf("│  Crawl: SKIP (no http_live.txt found)\n")
		return nil
	}

	crawlURLs := make(map[string]bool)

	katOut := filepath.Join(s.OutputFolder, "katana_raw.txt")
	args := []string{"-list", urlsFile, "-o", katOut, "-silent", "-d", "3", "-rl", "150", "-jc"}
	if s.Proxy.Active {
		args = append(args, "-proxy", s.Proxy.ProxyURL)
	}
	res := runner.RunTool(ctx, "katana", args, s.Proxy.GetEnv())
	if res.Err == nil {
		data, _ := os.ReadFile(katOut)
		for _, l := range strings.Split(string(data), "\n") {
			l = strings.TrimSpace(l)
			if l != "" {
				crawlURLs[l] = true
			}
		}
		s.Printf("│  katana: %d URLs crawled\n", len(crawlURLs))
	} else {
		s.Printf("│  katana: SKIP (%v)\n", res.Err)
	}

	goOut := filepath.Join(s.OutputFolder, "gospider_raw.txt")
	res = runner.RunTool(ctx, "gospider", []string{"-S", urlsFile, "-o", goOut, "-d", "2", "-c", "10", "--sitemap", "--robots"}, s.Proxy.GetEnv())
	if res.Err == nil {
		data, _ := os.ReadFile(goOut)
		goCount := 0
		for _, l := range strings.Split(string(data), "\n") {
			if strings.Contains(l, "http") {
				for _, part := range strings.Fields(l) {
					if strings.HasPrefix(part, "http") {
						crawlURLs[part] = true
						goCount++
					}
				}
			}
		}
		s.Printf("│  gospider: +%d URLs\n", goCount)
	} else {
		s.Printf("│  gospider: SKIP (%v)\n", res.Err)
	}

	var lines []string
	for u := range crawlURLs {
		lines = append(lines, u)
	}
	crawlFile := filepath.Join(s.OutputFolder, "urls_crawled.txt")
	os.WriteFile(crawlFile, []byte(strings.Join(lines, "\n")), 0644)
	s.URLs = append(s.URLs, lines...)
	s.Printf("│  Total Crawled URLs: %d\n", len(crawlURLs))
	return nil
}

// ═══════════════════════════════════════════════════════════════
// Phase 12: JS Analysis & Secret Extraction
// ═══════════════════════════════════════════════════════════════
type JSAnalysisPhase struct{}

func (p *JSAnalysisPhase) Name() string        { return "JS Analysis & Secret Extraction" }
func (p *JSAnalysisPhase) Description() string { return "Extract JS files, scan for API keys/tokens/secrets" }
func (p *JSAnalysisPhase) Execute(ctx context.Context, s *engine.State) error {
	jsURLs := make(map[string]bool)
	for _, u := range s.URLs {
		if strings.HasSuffix(u, ".js") || strings.Contains(u, ".js?") {
			jsURLs[u] = true
		}
	}

	jsFile := filepath.Join(s.OutputFolder, "js_files.txt")
	var jsLines []string
	for u := range jsURLs {
		jsLines = append(jsLines, u)
	}
	os.WriteFile(jsFile, []byte(strings.Join(jsLines, "\n")), 0644)
	s.Printf("│  JS files found: %d\n", len(jsURLs))

	urlsFile := filepath.Join(s.OutputFolder, "http_live.txt")
	if _, err := os.Stat(urlsFile); err == nil {
		res := runner.RunTool(ctx, "getJS", []string{"--input", urlsFile, "--complete"}, nil)
		if res.Err == nil {
			for _, l := range strings.Split(res.Stdout, "\n") {
				l = strings.TrimSpace(l)
				if l != "" && strings.HasSuffix(l, ".js") {
					jsURLs[l] = true
				}
			}
			s.Printf("│  getJS: OK (+extra JS links)\n")
		}
	}

	secretPatterns := []string{
		"api[_-]?key", "api[_-]?secret", "access[_-]?token", "auth[_-]?token",
		"client[_-]?secret", "password", "aws[_-]?access", "private[_-]?key",
		"bearer", "authorization", "secret[_-]?key", "firebase",
	}
	secretsFound := 0
	for u := range jsURLs {
		res := runner.RunTool(ctx, "curl", []string{"-s", "-m", "10", u}, nil)
		if res.Err == nil && res.Stdout != "" {
			lowerBody := strings.ToLower(res.Stdout)
			for _, pattern := range secretPatterns {
				if strings.Contains(lowerBody, pattern) {
					secretsFound++
					s.Findings = append(s.Findings, map[string]interface{}{
						"title": "Potential Secret in JS", "severity": "High",
						"url": u, "tool": "js_scanner", "evidence": "Pattern: " + pattern,
					})
					break
				}
			}
		}
		s.Governor.Throttle()
	}
	s.Printf("│  JS secrets found: %d\n", secretsFound)
	return nil
}

// ═══════════════════════════════════════════════════════════════
// Phase 13: Parameter Discovery
// ═══════════════════════════════════════════════════════════════
type ParamDiscoveryPhase struct{}

func (p *ParamDiscoveryPhase) Name() string        { return "Parameter Discovery" }
func (p *ParamDiscoveryPhase) Description() string { return "paramspider + arjun + URL param extraction" }
func (p *ParamDiscoveryPhase) Execute(ctx context.Context, s *engine.State) error {
	if len(s.Scope.Domains) == 0 {
		return nil
	}
	domain := s.Scope.Domains[0]
	paramURLs := make(map[string]bool)

	// Extract parameterized URLs already found
	for _, u := range s.URLs {
		if strings.Contains(u, "=") {
			paramURLs[u] = true
		}
	}
	s.Printf("│  Params from crawl/archive: %d\n", len(paramURLs))

	// paramspider — write to output folder explicitly
	paramOut := filepath.Join(s.OutputFolder, fmt.Sprintf("paramspider_%s.txt", sanitizeName(domain)))
	res := runner.RunTool(ctx, "paramspider", []string{"-d", domain, "--output", paramOut}, nil)
	if res.Err == nil {
		if data, err := os.ReadFile(paramOut); err == nil {
			count := 0
			for _, l := range strings.Split(string(data), "\n") {
				l = strings.TrimSpace(l)
				if l != "" {
					paramURLs[l] = true
					count++
				}
			}
			s.Printf("│  paramspider: %d param URLs\n", count)
		} else {
			// Fallback: try default output location that paramspider uses
			defaultOut := filepath.Join("output", domain+".txt")
			if data2, err2 := os.ReadFile(defaultOut); err2 == nil {
				count := 0
				for _, l := range strings.Split(string(data2), "\n") {
					l = strings.TrimSpace(l)
					if l != "" {
						paramURLs[l] = true
						count++
					}
				}
				s.Printf("│  paramspider: %d param URLs (fallback path)\n", count)
			} else {
				s.Printf("│  paramspider: ran but output not found\n")
			}
		}
	} else {
		s.Printf("│  paramspider: SKIP (%v)\n", res.Err)
	}

	// arjun — scan top 15 URLs
	topURLs := s.URLs
	if len(topURLs) > 15 {
		topURLs = topURLs[:15]
	}
	arjunFound := 0
	for _, u := range topURLs {
		arjunOut := filepath.Join(s.OutputFolder, "arjun_temp.json")
		res := runner.RunTool(ctx, "arjun", []string{"-u", u, "-oJ", arjunOut, "-q", "-t", "5"}, nil)
		if res.Err == nil {
			if data, err := os.ReadFile(arjunOut); err == nil {
				var arjunResult map[string]interface{}
				if json.Unmarshal(data, &arjunResult) == nil {
					for _, params := range arjunResult {
						if paramList, ok := params.([]interface{}); ok {
							for _, param := range paramList {
								if pStr, ok := param.(string); ok {
									s.Parameters[u] = append(s.Parameters[u], pStr)
									arjunFound++
								}
							}
						}
					}
				}
			}
		}
		s.Governor.Throttle()
	}
	s.Printf("│  arjun: %d params found across %d URLs\n", arjunFound, len(topURLs))

	var lines []string
	for u := range paramURLs {
		lines = append(lines, u)
	}
	paramFile := filepath.Join(s.OutputFolder, "params.txt")
	os.WriteFile(paramFile, []byte(strings.Join(lines, "\n")), 0644)
	s.Printf("│  Total Param URLs: %d\n", len(paramURLs))
	return nil
}

// ═══════════════════════════════════════════════════════════════
// Phase 14: CORS Misconfiguration
// ═══════════════════════════════════════════════════════════════
type CORSPhase struct{}

func (p *CORSPhase) Name() string        { return "CORS Misconfiguration Check" }
func (p *CORSPhase) Description() string { return "Tests CORS reflection, null origin, wildcard" }
func (p *CORSPhase) Execute(ctx context.Context, s *engine.State) error {
	corsVuln := 0
	testOrigins := []string{"https://evil.com", "null", "https://attacker.com"}

	targets := s.URLs
	if len(targets) > 50 {
		targets = targets[:50]
	}

	for _, u := range targets {
		for _, origin := range testOrigins {
			res := runner.RunTool(ctx, "curl", []string{"-s", "-m", "10", "-H", "Origin: " + origin, "-I", u}, nil)
			if res.Err == nil {
				lower := strings.ToLower(res.Stdout)
				if strings.Contains(lower, "access-control-allow-origin: "+strings.ToLower(origin)) ||
					strings.Contains(lower, "access-control-allow-origin: *") {
					corsVuln++
					s.Findings = append(s.Findings, map[string]interface{}{
						"title": "CORS Misconfiguration", "severity": "High",
						"url": u, "tool": "cors_check", "evidence": "Reflected origin: " + origin,
					})
					break
				}
			}
		}
		s.Governor.Throttle()
	}
	s.Printf("│  CORS: tested %d, vulnerable %d\n", len(targets), corsVuln)
	return nil
}
