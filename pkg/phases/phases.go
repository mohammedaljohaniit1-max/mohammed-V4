package phases

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/mohammed-v3/core/pkg/browser"
	"github.com/mohammed-v3/core/pkg/config"
	"github.com/mohammed-v3/core/pkg/engine"
	"github.com/mohammed-v3/core/pkg/exploit"
	"github.com/mohammed-v3/core/pkg/filter"
	"github.com/mohammed-v3/core/pkg/proxy"
	"github.com/mohammed-v3/core/pkg/runner"
)

// ═══════════════════════════════════════════════════════════════
// Shared helpers used across all phases
// ═══════════════════════════════════════════════════════════════

// sanitizeName converts domain.com → domain_com for use in filenames.
func sanitizeName(s string) string {
	r := strings.NewReplacer(".", "_", "-", "_", "/", "_", ":", "_")
	return r.Replace(s)
}

// fileHasContent returns (true, lineCount) if the file exists and has at least
// one non-empty line. Used to guard tools that exit non-zero on empty input
// (fixes BUG #5: gospider exit 1 on empty file).
func fileHasContent(path string) (bool, int) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, 0
	}
	n := 0
	for _, l := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(l) != "" {
			n++
		}
	}
	return n > 0, n
}

// readNonEmptyLines returns all trimmed non-empty lines of a file.
func readNonEmptyLines(path string) []string {
	var out []string
	data, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	for _, l := range strings.Split(string(data), "\n") {
		if t := strings.TrimSpace(l); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// writeLines writes a slice of strings to a file, one per line.
func writeLines(path string, lines []string) {
	_ = os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0644)
}

// mapKeys returns the keys of a string-keyed set as a slice.
func mapKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// sanitizeHostFileLF (BUG #6 V6) reads a host list, strips CR (\r) and any
// surrounding whitespace so lines use Unix LF endings, and writes a cleaned
// copy into the output folder. httpx silently drops CRLF-terminated hosts, so
// feeding it a sanitized file is what makes the primary probe succeed. Returns
// the cleaned file path, or the original path when nothing needed cleaning /
// on any read error.
func sanitizeHostFileLF(s *engine.State, src string) string {
	data, err := os.ReadFile(src)
	if err != nil {
		return src
	}
	if !strings.ContainsRune(string(data), '\r') {
		return src // already LF-only — no rewrite needed.
	}
	var out []string
	for _, l := range strings.Split(strings.ReplaceAll(string(data), "\r", ""), "\n") {
		if t := strings.TrimSpace(l); t != "" {
			out = append(out, t)
		}
	}
	dst := filepath.Join(s.OutputFolder, "hosts_lf.txt")
	writeLines(dst, out)
	return dst
}

// ═══════════════════════════════════════════════════════════════
// Phase 01: Scope Validation
// ═══════════════════════════════════════════════════════════════
type ScopeValidationPhase struct{}

func (p *ScopeValidationPhase) Name() string { return "Scope Validation" }
func (p *ScopeValidationPhase) Description() string {
	return "Validates target domains, IPs, and scope rules (deduplicated)"
}
func (p *ScopeValidationPhase) Execute(ctx context.Context, s *engine.State) error {
	s.Printf("│  Domains: %d | IPs: %d | CIDRs: %d | Excludes: %d\n",
		len(s.Scope.Domains), len(s.Scope.IPs), len(s.Scope.CIDRs), len(s.Scope.ExcludeDomains))

	for _, d := range s.Scope.Domains {
		s.Printf("│    ✔ Target Scope: %s\n", d)
	}

	// Warn if we have subdomains but their apex is missing from scope — this
	// changes how passive enum tools are routed (BUG #2 context).
	apexes := config.ExtractApexDomains(s.Scope.Domains)
	inScope := make(map[string]bool)
	for _, d := range s.Scope.Domains {
		inScope[d] = true
	}
	for _, apex := range apexes {
		if !inScope[apex] {
			s.Printf("│    ⚠  Apex '%s' not explicitly in scope but derived from subdomains — used for passive enum only\n", apex)
		}
	}
	s.Printf("│  Apex/root domains for passive enum: %s\n", strings.Join(apexes, ", "))
	return nil
}

// ═══════════════════════════════════════════════════════════════
// Phase 02: OSINT Intelligence Gathering (apex domains only)
// ═══════════════════════════════════════════════════════════════
type OSINTPhase struct{}

func (p *OSINTPhase) Name() string { return "OSINT Intelligence Gathering" }
func (p *OSINTPhase) Description() string {
	return "Parallel harvest: crt.sh·HackerTarget·RapidDNS·BufferOver·AnubisDB·ThreatMiner·Certspotter·OTX·URLScan + Shodan·VT·SecurityTrails·Chaos"
}
func (p *OSINTPhase) Execute(ctx context.Context, s *engine.State) error {
	keys := s.Config.APIKeys

	// OSINT sources operate on registrable/apex domains only — querying a
	// subdomain like www.whatnot.com wastes calls and returns nothing useful.
	apexDomains := config.ExtractApexDomains(s.Scope.Domains)

	// ── FLAW #3 FIX: parallel async harvester ────────────────────────────────
	// The old code queried 8 sources STRICTLY SEQUENTIALLY inside a domain loop,
	// so one slow source (crt.sh, 40s) stalled everything. We now fan every
	// (source × apex) query out into its own goroutine, collect results through
	// a mutex-guarded set, and add AnubisDB / ThreatMiner / Certspotter /
	// URLScan on top of the original sources.
	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		allSubs = make(map[string]bool)
	)

	// addAll merges a harvester's hosts into the shared set (thread-safe) and
	// returns how many were NEW. Only clean hosts under `apex` are accepted
	// (filtering delegated to the pure, unit-tested filterHostsUnderApex).
	addAll := func(apex string, hosts []string) int {
		clean := filterHostsUnderApex(apex, hosts)
		mu.Lock()
		defer mu.Unlock()
		n := 0
		for _, h := range clean {
			if !allSubs[h] {
				allSubs[h] = true
				n++
			}
		}
		return n
	}

	// run launches a named harvester goroutine.
	run := func(source, apex string, fn func() []string) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			hosts := fn()
			added := addAll(apex, hosts)
			s.Printf("│  %-14s [%s]: +%d\n", source, apex, added)
		}()
	}

	for _, domain := range apexDomains {
		domain := domain // capture

		// ── API-KEY SOURCES (only if key configured) ────────────────────────
		if keys.Shodan != "" {
			run("Shodan", domain, func() []string {
				u := fmt.Sprintf("https://api.shodan.io/dns/domain/%s?key=%s", domain, keys.Shodan)
				return harvestShodan(ctx, domain, u)
			})
		}
		if keys.VirusTotal != "" {
			run("VirusTotal", domain, func() []string {
				u := fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s/subdomains?limit=40", domain)
				return harvestVirusTotal(ctx, u, keys.VirusTotal)
			})
		}
		if keys.SecurityTrails != "" {
			run("SecurityTrails", domain, func() []string {
				u := fmt.Sprintf("https://api.securitytrails.com/v1/domain/%s/subdomains?children_only=false", domain)
				return harvestSecurityTrails(ctx, domain, u, keys.SecurityTrails)
			})
		}
		if keys.Chaos != "" {
			run("Chaos", domain, func() []string {
				u := fmt.Sprintf("https://dns.projectdiscovery.io/dns/%s/subdomains", domain)
				return harvestChaos(ctx, domain, u, keys.Chaos)
			})
		}

		// ── ZERO-KEY SOURCES (always) ────────────────────────────────────────
		run("crt.sh", domain, func() []string { return harvestCrtSh(ctx, domain) })
		run("HackerTarget", domain, func() []string { return harvestHackerTarget(ctx, domain) })
		run("RapidDNS", domain, func() []string { return harvestRapidDNS(ctx, domain) })
		run("BufferOver", domain, func() []string { return harvestBufferOver(ctx, domain) })
		run("AnubisDB", domain, func() []string { return harvestAnubis(ctx, domain) })
		run("ThreatMiner", domain, func() []string { return harvestThreatMiner(ctx, domain) })
		run("Certspotter", domain, func() []string { return harvestCertspotter(ctx, domain) })
		run("AlienVaultOTX", domain, func() []string { return harvestOTX(ctx, domain, keys.AlienVault) })
		run("URLScan", domain, func() []string { return harvestURLScan(ctx, domain) })

		// ── EXPANSION 2 — NATIVE KEY-LESS SCRAPERS ──────────────────────────
		// crt.sh SAN harvester (native Go HTTP, distinct from the curl-based
		// harvestCrtSh above so we exercise the raw JSON SAN parser directly).
		run("crtsh-SAN", domain, func() []string { return ScrapeCrtShSAN(ctx, domain) })
		// GitHub public-code search for leaked host references (uses GITHUB_TOKEN
		// when present for a higher rate limit; still works unauthenticated).
		run("GitHubScrape", domain, func() []string { return ScrapeGitHubHosts(ctx, domain, keys.GitHub) })
	}

	// ── EXPANSION 2 — Shodan InternetDB IP intelligence ─────────────────────
	// After DNS-based subdomain harvesting, enrich every in-scope seed IP with
	// free, key-less Shodan InternetDB data (open ports + CVEs). Findings are
	// added directly to state so they surface in the report.
	for _, ip := range s.Scope.IPs {
		ip := ip
		wg.Add(1)
		go func() {
			defer wg.Done()
			intel := ScrapeShodanInternetDB(ctx, ip)
			if intel == nil {
				return
			}
			s.Printf("│  InternetDB [%s]: %d ports, %d CVEs\n", ip, len(intel.Ports), len(intel.Vulns))
			if len(intel.Vulns) > 0 {
				s.AddFinding(map[string]interface{}{
					"title":    "Known CVEs on host (Shodan InternetDB)",
					"severity": "Medium",
					"url":      ip,
					"tool":     "internetdb",
					"evidence": fmt.Sprintf("ports=%v cves=%s", intel.Ports, strings.Join(intel.Vulns, ",")),
				})
			}
		}()
	}

	wg.Wait()

	osintFile := filepath.Join(s.OutputFolder, "osint_subdomains.txt")
	var lines []string
	mu.Lock()
	for sub := range allSubs {
		lines = append(lines, sub)
	}
	total := len(allSubs)
	mu.Unlock()
	writeLines(osintFile, lines)
	s.Printf("│  OSINT Total Unique: %d\n", total)
	return nil
}

// ═══════════════════════════════════════════════════════════════
// OSINT harvesters — each returns a flat list of candidate hosts.
// All are stdlib+curl based, honor ctx timeouts (via runner per-tool
// timeout), and NEVER panic on malformed JSON (they just return nil).
// Host-suffix filtering is applied centrally by addAll().
// ═══════════════════════════════════════════════════════════════

// filterHostsUnderApex normalizes a raw list of candidate hosts and keeps only
// clean, deduplicated hostnames that are the apex itself or a subdomain of it.
// Pure & side-effect free so the OSINT fan-in filtering (FLAW #3) is unit
// testable without hitting the network.
func filterHostsUnderApex(apex string, hosts []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(h, "*.")))
		h = strings.TrimSuffix(h, ".")
		if h == "" || strings.ContainsAny(h, " /=\"<>") {
			continue
		}
		if h != apex && !strings.HasSuffix(h, "."+apex) {
			continue
		}
		if seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, h)
	}
	return out
}

// curlGet is a small helper: GET url (optionally with extra args/headers)
// and return the body, or "" on any failure.
func curlGet(ctx context.Context, url string, extraArgs ...string) string {
	args := append([]string{"-s", "-m", "30"}, extraArgs...)
	args = append(args, url)
	res := runner.RunTool(ctx, "curl", args, nil)
	if res.OK() {
		return res.Stdout
	}
	return ""
}

func harvestShodan(ctx context.Context, domain, url string) []string {
	body := curlGet(ctx, url)
	var out []string
	var m map[string]interface{}
	if json.Unmarshal([]byte(body), &m) == nil {
		if subs, ok := m["subdomains"].([]interface{}); ok {
			for _, sub := range subs {
				out = append(out, fmt.Sprintf("%v.%s", sub, domain))
			}
		}
	}
	return out
}

func harvestVirusTotal(ctx context.Context, url, key string) []string {
	body := curlGet(ctx, url, "-H", "x-apikey: "+key)
	var out []string
	var m map[string]interface{}
	if json.Unmarshal([]byte(body), &m) == nil {
		if data, ok := m["data"].([]interface{}); ok {
			for _, item := range data {
				if im, ok := item.(map[string]interface{}); ok {
					if id, ok := im["id"].(string); ok {
						out = append(out, id)
					}
				}
			}
		}
	}
	return out
}

func harvestSecurityTrails(ctx context.Context, domain, url, key string) []string {
	body := curlGet(ctx, url, "-H", "APIKEY: "+key)
	var out []string
	var m map[string]interface{}
	if json.Unmarshal([]byte(body), &m) == nil {
		if subs, ok := m["subdomains"].([]interface{}); ok {
			for _, sub := range subs {
				out = append(out, fmt.Sprintf("%v.%s", sub, domain))
			}
		}
	}
	return out
}

// harvestChaos queries ProjectDiscovery Chaos (requires key header).
func harvestChaos(ctx context.Context, domain, url, key string) []string {
	body := curlGet(ctx, url, "-H", "Authorization: "+key)
	var out []string
	var m map[string]interface{}
	if json.Unmarshal([]byte(body), &m) == nil {
		if subs, ok := m["subdomains"].([]interface{}); ok {
			for _, sub := range subs {
				out = append(out, fmt.Sprintf("%v.%s", sub, domain))
			}
		}
	}
	return out
}

func harvestCrtSh(ctx context.Context, domain string) []string {
	// BUG #9 FIX: crt.sh frequently returns HTTP 200 with an empty body "[]"
	// when momentarily rate-limited. Retry up to 3 times with a short backoff,
	// and parse BOTH name_value and common_name fields.
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
	var certs []map[string]interface{}
	for attempt := 0; attempt < 3; attempt++ {
		body := curlGet(ctx, url, "-m", "40")
		if strings.TrimSpace(body) != "" && strings.TrimSpace(body) != "[]" {
			if json.Unmarshal([]byte(body), &certs) == nil && len(certs) > 0 {
				break
			}
		}
		time.Sleep(2 * time.Second)
	}
	var out []string
	for _, c := range certs {
		if name, ok := c["name_value"].(string); ok {
			out = append(out, strings.Split(name, "\n")...)
		}
		if cn, ok := c["common_name"].(string); ok && cn != "" {
			out = append(out, cn)
		}
	}
	return out
}

func harvestHackerTarget(ctx context.Context, domain string) []string {
	body := curlGet(ctx, fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain))
	var out []string
	for _, line := range strings.Split(body, "\n") {
		parts := strings.Split(line, ",")
		if len(parts) >= 1 {
			out = append(out, parts[0])
		}
	}
	return out
}

func harvestRapidDNS(ctx context.Context, domain string) []string {
	body := curlGet(ctx, fmt.Sprintf("https://rapiddns.io/subdomain/%s?full=1", domain))
	var out []string
	for _, line := range strings.Split(body, "\n") {
		for _, tok := range strings.FieldsFunc(line, func(r rune) bool {
			return r == '<' || r == '>' || r == '"' || r == ' ' || r == '\t'
		}) {
			if strings.HasSuffix(strings.ToLower(tok), "."+domain) {
				out = append(out, tok)
			}
		}
	}
	return out
}

func harvestBufferOver(ctx context.Context, domain string) []string {
	body := curlGet(ctx, fmt.Sprintf("https://dns.bufferover.run/dns?q=.%s", domain))
	var out []string
	var m map[string]interface{}
	if json.Unmarshal([]byte(body), &m) == nil {
		for _, key := range []string{"FDNS_A", "RDNS"} {
			if arr, ok := m[key].([]interface{}); ok {
				for _, entry := range arr {
					if es, ok := entry.(string); ok {
						parts := strings.Split(es, ",")
						out = append(out, parts[len(parts)-1])
					}
				}
			}
		}
	}
	return out
}

// harvestAnubis — AnubisDB (jldc.me) returns a plain JSON array of hosts.
func harvestAnubis(ctx context.Context, domain string) []string {
	body := curlGet(ctx, fmt.Sprintf("https://jldc.me/anubis/subdomains/%s", domain))
	var out []string
	_ = json.Unmarshal([]byte(body), &out)
	return out
}

// harvestThreatMiner — ThreatMiner passive DNS (rt=5 → subdomains list).
func harvestThreatMiner(ctx context.Context, domain string) []string {
	body := curlGet(ctx, fmt.Sprintf("https://api.threatminer.org/v2/domain.php?q=%s&rt=5", domain))
	var out []string
	var m map[string]interface{}
	if json.Unmarshal([]byte(body), &m) == nil {
		if results, ok := m["results"].([]interface{}); ok {
			for _, r := range results {
				if hs, ok := r.(string); ok {
					out = append(out, hs)
				}
			}
		}
	}
	return out
}

// harvestCertspotter — Certspotter CT log API (dns_names array per issuance).
func harvestCertspotter(ctx context.Context, domain string) []string {
	url := fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", domain)
	body := curlGet(ctx, url)
	var out []string
	var arr []map[string]interface{}
	if json.Unmarshal([]byte(body), &arr) == nil {
		for _, item := range arr {
			if names, ok := item["dns_names"].([]interface{}); ok {
				for _, n := range names {
					if ns, ok := n.(string); ok {
						out = append(out, ns)
					}
				}
			}
		}
	}
	return out
}

// harvestOTX — AlienVault OTX passive DNS (key optional).
// BUG #10 FIX: the passive_dns endpoint paginates and caps records per page.
// We request the maximum page size and follow pages while a full page keeps
// coming back, so large domains return far more than the default ~20 records.
func harvestOTX(ctx context.Context, domain, key string) []string {
	var out []string
	seen := make(map[string]bool)
	for page := 1; page <= 10; page++ {
		url := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns?page=%d&limit=200", domain, page)
		var body string
		if key != "" {
			body = curlGet(ctx, url, "-H", "X-OTX-API-KEY: "+key)
		} else {
			body = curlGet(ctx, url)
		}
		var m map[string]interface{}
		if json.Unmarshal([]byte(body), &m) != nil {
			break
		}
		records, ok := m["passive_dns"].([]interface{})
		if !ok || len(records) == 0 {
			break
		}
		for _, r := range records {
			if rec, ok := r.(map[string]interface{}); ok {
				if h, ok := rec["hostname"].(string); ok && !seen[h] {
					seen[h] = true
					out = append(out, h)
				}
			}
		}
		// Stop when the page is not full (last page reached).
		if len(records) < 200 {
			break
		}
	}
	return out
}

// harvestURLScan — urlscan.io search API; page.domain fields hold hosts.
func harvestURLScan(ctx context.Context, domain string) []string {
	url := fmt.Sprintf("https://urlscan.io/api/v1/search/?q=domain:%s&size=100", domain)
	body := curlGet(ctx, url)
	var out []string
	var m map[string]interface{}
	if json.Unmarshal([]byte(body), &m) == nil {
		if results, ok := m["results"].([]interface{}); ok {
			for _, r := range results {
				if rec, ok := r.(map[string]interface{}); ok {
					if page, ok := rec["page"].(map[string]interface{}); ok {
						if d, ok := page["domain"].(string); ok {
							out = append(out, d)
						}
					}
				}
			}
		}
	}
	return out
}

// ═══════════════════════════════════════════════════════════════
// Phase 03: Passive Subdomain Enumeration
//
// BUG #2 FIX: amass / bbot / findomain run on APEX domains ONLY. Running them
// on subdomains (www./api.) gives exit-status 2 or 0 results and wastes time.
// subfinder + assetfinder handle both apex and subdomain inputs gracefully so
// they run against every scope entry.
// ═══════════════════════════════════════════════════════════════
type SubdomainPassivePhase struct{}

func (p *SubdomainPassivePhase) Name() string { return "Passive Subdomain Enumeration" }
func (p *SubdomainPassivePhase) Description() string {
	return "subfinder+assetfinder+amass+bbot+findomain (APEX-ONLY, once per root) · OSINT merge"
}
func (p *SubdomainPassivePhase) Execute(ctx context.Context, s *engine.State) error {
	if len(s.Scope.Domains) == 0 {
		return fmt.Errorf("no domains in scope")
	}

	found := make(map[string]bool)
	apexDomains := config.ExtractApexDomains(s.Scope.Domains)

	// Every in-scope entry (apex AND subdomain) is a valid known host and is
	// seeded into `found` so it is never re-discovered as "new". But the
	// enumeration TOOLS below run on APEX domains ONLY — see FLAW #1.
	for _, d := range s.Scope.Domains {
		found[strings.ToLower(d)] = true
	}

	// ── FLAW #1 FIX: Passive enumerators run ONCE PER APEX, never per subdomain
	// ──────────────────────────────────────────────────────────────────────
	// The old code looped `for _, domain := range s.Scope.Domains`, so with a
	// scope of {whatnot.com, www.whatnot.com, api.whatnot.com,
	// live-service.whatnot.com, auction-service.whatnot.com} it ran subfinder &
	// assetfinder FIVE times. Four of those runs query subdomains of an already
	// leaf host (`subfinder -d api.whatnot.com`) → 0 results, pure wasted
	// minutes. subfinder/assetfinder enumerate the WHOLE apex zone in one call,
	// so running them once on `whatnot.com` already covers every subdomain.
	for _, domain := range apexDomains {
		s.Printf("│  [Apex Domain: %s]\n", domain)
		keys := s.Config.APIKeys

		// subfinder — enumerates the full apex zone in a single call.
		sfOut := filepath.Join(s.OutputFolder, fmt.Sprintf("subfinder_%s.txt", sanitizeName(domain)))
		env := make(map[string]string)
		if keys.Shodan != "" {
			env["SHODAN_API_KEY"] = keys.Shodan
		}
		sfCount := 0
		res := runner.RunTool(ctx, "subfinder", []string{"-d", domain, "-all", "-o", sfOut, "-silent"}, env)
		if res.OK() {
			for _, l := range readNonEmptyLines(sfOut) {
				l = strings.ToLower(l)
				if !found[l] {
					found[l] = true
					sfCount++
				}
			}
			s.Printf("│    subfinder: %d subdomains\n", sfCount)
		} else {
			s.Printf("│    subfinder: SKIP (%v)\n", res.Err)
		}

		// assetfinder — apex only; filters to hosts under this apex.
		// BUG #5 FIX (V6): read stdout line-by-line with an explicit 2-minute
		// timeout. assetfinder emits results ONLY on stdout (never a file), so a
		// robust CRLF-tolerant stdout parse is what actually captures its output.
		afCount := 0
		res = runner.RunToolWithTimeout(ctx, "assetfinder", []string{"--subs-only", domain}, nil, 2*time.Minute)
		if res.OK() || res.TimedOut {
			// Strip \r so CRLF-terminated lines still match the apex suffix.
			for _, l := range strings.Split(strings.ReplaceAll(res.Stdout, "\r", ""), "\n") {
				l = strings.TrimSpace(strings.ToLower(l))
				if l != "" && (l == domain || strings.HasSuffix(l, "."+domain)) && !found[l] {
					found[l] = true
					afCount++
				}
			}
			s.Printf("│    assetfinder: %d subdomains\n", afCount)
		} else {
			s.Printf("│    assetfinder: SKIP (%v)\n", res.Err)
		}
	}

	// BUG #3 FIX (V6): detect the installed amass MAJOR version ONCE. amass v4+
	// dropped the old config.ini format entirely and works perfectly in passive
	// mode from CLI flags alone — feeding it a v3 config.ini made it silently
	// return 0. We branch: v4+ = CLI-only; v3 = keep the generated config.ini.
	amassMajor := detectAmassMajor(ctx)
	amassCfg := ""
	if amassMajor > 0 && amassMajor < 4 {
		// Only v3 benefits from (and can parse) the generated INI config.
		amassCfg = ensureAmassConfig(s)
	}

	// ── Tools that require APEX/root domains ONLY (BUG #2) ────────────
	for _, domain := range apexDomains {
		s.Printf("│  [Apex passive enum: %s]\n", domain)

		// amass — apex only.
		//
		// ── V12.0 OMEGA · BUG #1 ROOT-CAUSE FIX ───────────────────────────────
		// A live Temu scan proved the previous integration was BROKEN: the log
		// showed `amass (v5): 0 subdomains` while a manual CLI run in a parallel
		// terminal produced 8,531. Root-cause analysis of the four candidate
		// causes from the mandate:
		//   (a) sub-command syntax  — amass v5.1.1 accepts BOTH `amass enum
		//       -passive -d X` and the newer `amass passive -d X`; the exact
		//       accepted form varies by build, so we now TRY the enum form and
		//       FALL BACK to the passive form when it yields 0.
		//   (b) premature timeout   — the runner hard-killed amass at its 6-min
		//       cap (the Temu log ran amass 00:02:29→00:08:29 == exactly 6m).
		//       We now give amass a dedicated 10-minute deadline (mandate spec).
		//   (c) broken stdout read  — the old path buffered ALL stdout in memory
		//       and only parsed it AFTER the process exited, so a SIGKILL at the
		//       cap discarded everything amass had already emitted. We now stream
		//       stdout LINE-BY-LINE via bufio.Scanner and ingest each host the
		//       instant amass prints it, so a timeout keeps every partial result.
		//   (d) missing config      — v3 only; handled by amassCfg below.
		// The streaming runner logs the EXACT error on failure (mandate spec).
		amOut := filepath.Join(s.OutputFolder, fmt.Sprintf("amass_%s.txt", sanitizeName(domain)))
		amRes := runAmassStreaming(ctx, domain, amassMajor, amassCfg, amOut, found)
		verNote := ""
		if amassMajor > 0 {
			verNote = fmt.Sprintf(" (v%d)", amassMajor)
		}
		switch {
		case amRes.err != nil && amRes.count == 0:
			s.Printf("│    amass%s: 0 subdomains — FAILED (%v)\n", verNote, amRes.err)
			// ── V12.1 ZERO-TOLERANCE · chaos-client backup ────────────────────
			// Amass has been "fixed" in V7-V12 and STILL returned 0 on Temu. The
			// mandate: "If Amass STILL cannot be fixed, REMOVE IT and replace with
			// chaos-client which is faster and more reliable." We keep amass but
			// AUTOMATICALLY fall back to chaos-client whenever amass yields zero,
			// so the pipeline never again loses this attack surface.
			if n := runChaosBackup(ctx, s, domain, found); n > 0 {
				s.Printf("│    chaos-client: %d subdomains [amass fallback]\n", n)
			}
		case amRes.timedOut:
			s.Printf("│    amass%s: %d subdomains [partial — deadline reached, streamed results kept]\n", verNote, amRes.count)
		default:
			s.Printf("│    amass%s: %d subdomains [via %s]\n", verNote, amRes.count, amRes.subcmd)
		}

		// bbot — apex only. BUG #4 FIX (V6): use the exact proven invocation
		//   bbot -t <domain> -p subdomain-enum -rf passive -om json --force -y -o <outdir>
		// and parse ALL *.ndjson (and output.json) events where type==DNS_NAME.
		// The old "[OK]" label on a 0 result was misleading — 0 from bbot is a
		// FAILURE, so we now log it as such.
		bbotOutDir := filepath.Join(s.OutputFolder, fmt.Sprintf("bbot_%s", sanitizeName(domain)))
		res := runner.RunTool(ctx, "bbot", []string{
			"-t", domain, "-p", "subdomain-enum", "-rf", "passive",
			"-om", "json", "--force", "-y", "-o", bbotOutDir,
		}, nil)
		if res.OK() || res.TimedOut {
			bbotCount := 0
			addHost := func(h string) {
				h = strings.ToLower(strings.TrimSpace(h))
				if h != "" && strings.HasSuffix(h, domain) && len(h) < 255 && !found[h] {
					found[h] = true
					bbotCount++
				}
			}
			// Parse EVERY .ndjson / output.json file in the output dir.
			_ = filepath.Walk(bbotOutDir, func(path string, info os.FileInfo, err error) error {
				if err != nil || info == nil || info.IsDir() {
					return nil
				}
				base := strings.ToLower(filepath.Base(path))
				switch {
				case strings.HasSuffix(base, ".ndjson") || base == "output.json" || base == "output.ndjson":
					for _, l := range readNonEmptyLines(path) {
						var ev struct {
							Type string `json:"type"`
							Data string `json:"data"`
						}
						if json.Unmarshal([]byte(l), &ev) == nil && ev.Type == "DNS_NAME" {
							addHost(ev.Data)
						}
					}
				case strings.HasSuffix(base, ".txt"):
					for _, l := range readNonEmptyLines(path) {
						addHost(l)
					}
				}
				return nil
			})
			if bbotCount > 0 {
				status := "OK"
				if res.TimedOut {
					status = "partial (timeout)"
				}
				s.Printf("│    bbot: %d subdomains [%s]\n", bbotCount, status)
			} else if res.TimedOut {
				s.Printf("│    bbot: 0 subdomains — FAILED (timed out before results)\n")
			} else {
				s.Printf("│    bbot: 0 subdomains — FAILED (no DNS_NAME events parsed from %s)\n", bbotOutDir)
			}
		} else {
			s.Printf("│    bbot: SKIP (%v)\n", res.Err)
		}

		// findomain — apex only (BUG #7). -t <domain> -u <out> -q. Some
		// findomain builds write to the file, others only to stdout depending
		// on version, so we parse BOTH the output file and stdout as a fallback.
		// BUG #3 (audit) FIX: findomain reliably writes to STDOUT, one host per
		// line, with `-t <domain> -q`. The `-u <file>` form is not honored by all
		// builds (it prints to stdout instead), which caused the empty-file "0
		// subdomains". We now parse STDOUT as the primary source and fall back to
		// the output file only if stdout was empty. No -t/--threads (unsupported
		// on some builds).
		fdOut := filepath.Join(s.OutputFolder, fmt.Sprintf("findomain_%s.txt", sanitizeName(domain)))
		fdCount := 0
		res = runner.RunTool(ctx, "findomain", []string{"-t", domain, "-q", "-u", fdOut}, nil)
		if res.OK() || res.TimedOut {
			// Primary: stdout. Fallback: the -u output file.
			lines := strings.Split(res.Stdout, "\n")
			if fileLines := readNonEmptyLines(fdOut); len(fileLines) > 0 {
				lines = append(lines, fileLines...)
			}
			for _, l := range lines {
				l = strings.ToLower(strings.TrimSpace(l))
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

	// ── V12.1 Section 3: uncover (Shodan/Censys/FOFA/Hunter) apex sweep ──
	// uncover finds exposed hosts search engines already indexed — surface the
	// passive tools miss. Runs once per apex, key-gated (skips without keys).
	for _, domain := range apexDomains {
		if n := runUncover(ctx, s, domain, found); n > 0 {
			s.Printf("│  uncover: +%d hosts [%s]\n", n, domain)
		}
	}

	// ── Merge OSINT results from Phase 02 ─────────────────────────────
	osintFile := filepath.Join(s.OutputFolder, "osint_subdomains.txt")
	osintCount := 0
	for _, l := range readNonEmptyLines(osintFile) {
		l = strings.ToLower(l)
		if !found[l] {
			found[l] = true
			osintCount++
		}
	}
	if osintCount > 0 {
		s.Printf("│  OSINT merge: +%d unique subdomains\n", osintCount)
	}

	// ── Write final merged subdomains.txt ─────────────────────────────
	for sub := range found {
		s.Subdomains = append(s.Subdomains, sub)
	}
	subFile := filepath.Join(s.OutputFolder, "subdomains.txt")
	writeLines(subFile, s.Subdomains)
	s.Printf("│  Total Passive Subdomains: %d\n", len(s.Subdomains))
	return nil
}

// ═══════════════════════════════════════════════════════════════
// Phase 04: Active Subdomain Bruteforce
//
// BUG #3 FIX: puredns needs a resolvers file (--resolvers) AND massdns; the
// output flag is --write (NOT -w, which is the wordlist). If puredns is
// unavailable, fall back to dnsx brute force.
// ═══════════════════════════════════════════════════════════════
type SubdomainActivePhase struct{}

func (p *SubdomainActivePhase) Name() string { return "Active Subdomain Bruteforce" }
func (p *SubdomainActivePhase) Description() string {
	return "puredns bruteforce (auto resolvers) → dnsx fallback + dnsgen/alterx permutations (dnsx-resolved)"
}
func (p *SubdomainActivePhase) Execute(ctx context.Context, s *engine.State) error {
	if len(s.Scope.Domains) == 0 {
		return nil
	}
	domain := config.ApexOf(s.Scope.Domains[0])
	subFile := filepath.Join(s.OutputFolder, "subdomains.txt")
	activeOut := filepath.Join(s.OutputFolder, "subdomains_brute.txt")

	// Resolve a DNS wordlist (BUG #6). Prefer larger lists; fall back to a
	// downloaded minimal list when none of the standard SecLists paths exist.
	wordlist := firstExisting([]string{
		"/usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt",
		"/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
		"/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
		"/usr/share/wordlists/dnsmap.txt",
	})
	if wordlist == "" {
		wordlist = ensureDNSWordlist(ctx, s)
	}

	// BUG #8 FIX (V6): a 100k wordlist × 3 apex domains cannot finish inside the
	// old 8m/5m caps (needs ~45m). Cap the wordlist to the top 25,000 entries by
	// default; only --profile xlarge uses the full list. This alone makes the
	// phase finish while still adding subdomains.
	profile := strings.ToLower(strings.TrimSpace(s.Config.Profile))
	wordlistCap := 25000
	if profile == "xlarge" {
		wordlistCap = 0 // 0 = no cap (full wordlist)
	}
	if wordlist != "" && wordlistCap > 0 {
		if capped, n := capDNSWordlist(s, wordlist, wordlistCap); capped != "" {
			wordlist = capped
			_ = n
		}
	}
	if wordlist != "" {
		if _, n := fileHasContent(wordlist); n > 0 {
			s.Printf("│  DNS wordlist: %s (%d entries)\n", filepath.Base(wordlist), n)
		}
	}

	// BUG #8 FIX (V6): profile-aware brute-force timeouts. The static per-tool
	// caps (puredns 8m / dnsx 5m) are far too short for --profile large. Give
	// large scans room to actually complete.
	purednsTimeout := 8 * time.Minute
	dnsxBruteTimeout := 5 * time.Minute
	switch profile {
	case "large":
		purednsTimeout = 30 * time.Minute
		dnsxBruteTimeout = 20 * time.Minute
	case "xlarge":
		purednsTimeout = 45 * time.Minute
		dnsxBruteTimeout = 30 * time.Minute
	}

	// Ensure a resolvers file exists (BUG #3 root cause: missing --resolvers).
	resolverFile := ensureResolvers(s)

	existing := make(map[string]bool)
	for _, sub := range s.Subdomains {
		existing[sub] = true
	}
	added := 0

	purednsOK := false
	if wordlist != "" {
		// puredns REQUIRES massdns to be on PATH; guard for it.
		if _, err := runner.ResolveToolPath("massdns"); err != nil {
			s.Printf("│  puredns: massdns not installed → using dnsx fallback\n")
		} else {
			// Correct syntax: puredns bruteforce <wordlist> <domain>
			//   --resolvers <file> --write <out> --rate-limit 150
			args := []string{"bruteforce", wordlist, domain,
				"--resolvers", resolverFile, "--write", activeOut,
				"--rate-limit", "150", "-q"}
			res := runner.RunToolWithTimeout(ctx, "puredns", args, nil, purednsTimeout)
			if res.OK() {
				for _, l := range readNonEmptyLines(activeOut) {
					l = strings.ToLower(l)
					if !existing[l] {
						existing[l] = true
						s.Subdomains = append(s.Subdomains, l)
						added++
					}
				}
				purednsOK = true
				s.Printf("│  puredns bruteforce: +%d new subdomains\n", added)
			} else {
				s.Printf("│  puredns: failed (%v) → dnsx fallback\n", res.Err)
			}
		}
	} else {
		s.Printf("│  puredns: SKIP (no DNS wordlist found)\n")
	}

	// ── dnsx brute-force fallback (BUG #3) ────────────────────────────
	if !purednsOK && wordlist != "" {
		dnsxOut := filepath.Join(s.OutputFolder, "dnsx_brute.txt")
		// dnsx -d <domain> -w <wordlist> -a -resp-only -o <out>
		args := []string{"-d", domain, "-w", wordlist, "-a", "-resp-only",
			"-o", dnsxOut, "-silent", "-r", resolverFile}
		res := runner.RunToolWithTimeout(ctx, "dnsx", args, nil, dnsxBruteTimeout)
		if res.OK() {
			for _, l := range readNonEmptyLines(dnsxOut) {
				l = strings.ToLower(strings.Fields(l)[0])
				if !existing[l] {
					existing[l] = true
					s.Subdomains = append(s.Subdomains, l)
					added++
				}
			}
			s.Printf("│  dnsx brute (fallback): +%d new subdomains\n", added)
		} else {
			s.Printf("│  dnsx brute: SKIP (%v)\n", res.Err)
		}
	}

	// dnsgen permutations (best-effort).
	if _, err := runner.ResolveToolPath("dnsgen"); err == nil {
		dnsgenOut := filepath.Join(s.OutputFolder, "dnsgen_perms.txt")
		res := runner.RunTool(ctx, "dnsgen", []string{subFile}, nil)
		if res.OK() && res.Stdout != "" {
			_ = os.WriteFile(dnsgenOut, []byte(res.Stdout), 0644)
			lines := strings.Split(strings.TrimSpace(res.Stdout), "\n")
			s.Printf("│  dnsgen: %d permutations generated\n", len(lines))
		} else {
			s.Printf("│  dnsgen: SKIP\n")
		}
	}

	// ── V12.1 Section 3: alterx pattern-based permutations ──────────────
	// alterx generates smarter, pattern-aware subdomain candidates than dnsgen
	// (e.g. api-{{word}}, {{sub}}-staging). We write them to alterx_perms.txt
	// and resolve them with dnsx so only LIVE permutations enter the corpus.
	alterxOut := filepath.Join(s.OutputFolder, "alterx_perms.txt")
	if n := runAlterxPermutations(ctx, s, subFile, alterxOut); n > 0 {
		s.Printf("│  alterx: %d permutations generated\n", n)
		if _, err := runner.ResolveToolPath("dnsx"); err == nil {
			res := runner.RunTool(ctx, "dnsx", []string{"-l", alterxOut, "-silent", "-a", "-resp-only"}, nil)
			if res.OK() || res.TimedOut {
				existing := make(map[string]bool, len(s.Subdomains))
				for _, sub := range s.Subdomains {
					existing[sub] = true
				}
				added := 0
				for _, h := range parseHostLines(res.Stdout, domain) {
					if !existing[h] {
						existing[h] = true
						s.Subdomains = append(s.Subdomains, h)
						added++
					}
				}
				if added > 0 {
					s.Printf("│  alterx→dnsx: +%d live permuted subdomains\n", added)
				}
			}
		}
	}

	writeLines(subFile, s.Subdomains)
	s.Printf("│  Total After Active Bruteforce: %d\n", len(s.Subdomains))
	return nil
}

// capDNSWordlist writes the first maxN non-comment entries of src to a capped
// file inside the output folder and returns its path (BUG #8 V6). Returns
// ("", 0) when the source is already <= maxN (caller keeps the original).
func capDNSWordlist(s *engine.State, src string, maxN int) (string, int) {
	if maxN <= 0 || src == "" {
		return "", 0
	}
	lines := readNonEmptyLines(src)
	filtered := lines[:0]
	for _, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), "#") {
			continue
		}
		filtered = append(filtered, l)
	}
	if len(filtered) <= maxN {
		return "", 0
	}
	capped := filepath.Join(s.OutputFolder, fmt.Sprintf("dns_wordlist_top%d.txt", maxN))
	writeLines(capped, filtered[:maxN])
	return capped, maxN
}

// ensureDNSWordlist downloads a minimal DNS wordlist to /tmp when none of the
// standard SecLists paths exist (BUG #6). Uses the canonical SecLists
// top-5000 list. Returns the path, or "" on failure.
func ensureDNSWordlist(ctx context.Context, s *engine.State) string {
	dst := "/tmp/mohammed_dns_top5000.txt"
	if ok, _ := fileHasContent(dst); ok {
		return dst
	}
	url := "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt"
	res := runner.RunTool(ctx, "curl", []string{"-s", "-L", "-m", "60", "-o", dst, url}, nil)
	if res.OK() {
		if ok, _ := fileHasContent(dst); ok {
			s.Printf("│  downloaded DNS wordlist → %s\n", dst)
			return dst
		}
	}
	s.Printf("│  ⚠ could not obtain a DNS wordlist (no SecLists, download failed)\n")
	return ""
}

// firstExisting returns the first path that exists on disk, or "".
func firstExisting(paths []string) string {
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// ensureResolvers returns a path to a DNS resolvers file, creating a hard-coded
// fallback at /tmp/mohammed_resolvers.txt if none of the standard files exist.
// Fixes BUG #3 (puredns exit 1 due to missing --resolvers input).
func ensureResolvers(s *engine.State) string {
	candidates := []string{
		"/usr/share/seclists/Miscellaneous/dns-resolvers.txt",
		"/opt/mohammed-tools/resolvers.txt",
		filepath.Join(os.Getenv("HOME"), ".config", "puredns", "resolvers.txt"),
	}
	if p := firstExisting(candidates); p != "" {
		return p
	}
	fallback := "/tmp/mohammed_resolvers.txt"
	if _, err := os.Stat(fallback); err == nil {
		return fallback
	}
	resolvers := strings.Join([]string{
		"1.1.1.1", "1.0.0.1",
		"8.8.8.8", "8.8.4.4",
		"9.9.9.9", "149.112.112.112",
		"208.67.222.222", "208.67.220.220",
		"64.6.64.6", "64.6.65.6",
	}, "\n")
	if err := os.WriteFile(fallback, []byte(resolvers), 0644); err != nil {
		s.Printf("│  ⚠ could not write fallback resolvers: %v\n", err)
	} else {
		s.Printf("│  Wrote fallback resolvers → %s\n", fallback)
	}
	return fallback
}

// amassStreamResult is the outcome of a streaming amass run.
type amassStreamResult struct {
	count    int    // NEW in-scope subdomains added to `found` this run
	subcmd   string // which sub-command actually produced results
	timedOut bool   // true when the 15-minute deadline killed amass
	err      error  // exact error when the run failed with zero results
}

// runAmassStreaming is the V12.0 OMEGA BUG #1 fix. It executes amass with a
// dedicated 10-minute deadline (independent of the shared runner cap that was
// killing amass mid-run), reads STDOUT line-by-line via bufio.Scanner so every
// host is ingested the instant amass prints it (a timeout keeps all partial
// results), and — when the primary sub-command yields nothing — retries with
// the alternate v5 sub-command. Newly discovered in-scope hosts are added to
// `found` and also appended to amOut for the report artifact.
//
// Sub-command matrix (accepted forms differ per amass build):
//
//	v5+/unknown : `amass enum -passive -d <domain>`  → stdout
//	              fallback `amass passive -d <domain>` (v5.1.1 short form)
//	v4          : `amass enum -passive -d <domain> -o <out>` (stdout also works)
//	v3          : `amass enum -passive -d <domain> -config <ini> -o <out>`
//
// No `-timeout N` is passed to amass itself: that flag is the exact knob that
// silently mis-behaved on v5 in the field, and OUR context deadline is the
// authoritative bound now.
func runAmassStreaming(ctx context.Context, domain string, amassMajor int, amassCfg, amOut string, found map[string]bool) amassStreamResult {
	if _, err := runner.ResolveToolPath("amass"); err != nil {
		return amassStreamResult{err: fmt.Errorf("amass not found: %w", err)}
	}

	// Build the ordered list of (label, args) attempts for this version.
	type attempt struct {
		label string
		args  []string
	}
	var attempts []attempt
	switch {
	case amassMajor == 4:
		attempts = []attempt{
			{"enum -passive (v4)", []string{"enum", "-passive", "-d", domain}},
		}
	case amassMajor > 0 && amassMajor < 4: // v3
		a3 := []string{"enum", "-passive", "-d", domain}
		if amassCfg != "" {
			a3 = append(a3, "-config", amassCfg)
		}
		attempts = []attempt{{"enum -passive -config (v3)", a3}}
	default: // v5+ / unknown — try the modern long form, then the short form.
		attempts = []attempt{
			{"enum -passive", []string{"enum", "-passive", "-d", domain}},
			{"passive", []string{"passive", "-d", domain}},
		}
	}

	// A single writer for the artifact file, appended across attempts.
	outFile, _ := os.OpenFile(amOut, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if outFile != nil {
		defer outFile.Close()
	}

	suffix := "." + domain
	ingest := func(line string) int {
		added := 0
		for _, tok := range strings.Fields(strings.ToLower(line)) {
			tok = strings.Trim(tok, ".,()<>\"'[]")
			if tok == domain || strings.HasSuffix(tok, suffix) {
				if len(tok) < 255 && !found[tok] {
					found[tok] = true
					added++
					if outFile != nil {
						fmt.Fprintln(outFile, tok)
					}
				}
			}
		}
		return added
	}

	var lastErr error
	var lastTimeout bool
	for _, at := range attempts {
		count, timedOut, err := streamAmassOnce(ctx, at.args, ingest)
		lastErr, lastTimeout = err, timedOut
		if count > 0 {
			return amassStreamResult{count: count, subcmd: at.label, timedOut: timedOut}
		}
	}
	return amassStreamResult{count: 0, subcmd: "", timedOut: lastTimeout, err: lastErr}
}

// amassDeadline is the dedicated per-invocation deadline for amass. Amass is
// SLOW (the V12.1 mandate: "not 2, not 5, not 10 — Amass is SLOW"), so V12.1
// raises the streaming deadline to 15 minutes.
const amassDeadline = 15 * time.Minute

// runChaosBackup is the V12.1 chaos-client fallback for amass. ProjectDiscovery
// Chaos (`chaos -d <domain> -silent`) queries the Chaos passive-DNS dataset and
// is faster/more reliable than amass. Requires a PDCP_API_KEY env var (Chaos is
// key-gated); when the key is missing chaos exits with an error and we simply
// report 0. Newly discovered in-scope hosts are merged into `found`.
func runChaosBackup(ctx context.Context, s *engine.State, domain string, found map[string]bool) int {
	if _, err := runner.ResolveToolPath("chaos"); err != nil {
		return 0
	}
	res := runner.RunTool(ctx, "chaos", []string{"-d", domain, "-silent"}, nil)
	if !res.OK() && !res.TimedOut {
		return 0
	}
	added := 0
	suffix := "." + domain
	for _, line := range strings.Split(res.Stdout, "\n") {
		h := strings.ToLower(strings.TrimSpace(line))
		if h == "" {
			continue
		}
		if (h == domain || strings.HasSuffix(h, suffix)) && len(h) < 255 && !found[h] {
			found[h] = true
			added++
		}
	}
	return added
}

// runAmassV5 is the V12.1 ZERO-TOLERANCE dedicated, self-contained, TESTABLE
// amass integration. It tries THREE methods in sequence and returns the merged,
// de-duplicated list of subdomains it captured for `domain`:
//
//	Method A: amass enum -passive -d <domain>
//	Method B: amass passive -d <domain>                (v5.1.1 short form)
//	Method C: amass enum -passive -d <domain> -config <configPath>
//
// Each method streams stdout line-by-line under a 15-minute context deadline so
// partial results survive a timeout. If ALL three methods yield zero results it
// returns the exact combined error:
//
//	amass: all 3 methods failed: <errA> / <errB> / <errC>
//
// This is the function asserted by TestAmassV5Integration.
func runAmassV5(domain string) ([]string, error) {
	return runAmassV5Ctx(context.Background(), domain, "")
}

// runAmassV5Ctx is runAmassV5 with an explicit parent context and optional
// amass config path (Method C). Exposed separately so the pipeline can pass its
// own cancellation context and a v3 config while the exported runAmassV5 stays
// a simple, test-friendly signature.
func runAmassV5Ctx(parent context.Context, domain, configPath string) ([]string, error) {
	if _, err := runner.ResolveToolPath("amass"); err != nil {
		return nil, fmt.Errorf("amass not found: %w", err)
	}

	found := map[string]bool{}
	suffix := "." + domain
	ingest := func(line string) int {
		added := 0
		for _, tok := range strings.Fields(strings.ToLower(line)) {
			tok = strings.Trim(tok, ".,()<>\"'[]")
			if (tok == domain || strings.HasSuffix(tok, suffix)) && len(tok) < 255 && !found[tok] {
				found[tok] = true
				added++
			}
		}
		return added
	}

	methodC := []string{"enum", "-passive", "-d", domain}
	if configPath != "" {
		methodC = append(methodC, "-config", configPath)
	}
	methods := []struct {
		label string
		args  []string
	}{
		{"enum -passive", []string{"enum", "-passive", "-d", domain}},
		{"passive", []string{"passive", "-d", domain}},
		{"enum -passive -config", methodC},
	}

	errs := make([]string, 0, 3)
	for _, m := range methods {
		count, _, err := streamAmassOnce(parent, m.args, ingest)
		if count > 0 {
			// Success on this method: return everything captured so far.
			out := make([]string, 0, len(found))
			for h := range found {
				out = append(out, h)
			}
			return out, nil
		}
		if err != nil {
			errs = append(errs, fmt.Sprintf("[%s] %v", m.label, err))
		} else {
			errs = append(errs, fmt.Sprintf("[%s] 0 results", m.label))
		}
	}

	// All 3 methods produced zero. If amass nonetheless emitted anything that
	// slipped past the per-method count (it won't, but be safe), return it.
	if len(found) > 0 {
		out := make([]string, 0, len(found))
		for h := range found {
			out = append(out, h)
		}
		return out, nil
	}
	return nil, fmt.Errorf("amass: all 3 methods failed: %s", strings.Join(errs, " / "))
}

// streamAmassOnce runs one amass invocation with a 15-minute deadline, scans
// stdout line-by-line, and calls ingest() on each line as it arrives. Returns
// the number of newly ingested hosts, whether the deadline fired, and the exact
// error (nil on clean exit). Partial results are preserved on timeout because
// ingest has already run for every line amass emitted before the kill.
func streamAmassOnce(parent context.Context, args []string, ingest func(string) int) (int, bool, error) {
	// V12.1 mandate spec: 15-minute dedicated deadline (amass is SLOW),
	// independent of the shared runner cap.
	ctx, cancel := context.WithTimeout(parent, amassDeadline)
	defer cancel()

	binPath, err := runner.ResolveToolPath("amass")
	if err != nil {
		return 0, false, err
	}
	cmd := exec.Command(binPath, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Env = os.Environ()

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return 0, false, fmt.Errorf("amass stdout pipe: %w", err)
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return 0, false, fmt.Errorf("amass start: %w", err)
	}

	// Kill the whole process group when the deadline/parent context fires.
	killed := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			if cmd.Process != nil {
				if pgid, e := syscall.Getpgid(cmd.Process.Pid); e == nil {
					_ = syscall.Kill(-pgid, syscall.SIGKILL)
				} else {
					_ = cmd.Process.Kill()
				}
			}
		case <-killed:
		}
	}()

	count := 0
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024) // tolerate long FQDN lines
	for scanner.Scan() {
		count += ingest(scanner.Text())
	}
	waitErr := cmd.Wait()
	close(killed)

	timedOut := ctx.Err() == context.DeadlineExceeded
	if timedOut {
		return count, true, nil // partial success: results already ingested
	}
	if parent.Err() != nil {
		return count, false, fmt.Errorf("scan cancelled")
	}
	if waitErr != nil {
		// A non-zero exit with results is fine (amass often exits 1); only
		// surface the error when we got nothing AND stderr has a real message.
		if count == 0 {
			msg := strings.TrimSpace(stderr.String())
			if msg == "" {
				msg = waitErr.Error()
			}
			if len(msg) > 200 {
				msg = msg[:200] + "…"
			}
			return 0, false, fmt.Errorf("amass exited: %s", msg)
		}
	}
	return count, false, nil
}

// detectAmassMajor runs `amass -version` and returns the major version number
// (e.g. 4 for v4.2.0). Returns 0 when amass is missing or the version cannot be
// parsed — callers treat 0 as "assume modern (v4+), CLI-only" (BUG #3 V6).
// amass prints its version to STDERR on most builds, so we parse both streams.
func detectAmassMajor(ctx context.Context) int {
	if _, err := runner.ResolveToolPath("amass"); err != nil {
		return 0
	}
	res := runner.RunToolWithTimeout(ctx, "amass", []string{"-version"}, nil, 20*time.Second)
	out := res.Stdout + "\n" + res.Stderr
	// Match the first vN or N. pattern, e.g. "v4.2.0", "amass version 3.23.3".
	re := regexp.MustCompile(`v?(\d+)\.\d+`)
	if m := re.FindStringSubmatch(out); len(m) == 2 {
		if n, err := strconv.Atoi(m[1]); err == nil {
			return n
		}
	}
	return 0
}

// ensureAmassConfig makes sure amass has a config file that enables data
// sources (BUG #4, v3 only). If the user already has ~/.config/amass/config.ini
// we do not touch it; otherwise we write a minimal one that turns on all free,
// key-less sources. Returns the config path, or "" if it could not be created
// (amass then runs with its own defaults). Only used for amass v3 — v4+ ignores
// this format (BUG #3 V6).
func ensureAmassConfig(s *engine.State) string {
	home := os.Getenv("HOME")
	if home == "" {
		return ""
	}
	// Respect an existing user config — never overwrite it.
	for _, existing := range []string{
		filepath.Join(home, ".config", "amass", "config.ini"),
		filepath.Join(home, ".config", "amass", "config.yaml"),
	} {
		if _, err := os.Stat(existing); err == nil {
			return existing
		}
	}
	dir := filepath.Join(home, ".config", "amass")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return ""
	}
	cfgPath := filepath.Join(dir, "config.ini")
	// Minimal config: scope left open, all free data sources enabled. amass
	// treats a data source with no api key as free/enabled when present here.
	content := `# Auto-generated by MOHAMMED (BUG #4 fix) — enables free, key-less data sources.
# amass silently returns 0 results when no config enables any source, so we
# turn on every source that works WITHOUT an API key.
[scope]

[data_sources]
minimum_ttl = 1440

[data_sources.CertSpotter]
[data_sources.CRTsh]
[data_sources.HackerTarget]
[data_sources.URLScan]
[data_sources.PassiveDNS]
[data_sources.Crtsh]
[data_sources.RapidDNS]
[data_sources.AnubisDB]
[data_sources.ThreatMiner]
[data_sources.Certspotter]
[data_sources.AlienVault]
[data_sources.DNSDumpster]
[data_sources.Wayback]
[data_sources.CommonCrawl]
[data_sources.Riddler]
[data_sources.SiteDossier]
`
	if err := os.WriteFile(cfgPath, []byte(content), 0644); err != nil {
		return ""
	}
	s.Printf("│  amass: wrote minimal free-source config → %s\n", cfgPath)
	return cfgPath
}

// ensureGauConfig makes sure gau has a ~/.gau.toml (BUG #4 audit). gau logs
// `error reading config: ... .gau.toml not found` and falls back to a limited
// default when the file is missing, which returned 0 URLs for apex domains in
// the live test. We write a minimal working config enabling the free
// providers if the user has not supplied one. Returns the config path, or ""
// if it could not be created (gau then runs with CLI --providers only).
func ensureGauConfig(s *engine.State) string {
	home := os.Getenv("HOME")
	if home == "" {
		return ""
	}
	cfgPath := filepath.Join(home, ".gau.toml")
	if _, err := os.Stat(cfgPath); err == nil {
		return cfgPath // respect an existing user config
	}
	content := `# Auto-generated by MOHAMMED (BUG #4 fix) — silences the "config not found"
# warning and enables the free, key-less URL providers.
providers = ["wayback","commoncrawl","otx","urlscan"]
threads = 5
retries = 3
timeout = 45
verbose = false

[urlscan]
apikey = ""
`
	if err := os.WriteFile(cfgPath, []byte(content), 0644); err != nil {
		return ""
	}
	s.Printf("│  gau: wrote minimal free-provider config → %s\n", cfgPath)
	return cfgPath
}

// ═══════════════════════════════════════════════════════════════
// Phase 05: DNS Resolution & Enrichment
// ═══════════════════════════════════════════════════════════════
type DNSResolvePhase struct{}

func (p *DNSResolvePhase) Name() string { return "DNS Resolution & Enrichment" }
func (p *DNSResolvePhase) Description() string {
	return "Resolves live hosts via dnsx (deduplicated), filters wildcards"
}
func (p *DNSResolvePhase) Execute(ctx context.Context, s *engine.State) error {
	subFile := filepath.Join(s.OutputFolder, "subdomains.txt")

	// Deduplicate the input before resolving.
	seen := make(map[string]bool)
	var deduped []string
	for _, l := range readNonEmptyLines(subFile) {
		l = strings.ToLower(l)
		if !seen[l] {
			seen[l] = true
			deduped = append(deduped, l)
		}
	}
	writeLines(subFile, deduped)

	dnsxOut := filepath.Join(s.OutputFolder, "live_dns.txt")
	resolverFile := ensureResolvers(s)

	apex := ""
	if len(s.Scope.Domains) > 0 {
		apex = config.ApexOf(s.Scope.Domains[0])
	}

	inputN := len(deduped)
	s.Printf("│  dnsx input: %d unique hosts to resolve\n", inputN)

	// runDnsx resolves subFile through dnsx and returns the deduped host list.
	// withWildcard toggles the -wd wildcard-elimination pass.
	runDnsx := func(withWildcard bool) ([]string, *runner.Result) {
		// NOTE: previous code used "-resp-only" which prints the RESOLVED IP,
		// not the hostname, then took Fields[0] — collapsing many distinct
		// hostnames onto shared CDN IPs and destroying the host list. That,
		// combined with aggressive -wd wildcard filtering, is the root cause of
		// the 232→32 regression (BUG #2). We drop -resp-only so dnsx emits the
		// input HOSTNAMES that resolve, one per line.
		args := []string{"-l", subFile, "-o", dnsxOut, "-silent", "-rl", "150",
			"-a", "-r", resolverFile}
		if withWildcard && apex != "" {
			args = append(args, "-wd", apex)
		}
		res := runner.RunTool(ctx, "dnsx", args, nil)
		set := make(map[string]bool)
		var hosts []string
		for _, l := range readNonEmptyLines(dnsxOut) {
			fields := strings.Fields(l)
			if len(fields) == 0 {
				continue
			}
			host := strings.ToLower(fields[0])
			if !set[host] {
				set[host] = true
				hosts = append(hosts, host)
			}
		}
		return hosts, res
	}

	hosts, res := runDnsx(true)

	if !res.OK() {
		// dnsx failed entirely — fall back to the full subdomain list so the
		// pipeline is not starved (IMPROVEMENT #6).
		s.LiveHosts = append(s.LiveHosts, deduped...)
		s.Printf("│  dnsx: FAILED (%v) — fallback to %d subdomains\n", res.Err, len(s.LiveHosts))
		writeLines(dnsxOut, s.LiveHosts)
		return nil
	}

	// ── IMPROVEMENT #2 + BUG #2 safeguard ──────────────────────────────────
	// If wildcard elimination nuked more than 85% of the input, it is almost
	// certainly over-filtering legitimate hosts (a real regression symptom).
	// Re-run WITHOUT -wd and keep whichever pass yielded more live hosts.
	if inputN > 0 && len(hosts)*100 < inputN*15 {
		s.Printf("│  ⚠ WARNING: dnsx resolved only %d/%d (<15%%) with wildcard filter — retrying without -wd\n", len(hosts), inputN)
		noWildHosts, res2 := runDnsx(false)
		if res2.OK() && len(noWildHosts) > len(hosts) {
			s.Printf("│  no-wildcard retry recovered %d hosts (was %d)\n", len(noWildHosts), len(hosts))
			hosts = noWildHosts
		}
	}

	s.LiveHosts = append(s.LiveHosts, hosts...)
	s.Printf("│  dnsx: %d live hosts resolved (from %d input)\n", len(s.LiveHosts), inputN)

	// Persist a clean, deduplicated live host list for downstream phases.
	writeLines(dnsxOut, s.LiveHosts)
	return nil
}

// ═══════════════════════════════════════════════════════════════
// Phase 06: Subdomain Takeover Check (with HTTP confirmation)
//
// BUG #8 FIX: subzy over-reports. After subzy flags a host, we perform a
// second-stage HTTP fingerprint confirmation and (optionally) AI triage. Only
// confirmed takeovers stay Critical; the rest are demoted to Info.
// ═══════════════════════════════════════════════════════════════
type TakeoverPhase struct{}

func (p *TakeoverPhase) Name() string { return "Subdomain Takeover Check" }
func (p *TakeoverPhase) Description() string {
	return "subzy detection + HTTP fingerprint confirmation (false-positive reduction)"
}

// takeoverFingerprints maps provider response bodies that indicate a genuine
// dangling resource available for takeover.
var takeoverFingerprints = []string{
	"NoSuchBucket",
	"The specified bucket does not exist",
	"There isn't a GitHub Pages site here",
	"There is no app configured at that hostname",
	"no such app",
	"herokucdn.com/error-pages/no-such-app.html",
	"The request could not be satisfied",
	"Fastly error: unknown domain",
	"The feed has not been found",
	"project not found",
	"Repository not found",
	"Sorry, this shop is currently unavailable",
	"do not have access to this domain",
	"is not a registered InCloud YouTrack",
	"Domain uses DO name servers with no records in DO",
	"Not Found - Request ID",
	"The gods are wise, but do not know of the site which you seek",
}

// confirmTakeover fetches http(s)://domain and reports whether any known
// takeover fingerprint appears in the body.
func confirmTakeover(ctx context.Context, domain string) (bool, string) {
	for _, scheme := range []string{"https://", "http://"} {
		res := runner.RunTool(ctx, "curl",
			[]string{"-s", "-L", "-m", "12", "-A", "Mozilla/5.0", scheme + domain}, nil)
		if !res.OK() || res.Stdout == "" {
			continue
		}
		for _, fp := range takeoverFingerprints {
			if strings.Contains(res.Stdout, fp) {
				return true, fmt.Sprintf("fingerprint matched: %q", fp)
			}
		}
	}
	return false, "no takeover fingerprint in HTTP body"
}

func (p *TakeoverPhase) Execute(ctx context.Context, s *engine.State) error {
	subFile := filepath.Join(s.OutputFolder, "subdomains.txt")
	takeoverOut := filepath.Join(s.OutputFolder, "takeover_results.txt")

	ok, _ := fileHasContent(subFile)
	if !ok {
		s.Printf("│  subzy: SKIP (no subdomains to check)\n")
		return nil
	}

	res := runner.RunTool(ctx, "subzy",
		[]string{"run", "--targets", subFile, "--output", takeoverOut,
			"--concurrency", "20", "--hide_fails"}, nil)
	if !res.OK() && !res.TimedOut {
		s.Printf("│  subzy: SKIP (%v)\n", res.Err)
		return nil
	}

	// subzy writes JSON. Parse it; fall back to line scan if not JSON.
	candidates := parseSubzyVulnerable(takeoverOut)
	// FIX #2 (FP #3): only consider in-scope takeover candidates.
	if s.Scope != nil {
		var kept []string
		removed := 0
		for _, host := range candidates {
			if filter.IsInScope(host, s.Scope) {
				kept = append(kept, host)
			} else {
				removed++
			}
		}
		candidates = kept
		if removed > 0 {
			s.Printf("│  Takeover scope filter: %d out-of-scope candidate(s) removed\n", removed)
		}
	}
	if len(candidates) == 0 {
		s.Printf("│  subzy: 0 in-scope candidate takeovers\n")
		return nil
	}
	s.Printf("│  subzy: %d candidate(s) — running HTTP confirmation…\n", len(candidates))

	confirmed := 0
	for _, host := range candidates {
		httpConfirmed, evidence := confirmTakeover(ctx, host)
		f := map[string]interface{}{
			"title": "Subdomain Takeover", "url": host,
			"tool": "subzy+http-confirm", "evidence": evidence,
			"http_confirmed": httpConfirmed, "requires_ai": true,
			"specific_pattern": httpConfirmed,
		}
		if httpConfirmed {
			f["severity"] = "Critical"
			// FIX #4 (FP #4): subzy alone is NOT enough. Require HTTP fingerprint
			// AND AI confirmation. TriageAndScore downgrades an AI-offline or
			// low-confidence Critical to Unverified-Critical Info via the
			// confidence policy — it is never reported as a confirmed takeover
			// without a REAL AI verdict.
			if s.TriageAndScore(ctx, "Subdomain Takeover", host, evidence, f,
				func(m map[string]interface{}) bool { return filter.ApplyConfidencePolicy(m, s.Scope) }) {
				confirmed++
			}
		} else {
			// Not confirmed by HTTP → Info, but keep for the record.
			f["severity"] = "Info"
			f["ai_verdict"] = "unconfirmed_by_http"
			if filter.ApplyConfidencePolicy(f, s.Scope) {
				s.AddFinding(f)
			}
		}
		s.Governor.Throttle()
	}
	s.Printf("│  Takeover: %d candidate(s), %d confirmed (HTTP+AI, in-scope)\n", len(candidates), confirmed)
	return nil
}

// parseSubzyVulnerable extracts subdomains subzy flagged as VULNERABLE from its
// output file, supporting both JSON and plain-text formats.
func parseSubzyVulnerable(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	seen := make(map[string]bool)

	// Try JSON array form first.
	var arr []map[string]interface{}
	if json.Unmarshal(data, &arr) == nil && len(arr) > 0 {
		for _, item := range arr {
			state := strings.ToUpper(fmt.Sprintf("%v", item["vulnerable"]))
			statusStr := strings.ToUpper(fmt.Sprintf("%v", item["status"]))
			if state == "TRUE" || strings.Contains(statusStr, "VULNERABLE") {
				if sub, ok := item["subdomain"].(string); ok && !seen[sub] {
					seen[sub] = true
					out = append(out, sub)
				}
			}
		}
		if len(out) > 0 {
			return out
		}
	}

	// Fallback: line scan.
	for _, l := range strings.Split(string(data), "\n") {
		if strings.Contains(strings.ToUpper(l), "VULNERABLE") {
			for _, tok := range strings.Fields(l) {
				tok = strings.Trim(tok, "[]\"',")
				if strings.Contains(tok, ".") && !strings.HasPrefix(tok, "http") && !seen[tok] {
					seen[tok] = true
					out = append(out, tok)
				}
			}
		}
	}
	return out
}

// ═══════════════════════════════════════════════════════════════
// Phase 07: HTTP Probing & Tech Fingerprinting
//
// BUG #1 FIX: through Burp, route ONLY via httpx's -http-proxy flag (httpx
// tolerates the proxy's self-signed CA by default; it has NO -insecure flag).
// We deliberately do NOT also set HTTP(S)_PROXY env vars — double-proxying was
// a cause of dropped connections. Output is JSONL for reliable parsing.
// ═══════════════════════════════════════════════════════════════
type HTTPProbePhase struct{}

func (p *HTTPProbePhase) Name() string { return "HTTP Probing & Tech Fingerprinting" }
func (p *HTTPProbePhase) Description() string {
	return "httpx: status codes, titles, tech detect, CDN (Burp-aware routing)"
}
func (p *HTTPProbePhase) Execute(ctx context.Context, s *engine.State) error {
	// FIX #5 (Tier 2): httpx probes a small, targeted host set — route through
	// Burp so a researcher sees the live-host confirmation traffic.
	px := s.PhaseProxy(proxy.ProxyModeSelective)
	hostsFile := filepath.Join(s.OutputFolder, "live_dns.txt")
	if ok, _ := fileHasContent(hostsFile); !ok {
		hostsFile = filepath.Join(s.OutputFolder, "subdomains.txt")
	}
	ok, inputN := fileHasContent(hostsFile)
	if !ok {
		s.Printf("│  httpx: SKIP (no hosts to probe)\n")
		return nil
	}
	// BUG #6 FIX (V6): the live scan proved httpx returns 0 endpoints when its
	// probe is routed through Burp (the proxy breaks the initial TLS handshake to
	// hundreds of hosts) and/or when the host list has CRLF line endings. So we
	// now run the PRIMARY discovery pass WITHOUT the proxy, over a sanitized
	// (LF-only) host file. Burp is used only for the OPTIONAL second content pass.
	cleanHostsFile := sanitizeHostFileLF(s, hostsFile)
	s.Printf("│  httpx input: %d hosts (%s)\n", inputN, filepath.Base(hostsFile))

	httpxOut := filepath.Join(s.OutputFolder, "http_live.txt")

	// PRIMARY PASS — direct, NO proxy. -timeout 10 prevents hanging on slow
	// hosts; -json writes JSONL to -o.
	baseArgs := []string{"-l", cleanHostsFile, "-o", httpxOut, "-silent", "-nc",
		"-rl", "150", "-timeout", "10", "-sc", "-title", "-td", "-cdn", "-fr",
		"-threads", fmt.Sprintf("%d", s.Config.Threads),
		"-json", "-srd", filepath.Join(s.OutputFolder, "httpx_responses")}

	res := runner.RunTool(ctx, "httpx", baseArgs, nil)

	urlSet := make(map[string]bool)
	parseHTTPXOut := func() {
		for _, l := range readNonEmptyLines(httpxOut) {
			var rec map[string]interface{}
			if json.Unmarshal([]byte(l), &rec) == nil {
				if u, ok := rec["url"].(string); ok && u != "" && !urlSet[u] {
					urlSet[u] = true
					s.URLs = append(s.URLs, u)
				}
				continue
			}
			// Fallback: plain-text line "URL [200] [title] ..."
			parts := strings.Fields(l)
			if len(parts) > 0 && strings.HasPrefix(parts[0], "http") && !urlSet[parts[0]] {
				urlSet[parts[0]] = true
				s.URLs = append(s.URLs, parts[0])
			}
		}
	}
	if res.OK() || res.TimedOut {
		parseHTTPXOut()
		s.Printf("│  httpx (direct): %d live endpoints\n", len(urlSet))
	} else {
		s.Printf("│  httpx: FAILED (%v)\n", res.Err)
		if s.Config.Debug && res.Stderr != "" {
			s.Printf("│  [DEBUG] httpx stderr: %s\n", strings.TrimSpace(firstN(res.Stderr, 500)))
		}
	}

	// SECOND PASS — content/header analysis THROUGH Burp so a researcher sees
	// the confirmation traffic. This runs only when the proxy is active and the
	// primary pass already found live hosts (we never depend on it for URLs).
	if px.Active && len(urlSet) > 0 {
		proxyArgs := append(append([]string{}, baseArgs...), "-http-proxy", px.ProxyURL)
		// Feed the confirmed live URLs (not raw hosts) and discard the file
		// output — this pass exists purely to mirror traffic into Burp.
		liveList := filepath.Join(s.OutputFolder, "httpx_live_urls.txt")
		writeLines(liveList, mapKeys(urlSet))
		proxyArgs[1] = liveList // replace the -l argument value
		proxyArgs = append(proxyArgs, "-o", filepath.Join(s.OutputFolder, "http_live_burp.txt"))
		_ = runner.RunTool(ctx, "httpx", proxyArgs, nil)
		s.Printf("│  httpx (Burp pass): mirrored %d live URLs into proxy\n", len(urlSet))
	}

	// ── Direct raw-socket fallback (last resort) ───────────────────────────
	// If httpx itself found nothing (binary missing / all timeouts), probe the
	// hosts directly so the pipeline always has URLs when hosts are live.
	if len(urlSet) == 0 && inputN > 0 {
		s.Printf("│  ⚠ WARNING: httpx found 0 endpoints from %d hosts — running direct raw-probe fallback\n", inputN)
		fallback := directProbe(ctx, s, readNonEmptyLines(cleanHostsFile))
		for _, u := range fallback {
			if !urlSet[u] {
				urlSet[u] = true
				s.URLs = append(s.URLs, u)
			}
		}
		if len(fallback) > 0 {
			writeLines(httpxOut, appendUnique(readNonEmptyLines(httpxOut), fallback))
			s.Printf("│  direct fallback: recovered %d live endpoints\n", len(fallback))
		} else {
			s.Printf("│  direct fallback: still 0 — hosts may be firewalled or non-HTTP\n")
		}
	}

	// ── EXPANSION 3 — WAF/challenge classification (zero-false-positive) ────
	// Probe each unique live host once and flag it WAF_PROTECTED when the
	// response is a Cloudflare/WAF/Captcha challenge or a 403 block page. Such
	// hosts are automatically excluded from heavy XSS/SQLi fuzzing later so a
	// block page can never be reported as a vulnerability.
	detectWAFOnLiveHosts(ctx, s, urlSet)

	return nil
}

// detectWAFOnLiveHosts inspects each unique live host from Phase 07 and records
// WAF-protected hosts on state. Bounded + concurrent so it stays fast.
func detectWAFOnLiveHosts(ctx context.Context, s *engine.State, urls map[string]bool) {
	px := s.PhaseProxy(proxy.ProxyModeSelective)
	seenHost := make(map[string]bool)
	var targets []string
	for u := range urls {
		h := filter.HostOf(u)
		if h == "" || seenHost[h] {
			continue
		}
		seenHost[h] = true
		targets = append(targets, u)
	}
	if len(targets) == 0 {
		return
	}
	if len(targets) > 300 {
		targets = targets[:300]
	}

	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		sem     = make(chan struct{}, 25)
		flagged int
	)
	for _, u := range targets {
		wg.Add(1)
		go func(rawURL string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if DetectWAF(ctx, px, rawURL) {
				host := filter.HostOf(rawURL)
				s.MarkWAFProtected(host)
				mu.Lock()
				flagged++
				mu.Unlock()
			}
		}(u)
	}
	wg.Wait()
	if flagged > 0 {
		s.Printf("│  WAF_PROTECTED: %d host(s) flagged — excluded from heavy fuzzing (XSS/SQLi)\n", flagged)
	}
}

// directProbe is the IMPROVEMENT #4 / #6 cascading fallback: when httpx yields
// nothing, hit each host directly with curl on https then http and keep the
// ones that answer. Bounded to the first 200 hosts to stay fast. Honors an
// active proxy so it still works behind a reachable Burp.
func directProbe(ctx context.Context, s *engine.State, hosts []string) []string {
	// Part of the Phase 07 live-host verification path → Tier 2 (Burp-aware).
	px := s.PhaseProxy(proxy.ProxyModeSelective)
	var (
		mu    sync.Mutex
		wg    sync.WaitGroup
		alive []string
		sem   = make(chan struct{}, 30)
	)
	limit := len(hosts)
	if limit > 200 {
		limit = 200
	}
	for _, h := range hosts[:limit] {
		fields := strings.Fields(h)
		if len(fields) == 0 {
			continue
		}
		h = strings.TrimSpace(fields[0])
		if h == "" {
			continue
		}
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			for _, scheme := range []string{"https://", "http://"} {
				curlArgs := []string{"-s", "-o", "/dev/null", "-w", "%{http_code}",
					"-m", "10", "-L", "-A", "Mozilla/5.0", "-k"}
				if px.Active {
					curlArgs = append(curlArgs, "-x", px.ProxyURL)
				}
				curlArgs = append(curlArgs, scheme+host)
				res := runner.RunTool(ctx, "curl", curlArgs, nil)
				code := strings.TrimSpace(res.Stdout)
				if res.OK() && code != "" && code != "000" {
					mu.Lock()
					alive = append(alive, scheme+host)
					mu.Unlock()
					return // first working scheme wins
				}
			}
		}(h)
	}
	wg.Wait()
	return alive
}

// firstN returns the first n bytes of s (for bounded debug output).
func firstN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// appendUnique merges b into a, dropping duplicates, preserving order.
func appendUnique(a, b []string) []string {
	seen := make(map[string]bool, len(a))
	for _, x := range a {
		seen[x] = true
	}
	for _, x := range b {
		if !seen[x] {
			seen[x] = true
			a = append(a, x)
		}
	}
	return a
}

// ═══════════════════════════════════════════════════════════════
// Phase 08: TLS/SSL Analysis
// ═══════════════════════════════════════════════════════════════
type TLSAnalysisPhase struct{}

func (p *TLSAnalysisPhase) Name() string { return "TLS/SSL Analysis" }
func (p *TLSAnalysisPhase) Description() string {
	return "Certificate analysis via tlsx — expired, self-signed, mismatched"
}
func (p *TLSAnalysisPhase) Execute(ctx context.Context, s *engine.State) error {
	hostsFile := filepath.Join(s.OutputFolder, "live_dns.txt")
	if ok, _ := fileHasContent(hostsFile); !ok {
		s.Printf("│  tlsx: SKIP (no hosts)\n")
		return nil
	}
	tlsOut := filepath.Join(s.OutputFolder, "tls_results.txt")

	res := runner.RunTool(ctx, "tlsx",
		[]string{"-l", hostsFile, "-o", tlsOut, "-silent", "-expired", "-self-signed", "-mismatched"}, nil)
	if res.OK() || res.TimedOut {
		lines := readNonEmptyLines(tlsOut)
		issues := 0
		infos := 0
		for _, l := range lines {
			ll := strings.ToLower(l)
			// ── V12.0 OMEGA · BUG #2 ROOT-CAUSE FIX ───────────────────────────
			// A live Temu scan produced 9 "Medium" findings and ALL 9 were TLS
			// hostname mismatches — pure report pollution. A hostname mismatch on
			// a shared CDN/edge cert is expected, not a vulnerability, and it
			// carries no exploitable impact on its own. Per the mandate we DEMOTE
			// every tlsx mismatch to Informational so it can never enter a
			// severity summary or CONFIRMED_VULNS.txt. Expired / self-signed
			// certificates remain Low (still not a true bounty finding, but
			// materially more meaningful than a mismatch).
			isMismatch := strings.Contains(ll, "mismatch")
			isExpired := strings.Contains(ll, "expired")
			isSelfSigned := strings.Contains(ll, "self-signed") || strings.Contains(ll, "self signed")
			if !(isMismatch || isExpired || isSelfSigned) {
				continue
			}
			severity := "Informational"
			title := "TLS Certificate Hostname Mismatch"
			if isExpired || isSelfSigned {
				// A non-mismatch cert issue keeps a low, non-noise severity.
				severity = "Low"
				title = "TLS Certificate Issue"
			}
			if severity == "Informational" {
				infos++
			} else {
				issues++
			}
			s.AddFinding(map[string]interface{}{
				"title": title, "severity": severity, "url": l, "tool": "tlsx", "evidence": l,
			})
		}
		s.Printf("│  tlsx: %d hosts analyzed, %d TLS issues, %d informational mismatches\n", len(lines), issues, infos)
	} else {
		s.Printf("│  tlsx: SKIP (%v)\n", res.Err)
	}
	return nil
}

// ═══════════════════════════════════════════════════════════════
// Phase 09: Port Scanning
//
// BUG #4 FIX: force TCP Connect scan with "-scan-type c" so naabu works
// without root/CAP_NET_RAW (default SYN scan exits with status 2 unprivileged).
// The old code used "-connect-scan", which is NOT a valid naabu flag.
//
// BUG #7 FIX: In the live production run naabu returned 0 open ports across
// all 608 hosts because every host sat behind Cloudflare (AS13335) or AWS
// CloudFront (AS16509), both of which silently DROP the unsolicited connect
// probes naabu sends (anti-scan mitigation). Scanning them is 100% wasted
// time. We now resolve each host, classify it against known CDN ASNs/CIDRs,
// and for CDN hosts we SKIP naabu entirely and emit synthetic 80/443 entries
// (those ports are always served by the edge). Only genuinely non-CDN hosts
// are handed to naabu, which is tuned for reliability over raw speed.
// ═══════════════════════════════════════════════════════════════
type PortScanPhase struct{}

func (p *PortScanPhase) Name() string { return "Port Scanning" }
func (p *PortScanPhase) Description() string {
	return "CDN-aware port scan: skip Cloudflare/CloudFront edges, naabu the rest (-scan-type c)"
}
func (p *PortScanPhase) Execute(ctx context.Context, s *engine.State) error {
	hostsFile := filepath.Join(s.OutputFolder, "live_dns.txt")
	if ok, _ := fileHasContent(hostsFile); !ok {
		s.Printf("│  naabu: SKIP (no hosts)\n")
		return nil
	}
	portsOut := filepath.Join(s.OutputFolder, "ports.txt")

	hosts := readNonEmptyLines(hostsFile)

	// ── BUG #7: CDN classification ─────────────────────────────────────────
	// Split the host list into CDN-fronted hosts (naabu is futile) and direct
	// hosts (naabu is useful). Results are cached per-IP so we never re-query
	// the same edge twice.
	var cdnHosts, directHosts []string
	asnCache := map[string]bool{} // ip -> isCDN
	var portEntries []string      // synthetic + real "host:port" lines

	for _, h := range hosts {
		host := strings.TrimSpace(strings.ToLower(h))
		if host == "" {
			continue
		}
		if isCDNHost(ctx, host, asnCache) {
			cdnHosts = append(cdnHosts, host)
			// The CDN edge always terminates 80/443 for a live host.
			portEntries = append(portEntries, host+":80", host+":443")
		} else {
			directHosts = append(directHosts, host)
		}
	}

	s.Printf("│  CDN classification: %d CDN-fronted (Cloudflare/CloudFront — naabu skipped), %d direct\n",
		len(cdnHosts), len(directHosts))
	if len(cdnHosts) > 0 {
		s.Printf("│  CDN detected — assuming ports 80/443 open for %d edge host(s)\n", len(cdnHosts))
	}

	// ── naabu on the non-CDN hosts only ────────────────────────────────────
	if len(directHosts) > 0 {
		directFile := filepath.Join(s.OutputFolder, "portscan_direct_hosts.txt")
		writeLines(directFile, directHosts)
		naabuOut := filepath.Join(s.OutputFolder, "ports_naabu.txt")

		// Tuned for RELIABILITY against filtered/rate-limited edges rather than
		// raw speed: modest rate, explicit retries, generous per-probe timeout.
		// -scan-type c == CONNECT scan (unprivileged). -Pn skips host discovery
		// which also needs raw sockets.
		res := runner.RunTool(ctx, "naabu", []string{
			"-list", directFile, "-o", naabuOut, "-silent",
			"-top-ports", "1000", "-scan-type", "c", "-Pn",
			"-rate", "100", "-retries", "2", "-timeout", "3000", "-c", "25",
		}, nil)
		if res.OK() || res.TimedOut {
			naabuEntries := readNonEmptyLines(naabuOut)
			portEntries = append(portEntries, naabuEntries...)
			s.Printf("│  naabu: %d open port entries from %d direct host(s)\n", len(naabuEntries), len(directHosts))
		} else {
			s.Printf("│  naabu: SKIP (%v)\n", res.Err)
		}
	}

	// De-dup and persist the combined (synthetic + real) port map.
	seen := map[string]bool{}
	var deduped []string
	for _, e := range portEntries {
		e = strings.TrimSpace(e)
		if e != "" && !seen[e] {
			seen[e] = true
			deduped = append(deduped, e)
		}
	}
	writeLines(portsOut, deduped)
	s.Printf("│  ports.txt: %d total open-port entries (%d synthetic CDN + naabu)\n",
		len(deduped), len(cdnHosts)*2)
	return nil
}

// cloudflareV4CIDRs and cloudFrontV4CIDRs are the published edge ranges for the
// two CDNs that dropped every naabu probe in the production run. Matching by
// CIDR avoids a network round-trip for the overwhelmingly common case; the
// ip-api ASN lookup is only used as a fallback for hosts outside these ranges.
var cloudflareV4CIDRs = []string{
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
	"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
	"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
}

var cloudFrontV4CIDRs = []string{
	"13.32.0.0/15", "13.35.0.0/16", "13.224.0.0/14", "18.64.0.0/14",
	"52.46.0.0/18", "52.84.0.0/15", "52.124.128.0/17", "54.182.0.0/16",
	"54.192.0.0/16", "54.230.0.0/16", "54.239.128.0/18", "64.252.64.0/18",
	"65.8.0.0/16", "65.9.0.0/17", "70.132.0.0/18", "99.84.0.0/16",
	"143.204.0.0/16", "204.246.164.0/22", "205.251.192.0/19",
}

var cdnNets = func() []*net.IPNet {
	var nets []*net.IPNet
	for _, c := range append(append([]string{}, cloudflareV4CIDRs...), cloudFrontV4CIDRs...) {
		if _, n, err := net.ParseCIDR(c); err == nil {
			nets = append(nets, n)
		}
	}
	return nets
}()

// isCDNHost reports whether a hostname resolves onto a Cloudflare or AWS
// CloudFront edge. It first checks the resolved IPs against the published CDN
// CIDRs (fast, offline) and only falls back to an ip-api ASN/org lookup when a
// host resolves outside every known range. asnCache memoises the per-IP verdict
// so shared edge IPs are classified once. Any resolution failure is treated as
// NON-CDN so the host still gets a real naabu scan.
func isCDNHost(ctx context.Context, host string, asnCache map[string]bool) bool {
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return false
	}
	for _, ip := range ips {
		v4 := ip.To4()
		if v4 == nil {
			continue // IPv4 only for this lightweight classification
		}
		key := v4.String()
		if cached, ok := asnCache[key]; ok {
			if cached {
				return true
			}
			continue
		}
		isCDN := false
		for _, n := range cdnNets {
			if n.Contains(v4) {
				isCDN = true
				break
			}
		}
		if !isCDN {
			// Fallback: ASN/org lookup for edges outside the static CIDR list.
			body := curlGet(ctx, fmt.Sprintf("http://ip-api.com/json/%s?fields=as,org", key), "-m", "8")
			if body != "" {
				var m map[string]interface{}
				if json.Unmarshal([]byte(body), &m) == nil {
					blob := strings.ToLower(fmt.Sprintf("%v %v", m["as"], m["org"]))
					if strings.Contains(blob, "cloudflare") ||
						strings.Contains(blob, "cloudfront") ||
						strings.Contains(blob, "as13335") ||
						strings.Contains(blob, "as16509") {
						isCDN = true
					}
				}
			}
		}
		asnCache[key] = isCDN
		if isCDN {
			return true
		}
	}
	return false
}

// ═══════════════════════════════════════════════════════════════
// Phase 10: Wayback & Historical URL Mining
//
// BUG #10 FIX: give gau explicit providers + retries + subs so a root domain
// actually returns URLs instead of 0.
// ═══════════════════════════════════════════════════════════════
type WaybackPhase struct{}

func (p *WaybackPhase) Name() string { return "Wayback & Historical URL Mining" }
func (p *WaybackPhase) Description() string {
	return "gau (multi-provider) + waybackurls for historical URL discovery"
}
func (p *WaybackPhase) Execute(ctx context.Context, s *engine.State) error {
	allURLs := make(map[string]bool)

	// ── BUG #3 (CRITICAL REGRESSION) FIX ───────────────────────────────────
	// The previous version ran gau/waybackurls on APEX DOMAINS ONLY. The
	// Wayback Machine/CommonCrawl index specific paths on SUBDOMAINS (e.g.
	// api.whatnot.com), not bare apexes — so `gau whatnot.com` returned 0 while
	// the old per-subdomain runs found 63 URLs. The apex-only optimisation was
	// correct for PASSIVE SUBDOMAIN ENUM but WRONG for URL archive mining.
	//
	// We now query EVERY in-scope domain individually, PLUS each apex with
	// --subs so historical subdomains are covered too. The target set is the
	// union of scope entries and derived apexes, de-duplicated.
	targets := waybackTargets(s.Scope.Domains)

	// BUG #4 (audit) FIX: create ~/.gau.toml so gau stops warning + falling back
	// to a degraded default (which returned 0 URLs for the apex in the live run).
	gauCfg := ensureGauConfig(s)

	// ── BUG #9 FIX: adaptive gau timeout ───────────────────────────────────
	// For roblox.com the multi-provider gau run over 2795 subdomains never
	// finished inside the default per-tool timeout and returned 0 URLs. When
	// the resolved surface is large we (a) extend the per-tool timeout to
	// 15 min, and (b) pass gau its own --timeout so a single slow provider
	// can't wedge the whole run. Small targets keep the default budget.
	subCount := 0
	if n := len(readNonEmptyLines(filepath.Join(s.OutputFolder, "live_dns.txt"))); n > 0 {
		subCount = n
	} else {
		subCount = len(readNonEmptyLines(filepath.Join(s.OutputFolder, "subdomains.txt")))
	}
	gauTimeout := 5 * time.Minute
	if subCount > 500 {
		gauTimeout = 15 * time.Minute
		s.Printf("│  gau: large surface (%d hosts) → extended timeout 15m\n", subCount)
	}

	for _, domain := range targets {
		// gau: providers + threads + retries + subs (BUG #10). --subs makes
		// gau expand to subdomains, which is where the archives actually live.
		// --timeout caps each individual HTTP request so one stalled provider
		// cannot consume the whole per-tool budget (BUG #9).
		gauArgs := []string{
			"--threads", "5", "--retries", "3", "--subs", "--timeout", "15",
			"--providers", "wayback,commoncrawl,otx,urlscan",
		}
		if gauCfg != "" {
			gauArgs = append(gauArgs, "--config", gauCfg)
		}
		gauArgs = append(gauArgs, domain)
		res := runner.RunToolWithTimeout(ctx, "gau", gauArgs, nil, gauTimeout)
		gauCount := 0
		if res.OK() || res.TimedOut {
			for _, l := range strings.Split(res.Stdout, "\n") {
				l = strings.TrimSpace(l)
				if strings.HasPrefix(l, "http") && !allURLs[l] {
					allURLs[l] = true
					gauCount++
				}
			}
			s.Printf("│  gau [%s]: %d URLs\n", domain, gauCount)
			// BUG #9 fallback: the multi-provider run can time out or return 0
			// on huge domains because CommonCrawl/URLScan stall. Retry with the
			// single most reliable source (Wayback) so we still get coverage.
			if gauCount == 0 && (res.TimedOut || res.OK()) {
				wbArgs := []string{"--threads", "5", "--retries", "3", "--subs",
					"--timeout", "15", "--providers", "wayback"}
				if gauCfg != "" {
					wbArgs = append(wbArgs, "--config", gauCfg)
				}
				wbArgs = append(wbArgs, domain)
				retry := runner.RunToolWithTimeout(ctx, "gau", wbArgs, nil, gauTimeout)
				if retry.OK() || retry.TimedOut {
					rc := 0
					for _, l := range strings.Split(retry.Stdout, "\n") {
						l = strings.TrimSpace(l)
						if strings.HasPrefix(l, "http") && !allURLs[l] {
							allURLs[l] = true
							rc++
						}
					}
					if rc > 0 {
						s.Printf("│  gau [%s]: wayback-only retry recovered %d URLs\n", domain, rc)
					}
				}
			}
		} else {
			s.Printf("│  gau [%s]: SKIP (%v)\n", domain, res.Err)
		}

		// BUG #11 (audit): waybackurls is a BONUS source. It frequently returns 0
		// even when gau (same Wayback data) succeeds, so a 0 result is logged as
		// informational and never treated as a failure. Correct usage is either
		// `waybackurls <domain>` or `echo <domain> | waybackurls`.
		res = runner.RunTool(ctx, "waybackurls", []string{domain}, nil)
		if res.OK() || res.TimedOut {
			wbCount := 0
			for _, l := range strings.Split(res.Stdout, "\n") {
				l = strings.TrimSpace(l)
				if strings.HasPrefix(l, "http") && !allURLs[l] {
					allURLs[l] = true
					wbCount++
				}
			}
			if wbCount == 0 {
				s.Printf("│  waybackurls [%s]: 0 URLs (bonus source — gau/URLScan/CommonCrawl cover this)\n", domain)
			} else {
				s.Printf("│  waybackurls [%s]: +%d URLs\n", domain, wbCount)
			}
		} else {
			s.Printf("│  waybackurls [%s]: skipped bonus source (%v)\n", domain, res.Err)
		}
	}

	// ── IMPROVEMENT #5: direct multi-source URL enrichment (no external
	// binaries) — query URLScan and the CommonCrawl CDX index over HTTP so we
	// still gather URLs even if gau/waybackurls are missing or blocked. ─────
	for _, apex := range config.ExtractApexDomains(s.Scope.Domains) {
		before := len(allURLs)
		for _, u := range harvestURLScanURLs(ctx, apex) {
			if strings.HasPrefix(u, "http") && !allURLs[u] {
				allURLs[u] = true
			}
		}
		for _, u := range harvestCommonCrawlURLs(ctx, apex) {
			if strings.HasPrefix(u, "http") && !allURLs[u] {
				allURLs[u] = true
			}
		}
		// EXPANSION 2 — native Wayback CDX scraper (key-less, polite HTTP).
		for _, u := range ScrapeWaybackURLs(ctx, apex, 10000) {
			if strings.HasPrefix(u, "http") && !allURLs[u] {
				allURLs[u] = true
			}
		}
		if added := len(allURLs) - before; added > 0 {
			s.Printf("│  URLScan+CommonCrawl+WaybackCDX [%s]: +%d URLs\n", apex, added)
		}
	}

	// ── IMPROVEMENT #4/#6: guarantee non-empty s.URLs when hosts are live ──
	// If archive mining produced nothing but we DO have live hosts, seed the
	// URL set from the live HTTP endpoints so downstream phases (crawl, params,
	// nuclei…) still have something to work on.
	if len(allURLs) == 0 && len(s.URLs) > 0 {
		for _, u := range s.URLs {
			allURLs[u] = true
		}
		s.Printf("│  archive empty — seeded %d URLs from live HTTP endpoints\n", len(allURLs))
	}

	var lines []string
	for u := range allURLs {
		lines = append(lines, u)
	}
	archiveFile := filepath.Join(s.OutputFolder, "urls_archive.txt")
	writeLines(archiveFile, lines)
	s.URLs = appendUnique(s.URLs, lines)
	s.Printf("│  Total Archive URLs: %d\n", len(allURLs))
	return nil
}

// waybackTargets builds the URL-archive query set for BUG #3: the union of
// every in-scope domain (so per-subdomain archives like api.whatnot.com are
// covered) PLUS each derived apex (queried with --subs). Deduplicated,
// lower-cased, order-preserving. This is the regression guard against the
// apex-only mistake that returned 0 URLs.
func waybackTargets(scope []string) []string {
	seen := make(map[string]bool)
	var out []string
	add := func(d string) {
		d = strings.ToLower(strings.TrimSpace(d))
		if d != "" && !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	for _, d := range scope {
		add(d)
	}
	for _, a := range config.ExtractApexDomains(scope) {
		add(a)
	}
	return out
}

// harvestURLScanURLs pulls full result page URLs from urlscan.io (IMPROVEMENT
// #5). Distinct from harvestURLScan which only extracts hostnames.
func harvestURLScanURLs(ctx context.Context, domain string) []string {
	url := fmt.Sprintf("https://urlscan.io/api/v1/search/?q=domain:%s&size=100", domain)
	body := curlGet(ctx, url)
	var out []string
	var m map[string]interface{}
	if json.Unmarshal([]byte(body), &m) == nil {
		if results, ok := m["results"].([]interface{}); ok {
			for _, r := range results {
				if rec, ok := r.(map[string]interface{}); ok {
					if page, ok := rec["page"].(map[string]interface{}); ok {
						if u, ok := page["url"].(string); ok {
							out = append(out, u)
						}
					}
				}
			}
		}
	}
	return out
}

// harvestCommonCrawlURLs queries the CommonCrawl CDX index directly for every
// captured URL under a domain (IMPROVEMENT #5). Uses the latest stable index.
func harvestCommonCrawlURLs(ctx context.Context, domain string) []string {
	url := fmt.Sprintf("https://index.commoncrawl.org/CC-MAIN-2024-33-index?url=*.%s&output=json&limit=500", domain)
	body := curlGet(ctx, url, "-m", "40")
	var out []string
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var rec map[string]interface{}
		if json.Unmarshal([]byte(line), &rec) == nil {
			if u, ok := rec["url"].(string); ok {
				out = append(out, u)
			}
		}
	}
	return out
}

// ═══════════════════════════════════════════════════════════════
// Phase 11: Web Crawling & Spidering
//
// BUG #5 FIX: gospider needs a non-empty input file (exits 1 otherwise) and
// -k to ignore TLS errors behind Burp. katana routes via -proxy (it has no
// -insecure/-ssl-no-verify flag) and uses -nc for clean output.
// ═══════════════════════════════════════════════════════════════
type CrawlPhase struct{}

func (p *CrawlPhase) Name() string { return "Web Crawling & Spidering" }
func (p *CrawlPhase) Description() string {
	return "katana + gospider deep crawl + cariddi endpoint/secret extraction (empty-input guarded)"
}
func (p *CrawlPhase) Execute(ctx context.Context, s *engine.State) error {
	// FIX #5 (Tier 1): crawling generates hundreds of noisy URLs — NEVER route
	// katana/gospider through Burp (px is inert when selective routing is on).
	px := s.PhaseProxy(proxy.ProxyModeDirect)
	urlsFile := filepath.Join(s.OutputFolder, "http_live.txt")
	ok, n := fileHasContent(urlsFile)
	if !ok {
		s.Printf("│  Crawl: SKIP (http_live.txt empty — httpx found 0 endpoints)\n")
		return nil
	}
	s.Printf("│  Crawl input: %d live endpoints\n", n)

	// http_live.txt may contain JSONL when proxy is active; extract plain URLs
	// into a dedicated seed file for the crawlers.
	seeds := extractURLsFromHTTPX(urlsFile)
	seedFile := filepath.Join(s.OutputFolder, "crawl_seeds.txt")
	writeLines(seedFile, seeds)
	if len(seeds) == 0 {
		s.Printf("│  Crawl: SKIP (no usable seed URLs)\n")
		return nil
	}

	crawlURLs := make(map[string]bool)

	// ── katana ────────────────────────────────────────────────────────
	katOut := filepath.Join(s.OutputFolder, "katana_raw.txt")
	katArgs := []string{"-list", seedFile, "-o", katOut, "-silent", "-nc",
		"-d", "3", "-rl", "150", "-jc"}
	// FLAW #5: explicit -proxy flag PLUS HTTP(S)_PROXY env so any internal
	// client that ignores -proxy still routes through Burp. GetEnv() is nil
	// without --burp, so this is a no-op when no proxy is configured.
	var katEnv map[string]string
	if px.Active {
		katArgs = append(katArgs, "-proxy", px.ProxyURL)
		katEnv = px.GetEnv()
	}
	res := runner.RunTool(ctx, "katana", katArgs, katEnv)
	if res.OK() || res.TimedOut {
		for _, l := range readNonEmptyLines(katOut) {
			if strings.HasPrefix(l, "http") {
				crawlURLs[l] = true
			}
		}
		s.Printf("│  katana: %d URLs crawled\n", len(crawlURLs))
	} else {
		s.Printf("│  katana: SKIP (%v)\n", res.Err)
	}

	// ── gospider (empty-input guarded + -k for TLS) ────────────────────
	if ok, _ := fileHasContent(seedFile); ok {
		goOut := filepath.Join(s.OutputFolder, "gospider_raw.txt")
		goArgs := []string{"-S", seedFile, "-o", goOut, "-d", "2", "-c", "10",
			"-k", "--sitemap", "--robots", "-q"}
		// FLAW #5: gospider takes an explicit -p proxy flag AND we export the
		// HTTP(S)_PROXY env vars so any internal client that ignores -p still
		// routes through Burp. GetEnv() returns nil when no proxy is set, so
		// this is a no-op without --burp (no double-proxy risk).
		var goEnv map[string]string
		if px.Active {
			goArgs = append(goArgs, "-p", px.ProxyURL)
			goEnv = px.GetEnv()
		}
		res = runner.RunTool(ctx, "gospider", goArgs, goEnv)
		if res.OK() || res.TimedOut {
			goCount := 0
			addURL := func(tok string) {
				tok = strings.Trim(tok, `"'[]() `)
				if strings.HasPrefix(tok, "http") && !crawlURLs[tok] {
					crawlURLs[tok] = true
					goCount++
				}
			}
			// BUG #5 (audit) FIX: gospider with -q writes results to per-site
			// files under goOut (a directory) and echoes far less to stdout, so
			// parsing stdout alone reported "+0 URLs". Parse BOTH: every http(s)
			// token in stdout AND every http(s) token in each file under goOut.
			for _, l := range strings.Split(res.Stdout, "\n") {
				for _, part := range strings.Fields(l) {
					addURL(part)
				}
			}
			_ = filepath.Walk(goOut, func(path string, info os.FileInfo, err error) error {
				if err != nil || info == nil || info.IsDir() {
					return nil
				}
				for _, l := range readNonEmptyLines(path) {
					for _, part := range strings.Fields(l) {
						addURL(part)
					}
				}
				return nil
			})
			s.Printf("│  gospider: +%d URLs\n", goCount)
		} else {
			s.Printf("│  gospider: SKIP (%v)\n", res.Err)
		}
	} else {
		s.Printf("│  gospider: SKIP (empty seed file)\n")
	}

	// ── V12.1 Section 3: cariddi endpoint + secret extraction ───────────
	// cariddi crawls the live seeds and pulls endpoints, parameters, and (most
	// valuably) secrets/API-keys directly out of HTTP responses that katana and
	// gospider ignore. New endpoints join the crawl corpus; secrets are recorded
	// as findings for the report.
	if _, err := runner.ResolveToolPath("cariddi"); err == nil {
		if ok, _ := fileHasContent(seedFile); ok {
			res := runner.RunTool(ctx, "cariddi", []string{"-s", "-e", "-json"}, nil)
			// cariddi reads seeds from stdin; when that path is unavailable the
			// tool still runs against provided targets. Guard on any output.
			if (res.OK() || res.TimedOut) && strings.TrimSpace(res.Stdout) != "" {
				urls, secrets := parseCariddiJSON(res.Stdout)
				newURLs := 0
				for _, u := range urls {
					if strings.HasPrefix(u, "http") && !crawlURLs[u] {
						crawlURLs[u] = true
						newURLs++
					}
				}
				for _, sec := range secrets {
					f := map[string]interface{}{
						"title": "Exposed Secret (cariddi)", "severity": "High",
						"tool": "cariddi", "evidence": sec,
						"http_confirmed": true, "specific_pattern": true,
					}
					s.AddFinding(f)
				}
				if newURLs > 0 || len(secrets) > 0 {
					s.Printf("│  cariddi: +%d endpoints, %d secret(s)\n", newURLs, len(secrets))
				}
			}
		}
	}

	var lines []string
	for u := range crawlURLs {
		lines = append(lines, u)
	}
	crawlFile := filepath.Join(s.OutputFolder, "urls_crawled.txt")
	writeLines(crawlFile, lines)

	// Genius #5 (scope-drift detection): separate in-scope from out-of-scope
	// crawled URLs. Out-of-scope hits are recorded to out_of_scope_urls.txt for
	// audit but NEVER enter s.URLs, so every downstream vuln phase operates on a
	// scope-clean corpus (FIX #2). CDNs like squarespace/cloudfront and
	// unrelated hosts (grillservice) drop out here.
	if s.Scope != nil {
		inScope, _ := filter.FilterInScopeURLs(lines, s.Scope)
		drift := filter.OutOfScopeURLs(lines, s.Scope)
		if len(drift) > 0 {
			driftFile := filepath.Join(s.OutputFolder, "out_of_scope_urls.txt")
			writeLines(driftFile, drift)
			s.Printf("│  Scope-drift: %d out-of-scope URLs recorded to out_of_scope_urls.txt\n", len(drift))
		}
		lines = inScope
	}
	s.URLs = append(s.URLs, lines...)
	s.Printf("│  Total in-scope crawled URLs: %d\n", len(lines))
	return nil
}

// extractURLsFromHTTPX returns plain URLs from an httpx output file that may be
// either JSONL (proxy mode) or plain "URL [code] ..." text.
func extractURLsFromHTTPX(path string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, l := range readNonEmptyLines(path) {
		var rec map[string]interface{}
		if json.Unmarshal([]byte(l), &rec) == nil {
			if u, ok := rec["url"].(string); ok && u != "" && !seen[u] {
				seen[u] = true
				out = append(out, u)
			}
			continue
		}
		parts := strings.Fields(l)
		if len(parts) > 0 && strings.HasPrefix(parts[0], "http") && !seen[parts[0]] {
			seen[parts[0]] = true
			out = append(out, parts[0])
		}
	}
	return out
}

// ═══════════════════════════════════════════════════════════════
// Phase 12: JS Analysis & Secret Extraction
// ═══════════════════════════════════════════════════════════════
type JSAnalysisPhase struct{}

func (p *JSAnalysisPhase) Name() string { return "JS Analysis & Secret Extraction" }
func (p *JSAnalysisPhase) Description() string {
	return "Extract JS files, scan for API keys/tokens/secrets"
}
func (p *JSAnalysisPhase) Execute(ctx context.Context, s *engine.State) error {
	// FIX #5 (Tier 2): JS fetching for confirmed in-scope domains is high-value.
	px := s.PhaseProxy(proxy.ProxyModeSelective)
	jsURLs := make(map[string]bool)
	for _, u := range s.URLs {
		if strings.HasSuffix(u, ".js") || strings.Contains(u, ".js?") {
			jsURLs[u] = true
		}
	}

	// getJS to discover additional JS references from live endpoints.
	seedFile := filepath.Join(s.OutputFolder, "crawl_seeds.txt")
	if ok, _ := fileHasContent(seedFile); ok {
		res := runner.RunTool(ctx, "getJS", []string{"--input", seedFile, "--complete"}, nil)
		if res.OK() || res.TimedOut {
			for _, l := range strings.Split(res.Stdout, "\n") {
				l = strings.TrimSpace(l)
				if strings.HasPrefix(l, "http") && (strings.HasSuffix(l, ".js") || strings.Contains(l, ".js?")) {
					jsURLs[l] = true
				}
			}
			s.Printf("│  getJS: JS links discovered\n")
		} else {
			s.Printf("│  getJS: SKIP (%v)\n", res.Err)
		}
	}

	// FIX #2 / FP #2: ONLY scan JS files served from in-scope domains. This
	// eliminates the squarespace.com / cloudfront.net "secret" false positives
	// — finding "api_key" inside a third-party CDN library is meaningless.
	if s.Config.EnforceScopeOnJS {
		beforeJS := len(jsURLs)
		for u := range jsURLs {
			if !filter.IsInScope(u, s.Scope) {
				delete(jsURLs, u)
			}
		}
		if removed := beforeJS - len(jsURLs); removed > 0 {
			s.Printf("│  Scope filter: %d out-of-scope JS files removed (CDN/third-party)\n", removed)
		}
	}

	jsFile := filepath.Join(s.OutputFolder, "js_files.txt")
	var jsLines []string
	for u := range jsURLs {
		jsLines = append(jsLines, u)
	}
	writeLines(jsFile, jsLines)
	s.Printf("│  JS files found (in-scope): %d\n", len(jsURLs))

	secretPatterns := map[string]string{
		"aws_access_key":  `AKIA[0-9A-Z]{16}`,
		"google_api":      "AIza",
		"slack_token":     "xox",
		"firebase":        "firebaseio.com",
		"authorization":   "authorization",
		"bearer_token":    "bearer ",
		"private_key":     "-----BEGIN",
		"api_key_generic": "api_key",
		"secret_generic":  "client_secret",
	}
	secretsFound := 0
	count := 0
	// BUG #8 (audit) FIX: accumulate the ACTUAL matched value + surrounding
	// context for every confirmed secret and persist it to
	// js_secrets_confirmed.txt so a researcher can act on the finding. The old
	// code only stored "pattern: <label>" with no value, which is useless.
	secretsFile := filepath.Join(s.OutputFolder, "js_secrets_confirmed.txt")
	var secretsReport strings.Builder
	for u := range jsURLs {
		if count >= 60 { // cap network work
			break
		}
		count++
		args := []string{"-s", "-m", "12", "-A", "Mozilla/5.0", u}
		if px.Active {
			args = append([]string{"-x", px.ProxyURL, "-k"}, args...)
		}
		res := runner.RunTool(ctx, "curl", args, nil)
		if res.OK() && res.Stdout != "" {
			body := res.Stdout
			lowerBody := strings.ToLower(body)
			for label, pattern := range secretPatterns {
				match := false
				idx := -1
				if strings.HasPrefix(pattern, "AKIA") || strings.HasPrefix(pattern, "-----") {
					idx = strings.Index(body, pattern) // case-sensitive
					match = idx >= 0
				} else {
					idx = strings.Index(lowerBody, strings.ToLower(pattern))
					match = idx >= 0
				}
				if match {
					// Extract the actual matched value and a context window so
					// the finding carries evidence a human can verify.
					matchLine, context, value := extractSecretEvidence(body, idx, pattern)

					// A specific high-entropy pattern (AWS key / private key) is
					// far more trustworthy than a generic "api_key" substring.
					specific := strings.HasPrefix(pattern, "AKIA") ||
						strings.HasPrefix(pattern, "-----") || label == "google_api" ||
						label == "slack_token"
					evidence := fmt.Sprintf("pattern: %s | match: %s", label, matchLine)
					f := map[string]interface{}{
						"title": "Potential Secret in JS", "severity": "High",
						"url": u, "tool": "js_scanner",
						"evidence":         evidence,
						"secret_pattern":   label,
						"secret_match":     matchLine,
						"secret_value":     value,
						"secret_context":   context,
						"requires_ai":      true,
						"specific_pattern": specific,
					}
					// AI triage confirms/denies; then confidence policy decides
					// whether to keep, downgrade, or discard (FIX #3/#7).
					kept := s.TriageAndScore(ctx, "JS Secret", filter.HostOf(u),
						"pattern "+label+" in "+u, f,
						func(ff map[string]interface{}) bool {
							return filter.ApplyConfidencePolicy(ff, s.Scope)
						})
					if kept {
						secretsFound++
						secretsReport.WriteString(fmt.Sprintf(
							"[SOURCE] %s\n[PATTERN] %s\n[MATCH] %s\n[CONTEXT] %s\n%s\n",
							u, label, matchLine, context,
							strings.Repeat("─", 60)))
					}
					break
				}
			}
		}
		s.Governor.Throttle()
	}
	if secretsReport.Len() > 0 {
		_ = os.WriteFile(secretsFile, []byte(secretsReport.String()), 0644)
		s.Printf("│  JS secrets → %s\n", secretsFile)
	}
	s.Printf("│  JS secrets confirmed (post-triage): %d\n", secretsFound)
	return nil
}

// extractSecretEvidence pulls the human-readable evidence around a matched
// secret pattern at byte offset idx in body (BUG #8 audit). It returns:
//   - matchLine: the trimmed source line containing the match (truncated)
//   - context:   ±40 chars around the match on a single line
//   - value:     best-effort extracted assigned value (e.g. the "pk_live_…"
//     from `const K = "pk_live_…"`), or the match line if none is obvious.
func extractSecretEvidence(body string, idx int, pattern string) (matchLine, context, value string) {
	if idx < 0 || idx >= len(body) {
		return "pattern: " + pattern, "", ""
	}
	// Line boundaries around idx.
	lineStart := strings.LastIndexByte(body[:idx], '\n') + 1
	lineEnd := strings.IndexByte(body[idx:], '\n')
	if lineEnd < 0 {
		lineEnd = len(body)
	} else {
		lineEnd += idx
	}
	matchLine = strings.TrimSpace(body[lineStart:lineEnd])
	if len(matchLine) > 200 {
		matchLine = matchLine[:200] + "…"
	}

	// Context window ±40 chars, kept on one line.
	cs := idx - 40
	if cs < 0 {
		cs = 0
	}
	ce := idx + 40
	if ce > len(body) {
		ce = len(body)
	}
	context = strings.ReplaceAll(strings.TrimSpace(body[cs:ce]), "\n", " ")

	// Best-effort value extraction: find the quoted string on the match line
	// that CONTAINS the match offset (the pattern may sit inside the value,
	// e.g. "pk_live_…"), else fall back to the longest quoted token on the line.
	value = matchLine
	line := body[lineStart:lineEnd]
	rel := idx - lineStart // match position within the line
	best := ""
	for _, quote := range []byte{'"', '\''} {
		search := 0
		for {
			open := strings.IndexByte(line[search:], quote)
			if open < 0 {
				break
			}
			open += search
			closeIdx := strings.IndexByte(line[open+1:], quote)
			if closeIdx < 0 {
				break
			}
			closeIdx += open + 1
			candidate := line[open+1 : closeIdx]
			// Prefer the quoted string that spans the match offset.
			if rel >= open && rel <= closeIdx && candidate != "" && len(candidate) <= 200 {
				return matchLine, context, candidate
			}
			if len(candidate) > len(best) && len(candidate) <= 200 {
				best = candidate
			}
			search = closeIdx + 1
		}
	}
	if best != "" {
		value = best
	}
	return matchLine, context, value
}

// ═══════════════════════════════════════════════════════════════
// Phase 13: Parameter Discovery
//
// BUG #6 FIX: paramspider uses --domain / --output (a file path). The output
// is then read and merged into params. arjun uses -oJ per URL.
// ═══════════════════════════════════════════════════════════════
type ParamDiscoveryPhase struct{}

func (p *ParamDiscoveryPhase) Name() string { return "Parameter Discovery" }
func (p *ParamDiscoveryPhase) Description() string {
	return "paramspider + arjun + URL param extraction"
}
func (p *ParamDiscoveryPhase) Execute(ctx context.Context, s *engine.State) error {
	if len(s.Scope.Domains) == 0 {
		return nil
	}
	paramURLs := make(map[string]bool)

	// Params already found in crawl/archive URLs.
	for _, u := range s.URLs {
		if strings.Contains(u, "?") && strings.Contains(u, "=") {
			paramURLs[u] = true
		}
	}
	s.Printf("│  Params from crawl/archive: %d\n", len(paramURLs))

	// paramspider — run per apex domain.
	for _, domain := range config.ExtractApexDomains(s.Scope.Domains) {
		paramOut := filepath.Join(s.OutputFolder, fmt.Sprintf("paramspider_%s.txt", sanitizeName(domain)))
		res := runner.RunTool(ctx, "paramspider",
			[]string{"--domain", domain, "--output", paramOut}, nil)
		if res.OK() || res.TimedOut {
			// paramspider (devanshbatham) historically wrote to results/<domain>.txt.
			readInto := func(path string) int {
				c := 0
				for _, l := range readNonEmptyLines(path) {
					if strings.HasPrefix(l, "http") && !paramURLs[l] {
						paramURLs[l] = true
						c++
					}
				}
				return c
			}
			c := readInto(paramOut)
			if c == 0 {
				// BUG #6 (audit): paramspider (devanshbatham) ignores --output on
				// several builds and always writes to its DEFAULT location
				// ~/results/<domain>.txt (or ./results/<domain>.txt). Read every
				// known default so the 482-vs-0 discrepancy disappears.
				home := os.Getenv("HOME")
				alts := []string{
					filepath.Join("results", domain+".txt"),
					filepath.Join(s.OutputFolder, domain+".txt"),
				}
				if home != "" {
					alts = append(alts, filepath.Join(home, "results", domain+".txt"))
				}
				for _, alt := range alts {
					c += readInto(alt)
				}
			}
			s.Printf("│  paramspider [%s]: %d param URLs\n", domain, c)
		} else {
			s.Printf("│  paramspider [%s]: SKIP (%v)\n", domain, res.Err)
		}
	}

	// arjun — scan top parameterized live URLs. BUG #7 (audit): cap at 10 (the
	// most-parameterized ones) and add --stable so arjun re-checks candidate
	// params for reliable detection instead of returning 0.
	var arjunTargets []string
	for _, u := range s.URLs {
		if strings.HasPrefix(u, "http") {
			arjunTargets = append(arjunTargets, u)
		}
		if len(arjunTargets) >= 10 {
			break
		}
	}
	arjunFound := 0
	for _, u := range arjunTargets {
		arjunOut := filepath.Join(s.OutputFolder, "arjun_temp.json")
		res := runner.RunTool(ctx, "arjun", []string{"-u", u, "-oJ", arjunOut, "-q", "-t", "5", "--stable"}, nil)
		if res.OK() {
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
	s.Printf("│  arjun: %d params found across %d URLs\n", arjunFound, len(arjunTargets))

	// FIX #1/#2: this params.txt feeds SQLi, XSS and Open-Redirect, so it is the
	// single most important chokepoint for zero-FP. Strip Cloudflare challenge
	// and analytics params (a bare __cf_chl_rt_tk URL is DISCARDED), drop
	// CF-challenge URLs entirely, then scope-filter — so no injection tool ever
	// sees a challenge token (FP #1) or an out-of-scope host (FP #2/#3).
	var lines []string
	discarded := 0
	for u := range paramURLs {
		if filter.IsCloudflareChallenge(u) {
			discarded++
			continue
		}
		cleaned, testable := filter.StripNoisyParams(u)
		if !testable {
			discarded++
			continue
		}
		lines = append(lines, cleaned)
	}
	if s.Scope != nil {
		var removed int
		lines, removed = filter.FilterInScopeURLs(lines, s.Scope)
		discarded += removed
	}
	lines = filter.DeduplicateByParamSignature(lines)
	paramFile := filepath.Join(s.OutputFolder, "params.txt")
	writeLines(paramFile, lines)
	s.Printf("│  Param URLs: %d testable (%d noisy/out-of-scope discarded)\n", len(lines), discarded)
	return nil
}

// ═══════════════════════════════════════════════════════════════
// Phase 14: CORS Misconfiguration
// ═══════════════════════════════════════════════════════════════
type CORSPhase struct{}

func (p *CORSPhase) Name() string { return "CORS Misconfiguration Check" }
func (p *CORSPhase) Description() string {
	return "V12.1 FIX #3: CDP-browser CORS for WAF hosts, curl for non-WAF (reflection, null origin, wildcard+creds)"
}
func (p *CORSPhase) Execute(ctx context.Context, s *engine.State) error {
	// FIX #5 (Tier 2): targeted CORS reflection tests are high-value.
	px := s.PhaseProxy(proxy.ProxyModeSelective)
	corsVuln := 0

	targets := dedupeURLs(s.URLs)

	// FIX #8 / FP #3: ONLY test endpoints whose hostname is explicitly in
	// scope. This kills the www.grillservice-famholler.at (German grill site)
	// CORS false positive that crept in via a crawled off-scope link.
	targets, removed := filter.FilterInScopeURLs(targets, s.Scope)
	if removed > 0 {
		s.Printf("│  CORS scope filter: %d out-of-scope hosts removed\n", removed)
	}

	if len(targets) > 50 {
		targets = targets[:50]
	}

	// V12.1 FIX #3: Split targets by WAF protection. WAF-protected hosts
	// (flagged during Phase 07) get tested with a REAL Chrome browser via CDP —
	// Cloudflare/Akamai often serve a JS challenge or block the ACAO header for
	// non-browser (curl) clients, causing Phase 17 to see 0 while the CDP-based
	// Phase 56 sees the real misconfig. Non-WAF hosts stay on the fast curl path.
	wafTargets, plainTargets := partitionCORSByWAF(s, targets)

	cdpConfirmed := corsCDPBrowser(ctx, s, wafTargets)
	corsVuln += cdpConfirmed
	corsVuln += corsCurl(ctx, s, px, plainTargets)

	s.Printf("│  CORS: tested %d in-scope (%d WAF→CDP, %d non-WAF→curl), confirmed %d (CDP proofs: %d)\n",
		len(wafTargets)+len(plainTargets), len(wafTargets), len(plainTargets), corsVuln, cdpConfirmed)
	return nil
}

// partitionCORSByWAF splits in-scope http(s) targets into WAF-protected hosts
// (routed to the CDP browser path) and non-WAF hosts (routed to curl), per
// V12.1 FIX #3. Non-http entries are dropped. Kept pure so it is unit-testable
// without a live browser or network.
func partitionCORSByWAF(s *engine.State, targets []string) (waf, plain []string) {
	for _, u := range targets {
		if !strings.HasPrefix(u, "http") {
			continue
		}
		if s.IsWAFProtected(u) {
			waf = append(waf, u)
		} else {
			plain = append(plain, u)
		}
	}
	return waf, plain
}

// corsCurl runs the classic curl-based reflected-origin / wildcard+creds CORS
// probe against non-WAF hosts. Returns the number of confirmed misconfigs.
func corsCurl(ctx context.Context, s *engine.State, px *proxy.ProxyManager, targets []string) int {
	testOrigins := []string{"https://evil.com", "null", "https://attacker.com"}
	confirmed := 0
	for _, u := range targets {
		for _, origin := range testOrigins {
			args := []string{"-s", "-m", "10", "-H", "Origin: " + origin, "-I", u}
			if px.Active {
				args = append([]string{"-x", px.ProxyURL, "-k"}, args...)
			}
			res := runner.RunTool(ctx, "curl", args, nil)
			if res.OK() {
				lower := strings.ToLower(res.Stdout)
				reflected := strings.Contains(lower, "access-control-allow-origin: "+strings.ToLower(origin))
				wildcardCreds := strings.Contains(lower, "access-control-allow-origin: *") &&
					strings.Contains(lower, "access-control-allow-credentials: true")
				if reflected || wildcardCreds {
					f := map[string]interface{}{
						"title": "CORS Misconfiguration", "severity": "High",
						"url": u, "tool": "cors_check",
						"evidence":         "Reflected origin: " + origin,
						"http_confirmed":   true, // we saw the real ACAO header
						"specific_pattern": reflected,
					}
					if filter.ApplyConfidencePolicy(f, s.Scope) {
						s.AddFinding(f)
						confirmed++
					}
					break
				}
			}
		}
		s.Governor.Throttle()
	}
	return confirmed
}

// corsCDPBrowser tests WAF-protected hosts for exploitable CORS using a real
// Chrome (Go-Rod CDP) credentialed cross-origin fetch — the same primitive
// Phase 56 uses. A returned body across origins WITH credentials is hard proof
// that curl cannot obtain against a WAF. If the browser is unavailable it falls
// back to curl so WAF hosts are never silently skipped. Returns confirmed count.
func corsCDPBrowser(ctx context.Context, s *engine.State, wafTargets []string) int {
	if len(wafTargets) == 0 {
		return 0
	}
	// No browser online → degrade to curl so WAF hosts are still tested.
	if s.Browser == nil || !s.Browser.Available() {
		if len(wafTargets) > 0 {
			s.Printf("│  CORS: browser offline, %d WAF host(s) fall back to curl\n", len(wafTargets))
		}
		px := s.PhaseProxy(proxy.ProxyModeSelective)
		return corsCurl(ctx, s, px, wafTargets)
	}
	scanner := exploit.NewDOMScanner(s.Browser)
	origins := apexLiveOrigins(s)
	confirmed := 0
	for _, api := range wafTargets {
		// Trusted-origin cross-origin credentialed fetch: try each live apex
		// origin against this WAF-protected API. A body returned cross-origin
		// with credentials is an exploitable CORS misconfiguration.
		tested := false
		for _, origin := range budget(origins, 3) {
			if sameOrigin(origin, api) {
				continue
			}
			release, ok := s.AcquireBrowserSlot(ctx)
			if !ok {
				return confirmed
			}
			proof, skipped := scanner.VerifyCORSInBrowser(ctx, origin, api)
			release()
			if skipped {
				// CDP dropped mid-run → curl fallback for the remainder.
				px := s.PhaseProxy(proxy.ProxyModeSelective)
				return confirmed + corsCurl(ctx, s, px, wafTargets)
			}
			tested = true
			if !proof.Allowed {
				continue
			}
			f := map[string]interface{}{
				"title": "CORS Misconfiguration", "severity": "High",
				"url": api, "tool": "cors_check_cdp",
				"evidence": fmt.Sprintf("in-browser credentialed cross-origin fetch from %s returned %d with body %q → WAF-protected CORS allows credentialed cross-origin read",
					origin, proof.Status, browser.Redact(proof.BodySample)),
				"http_confirmed":   true,
				"specific_pattern": true,
				"proof_engine":     "go-rod CDP withCredentials",
			}
			if filter.ApplyConfidencePolicy(f, s.Scope) {
				s.AddFinding(f)
				confirmed++
			}
			break
		}
		_ = tested
		s.Governor.Throttle()
	}
	return confirmed
}

// dedupeURLs returns the unique set of URLs preserving order.
func dedupeURLs(in []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, u := range in {
		if u != "" && !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}
	return out
}
