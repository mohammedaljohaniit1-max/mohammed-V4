package phases

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/mohammed-v3/core/pkg/config"
	"github.com/mohammed-v3/core/pkg/engine"
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
		afCount := 0
		res = runner.RunTool(ctx, "assetfinder", []string{"--subs-only", domain}, nil)
		if res.OK() {
			for _, l := range strings.Split(res.Stdout, "\n") {
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

	// BUG #4 FIX: amass passive silently returns nothing without a config file
	// that enables data sources. Generate a minimal one at the default path if
	// the user has not provided their own, BEFORE amass runs.
	amassCfg := ensureAmassConfig(s)

	// ── Tools that require APEX/root domains ONLY (BUG #2) ────────────
	for _, domain := range apexDomains {
		s.Printf("│  [Apex passive enum: %s]\n", domain)

		// amass — apex only. -timeout is in MINUTES. -config points at the
		// generated config so free sources are actually queried (BUG #4).
		amOut := filepath.Join(s.OutputFolder, fmt.Sprintf("amass_%s.txt", sanitizeName(domain)))
		amCount := 0
		amArgs := []string{"enum", "-passive", "-d", domain, "-o", amOut, "-timeout", "4"}
		if amassCfg != "" {
			amArgs = append(amArgs, "-config", amassCfg)
		}
		res := runner.RunTool(ctx, "amass", amArgs, nil)
		if res.OK() {
			for _, l := range readNonEmptyLines(amOut) {
				l = strings.ToLower(l)
				if strings.HasSuffix(l, domain) && !found[l] {
					found[l] = true
					amCount++
				}
			}
			s.Printf("│    amass: %d subdomains\n", amCount)
		} else if res.TimedOut {
			s.Printf("│    amass: partial (timed out) — parsing any output\n")
			for _, l := range readNonEmptyLines(amOut) {
				l = strings.ToLower(l)
				if strings.HasSuffix(l, domain) && !found[l] {
					found[l] = true
				}
			}
		} else {
			s.Printf("│    amass: SKIP (%v)\n", res.Err)
		}

		// bbot — apex only (BUG #5 FIX). The old `-p subdomain-enum -f passive`
		// preset pulls in slow modules (github_codesearch, certspotter, etc.)
		// that routinely blow past 10 minutes, so bbot always hit the runner
		// timeout with only partial output. We now EXCLUDE the slowest modules
		// with -em and keep only fast passive sources; results are read from the
		// output dir whether bbot finished or was still cut off.
		bbotOutDir := filepath.Join(s.OutputFolder, fmt.Sprintf("bbot_%s", sanitizeName(domain)))
		res = runner.RunTool(ctx, "bbot", []string{
			"-t", domain, "-p", "subdomain-enum", "-f", "passive",
			"-em", "github_codesearch,dnsbrute,dnsbrute_mutations,dnscommonsrv,massdns",
			"-o", bbotOutDir, "--force", "-y",
		}, nil)
		if res.OK() || res.TimedOut {
			bbotCount := 0
			_ = filepath.Walk(bbotOutDir, func(path string, info os.FileInfo, err error) error {
				if err != nil || info == nil || info.IsDir() {
					return nil
				}
				base := strings.ToLower(filepath.Base(path))
				if !strings.HasSuffix(base, ".txt") {
					return nil
				}
				for _, l := range readNonEmptyLines(path) {
					l = strings.ToLower(l)
					if strings.HasSuffix(l, domain) && len(l) < 255 && !found[l] {
						found[l] = true
						bbotCount++
					}
				}
				return nil
			})
			status := "OK"
			if res.TimedOut {
				status = "partial (timeout)"
			}
			s.Printf("│    bbot: %d subdomains [%s]\n", bbotCount, status)
		} else {
			s.Printf("│    bbot: SKIP (%v)\n", res.Err)
		}

		// findomain — apex only (BUG #7). -t <domain> -u <out> -q. Some
		// findomain builds write to the file, others only to stdout depending
		// on version, so we parse BOTH the output file and stdout as a fallback.
		fdOut := filepath.Join(s.OutputFolder, fmt.Sprintf("findomain_%s.txt", sanitizeName(domain)))
		fdCount := 0
		res = runner.RunTool(ctx, "findomain", []string{"-t", domain, "-u", fdOut, "-q"}, nil)
		if res.OK() {
			lines := readNonEmptyLines(fdOut)
			if len(lines) == 0 && res.Stdout != "" {
				// Fallback: parse stdout directly when the file came back empty.
				lines = strings.Split(res.Stdout, "\n")
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
	return "puredns bruteforce (auto resolvers) → dnsx fallback + dnsgen permutations"
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
	if wordlist != "" {
		if _, n := fileHasContent(wordlist); n > 0 {
			s.Printf("│  DNS wordlist: %s (%d entries)\n", filepath.Base(wordlist), n)
		}
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
			res := runner.RunTool(ctx, "puredns", args, nil)
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
		res := runner.RunTool(ctx, "dnsx", args, nil)
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

	writeLines(subFile, s.Subdomains)
	s.Printf("│  Total After Active Bruteforce: %d\n", len(s.Subdomains))
	return nil
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

// ensureAmassConfig makes sure amass has a config file that enables data
// sources (BUG #4). If the user already has ~/.config/amass/config.ini we do
// not touch it; otherwise we write a minimal one that turns on all free,
// key-less sources. Returns the config path, or "" if it could not be created
// (amass then runs with its own defaults).
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
	content := `# Auto-generated by MOHAMMED (BUG #4 fix) — enables free data sources.
[scope]

[data_sources]
minimum_ttl = 1440

[data_sources.Crtsh]
[data_sources.HackerTarget]
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
	if len(candidates) == 0 {
		s.Printf("│  subzy: 0 candidate takeovers\n")
		return nil
	}
	s.Printf("│  subzy: %d candidate(s) — running HTTP confirmation…\n", len(candidates))

	confirmed := 0
	for _, host := range candidates {
		httpConfirmed, evidence := confirmTakeover(ctx, host)
		f := map[string]interface{}{
			"title": "Subdomain Takeover", "url": host,
			"tool": "subzy+http-confirm", "evidence": evidence,
		}
		if httpConfirmed {
			f["severity"] = "Critical"
			// Second gate: AI triage before we commit to Critical.
			s.Triage(ctx, "Subdomain Takeover", host, evidence, f)
			confirmed++
		} else {
			// Not confirmed by HTTP → Info, but keep for the record.
			f["severity"] = "Info"
			f["ai_verdict"] = "unconfirmed_by_http"
			s.AddFinding(f)
		}
		s.Governor.Throttle()
	}
	s.Printf("│  Takeover: %d candidate(s), %d HTTP-confirmed Critical\n", len(candidates), confirmed)
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
	hostsFile := filepath.Join(s.OutputFolder, "live_dns.txt")
	if ok, _ := fileHasContent(hostsFile); !ok {
		hostsFile = filepath.Join(s.OutputFolder, "subdomains.txt")
	}
	ok, inputN := fileHasContent(hostsFile)
	if !ok {
		s.Printf("│  httpx: SKIP (no hosts to probe)\n")
		return nil
	}
	s.Printf("│  httpx input: %d hosts (%s)\n", inputN, filepath.Base(hostsFile))

	httpxOut := filepath.Join(s.OutputFolder, "http_live.txt")

	// -timeout 10 prevents hanging on slow hosts; -json writes JSONL to -o.
	args := []string{"-l", hostsFile, "-o", httpxOut, "-silent", "-nc",
		"-rl", "150", "-timeout", "10", "-sc", "-title", "-td", "-cdn", "-fr",
		"-threads", fmt.Sprintf("%d", s.Config.Threads),
		"-json", "-srd", filepath.Join(s.OutputFolder, "httpx_responses")}

	// BUG #1: only route through Burp when the proxy is ACTIVE. engine.Run now
	// forcibly sets Proxy.Active=false when Burp's connectivity test fails, so
	// reaching this branch means Burp really is up. This is the ONLY correct
	// way to route httpx through a proxy (it has no -insecure flag; it tolerates
	// the proxy CA by default).
	if s.Proxy.Active {
		args = append(args, "-http-proxy", s.Proxy.ProxyURL)
	}

	res := runner.RunTool(ctx, "httpx", args, nil)

	urlSet := make(map[string]bool)
	if res.OK() || res.TimedOut {
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
		s.Printf("│  httpx: %d live endpoints\n", len(urlSet))
	} else {
		s.Printf("│  httpx: FAILED (%v)\n", res.Err)
		if s.Config.Debug && res.Stderr != "" {
			s.Printf("│  [DEBUG] httpx stderr: %s\n", strings.TrimSpace(firstN(res.Stderr, 500)))
		}
	}

	// ── IMPROVEMENT #2 + #4: sanity check + direct fallback ────────────────
	// httpx finding 0 endpoints from N resolved hosts is a red flag. Rather
	// than silently break every downstream phase, probe the hosts directly
	// (scheme-prefixed) so the pipeline always has URLs when hosts are live.
	if len(urlSet) == 0 && inputN > 0 {
		s.Printf("│  ⚠ WARNING: httpx found 0 endpoints from %d hosts — running direct fallback probe\n", inputN)
		if s.Config.Debug {
			s.Printf("│  [DEBUG] httpx cmd was: httpx %s\n", strings.Join(args, " "))
		}
		fallback := directProbe(ctx, s, readNonEmptyLines(hostsFile))
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
	return nil
}

// directProbe is the IMPROVEMENT #4 / #6 cascading fallback: when httpx yields
// nothing, hit each host directly with curl on https then http and keep the
// ones that answer. Bounded to the first 200 hosts to stay fast. Honors an
// active proxy so it still works behind a reachable Burp.
func directProbe(ctx context.Context, s *engine.State, hosts []string) []string {
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
				if s.Proxy.Active {
					curlArgs = append(curlArgs, "-x", s.Proxy.ProxyURL)
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
		for _, l := range lines {
			ll := strings.ToLower(l)
			if strings.Contains(ll, "expired") || strings.Contains(ll, "self-signed") || strings.Contains(ll, "mismatched") {
				issues++
				s.AddFinding(map[string]interface{}{
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
//
// BUG #4 FIX: force TCP Connect scan with "-scan-type c" so naabu works
// without root/CAP_NET_RAW (default SYN scan exits with status 2 unprivileged).
// The old code used "-connect-scan", which is NOT a valid naabu flag.
// ═══════════════════════════════════════════════════════════════
type PortScanPhase struct{}

func (p *PortScanPhase) Name() string { return "Port Scanning" }
func (p *PortScanPhase) Description() string {
	return "naabu top-1000 ports, TCP connect scan (-scan-type c, no root needed)"
}
func (p *PortScanPhase) Execute(ctx context.Context, s *engine.State) error {
	hostsFile := filepath.Join(s.OutputFolder, "live_dns.txt")
	if ok, _ := fileHasContent(hostsFile); !ok {
		s.Printf("│  naabu: SKIP (no hosts)\n")
		return nil
	}
	portsOut := filepath.Join(s.OutputFolder, "ports.txt")

	// -scan-type c == CONNECT scan (unprivileged). -Pn skips host discovery
	// which also needs raw sockets.
	res := runner.RunTool(ctx, "naabu", []string{
		"-list", hostsFile, "-o", portsOut, "-silent",
		"-top-ports", "1000", "-scan-type", "c", "-Pn",
		"-rate", "1000", "-c", "25",
	}, nil)
	if res.OK() || res.TimedOut {
		lines := readNonEmptyLines(portsOut)
		s.Printf("│  naabu: %d open port entries\n", len(lines))
	} else {
		s.Printf("│  naabu: SKIP (%v)\n", res.Err)
	}
	return nil
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

	for _, domain := range targets {
		// gau: providers + threads + retries + subs (BUG #10). --subs makes
		// gau expand to subdomains, which is where the archives actually live.
		gauArgs := []string{
			"--threads", "5", "--retries", "3", "--subs",
			"--providers", "wayback,commoncrawl,otx,urlscan", domain,
		}
		res := runner.RunTool(ctx, "gau", gauArgs, nil)
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
		} else {
			s.Printf("│  gau [%s]: SKIP (%v)\n", domain, res.Err)
		}

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
			s.Printf("│  waybackurls [%s]: %d URLs\n", domain, wbCount)
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
		if added := len(allURLs) - before; added > 0 {
			s.Printf("│  URLScan+CommonCrawl [%s]: +%d URLs\n", apex, added)
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
	return "katana + gospider deep crawl on live endpoints (empty-input guarded)"
}
func (p *CrawlPhase) Execute(ctx context.Context, s *engine.State) error {
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
	if s.Proxy.Active {
		katArgs = append(katArgs, "-proxy", s.Proxy.ProxyURL)
		katEnv = s.Proxy.GetEnv()
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
		if s.Proxy.Active {
			goArgs = append(goArgs, "-p", s.Proxy.ProxyURL)
			goEnv = s.Proxy.GetEnv()
		}
		res = runner.RunTool(ctx, "gospider", goArgs, goEnv)
		if res.OK() || res.TimedOut {
			goCount := 0
			// gospider prints to stdout and to files under goOut (a dir).
			for _, l := range strings.Split(res.Stdout, "\n") {
				for _, part := range strings.Fields(l) {
					if strings.HasPrefix(part, "http") && !crawlURLs[part] {
						crawlURLs[part] = true
						goCount++
					}
				}
			}
			s.Printf("│  gospider: +%d URLs\n", goCount)
		} else {
			s.Printf("│  gospider: SKIP (%v)\n", res.Err)
		}
	} else {
		s.Printf("│  gospider: SKIP (empty seed file)\n")
	}

	var lines []string
	for u := range crawlURLs {
		lines = append(lines, u)
	}
	crawlFile := filepath.Join(s.OutputFolder, "urls_crawled.txt")
	writeLines(crawlFile, lines)
	s.URLs = append(s.URLs, lines...)
	s.Printf("│  Total Crawled URLs: %d\n", len(crawlURLs))
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

	jsFile := filepath.Join(s.OutputFolder, "js_files.txt")
	var jsLines []string
	for u := range jsURLs {
		jsLines = append(jsLines, u)
	}
	writeLines(jsFile, jsLines)
	s.Printf("│  JS files found: %d\n", len(jsURLs))

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
	for u := range jsURLs {
		if count >= 60 { // cap network work
			break
		}
		count++
		args := []string{"-s", "-m", "12", "-A", "Mozilla/5.0", u}
		if s.Proxy.Active {
			args = append([]string{"-x", s.Proxy.ProxyURL, "-k"}, args...)
		}
		res := runner.RunTool(ctx, "curl", args, nil)
		if res.OK() && res.Stdout != "" {
			body := res.Stdout
			lowerBody := strings.ToLower(body)
			for label, pattern := range secretPatterns {
				match := false
				if strings.HasPrefix(pattern, "AKIA") || strings.HasPrefix(pattern, "-----") {
					match = strings.Contains(body, pattern) // case-sensitive
				} else {
					match = strings.Contains(lowerBody, strings.ToLower(pattern))
				}
				if match {
					secretsFound++
					s.AddFinding(map[string]interface{}{
						"title": "Potential Secret in JS", "severity": "High",
						"url": u, "tool": "js_scanner", "evidence": "pattern: " + label,
					})
					break
				}
			}
		}
		s.Governor.Throttle()
	}
	s.Printf("│  JS secrets flagged: %d\n", secretsFound)
	return nil
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
				// Try known default locations.
				for _, alt := range []string{
					filepath.Join("results", domain+".txt"),
					filepath.Join(s.OutputFolder, domain+".txt"),
				} {
					c += readInto(alt)
				}
			}
			s.Printf("│  paramspider [%s]: %d param URLs\n", domain, c)
		} else {
			s.Printf("│  paramspider [%s]: SKIP (%v)\n", domain, res.Err)
		}
	}

	// arjun — scan top parameterized live URLs.
	var arjunTargets []string
	for _, u := range s.URLs {
		if strings.HasPrefix(u, "http") {
			arjunTargets = append(arjunTargets, u)
		}
		if len(arjunTargets) >= 15 {
			break
		}
	}
	arjunFound := 0
	for _, u := range arjunTargets {
		arjunOut := filepath.Join(s.OutputFolder, "arjun_temp.json")
		res := runner.RunTool(ctx, "arjun", []string{"-u", u, "-oJ", arjunOut, "-q", "-t", "5"}, nil)
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

	var lines []string
	for u := range paramURLs {
		lines = append(lines, u)
	}
	paramFile := filepath.Join(s.OutputFolder, "params.txt")
	writeLines(paramFile, lines)
	s.Printf("│  Total Param URLs: %d\n", len(paramURLs))
	return nil
}

// ═══════════════════════════════════════════════════════════════
// Phase 14: CORS Misconfiguration
// ═══════════════════════════════════════════════════════════════
type CORSPhase struct{}

func (p *CORSPhase) Name() string { return "CORS Misconfiguration Check" }
func (p *CORSPhase) Description() string {
	return "Tests CORS reflection, null origin, wildcard"
}
func (p *CORSPhase) Execute(ctx context.Context, s *engine.State) error {
	corsVuln := 0
	testOrigins := []string{"https://evil.com", "null", "https://attacker.com"}

	targets := dedupeURLs(s.URLs)
	if len(targets) > 50 {
		targets = targets[:50]
	}

	for _, u := range targets {
		if !strings.HasPrefix(u, "http") {
			continue
		}
		for _, origin := range testOrigins {
			args := []string{"-s", "-m", "10", "-H", "Origin: " + origin, "-I", u}
			if s.Proxy.Active {
				args = append([]string{"-x", s.Proxy.ProxyURL, "-k"}, args...)
			}
			res := runner.RunTool(ctx, "curl", args, nil)
			if res.OK() {
				lower := strings.ToLower(res.Stdout)
				if strings.Contains(lower, "access-control-allow-origin: "+strings.ToLower(origin)) ||
					strings.Contains(lower, "access-control-allow-origin: *") {
					corsVuln++
					s.AddFinding(map[string]interface{}{
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
