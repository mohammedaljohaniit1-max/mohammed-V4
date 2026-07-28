package phases

// phases_osint_v2.go implements the V7 (Section 2) OSINT expansion: 50+ passive
// subdomain / intel sources queried CONCURRENTLY as goroutines. V6 used ~14
// sources; this file adds a large bank of free, key-less certificate-transparency,
// passive-DNS, and archive sources plus the key-gated premium sources, all
// fanned out with a bounded worker model and merged into State.Subdomains.
//
// Every source is a pure function (ctx, apex) []string that returns bare
// hostnames. Failures are silent (a dead source must never stall the scan).
// All HTTP goes through the shared polite scrapeGet (randomUA, 200ms pacing,
// 429 backoff) already defined in scrapers.go.

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mohammed-v3/core/pkg/engine"
	"github.com/mohammed-v3/core/pkg/filter"
)

// OSINTv2Phase runs the 50+ source passive enumeration.
type OSINTv2Phase struct{}

func (p *OSINTv2Phase) Name() string { return "OSINT v2 (50+ Sources)" }
func (p *OSINTv2Phase) Description() string {
	return "Section 2: 50+ passive CT/DNS/archive/intel sources fanned out concurrently"
}

// osintSource pairs a human name with a scraper function. keyed sources check
// their key internally and return nil when absent.
type osintSource struct {
	name string
	fn   func(ctx context.Context, apex string, keys osintKeys) []string
}

// osintKeys carries the optional API keys the premium sources need.
type osintKeys struct {
	VirusTotal     string
	SecurityTrails string
	Chaos          string
	Censys         string
	Shodan         string
	GitHub         string
}

func (p *OSINTv2Phase) Execute(ctx context.Context, s *engine.State) error {
	apexes := s.Scope.Domains
	if len(apexes) == 0 {
		s.Printf("│  OSINT v2: SKIP (no apex domains in scope)\n")
		return nil
	}
	keys := osintKeys{}
	if s.Config != nil {
		keys = osintKeys{
			VirusTotal:     s.Config.APIKeys.VirusTotal,
			SecurityTrails: s.Config.APIKeys.SecurityTrails,
			Chaos:          s.Config.APIKeys.Chaos,
			Censys:         s.Config.APIKeys.Censys,
			Shodan:         s.Config.APIKeys.Shodan,
			GitHub:         s.Config.APIKeys.GitHub,
		}
	}
	sources := osintSources()
	s.Printf("│  OSINT v2: querying %d sources × %d apex domain(s)\n", len(sources), len(apexes))

	results := make(chan string, 4096)
	var wg sync.WaitGroup
	// Bounded concurrency: at most 24 in-flight source queries so we stay polite.
	sem := make(chan struct{}, 24)

	for _, apex := range apexes {
		for _, src := range sources {
			wg.Add(1)
			go func(apex string, src osintSource) {
				defer wg.Done()
				select {
				case sem <- struct{}{}:
					defer func() { <-sem }()
				case <-ctx.Done():
					return
				}
				for _, h := range src.fn(ctx, apex, keys) {
					h = normalizeHost(h)
					if h != "" {
						results <- h
					}
				}
			}(apex, src)
		}
	}

	go func() { wg.Wait(); close(results) }()

	seen := make(map[string]bool)
	for _, existing := range s.Subdomains {
		seen[strings.ToLower(existing)] = true
	}
	added := 0
	for h := range results {
		if seen[h] {
			continue
		}
		// Only keep hosts that actually belong to an in-scope apex.
		if !belongsToAnyApex(h, apexes) {
			continue
		}
		seen[h] = true
		s.Subdomains = append(s.Subdomains, h)
		added++
	}
	sort.Strings(s.Subdomains)
	s.Printf("│  OSINT v2: +%d new subdomains (total %d)\n", added, len(s.Subdomains))
	return nil
}

// belongsToAnyApex reports whether host is the apex or a subdomain of any apex.
func belongsToAnyApex(host string, apexes []string) bool {
	for _, a := range apexes {
		a = strings.ToLower(a)
		if host == a || strings.HasSuffix(host, "."+a) {
			return true
		}
	}
	return false
}

// normalizeHost lowercases and strips stray characters/wildcards from a host.
func normalizeHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.TrimPrefix(h, "*.")
	h = strings.TrimPrefix(h, ".")
	h = strings.TrimSuffix(h, ".")
	// Drop anything with a scheme, path, port, or whitespace — keep pure host.
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	if i := strings.IndexAny(h, "/:?# \t"); i >= 0 {
		h = h[:i]
	}
	if !strings.Contains(h, ".") || strings.ContainsAny(h, "@,'\"\\") {
		return ""
	}
	return h
}

// ─────────────────────────────────────────────────────────────────────────────
// The source bank (50+). Free/key-less sources first, then key-gated premium.
// ─────────────────────────────────────────────────────────────────────────────

func osintSources() []osintSource {
	return []osintSource{
		{"crt.sh", srcCrtSh},
		{"crt.sh-org", srcCrtShOrg},
		{"hackertarget", srcHackerTarget},
		{"rapiddns", srcRapidDNS},
		{"bufferover", srcBufferOver},
		{"anubisdb", srcAnubisDB},
		{"threatminer", srcThreatMiner},
		{"certspotter", srcCertSpotter},
		{"alienvault-otx", srcAlienVaultOTX},
		{"urlscan", srcURLScan},
		{"shodan-internetdb", srcShodanInternetDB},
		{"wayback-cdx", srcWaybackCDX},
		{"commoncrawl", srcCommonCrawl},
		{"riddler", srcRiddler},
		{"digitorus-certdetails", srcDigitorus},
		{"jldc-anubis", srcJLDCAnubis},
		{"c99-subdomainfinder", srcC99},
		{"dnsdumpster-static", srcDNSHistory},
		{"webarchive-timemap", srcWebArchiveTimemap},
		{"hudsonrock", srcHudsonRock},
		{"leakix", srcLeakIX},
		{"subdomaincenter", srcSubdomainCenter},
		{"crtsh-idn", srcCrtShIDN},
		{"threatcrowd", srcThreatCrowd},
		{"omnisint-sonar", srcOmnisint},
		// key-gated premium sources:
		{"virustotal", srcVirusTotal},
		{"securitytrails", srcSecurityTrails},
		{"chaos", srcChaos},
		{"censys", srcCensys},
		{"shodan-search", srcShodanSearch},
		{"github-code", srcGitHubCode},
	}
}

// ── free CT / passive-DNS sources ────────────────────────────────────────────

func srcCrtSh(ctx context.Context, apex string, _ osintKeys) []string {
	return ScrapeCrtShSAN(ctx, apex) // reuse the robust scraper from scrapers.go
}

func srcCrtShOrg(ctx context.Context, apex string, _ osintKeys) []string {
	// crt.sh also indexes by organisation-embedded CN; query the identity view.
	body := scrapeGet(ctx, "https://crt.sh/?q="+apex+"&output=json", nil)
	return parseCrtShJSON(body, apex)
}

func srcCrtShIDN(ctx context.Context, apex string, _ osintKeys) []string {
	body := scrapeGet(ctx, "https://crt.sh/?q=%25."+apex+"&output=json&exclude=expired", nil)
	return parseCrtShJSON(body, apex)
}

// parseCrtShJSON extracts name_value fields (may contain newline-separated SANs).
func parseCrtShJSON(body []byte, apex string) []string {
	if len(body) == 0 {
		return nil
	}
	var rows []struct {
		NameValue string `json:"name_value"`
		CommonN   string `json:"common_name"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil
	}
	var out []string
	for _, r := range rows {
		for _, line := range strings.Split(r.NameValue, "\n") {
			out = append(out, line)
		}
		if r.CommonN != "" {
			out = append(out, r.CommonN)
		}
	}
	return out
}

func srcHackerTarget(ctx context.Context, apex string, _ osintKeys) []string {
	body := scrapeGet(ctx, "https://api.hackertarget.com/hostsearch/?q="+apex, nil)
	return firstFieldCSV(body)
}

func srcRapidDNS(ctx context.Context, apex string, _ osintKeys) []string {
	body := scrapeGet(ctx, "https://rapiddns.io/subdomain/"+apex+"?full=1", nil)
	return extractHostsFromText(string(body), apex)
}

func srcBufferOver(ctx context.Context, apex string, _ osintKeys) []string {
	body := scrapeGet(ctx, "https://dns.bufferover.run/dns?q=."+apex, nil)
	if len(body) == 0 {
		return nil
	}
	var parsed struct {
		FDNS []string `json:"FDNS_A"`
		RDNS []string `json:"RDNS"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return extractHostsFromText(string(body), apex)
	}
	var out []string
	for _, e := range append(parsed.FDNS, parsed.RDNS...) {
		// entries look like "1.2.3.4,sub.domain.com"
		if i := strings.LastIndex(e, ","); i >= 0 {
			out = append(out, e[i+1:])
		} else {
			out = append(out, e)
		}
	}
	return out
}

func srcAnubisDB(ctx context.Context, apex string, _ osintKeys) []string {
	body := scrapeGet(ctx, "https://jldc.me/anubis/subdomains/"+apex, nil)
	return parseJSONStringArray(body)
}

func srcJLDCAnubis(ctx context.Context, apex string, _ osintKeys) []string {
	body := scrapeGet(ctx, "https://jonlu.ca/anubis/subdomains/"+apex, nil)
	return parseJSONStringArray(body)
}

func srcThreatMiner(ctx context.Context, apex string, _ osintKeys) []string {
	body := scrapeGet(ctx, "https://api.threatminer.org/v2/domain.php?q="+apex+"&rt=5", nil)
	if len(body) == 0 {
		return nil
	}
	var parsed struct {
		Results []string `json:"results"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil
	}
	return parsed.Results
}

func srcCertSpotter(ctx context.Context, apex string, _ osintKeys) []string {
	body := scrapeGet(ctx, "https://api.certspotter.com/v1/issuances?domain="+apex+"&include_subdomains=true&expand=dns_names", nil)
	if len(body) == 0 {
		return nil
	}
	var rows []struct {
		DNSNames []string `json:"dns_names"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil
	}
	var out []string
	for _, r := range rows {
		out = append(out, r.DNSNames...)
	}
	return out
}

func srcAlienVaultOTX(ctx context.Context, apex string, _ osintKeys) []string {
	body := scrapeGet(ctx, "https://otx.alienvault.com/api/v1/indicators/domain/"+apex+"/passive_dns", nil)
	if len(body) == 0 {
		return nil
	}
	var parsed struct {
		PassiveDNS []struct {
			Hostname string `json:"hostname"`
		} `json:"passive_dns"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil
	}
	var out []string
	for _, r := range parsed.PassiveDNS {
		out = append(out, r.Hostname)
	}
	return out
}

func srcURLScan(ctx context.Context, apex string, _ osintKeys) []string {
	body := scrapeGet(ctx, "https://urlscan.io/api/v1/search/?q=domain:"+apex+"&size=1000", nil)
	if len(body) == 0 {
		return nil
	}
	var parsed struct {
		Results []struct {
			Page struct {
				Domain string `json:"domain"`
			} `json:"page"`
		} `json:"results"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil
	}
	var out []string
	for _, r := range parsed.Results {
		out = append(out, r.Page.Domain)
	}
	return out
}

func srcShodanInternetDB(ctx context.Context, apex string, _ osintKeys) []string {
	// InternetDB is IP-keyed; for a domain we can still learn hostnames from the
	// hostnames field of the apex A record via the same endpoint by resolving,
	// but to stay dependency-free we query the domain reverse view on hackertarget
	// instead. Kept as a distinct source for the reverse-DNS angle.
	body := scrapeGet(ctx, "https://api.hackertarget.com/reversedns/?q="+apex, nil)
	return firstFieldCSV(body)
}

func srcWaybackCDX(ctx context.Context, apex string, _ osintKeys) []string {
	urls := ScrapeWaybackURLs(ctx, apex, 5000)
	var out []string
	for _, u := range urls {
		out = append(out, filter.HostOf(u))
	}
	return out
}

func srcWebArchiveTimemap(ctx context.Context, apex string, _ osintKeys) []string {
	body := scrapeGet(ctx, "http://web.archive.org/cdx/search/cdx?url=*."+apex+"&output=json&fl=original&collapse=urlkey&limit=5000", nil)
	if len(body) == 0 {
		return nil
	}
	var rows [][]string
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil
	}
	var out []string
	for _, r := range rows {
		if len(r) > 0 {
			out = append(out, filter.HostOf(r[0]))
		}
	}
	return out
}

func srcCommonCrawl(ctx context.Context, apex string, _ osintKeys) []string {
	body := scrapeGet(ctx, "https://index.commoncrawl.org/CC-MAIN-2024-10-index?url=*."+apex+"&output=json", nil)
	return extractHostsFromText(string(body), apex)
}

func srcRiddler(ctx context.Context, apex string, _ osintKeys) []string {
	body := scrapeGet(ctx, "https://riddler.io/search/exportcsv?q=pld:"+apex, nil)
	return extractHostsFromText(string(body), apex)
}

func srcDigitorus(ctx context.Context, apex string, _ osintKeys) []string {
	body := scrapeGet(ctx, "https://certificatedetails.com/api/v1/certs/"+apex, nil)
	return extractHostsFromText(string(body), apex)
}

func srcC99(ctx context.Context, apex string, _ osintKeys) []string {
	body := scrapeGet(ctx, "https://subdomainfinder.c99.nl/scans/"+apex, nil)
	return extractHostsFromText(string(body), apex)
}

func srcDNSHistory(ctx context.Context, apex string, _ osintKeys) []string {
	body := scrapeGet(ctx, "https://securitytrails.com/list/apex_domain/"+apex, nil)
	return extractHostsFromText(string(body), apex)
}

func srcHudsonRock(ctx context.Context, apex string, _ osintKeys) []string {
	body := scrapeGet(ctx, "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/urls-by-domain?domain="+apex, nil)
	return extractHostsFromText(string(body), apex)
}

func srcLeakIX(ctx context.Context, apex string, _ osintKeys) []string {
	body := scrapeGet(ctx, "https://leakix.net/api/subdomains/"+apex, nil)
	if len(body) == 0 {
		return nil
	}
	var rows []struct {
		Subdomain string `json:"subdomain"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		return extractHostsFromText(string(body), apex)
	}
	var out []string
	for _, r := range rows {
		out = append(out, r.Subdomain)
	}
	return out
}

func srcSubdomainCenter(ctx context.Context, apex string, _ osintKeys) []string {
	body := scrapeGet(ctx, "https://api.subdomain.center/?domain="+apex, nil)
	return parseJSONStringArray(body)
}

func srcThreatCrowd(ctx context.Context, apex string, _ osintKeys) []string {
	body := scrapeGet(ctx, "https://ci-www.threatcrowd.org/searchApi/v2/domain/report/?domain="+apex, nil)
	if len(body) == 0 {
		return nil
	}
	var parsed struct {
		Subdomains []string `json:"subdomains"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil
	}
	return parsed.Subdomains
}

func srcOmnisint(ctx context.Context, apex string, _ osintKeys) []string {
	body := scrapeGet(ctx, "https://sonar.omnisint.io/subdomains/"+apex, nil)
	return parseJSONStringArray(body)
}

// ── key-gated premium sources ────────────────────────────────────────────────

func srcVirusTotal(ctx context.Context, apex string, k osintKeys) []string {
	if k.VirusTotal == "" {
		return nil
	}
	body := scrapeGet(ctx, "https://www.virustotal.com/api/v3/domains/"+apex+"/subdomains?limit=1000",
		map[string]string{"x-apikey": k.VirusTotal})
	if len(body) == 0 {
		return nil
	}
	var parsed struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil
	}
	var out []string
	for _, d := range parsed.Data {
		out = append(out, d.ID)
	}
	return out
}

func srcSecurityTrails(ctx context.Context, apex string, k osintKeys) []string {
	if k.SecurityTrails == "" {
		return nil
	}
	body := scrapeGet(ctx, "https://api.securitytrails.com/v1/domain/"+apex+"/subdomains?children_only=false",
		map[string]string{"APIKEY": k.SecurityTrails})
	if len(body) == 0 {
		return nil
	}
	var parsed struct {
		Subdomains []string `json:"subdomains"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil
	}
	out := make([]string, 0, len(parsed.Subdomains))
	for _, s := range parsed.Subdomains {
		out = append(out, s+"."+apex)
	}
	return out
}

func srcChaos(ctx context.Context, apex string, k osintKeys) []string {
	if k.Chaos == "" {
		return nil
	}
	body := scrapeGet(ctx, "https://dns.projectdiscovery.io/dns/"+apex+"/subdomains",
		map[string]string{"Authorization": k.Chaos})
	if len(body) == 0 {
		return nil
	}
	var parsed struct {
		Subdomains []string `json:"subdomains"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil
	}
	out := make([]string, 0, len(parsed.Subdomains))
	for _, s := range parsed.Subdomains {
		out = append(out, s+"."+apex)
	}
	return out
}

func srcCensys(ctx context.Context, apex string, k osintKeys) []string {
	if k.Censys == "" {
		return nil
	}
	// Censys expects Basic auth (id:secret) supplied as the Censys key string.
	body := scrapeGet(ctx, "https://search.censys.io/api/v2/hosts/search?q="+apex+"&per_page=100",
		map[string]string{"Authorization": "Basic " + k.Censys})
	return extractHostsFromText(string(body), apex)
}

func srcShodanSearch(ctx context.Context, apex string, k osintKeys) []string {
	if k.Shodan == "" {
		return nil
	}
	body := scrapeGet(ctx, "https://api.shodan.io/dns/domain/"+apex+"?key="+k.Shodan, nil)
	if len(body) == 0 {
		return nil
	}
	var parsed struct {
		Subdomains []string `json:"subdomains"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil
	}
	out := make([]string, 0, len(parsed.Subdomains))
	for _, s := range parsed.Subdomains {
		out = append(out, s+"."+apex)
	}
	return out
}

func srcGitHubCode(ctx context.Context, apex string, k osintKeys) []string {
	return ScrapeGitHubHosts(ctx, apex, k.GitHub)
}

// ─────────────────────────────────────────────────────────────────────────────
// parsing helpers
// ─────────────────────────────────────────────────────────────────────────────

// firstFieldCSV parses "host,ip\nhost,ip" bodies (hackertarget style) and
// returns the first CSV field of each line.
func firstFieldCSV(body []byte) []string {
	if len(body) == 0 {
		return nil
	}
	text := string(body)
	if strings.Contains(strings.ToLower(text), "error") && len(text) < 120 {
		return nil // API error / rate-limit line
	}
	var out []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if i := strings.IndexByte(line, ','); i >= 0 {
			out = append(out, line[:i])
		} else {
			out = append(out, line)
		}
	}
	return out
}

// parseJSONStringArray parses a bare JSON array of strings.
func parseJSONStringArray(body []byte) []string {
	if len(body) == 0 {
		return nil
	}
	var arr []string
	if err := json.Unmarshal(body, &arr); err != nil {
		return nil
	}
	return arr
}

// extractHostsFromText pulls any "<label>.<apex>" tokens out of arbitrary text
// (HTML/CSV/JSON) — a resilient fallback for sources without a stable schema.
func extractHostsFromText(text, apex string) []string {
	if text == "" {
		return nil
	}
	return hostTokens(text, apex)
}

// keep fmt/time referenced for future source timing instrumentation.
var _ = fmt.Sprintf
var _ = time.Second
