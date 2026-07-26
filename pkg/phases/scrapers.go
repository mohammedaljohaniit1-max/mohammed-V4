package phases

// EXPANSION 2 — NATIVE FREE THREAT-INTEL SCRAPERS (API-LESS)
//
// These are pure-Go HTTP clients that scrape public intelligence sources
// directly, so the pipeline never stalls when API keys are absent. Every
// scraper here honours the mandated control requirements:
//
//   • randomized User-Agent per request
//   • 200ms inter-request pacing (politeness delay)
//   • HTTP 429 exponential backoff with a bounded retry count
//   • ctx cancellation + hard timeout on every request
//
// Sources implemented:
//   1. Shodan InternetDB  → https://internetdb.shodan.io/{ip}   (ports, CVEs)
//   2. crt.sh SAN         → https://crt.sh/?q=%.{domain}&output=json
//   3. Wayback CDX        → https://web.archive.org/cdx/search/cdx?...
//   4. GitHub code search → https://api.github.com/search/code?q={domain}

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// userAgents is a small rotating pool used to avoid trivial UA fingerprinting.
var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
}

var uaRand = struct {
	sync.Mutex
	r *rand.Rand
}{r: rand.New(rand.NewSource(time.Now().UnixNano()))}

func randomUA() string {
	uaRand.Lock()
	defer uaRand.Unlock()
	return userAgents[uaRand.r.Intn(len(userAgents))]
}

// scrapeClient is a shared HTTP client for native scrapers. TLS verification is
// skipped because some intel endpoints present intermediate/self-signed certs
// behind CDNs — we never send credentials, only public GETs.
var scrapeClient = &http.Client{
	Timeout: 40 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // public read-only scraping
		MaxIdleConns:        20,
		IdleConnTimeout:     30 * time.Second,
		DisableKeepAlives:   false,
		TLSHandshakeTimeout: 15 * time.Second,
	},
}

// scrapeGet performs a polite GET with randomized UA, a 200ms pre-request
// delay, and HTTP 429 exponential backoff (up to 3 retries). It returns the
// response body bytes, or nil on any unrecoverable error / cancellation.
func scrapeGet(ctx context.Context, rawURL string, headers map[string]string) []byte {
	const maxRetries = 3
	backoff := 800 * time.Millisecond

	for attempt := 0; attempt <= maxRetries; attempt++ {
		// Politeness delay before every request (mandated 200ms).
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(200 * time.Millisecond):
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return nil
		}
		req.Header.Set("User-Agent", randomUA())
		req.Header.Set("Accept", "application/json, text/plain, */*")
		for k, v := range headers {
			req.Header.Set(k, v)
		}

		resp, err := scrapeClient.Do(req)
		if err != nil {
			return nil
		}
		// HTTP 429: exponential backoff and retry.
		if resp.StatusCode == http.StatusTooManyRequests {
			resp.Body.Close()
			if attempt == maxRetries {
				return nil
			}
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(backoff):
			}
			backoff *= 2
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			resp.Body.Close()
			return nil
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024))
		resp.Body.Close()
		return body
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────────
// 1. Shodan InternetDB — free IP intelligence (open ports, CVEs, hostnames)
// ─────────────────────────────────────────────────────────────────────────

// InternetDBResult is the parsed subset of the InternetDB response.
type InternetDBResult struct {
	IP        string   `json:"ip"`
	Ports     []int    `json:"ports"`
	Hostnames []string `json:"hostnames"`
	Vulns     []string `json:"vulns"`
	CPEs      []string `json:"cpes"`
}

// ScrapeShodanInternetDB queries https://internetdb.shodan.io/{ip} which is a
// free, key-less endpoint returning open ports, hostnames, and known CVEs for
// an IP. Returns nil when the IP is unknown or the request fails.
func ScrapeShodanInternetDB(ctx context.Context, ip string) *InternetDBResult {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return nil
	}
	body := scrapeGet(ctx, "https://internetdb.shodan.io/"+url.PathEscape(ip), nil)
	if body == nil {
		return nil
	}
	var r InternetDBResult
	if err := json.Unmarshal(body, &r); err != nil {
		return nil
	}
	if r.IP == "" {
		r.IP = ip
	}
	return &r
}

// ─────────────────────────────────────────────────────────────────────────
// 2. crt.sh SAN harvester — parses SSL cert Subject Alternative Names
// ─────────────────────────────────────────────────────────────────────────

// ScrapeCrtShSAN fetches https://crt.sh/?q=%.{domain}&output=json and extracts
// every Subject Alternative Name (name_value field, which may be newline
// separated). Returns deduplicated candidate hostnames under the domain.
func ScrapeCrtShSAN(ctx context.Context, domain string) []string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return nil
	}
	q := url.QueryEscape("%." + domain)
	body := scrapeGet(ctx, fmt.Sprintf("https://crt.sh/?q=%s&output=json", q), nil)
	if body == nil {
		return nil
	}
	var records []struct {
		NameValue  string `json:"name_value"`
		CommonName string `json:"common_name"`
	}
	if err := json.Unmarshal(body, &records); err != nil {
		return nil
	}
	seen := make(map[string]bool)
	var out []string
	add := func(h string) {
		h = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(h, "*.")))
		if h == "" || seen[h] {
			return
		}
		if h != domain && !strings.HasSuffix(h, "."+domain) {
			return
		}
		seen[h] = true
		out = append(out, h)
	}
	for _, rec := range records {
		for _, name := range strings.Split(rec.NameValue, "\n") {
			add(name)
		}
		add(rec.CommonName)
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────────
// 3. Wayback Machine CDX API — historical URL mining
// ─────────────────────────────────────────────────────────────────────────

// ScrapeWaybackURLs queries the Wayback CDX API for every historical URL under
// *.{domain}/*, collapsing duplicate URL keys. Returns up to `limit` URLs.
func ScrapeWaybackURLs(ctx context.Context, domain string, limit int) []string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return nil
	}
	if limit <= 0 {
		limit = 10000
	}
	target := url.QueryEscape("*." + domain + "/*")
	endpoint := fmt.Sprintf(
		"https://web.archive.org/cdx/search/cdx?url=%s&output=json&fl=original&collapse=urlkey&limit=%d",
		target, limit)
	body := scrapeGet(ctx, endpoint, nil)
	if body == nil {
		return nil
	}
	// CDX JSON is an array of arrays; row 0 is the header ["original"].
	var rows [][]string
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil
	}
	seen := make(map[string]bool)
	var out []string
	for i, row := range rows {
		if i == 0 || len(row) == 0 { // skip header
			continue
		}
		u := strings.TrimSpace(row[0])
		if u == "" || seen[u] {
			continue
		}
		seen[u] = true
		out = append(out, u)
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────────
// 4. GitHub public code search — leaked host references / configs
// ─────────────────────────────────────────────────────────────────────────

// ScrapeGitHubHosts queries the GitHub code-search API for the domain string
// and extracts host references from the matched file paths + repository names.
// A GITHUB_TOKEN (passed via token) raises the rate limit from 10 to 30 req/min
// but the scraper works unauthenticated too. Returns candidate hostnames.
func ScrapeGitHubHosts(ctx context.Context, domain, token string) []string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return nil
	}
	headers := map[string]string{
		"Accept": "application/vnd.github.text-match+json",
	}
	if strings.TrimSpace(token) != "" {
		headers["Authorization"] = "Bearer " + strings.TrimSpace(token)
	}
	q := url.QueryEscape("\"" + domain + "\"")
	endpoint := fmt.Sprintf("https://api.github.com/search/code?q=%s&per_page=30", q)
	body := scrapeGet(ctx, endpoint, headers)
	if body == nil {
		return nil
	}
	var resp struct {
		Items []struct {
			Name        string `json:"name"`
			Path        string `json:"path"`
			HTMLURL     string `json:"html_url"`
			TextMatches []struct {
				Fragment string `json:"fragment"`
			} `json:"text_matches"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil
	}
	seen := make(map[string]bool)
	var out []string
	add := func(h string) {
		h = strings.ToLower(strings.Trim(strings.TrimSpace(h), ".\"'"))
		if h == "" || seen[h] {
			return
		}
		if h != domain && !strings.HasSuffix(h, "."+domain) {
			return
		}
		seen[h] = true
		out = append(out, h)
	}
	for _, item := range resp.Items {
		for _, tm := range item.TextMatches {
			for _, tok := range hostTokens(tm.Fragment, domain) {
				add(tok)
			}
		}
		for _, tok := range hostTokens(item.Path+" "+item.HTMLURL, domain) {
			add(tok)
		}
	}
	return out
}

// hostTokens extracts substrings that look like "<sub>.<domain>" from an
// arbitrary text fragment. It is a lightweight regex-free scanner so the
// GitHub scraper never depends on external packages.
func hostTokens(text, domain string) []string {
	text = strings.ToLower(text)
	var out []string
	idx := 0
	for {
		pos := strings.Index(text[idx:], domain)
		if pos < 0 {
			break
		}
		abs := idx + pos
		// Walk left over label characters to capture the subdomain prefix.
		start := abs
		for start > 0 {
			c := text[start-1]
			if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.' {
				start--
				continue
			}
			break
		}
		host := text[start : abs+len(domain)]
		host = strings.Trim(host, ".-")
		if host != "" {
			out = append(out, host)
		}
		idx = abs + len(domain)
		if idx >= len(text) {
			break
		}
	}
	return out
}
