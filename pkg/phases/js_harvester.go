package phases

import (
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/mohammed-v3/core/pkg/engine"
	"github.com/mohammed-v3/core/pkg/filter"
	"github.com/mohammed-v3/core/pkg/governor"
)

// JSHarvesterPhase extracts JavaScript script bundles from live web pages,
// parses secret credentials (AWS, Google, Bearer, RSA/SSH) with Shannon entropy checks,
// discovers hidden internal API routes, and detects exposed .js.map source maps.
type JSHarvesterPhase struct{}

func (p *JSHarvesterPhase) Name() string { return "JavaScript & Source-Map Harvester" }
func (p *JSHarvesterPhase) Description() string {
	return "Client-side bundle scraping, Shannon entropy credential verification, internal route harvesting & source map detection"
}

// SecretPattern defines credential signatures to scan in JavaScript bundles.
type SecretPattern struct {
	Name       string
	Regex      *regexp.Regexp
	MinEntropy float64
	Severity   string
}

var (
	scriptSrcRegex = regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+\.js(\?[^"']*)?)["']`)
	apiRouteRegex  = regexp.MustCompile(`(?i)["'](/api/v[0-9]/[a-zA-Z0-9_\-/]+)["']`)
	genericPathRe  = regexp.MustCompile(`(?i)["'](/(?:v1|v2|v3|graphql|internal|admin|auth|user)/[a-zA-Z0-9_\-/]+)["']`)

	secretPatterns = []SecretPattern{
		{
			Name:       "AWS Access Key ID",
			Regex:      regexp.MustCompile(`\b(AKIA[0-9A-Z]{16})\b`),
			MinEntropy: 2.8,
			Severity:   "High",
		},
		{
			Name:       "Google API Key",
			Regex:      regexp.MustCompile(`\b(AIza[0-9A-Za-z\-_]{35})\b`),
			MinEntropy: 3.0,
			Severity:   "High",
		},
		{
			Name:       "Bearer Token",
			Regex:      regexp.MustCompile(`(?i)bearer\s+([a-zA-Z0-9_\-\.]{25,})`),
			MinEntropy: 3.2,
			Severity:   "High",
		},
		{
			Name:       "Private RSA/SSH Key Block",
			Regex:      regexp.MustCompile(`-----BEGIN (?:RSA )?PRIVATE KEY-----`),
			MinEntropy: 0,
			Severity:   "Critical",
		},
	}
)

// ShannonEntropy calculates the information entropy of a candidate string.
func ShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	counts := make(map[rune]float64)
	for _, r := range s {
		counts[r]++
	}
	length := float64(len(s))
	var entropy float64
	for _, count := range counts {
		freq := count / length
		entropy -= freq * math.Log2(freq)
	}
	return entropy
}

func (p *JSHarvesterPhase) Execute(ctx context.Context, s *engine.State) error {
	if len(s.LiveHosts) == 0 {
		s.Printf("│  JS Harvester: SKIP (no live hosts)\n")
		return nil
	}

	s.Printf("│  JS Harvester: analyzing client-side bundles across %d live targets\n", len(s.LiveHosts))

	gov := governor.NewGovernor(2,
		governor.WithMaxRPS(2.0),
		governor.WithConcurrency(2),
		governor.WithJitter(100*time.Millisecond, 250*time.Millisecond),
	)

	client := gov.WrapClient(&http.Client{
		Timeout: 8 * time.Second,
	})

	hosts := filter.PrioritizeLiveTargets(s.LiveHosts)
	var allScriptURLs []string
	seenScripts := make(map[string]bool)
	var mu sync.Mutex

	// 1. Bundle Scraper: Extract script URLs from landing pages
	for _, host := range hosts {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		baseURL := host
		if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
			baseURL = "https://" + baseURL
		}
		baseURL = strings.TrimRight(baseURL, "/")

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "MOHAMMED-JSHarvester/1.0")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
		resp.Body.Close()
		if err != nil {
			continue
		}

		matches := scriptSrcRegex.FindAllStringSubmatch(string(body), -1)
		for _, m := range matches {
			if len(m) < 2 {
				continue
			}
			src := m[1]
			resolvedURL := resolveURL(baseURL, src)
			if resolvedURL == "" || !filter.IsInScope(resolvedURL, s.Scope) {
				continue
			}

			mu.Lock()
			if !seenScripts[resolvedURL] {
				seenScripts[resolvedURL] = true
				allScriptURLs = append(allScriptURLs, resolvedURL)
			}
			mu.Unlock()
		}
	}

	s.Printf("│  JS Harvester: discovered %d unique in-scope JS script bundles\n", len(allScriptURLs))

	// 2. Secret & Route Extraction across bundles
	var wg sync.WaitGroup
	sem := make(chan struct{}, 2) // bounded concurrency

	for _, jsURL := range allScriptURLs {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(u string) {
			defer wg.Done()
			defer func() { <-sem }()

			p.analyzeScript(ctx, s, u, client)
		}(jsURL)
	}
	wg.Wait()

	return nil
}

func (p *JSHarvesterPhase) analyzeScript(ctx context.Context, s *engine.State, jsURL string, client *http.Client) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jsURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "MOHAMMED-JSHarvester/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024)) // 2MB max
	if err != nil {
		return
	}
	content := string(bodyBytes)

	// A. Scan for hardcoded credentials with Shannon Entropy validation
	for _, sp := range secretPatterns {
		matches := sp.Regex.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) == 0 {
				continue
			}
			candidate := match[0]
			if len(match) > 1 {
				candidate = match[1]
			}

			// Validate entropy threshold to reject placeholders like 'AKIAEXAMPLEKEY12345'
			if sp.MinEntropy > 0 {
				entropy := ShannonEntropy(candidate)
				if entropy < sp.MinEntropy {
					continue
				}
			}

			// Truncate candidate display for safe reporting
			displayKey := candidate
			if len(displayKey) > 12 {
				displayKey = displayKey[:6] + "..." + displayKey[len(displayKey)-4:]
			}

			s.AddFinding(map[string]interface{}{
				"title":          fmt.Sprintf("Exposed %s in JavaScript Bundle", sp.Name),
				"severity":       sp.Severity,
				"url":            jsURL,
				"evidence":       fmt.Sprintf("Matched signature %q with entropy %.2f (pattern: %s)", displayKey, ShannonEntropy(candidate), sp.Name),
				"tool":           "js_harvester",
				"confidence":     85,
				"http_confirmed": true,
			})
			break // Record once per secret type per bundle
		}
	}

	// B. Internal Endpoint Harvesting: Extract hidden paths and append to state URLs
	apiMatches := apiRouteRegex.FindAllStringSubmatch(content, -1)
	for _, m := range apiMatches {
		if len(m) > 1 {
			discoveredPath := m[1]
			parsedURL, err := url.Parse(jsURL)
			if err == nil {
				origin := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
				fullDiscoveredURL := origin + discoveredPath
				if filter.IsInScope(fullDiscoveredURL, s.Scope) {
					s.AddURL(fullDiscoveredURL)
				}
			}
		}
	}

	genericMatches := genericPathRe.FindAllStringSubmatch(content, -1)
	for _, m := range genericMatches {
		if len(m) > 1 {
			discoveredPath := m[1]
			parsedURL, err := url.Parse(jsURL)
			if err == nil {
				origin := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
				fullDiscoveredURL := origin + discoveredPath
				if filter.IsInScope(fullDiscoveredURL, s.Scope) {
					s.AddURL(fullDiscoveredURL)
				}
			}
		}
	}

	// C. Source Map Discovery (*.js.map)
	mapURL := jsURL + ".map"
	mapReq, err := http.NewRequestWithContext(ctx, http.MethodGet, mapURL, nil)
	if err == nil {
		mapReq.Header.Set("User-Agent", "MOHAMMED-JSHarvester/1.0")
		mapResp, err := client.Do(mapReq)
		if err == nil {
			defer mapResp.Body.Close()
			if mapResp.StatusCode == http.StatusOK {
				mapHead, err := io.ReadAll(io.LimitReader(mapResp.Body, 512))
				if err == nil && (strings.Contains(string(mapHead), `"version"`) || strings.Contains(string(mapHead), `"sources"`)) {
					s.AddFinding(map[string]interface{}{
						"title":          "Exposed JavaScript Source Map (.js.map)",
						"severity":       "Medium",
						"url":            mapURL,
						"evidence":       "Source map file is publicly accessible and contains unbundled source code mapping",
						"tool":           "js_harvester",
						"confidence":     90,
						"http_confirmed": true,
					})
				}
			}
		}
	}
}

func resolveURL(baseStr, refStr string) string {
	baseURL, err := url.Parse(baseStr)
	if err != nil {
		return ""
	}
	refURL, err := url.Parse(refStr)
	if err != nil {
		return ""
	}
	return baseURL.ResolveReference(refURL).String()
}
