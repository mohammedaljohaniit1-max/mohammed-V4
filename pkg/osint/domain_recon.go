package osint

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// DomainAssetBundle stores passive, 100% external reconnaissance results
// gathered without sending a single packet to the target infrastructure.
type DomainAssetBundle struct {
	Domain        string   `json:"domain"`
	Subdomains    []string `json:"subdomains"`
	ArchiveURLs   []string `json:"archive_urls"`
	PassiveIPs    []string `json:"passive_ips"`
	DanglingCNAME []string `json:"dangling_cnames"`
}

// CrtShEntry matches the JSON structure returned by crt.sh
type CrtShEntry struct {
	NameValue string `json:"name_value"`
}

// OTXPassiveDNS matches the response structure from AlienVault OTX
type OTXPassiveDNS struct {
	PassiveDNS []struct {
		Hostname string `json:"hostname"`
		Address  string `json:"address"`
	} `json:"passive_dns"`
}

// PassiveCollector runs external-only OSINT against public aggregators.
type PassiveCollector struct {
	Client   *http.Client
	Resolver *net.Resolver
}

// NewPassiveCollector initializes a passive collector using trusted external resolvers
// and an isolated HTTP client with strict timeouts.
func NewPassiveCollector(timeout time.Duration) *PassiveCollector {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: false},
		MaxIdleConns:        10,
		IdleConnTimeout:     30 * time.Second,
		DisableKeepAlives:   false,
		TLSHandshakeTimeout: 5 * time.Second,
	}

	// Use public DNS resolvers (Cloudflare 1.1.1.1 and Google 8.8.8.8)
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, "udp", "1.1.1.1:53")
		},
	}

	return &PassiveCollector{
		Client: &http.Client{
			Timeout:   timeout,
			Transport: transport,
		},
		Resolver: resolver,
	}
}

// CollectExternal gathers assets for target domain purely via external sources.
func (pc *PassiveCollector) CollectExternal(ctx context.Context, domain string) (*DomainAssetBundle, error) {
	bundle := &DomainAssetBundle{
		Domain:        strings.ToLower(strings.TrimSpace(domain)),
		Subdomains:    make([]string, 0),
		ArchiveURLs:   make([]string, 0),
		PassiveIPs:    make([]string, 0),
		DanglingCNAME: make([]string, 0),
	}

	subMap := make(map[string]bool)
	subMap[bundle.Domain] = true

	// 1. Certificate Transparency via crt.sh
	crtSubs, err := pc.FetchCrtSh(ctx, bundle.Domain)
	if err == nil {
		for _, s := range crtSubs {
			subMap[s] = true
		}
	}

	// 2. AlienVault OTX Passive DNS
	otxSubs, otxIPs, err := pc.FetchAlienVaultOTX(ctx, bundle.Domain)
	if err == nil {
		for _, s := range otxSubs {
			subMap[s] = true
		}
		bundle.PassiveIPs = append(bundle.PassiveIPs, otxIPs...)
	}

	// 3. Wayback Machine Historical URLs
	waybackURLs, err := pc.FetchWaybackURLs(ctx, bundle.Domain)
	if err == nil {
		bundle.ArchiveURLs = append(bundle.ArchiveURLs, waybackURLs...)
		for _, u := range waybackURLs {
			if parsed, pErr := url.Parse(u); pErr == nil {
				h := strings.ToLower(parsed.Hostname())
				if strings.HasSuffix(h, "."+bundle.Domain) || h == bundle.Domain {
					subMap[h] = true
				}
			}
		}
	}

	for s := range subMap {
		bundle.Subdomains = append(bundle.Subdomains, s)
	}
	sort.Strings(bundle.Subdomains)
	bundle.PassiveIPs = dedupStrings(bundle.PassiveIPs)
	bundle.ArchiveURLs = dedupStrings(bundle.ArchiveURLs)

	// 4. Passive CNAME inspection for subdomain takeover detection via public DNS
	bundle.DanglingCNAME = pc.DetectDanglingCNAMEs(ctx, bundle.Subdomains)

	return bundle, nil
}

// FetchCrtSh queries crt.sh's public certificate transparency logs.
func (pc *PassiveCollector) FetchCrtSh(ctx context.Context, domain string) ([]string, error) {
	targetURL := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", url.QueryEscape(domain))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "MOHAMMED-Safe-Passive-OSINT/1.0")
	req.Header.Set("Accept", "application/json")

	resp, err := pc.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, err
	}

	var entries []CrtShEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, err
	}

	var subdomains []string
	cleanApex := strings.ToLower(strings.TrimSpace(domain))
	for _, entry := range entries {
		lines := strings.Split(entry.NameValue, "\n")
		for _, raw := range lines {
			sub := strings.TrimSpace(strings.ToLower(raw))
			sub = strings.TrimPrefix(sub, "*.")
			if (strings.HasSuffix(sub, "."+cleanApex) || sub == cleanApex) && !strings.Contains(sub, " ") {
				subdomains = append(subdomains, sub)
			}
		}
	}

	return dedupStrings(subdomains), nil
}

// FetchAlienVaultOTX retrieves passive DNS records from AlienVault without target interaction.
func (pc *PassiveCollector) FetchAlienVaultOTX(ctx context.Context, domain string) ([]string, []string, error) {
	targetURL := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", url.PathEscape(domain))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", "MOHAMMED-Safe-Passive-OSINT/1.0")

	resp, err := pc.Client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("otx status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return nil, nil, err
	}

	var otxData OTXPassiveDNS
	if err := json.Unmarshal(body, &otxData); err != nil {
		return nil, nil, err
	}

	var subs []string
	var ips []string
	cleanApex := strings.ToLower(strings.TrimSpace(domain))

	for _, item := range otxData.PassiveDNS {
		h := strings.ToLower(strings.TrimSpace(item.Hostname))
		if strings.HasSuffix(h, "."+cleanApex) || h == cleanApex {
			subs = append(subs, h)
		}
		addr := strings.TrimSpace(item.Address)
		if net.ParseIP(addr) != nil {
			ips = append(ips, addr)
		}
	}

	return dedupStrings(subs), dedupStrings(ips), nil
}

// FetchWaybackURLs gets archived endpoints from the Wayback Machine.
func (pc *PassiveCollector) FetchWaybackURLs(ctx context.Context, domain string) ([]string, error) {
	targetURL := fmt.Sprintf("https://web.archive.org/cdx/search/cdx?url=*.%s/*&output=json&collapse=urlkey&fl=original&limit=1000", url.QueryEscape(domain))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "MOHAMMED-Safe-Passive-OSINT/1.0")

	resp, err := pc.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("wayback status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return nil, err
	}

	var rows [][]string
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, err
	}

	var urls []string
	for i, row := range rows {
		if i == 0 || len(row) == 0 {
			continue // skip header
		}
		rawURL := strings.TrimSpace(row[0])
		if rawURL != "" {
			urls = append(urls, rawURL)
		}
	}

	return dedupStrings(urls), nil
}

// Known dangling CNAME providers susceptible to takeover
var danglingSignatures = []string{
	"s3.amazonaws.com",
	"github.io",
	"azurewebsites.net",
	"pantheonsite.io",
	"herokuapp.com",
	"zendesk.com",
	"surge.sh",
	"ghost.io",
}

// DetectDanglingCNAMEs checks if any subdomains have CNAMEs pointing to cloud platforms
// without active DNS A/AAAA records (resolving exclusively through public DNS).
func (pc *PassiveCollector) DetectDanglingCNAMEs(ctx context.Context, subdomains []string) []string {
	var dangling []string

	for _, sub := range subdomains {
		select {
		case <-ctx.Done():
			return dangling
		default:
		}

		cname, err := pc.Resolver.LookupCNAME(ctx, sub)
		if err != nil {
			continue
		}
		cname = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(cname)), ".")
		if cname == "" || cname == strings.ToLower(sub) {
			continue
		}

		// Check against known dangling cloud provider targets
		matchedProvider := false
		for _, provider := range danglingSignatures {
			if strings.HasSuffix(cname, provider) {
				matchedProvider = true
				break
			}
		}

		if matchedProvider {
			// Verify if the canonical target resolves to any IP address
			ips, err := pc.Resolver.LookupHost(ctx, cname)
			if err != nil || len(ips) == 0 {
				// NXDOMAIN / Unresolved CNAME pointing to provider indicates a dangling takeover risk!
				dangling = append(dangling, fmt.Sprintf("%s -> %s (UNRESOLVED CNAME)", sub, cname))
			}
		}
	}

	return dedupStrings(dangling)
}

func dedupStrings(in []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, s := range in {
		trimmed := strings.TrimSpace(s)
		if trimmed != "" && !seen[trimmed] {
			seen[trimmed] = true
			out = append(out, trimmed)
		}
	}
	return out
}
