package proxy

import (
	"fmt"
	"net/http"
	"net/url"
	"time"
)

type ProxyManager struct {
	ProxyURL string
	Active   bool

	// Selective enables the two-tier routing model (FIX #5). When true, only
	// Tier-2 (confirmed, high-value security) phases route through Burp; noisy
	// discovery phases (Tier 1) always go direct. When false, the legacy
	// behaviour applies (every proxy-aware phase uses Burp when Active).
	Selective bool
}

// ProxyMode selects whether a given tool invocation routes through Burp.
type ProxyMode int

const (
	// ProxyModeDirect never touches Burp — high-volume, low-signal discovery
	// (subdomain enum, DNS, port scan, archive mining, crawling, fuzzing).
	ProxyModeDirect ProxyMode = iota
	// ProxyModeSelective routes through Burp only when the proxy is Active
	// (targeted, confirmed security verification requests).
	ProxyModeSelective
)

func NewProxyManager(proxyURL string) *ProxyManager {
	if proxyURL == "" {
		return &ProxyManager{Active: false}
	}
	return &ProxyManager{
		ProxyURL: proxyURL,
		Active:   true,
	}
}

// For returns a ProxyManager view appropriate to the requested routing mode.
//
//   - ProxyModeDirect  → an inert manager (Active=false, no URL) so callers
//     that gate on Active automatically bypass Burp. This is the Tier-1 path.
//   - ProxyModeSelective → the real manager (Burp used when Active).
//
// When Selective routing is disabled in config, every mode returns the real
// manager (legacy whole-scan proxying).
func (p *ProxyManager) For(mode ProxyMode) *ProxyManager {
	if p == nil {
		return &ProxyManager{Active: false}
	}
	if !p.Selective {
		return p // legacy: proxy everything that is proxy-aware
	}
	if mode == ProxyModeDirect {
		return &ProxyManager{Active: false}
	}
	return p
}

// UseBurp is a convenience predicate: true when this manager is actively
// routing through Burp for the given mode.
func (p *ProxyManager) UseBurp(mode ProxyMode) bool {
	eff := p.For(mode)
	return eff.Active && eff.ProxyURL != ""
}

func (p *ProxyManager) TestConnection() error {
	if !p.Active {
		return nil
	}

	u, err := url.Parse(p.ProxyURL)
	if err != nil {
		return fmt.Errorf("invalid proxy URL: %w", err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(u),
		},
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get("http://httpbin.org/ip")
	if err != nil {
		return fmt.Errorf("proxy connection check failed: %w", err)
	}
	defer resp.Body.Close()

	return nil
}

func (p *ProxyManager) GetEnv() map[string]string {
	if !p.Active {
		return nil
	}
	return map[string]string{
		"HTTP_PROXY":  p.ProxyURL,
		"HTTPS_PROXY": p.ProxyURL,
		"http_proxy":  p.ProxyURL,
		"https_proxy": p.ProxyURL,
	}
}
