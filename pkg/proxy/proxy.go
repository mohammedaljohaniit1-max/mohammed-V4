package proxy

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"sync"
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

	// transport is the lazily-created HTTP transport for Burp-routed requests.
	// REPAIR #5: keep-alives are DISABLED and idle connections are closed after
	// every phase to eradicate the "Unsolicited response on idle HTTP channel"
	// spam that Burp emits when idle keep-alive sockets time out during tool
	// handoffs. mu guards lazy creation across concurrent phases.
	mu        sync.Mutex
	transport *http.Transport
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

// Transport returns a shared *http.Transport configured for Burp routing.
// REPAIR #5: DisableKeepAlives is TRUE so each request opens a fresh
// connection and no idle keep-alive socket is left to time out against Burp
// (the root cause of the "Unsolicited response on idle HTTP channel" flood).
// Returns a plain (non-proxied) transport when the manager is inactive.
func (p *ProxyManager) Transport() *http.Transport {
	if p == nil {
		return &http.Transport{DisableKeepAlives: true}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.transport != nil {
		return p.transport
	}
	tr := &http.Transport{
		DisableKeepAlives:   true, // REPAIR #5 — no idle keep-alive sockets to Burp
		MaxIdleConns:        0,
		IdleConnTimeout:     5 * time.Second,
		TLSHandshakeTimeout: 15 * time.Second,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // intercepting proxy CA
	}
	if p.Active && p.ProxyURL != "" {
		if pu, err := url.Parse(p.ProxyURL); err == nil {
			tr.Proxy = http.ProxyURL(pu)
		}
	}
	p.transport = tr
	return tr
}

// CloseIdleConnections closes every idle connection held by this manager's
// transport. REPAIR #5: the engine calls this after each phase completes so no
// idle Burp keep-alive socket survives a tool handoff. Safe to call on a nil
// manager or before the transport is created (both no-ops).
func (p *ProxyManager) CloseIdleConnections() {
	if p == nil {
		return
	}
	p.mu.Lock()
	tr := p.transport
	p.mu.Unlock()
	if tr != nil {
		tr.CloseIdleConnections()
	}
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
