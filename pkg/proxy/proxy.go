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
}

func NewProxyManager(proxyURL string) *ProxyManager {
	if proxyURL == "" {
		return &ProxyManager{Active: false}
	}
	return &ProxyManager{
		ProxyURL: proxyURL,
		Active:   true,
	}
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
