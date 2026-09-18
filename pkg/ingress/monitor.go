package ingress

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// EndpointHealth stores the health check and TLS/header consistency information.
type EndpointHealth struct {
	Host         string        `json:"host"`
	ResolvedIPs  []string      `json:"resolved_ips"`
	CertSubject  string        `json:"cert_subject,omitempty"`
	CertSANs     []string      `json:"cert_sans,omitempty"`
	CertExpiry   time.Time     `json:"cert_expiry,omitempty"`
	StatusCode   int           `json:"status_code"`
	ServerHeader string        `json:"server_header,omitempty"`
	Latency      time.Duration `json:"latency"`
	Healthy      bool          `json:"healthy"`
	ErrorMessage string        `json:"error_message,omitempty"`
}

// IngressMonitor performs passive DNS/TLS and endpoint health correlation for SRE monitoring.
type IngressMonitor struct {
	client  *http.Client
	timeout time.Duration
}

// NewIngressMonitor creates a configured IngressMonitor instance.
func NewIngressMonitor(timeout time.Duration) *IngressMonitor {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &IngressMonitor{
		timeout: timeout,
		client: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: false,
				},
			},
		},
	}
}

// CheckEndpoint resolves DNS records, verifies TLS certificate metadata, and probes HTTP response headers.
func (m *IngressMonitor) CheckEndpoint(ctx context.Context, targetHost string) *EndpointHealth {
	health := &EndpointHealth{
		Host:        targetHost,
		ResolvedIPs: make([]string, 0),
		CertSANs:    make([]string, 0),
	}

	callCtx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()

	// 1. DNS Resolution (A and AAAA records)
	hostOnly := targetHost
	if h, _, err := net.SplitHostPort(targetHost); err == nil {
		hostOnly = h
	}

	ips, err := net.DefaultResolver.LookupIP(callCtx, "ip", hostOnly)
	if err == nil {
		for _, ip := range ips {
			health.ResolvedIPs = append(health.ResolvedIPs, ip.String())
		}
	}

	// 2. HTTP Probe and Certificate Metadata Verification
	start := time.Now()
	url := targetHost
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "https://" + url
	}

	req, err := http.NewRequestWithContext(callCtx, http.MethodGet, url, nil)
	if err != nil {
		health.Healthy = false
		health.ErrorMessage = fmt.Sprintf("failed to construct request: %v", err)
		return health
	}
	req.Header.Set("User-Agent", "Mohammed-IngressMonitor/1.0 (SRE; HealthCheck)")

	resp, err := m.client.Do(req)
	health.Latency = time.Since(start)

	if err != nil {
		health.Healthy = false
		health.ErrorMessage = err.Error()
		return health
	}
	defer resp.Body.Close()

	health.StatusCode = resp.StatusCode
	health.ServerHeader = resp.Header.Get("Server")
	health.Healthy = resp.StatusCode >= 200 && resp.StatusCode < 500

	// Extract TLS certificate SANs and expiry if TLS was negotiated
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		cert := resp.TLS.PeerCertificates[0]
		health.CertSubject = cert.Subject.CommonName
		health.CertExpiry = cert.NotAfter
		health.CertSANs = append(health.CertSANs, cert.DNSNames...)
	}

	return health
}

// CompareEndpoints runs health checks across multiple target hosts concurrently and returns results.
func (m *IngressMonitor) CompareEndpoints(ctx context.Context, hosts []string) []*EndpointHealth {
	var wg sync.WaitGroup
	var mu sync.Mutex
	results := make([]*EndpointHealth, 0, len(hosts))

	for _, host := range hosts {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			res := m.CheckEndpoint(ctx, h)
			mu.Lock()
			results = append(results, res)
			mu.Unlock()
		}(host)
	}

	wg.Wait()
	return results
}
