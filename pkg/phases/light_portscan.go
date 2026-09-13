package phases

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mohammed-v3/core/pkg/engine"
	"github.com/mohammed-v3/core/pkg/filter"
	"github.com/mohammed-v3/core/pkg/governor"
)

// Top100WebAdminPorts represents the high-yield web, admin, diagnostic, and database
// service ports commonly checked in modern ASM and bug bounty methodologies (Coffinxp style).
// It strictly avoids scanning the full 65535 range.
var Top100WebAdminPorts = []int{
	// Standard web
	80, 443, 8080, 8443, 8000, 8888, 8008, 8081, 8088, 8880,
	// Dev & app frameworks
	3000, 3001, 4000, 4200, 5000, 5001, 5500, 7000, 7001, 7070,
	// Admin & internal management
	9000, 9001, 9090, 9091, 9443, 9999, 10000, 10443, 8082, 8083,
	// Containers & cloud orchestrators
	2375, 2376, 6443, 8001, 8500, 8501, 8848, 9200, 9300, 9600,
	// Alternative proxies & gateways
	81, 82, 88, 444, 4443, 8009, 8085, 8086, 8087, 8089,
	8090, 8091, 8181, 8282, 8383, 8881, 8882, 8883, 8884, 8885,
	// Database & cache interfaces with web dashboards
	1433, 1521, 3306, 3389, 5432, 5984, 6379, 7474, 8098, 11211,
	// CI/CD & diagnostics
	8084, 8088, 8099, 8161, 8888, 8983, 9002, 9003, 9080, 9100,
	// Remote access & control
	2082, 2083, 2086, 2087, 2095, 2096, 2222, 5601, 7002, 7003,
}

// LightPortScanPhase executes targeted Top-100 port checks on verified live IPs/hosts
// using our rate-limited governor to ensure zero DoS or server strain.
type LightPortScanPhase struct{}

func (p *LightPortScanPhase) Name() string { return "Lightweight Top-100 Port Scan" }
func (p *LightPortScanPhase) Description() string {
	return "Surgically checks Top 100 web/admin ports on verified live targets without scanning 65535 ports"
}

func (p *LightPortScanPhase) Execute(ctx context.Context, s *engine.State) error {
	if len(s.LiveHosts) == 0 {
		s.Printf("│  Light Portscan: SKIP (no live hosts)\n")
		return nil
	}

	hosts := filter.PrioritizeLiveTargets(s.LiveHosts)
	// Bounded sample to stay polite and fast on large enterprise scopes
	if len(hosts) > 100 {
		hosts = hosts[:100]
	}

	s.Printf("│  Light Portscan: scanning Top-100 web/admin ports across %d live host(s) (concurrency <= 2)\n", len(hosts))

	gov := governor.NewGovernor(2,
		governor.WithMaxRPS(2.0),
		governor.WithConcurrency(2),
		governor.WithJitter(200*time.Millisecond, 400*time.Millisecond),
	)

	var (
		mu        sync.Mutex
		wg        sync.WaitGroup
		openPorts = make(map[string][]int)
	)

	sem := make(chan struct{}, 2) // Strictly cap concurrent workers <= 2

	for _, rawHost := range hosts {
		host := cleanHost(rawHost)
		if host == "" {
			continue
		}

		// Resolve host IP to confirm it is live before probing ports
		ips, err := net.LookupHost(host)
		if err != nil || len(ips) == 0 {
			continue
		}

		for _, port := range Top100WebAdminPorts {
			select {
			case <-ctx.Done():
				return nil
			default:
			}

			wg.Add(1)
			sem <- struct{}{}

			go func(targetHost string, targetPort int) {
				defer wg.Done()
				defer func() { <-sem }()

				gov.Throttle()

				address := fmt.Sprintf("%s:%d", targetHost, targetPort)
				d := net.Dialer{Timeout: 2 * time.Second}
				conn, err := d.DialContext(ctx, "tcp", address)
				if err != nil {
					return
				}
				_ = conn.Close()

				mu.Lock()
				openPorts[targetHost] = append(openPorts[targetHost], targetPort)
				mu.Unlock()
			}(host, port)
		}
	}

	wg.Wait()

	totalOpen := 0
	for host, ports := range openPorts {
		sort.Ints(ports)
		totalOpen += len(ports)
		s.Printf("│  [+] %s: %d open web/admin port(s): %v\n", host, len(ports), ports)
		for _, port := range ports {
			scheme := "http"
			if port == 443 || port == 8443 || port == 9443 || port == 10443 {
				scheme = "https"
			}
			endpoint := fmt.Sprintf("%s://%s:%d", scheme, host, port)
			s.URLs = append(s.URLs, endpoint)
		}
	}

	s.Printf("│  Light Portscan: complete, found %d active port surface(s)\n", totalOpen)
	return nil
}

func cleanHost(raw string) string {
	raw = strings.TrimPrefix(raw, "http://")
	raw = strings.TrimPrefix(raw, "https://")
	if idx := strings.Index(raw, "/"); idx >= 0 {
		raw = raw[:idx]
	}
	if idx := strings.Index(raw, ":"); idx >= 0 {
		raw = raw[:idx]
	}
	return strings.TrimSpace(raw)
}
