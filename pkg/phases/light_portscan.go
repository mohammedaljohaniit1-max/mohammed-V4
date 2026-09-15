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
	// Database & cache interfaces with web dashboards
	1433, 1521, 3306, 3389, 5432, 5984, 6379, 7474, 8098, 11211,
	// CI/CD & diagnostics
	8084, 8088, 8099, 8161, 8888, 8983, 9002, 9003, 9080, 9100,
	// Remote access & control
	2082, 2083, 2086, 2087, 2095, 2096, 2222, 5601, 7002, 7003,
}

// LightPortScanPhase executes targeted Top-100 port checks on IP-deduplicated targets
// using an asynchronous connect pool with a 500ms socket timeout.
type LightPortScanPhase struct{}

func (p *LightPortScanPhase) Name() string { return "High-Speed IP-Deduplicated Port Scanner" }
func (p *LightPortScanPhase) Description() string {
	return "Resolves subdomains to unique IPv4s, deduplicates edge IPs, and scans Top-100 web/admin ports via a 20-worker asynchronous dial pool (<=500ms socket timeout)"
}

func (p *LightPortScanPhase) Execute(ctx context.Context, s *engine.State) error {
	if len(s.LiveHosts) == 0 && len(s.Subdomains) == 0 {
		s.Printf("│  Light Portscan: SKIP (no live hosts or subdomains)\n")
		return nil
	}

	targets := s.LiveHosts
	if len(targets) == 0 {
		targets = s.Subdomains
	}
	hosts := filter.PrioritizeLiveTargets(targets)

	s.Printf("│  Light Portscan: resolving and deduplicating IP addresses for %d target host(s)...\n", len(hosts))

	// 1. IP Deduplication Engine
	ipToHosts := make(map[string][]string)
	var ipList []string

	for _, rawHost := range hosts {
		clean := cleanHost(rawHost)
		if clean == "" {
			continue
		}

		// Resolve host IPv4 addresses
		ips, err := net.LookupIP(clean)
		if err != nil {
			continue
		}

		for _, ip := range ips {
			ipv4 := ip.To4()
			if ipv4 == nil {
				continue
			}
			ipStr := ipv4.String()
			if len(ipToHosts[ipStr]) == 0 {
				ipList = append(ipList, ipStr)
			}
			ipToHosts[ipStr] = append(ipToHosts[ipStr], clean)
		}
	}

	if len(ipList) == 0 {
		s.Printf("│  Light Portscan: no resolvable IPv4 addresses discovered\n")
		return nil
	}

	s.Printf("│  Light Portscan: deduplicated %d hosts -> %d unique IP address(es)\n", len(hosts), len(ipList))

	// 2. Asynchronous Connect Pool (20 concurrent dialers, 500ms timeout per socket)
	workerCount := 20
	if len(ipList) < workerCount {
		workerCount = len(ipList)
	}
	if workerCount < 5 {
		workerCount = 5
	}

	sem := make(chan struct{}, workerCount)
	var (
		mu        sync.Mutex
		wg        sync.WaitGroup
		openPorts = make(map[string][]int) // IP -> open ports
	)

	// Bounded governor rate
	gov := governor.NewGovernor(20,
		governor.WithMaxRPS(50.0),
		governor.WithConcurrency(workerCount),
		governor.WithJitter(5*time.Millisecond, 20*time.Millisecond),
	)

	startTime := time.Now()

	for _, ip := range ipList {
		for _, port := range Top100WebAdminPorts {
			select {
			case <-ctx.Done():
				return nil
			default:
			}

			wg.Add(1)
			sem <- struct{}{}

			go func(targetIP string, targetPort int) {
				defer wg.Done()
				defer func() { <-sem }()

				gov.Throttle()

				address := fmt.Sprintf("%s:%d", targetIP, targetPort)
				d := net.Dialer{Timeout: 500 * time.Millisecond}
				conn, err := d.DialContext(ctx, "tcp", address)
				if err != nil {
					return
				}
				_ = conn.Close()

				mu.Lock()
				openPorts[targetIP] = append(openPorts[targetIP], targetPort)
				mu.Unlock()
			}(ip, port)
		}
	}

	wg.Wait()
	duration := time.Since(startTime).Round(time.Millisecond)

	// 3. Map open ports back to the associated virtual hostnames for HTTP verification
	totalOpen := 0
	for ip, ports := range openPorts {
		sort.Ints(ports)
		totalOpen += len(ports)
		associatedHosts := ipToHosts[ip]

		s.Printf("│  [+] IP %s open port(s): %v (hosts: %s)\n", ip, ports, strings.Join(associatedHosts, ", "))

		for _, port := range ports {
			scheme := "http"
			if port == 443 || port == 8443 || port == 9443 || port == 10443 {
				scheme = "https"
			}

			for _, host := range associatedHosts {
				endpoint := fmt.Sprintf("%s://%s:%d", scheme, host, port)
				s.AddURL(endpoint)
			}
		}
	}

	s.Printf("│  Light Portscan: scan complete in %v, identified %d open port surface(s)\n", duration, totalOpen)
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
