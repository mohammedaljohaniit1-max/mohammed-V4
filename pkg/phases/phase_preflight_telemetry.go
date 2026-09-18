package phases

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mohammed-v3/core/pkg/beacon"
	"github.com/mohammed-v3/core/pkg/cache"
	"github.com/mohammed-v3/core/pkg/collector"
	"github.com/mohammed-v3/core/pkg/config"
	"github.com/mohammed-v3/core/pkg/contract"
	"github.com/mohammed-v3/core/pkg/engine"
	"github.com/mohammed-v3/core/pkg/filter"
	"github.com/mohammed-v3/core/pkg/ingress"
)

// PreFlightTelemetryPayload aggregates Phase 0 telemetry across all audited apex domains.
type PreFlightTelemetryPayload struct {
	ExecutedAt       time.Time                               `json:"executed_at"`
	TotalDiscovered  int                                     `json:"total_discovered_routes"`
	TotalCacheChecks int                                     `json:"total_cache_checks"`
	Reports          map[string]*collector.AuditReport       `json:"reports"`
	AggregatedRoutes []string                                `json:"aggregated_routes"`
	CacheConformance map[string]cache.CacheConformanceReport `json:"cache_conformance"`
}

// Global active correlator instance accessible across the scan lifecycle.
var (
	activeCorrelator *beacon.Correlator
)

// ActiveCorrelator returns the active beacon trace correlator for the running scan.
func ActiveCorrelator() *beacon.Correlator {
	if activeCorrelator == nil {
		activeCorrelator = beacon.NewCorrelator()
	}
	return activeCorrelator
}

// PreFlightTelemetryPhase implements Phase 0: Pre-Flight Telemetry & Asset Enrichment.
// It executes standalone SRE ingress checks, JS bundle and map route extraction,
// and RFC 7234 cache conformance validation, injecting discovered routes into the pipeline.
type PreFlightTelemetryPhase struct{}

func (p *PreFlightTelemetryPhase) Name() string {
	return "Phase 0: Pre-Flight Telemetry & Asset Enrichment"
}

func (p *PreFlightTelemetryPhase) Description() string {
	return "Non-invasive SRE ingress verification, JS/.map route discovery, RFC 7234 cache evaluation, and trace correlation"
}

func (p *PreFlightTelemetryPhase) Execute(ctx context.Context, s *engine.State) error {
	correlator := ActiveCorrelator()

	// Determine in-scope targets for Pre-Flight Telemetry
	apexes := config.ApexDomainsForEnum(s.Scope.Domains, s.Scope.ExcludeDomains)
	if len(apexes) == 0 && len(s.Scope.Domains) > 0 {
		apexes = s.Scope.Domains
	}

	auditDir := filepath.Join(s.OutputFolder, "telemetry")
	_ = os.MkdirAll(auditDir, 0755)

	auditEngine := collector.NewUnifiedAuditEngine(5*time.Second, auditDir)

	payload := &PreFlightTelemetryPayload{
		ExecutedAt:       time.Now(),
		Reports:          make(map[string]*collector.AuditReport),
		AggregatedRoutes: make([]string, 0),
		CacheConformance: make(map[string]cache.CacheConformanceReport),
	}

	// Initial seeds or bundles if present
	var initialBundles []string

	for _, apex := range apexes {
		targetHost := apex
		if !strings.HasPrefix(targetHost, "http://") && !strings.HasPrefix(targetHost, "https://") {
			targetHost = "https://" + targetHost
		}

		report, err := auditEngine.ExecuteAudit(ctx, targetHost, initialBundles)
		if err != nil {
			s.Printf("│  [Pre-Flight Telemetry] Target %s error: %v\n", apex, err)
			continue
		}

		payload.Reports[apex] = report

		// Ingress metrics display
		tlsStatus := "Invalid/Untrusted"
		serverBanner := "Unknown"
		latency := "0ms"

		if report.IngressHealth != nil {
			if report.IngressHealth.CertSubject != "" || report.IngressHealth.Healthy {
				tlsStatus = "TLS Valid"
			}
			if report.IngressHealth.ServerHeader != "" {
				serverBanner = report.IngressHealth.ServerHeader
			}
			latency = fmt.Sprintf("%v", report.IngressHealth.Latency)
		}

		// Connect discovered routes to URL corpus
		addedCount := 0
		for _, r := range report.DiscoveredRoutes {
			payload.AggregatedRoutes = append(payload.AggregatedRoutes, r)
			// Construct absolute canonical URL
			fullURL := fmt.Sprintf("%s%s", targetHost, r)
			if u, err := url.Parse(fullURL); err == nil {
				cleanURL := u.String()
				if filter.IsInScope(cleanURL, s.Scope) {
					s.AddURL(cleanURL)
					addedCount++
				}
			}
		}

		for pathKey, cc := range report.CacheReports {
			payload.CacheConformance[targetHost+pathKey] = cc
		}

		// Visual UI block as specified
		s.Printf("╭─ PHASE 0: PRE-FLIGHT TELEMETRY & ASSET ENRICHMENT ────────────────\n")
		s.Printf("│  Target           : %s\n", apex)
		s.Printf("│  Ingress Health   : [%s | Server: %s | Latency: %s]\n", tlsStatus, serverBanner, latency)
		s.Printf("│  Client Asset Map : %d internal API routes recovered from JS/.map\n", len(report.DiscoveredRoutes))
		s.Printf("│  Cache Evaluation : %d routes analyzed for RFC 7234 conformance\n", len(report.CacheReports))
		s.Printf("│  Beacon Correlator: ACTIVE (in-memory asynchronous tracking)\n")
		s.Printf("╰───────────────────────────────────────────────────────────────────\n")
	}

	payload.TotalDiscovered = len(payload.AggregatedRoutes)
	payload.TotalCacheChecks = len(payload.CacheConformance)

	// Persist complete audit output to output/<target>/audit_telemetry.json
	telemetryFile := filepath.Join(s.OutputFolder, "audit_telemetry.json")
	if data, err := json.MarshalIndent(payload, "", "  "); err == nil {
		_ = os.WriteFile(telemetryFile, data, 0644)
	}

	// Register a baseline trace token for verification
	if _, err := correlator.Register("phase0_preflight"); err == nil {
		s.Printf("│  [+] Active trace token primed for background correlation\n")
	}

	return nil
}

// Compile-time interface check
var _ engine.Phase = (*PreFlightTelemetryPhase)(nil)
var _ = (*contract.TestResult)(nil)
var _ = (*ingress.EndpointHealth)(nil)
