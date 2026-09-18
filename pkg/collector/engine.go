package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/mohammed-v3/core/pkg/beacon"
	"github.com/mohammed-v3/core/pkg/cache"
	"github.com/mohammed-v3/core/pkg/contract"
	"github.com/mohammed-v3/core/pkg/drift"
	"github.com/mohammed-v3/core/pkg/ingress"
)

// AuditReport summarizes the quality assurance, asset inventory, cache evaluation, and contract testing results.
type AuditReport struct {
	TargetHost       string                                  `json:"target_host"`
	IngressHealth    *ingress.EndpointHealth                 `json:"ingress_health"`
	DiscoveredRoutes []string                                `json:"discovered_routes"`
	ContractResults  []*contract.TestResult                  `json:"contract_results"`
	CacheReports     map[string]cache.CacheConformanceReport `json:"cache_reports,omitempty"`
	ExecutedAt       time.Time                               `json:"executed_at"`
	ExecutionSuccess bool                                    `json:"execution_success"`
	Summary          string                                  `json:"summary"`
}

// UnifiedAuditEngine coordinates non-invasive ingress monitoring, frontend route discovery, contract boundary testing, and beacon/cache telemetry.
type UnifiedAuditEngine struct {
	mu             sync.RWMutex
	monitor        *ingress.IngressMonitor
	routeParser    *drift.RouteParser
	correlator     *beacon.Correlator
	outputDir      string
	defaultTimeout time.Duration
}

// NewUnifiedAuditEngine instantiates a UnifiedAuditEngine.
func NewUnifiedAuditEngine(timeout time.Duration, outputDir string) *UnifiedAuditEngine {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if outputDir == "" {
		outputDir = "output"
	}
	return &UnifiedAuditEngine{
		monitor:        ingress.NewIngressMonitor(timeout),
		routeParser:    drift.NewRouteParser(),
		correlator:     beacon.NewCorrelator(),
		outputDir:      outputDir,
		defaultTimeout: timeout,
	}
}

// Correlator returns the underlying asynchronous trace correlator.
func (e *UnifiedAuditEngine) Correlator() *beacon.Correlator {
	return e.correlator
}

// ParseBundles inspects provided JavaScript bundle contents and returns all identified API routes.
func (e *UnifiedAuditEngine) ParseBundles(bundles []string) []string {
	seen := make(map[string]bool)
	var routes []string

	for idx, bundleContent := range bundles {
		name := fmt.Sprintf("bundle_%d.js", idx)
		extracted := e.routeParser.ParseBundle(bundleContent, name)
		for _, r := range extracted {
			if !seen[r.Path] {
				seen[r.Path] = true
				routes = append(routes, r.Path)
			}
		}
	}
	return routes
}

// ExecuteAudit runs ingress verification, catalogs routes from bundles, saves output/routes.json, and executes boundary and cache conformance tests.
func (e *UnifiedAuditEngine) ExecuteAudit(ctx context.Context, targetHost string, jsBundles []string) (*AuditReport, error) {
	report := &AuditReport{
		TargetHost:   targetHost,
		ExecutedAt:   time.Now(),
		CacheReports: make(map[string]cache.CacheConformanceReport),
	}

	callCtx, cancel := context.WithTimeout(ctx, e.defaultTimeout*3)
	defer cancel()

	// 1. Ingress & TLS Verification
	report.IngressHealth = e.monitor.CheckEndpoint(callCtx, targetHost)

	// 2. Frontend Asset Route Extraction
	discovered := e.ParseBundles(jsBundles)
	report.DiscoveredRoutes = discovered

	// Save catalog to output/routes.json
	_ = os.MkdirAll(e.outputDir, 0755)
	routesFilePath := filepath.Join(e.outputDir, "routes.json")
	if routesData, err := json.MarshalIndent(discovered, "", "  "); err == nil {
		_ = os.WriteFile(routesFilePath, routesData, 0644)
	}

	// 3. API Contract Conformance & Cache Conformance Testing
	baseURL := targetHost
	if baseURL != "" {
		client := contract.NewContractClient(baseURL, e.defaultTimeout)
		var suite []contract.TestCase

		// Create standard boundary test cases for discovered routes
		for _, r := range discovered {
			suite = append(suite, contract.TestCase{
				Name:             "boundary_malformed_input_" + r,
				Method:           http.MethodPost,
				Path:             r,
				Payload:          map[string]interface{}{"amount": -1, "id": ""},
				ExpectedStatuses: []int{http.StatusBadRequest, http.StatusUnprocessableEntity, http.StatusNotFound, http.StatusMethodNotAllowed},
			})
		}

		if len(suite) > 0 {
			results := client.RunSuite(callCtx, suite)
			report.ContractResults = results

			// Also perform defensive RFC 7234 cache header evaluation on discovered routes
			httpClient := &http.Client{Timeout: e.defaultTimeout}
			for _, r := range discovered {
				reqURL := fmt.Sprintf("%s%s", baseURL, r)
				req, reqErr := http.NewRequestWithContext(callCtx, http.MethodGet, reqURL, nil)
				if reqErr == nil {
					resp, respErr := httpClient.Do(req)
					if respErr == nil {
						report.CacheReports[r] = cache.EvaluateResponseHeaders(resp.Header)
						resp.Body.Close()
					}
				}
			}
		}
	}

	report.ExecutionSuccess = true
	report.Summary = fmt.Sprintf("Audit completed. Health: %v. Discovered Routes: %d. Contract Tests Executed: %d. Cache Checks: %d",
		report.IngressHealth.Healthy, len(report.DiscoveredRoutes), len(report.ContractResults), len(report.CacheReports))

	return report, nil
}
