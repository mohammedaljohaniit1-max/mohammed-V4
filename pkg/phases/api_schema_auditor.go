package phases

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/mohammed-v3/core/pkg/engine"
	"github.com/mohammed-v3/core/pkg/filter"
	"github.com/mohammed-v3/core/pkg/governor"
)

// APISchemaAuditorPhase recursively parses discovered OpenAPI/Swagger schemas,
// extracts paths and HTTP methods, and audits administrative/sensitive endpoints
// for broken authentication and BOLA/IDOR parameters.
type APISchemaAuditorPhase struct{}

func (p *APISchemaAuditorPhase) Name() string { return "API Schema Auditor" }
func (p *APISchemaAuditorPhase) Description() string {
	return "Recursive in-memory OpenAPI/Swagger schema parser, privilege checks & BOLA/IDOR parameter discovery"
}

// openAPISchema represents a minimal OpenAPI / Swagger v2 / v3 JSON document.
type openAPISchema struct {
	Swagger string                                     `json:"swagger"`
	OpenAPI string                                     `json:"openapi"`
	Paths   map[string]map[string]openAPIOperationSpec `json:"paths"`
}

type openAPIOperationSpec struct {
	Summary     string        `json:"summary"`
	OperationID string        `json:"operationId"`
	Parameters  []interface{} `json:"parameters"`
}

// sensitivePathKeywords are route tokens indicating administrative, internal, or privileged operations.
var sensitivePathKeywords = []string{
	"mgmt", "admin", "user", "delete", "create", "token", "export", "config", "internal",
}

func isPrivilegedRoute(route string) bool {
	lower := strings.ToLower(route)
	for _, kw := range sensitivePathKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

func containsBOLAIdentifier(route string) (bool, string) {
	// Look for {id}, {userId}, {uimUserId}, {campaignKey}, etc.
	start := strings.Index(route, "{")
	end := strings.Index(route, "}")
	if start != -1 && end != -1 && end > start {
		param := route[start+1 : end]
		return true, param
	}
	return false, ""
}

func (p *APISchemaAuditorPhase) Execute(ctx context.Context, s *engine.State) error {
	if len(s.LiveHosts) == 0 {
		s.Printf("│  API Schema Auditor: SKIP (no live hosts)\n")
		return nil
	}

	s.Printf("│  API Schema Auditor: probing OpenAPI/Swagger schemas across live targets\n")

	// Schema probe candidates
	schemaPaths := []string{
		"/v3/api-docs",
		"/v2/api-docs",
		"/swagger.json",
		"/openapi.json",
		"/api/swagger.json",
		"/api/v3/api-docs",
		"/docs/swagger.json",
	}

	gov := governor.NewGovernor(2,
		governor.WithMaxRPS(2.0),
		governor.WithConcurrency(2),
		governor.WithJitter(150*time.Millisecond, 300*time.Millisecond),
	)

	client := gov.WrapClient(&http.Client{
		Timeout: 8 * time.Second,
	})

	hosts := filter.PrioritizeLiveTargets(s.LiveHosts)
	var discoveredSchemas []string

	for _, host := range hosts {
		baseURL := host
		if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
			baseURL = "https://" + baseURL
		}
		baseURL = strings.TrimRight(baseURL, "/")

		for _, sp := range schemaPaths {
			select {
			case <-ctx.Done():
				return nil
			default:
			}

			targetURL := baseURL + sp
			if !filter.IsInScope(targetURL, s.Scope) {
				continue
			}

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", "MOHAMMED-API-Auditor/1.0")
			req.Header.Set("Accept", "application/json, text/plain, */*")

			resp, err := client.Do(req)
			if err != nil {
				continue
			}

			if resp.StatusCode == http.StatusOK {
				body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024)) // 2MB limit
				resp.Body.Close()
				if err != nil {
					continue
				}

				var schema openAPISchema
				if err := json.Unmarshal(body, &schema); err == nil && len(schema.Paths) > 0 {
					s.Printf("│  [+] Discovered valid OpenAPI schema at %s (%d routes)\n", targetURL, len(schema.Paths))
					discoveredSchemas = append(discoveredSchemas, targetURL)
					p.auditSchema(ctx, s, baseURL, schema, client)
				}
			} else {
				resp.Body.Close()
			}
		}
	}

	s.Printf("│  API Schema Auditor: audited %d discovered schema(s)\n", len(discoveredSchemas))
	return nil
}

func (p *APISchemaAuditorPhase) auditSchema(ctx context.Context, s *engine.State, baseURL string, schema openAPISchema, client *http.Client) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, 2) // bounded concurrency

	for route, methods := range schema.Paths {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// 1. Check for BOLA / IDOR parameter indicators
		if hasBOLA, paramName := containsBOLAIdentifier(route); hasBOLA {
			fullURL := baseURL + route
			s.AddFinding(map[string]interface{}{
				"title":      "API Object-Level Identifier Parameter (Potential BOLA/IDOR)",
				"severity":   "Medium",
				"url":        fullURL,
				"evidence":   fmt.Sprintf("Route defines identifier parameter {%s} requiring authorization verification", paramName),
				"tool":       "api_schema_auditor",
				"confidence": 75,
			})
		}

		// 2. Sensitive / Admin route privilege check
		if isPrivilegedRoute(route) {
			// Probe only GET or parameter-less routes
			for method := range methods {
				upperMethod := strings.ToUpper(method)
				if upperMethod != "GET" && upperMethod != "OPTIONS" {
					continue
				}

				// If route contains parameters like {id}, skip blind active request to avoid 404/500
				if strings.Contains(route, "{") {
					continue
				}

				targetURL := baseURL + route
				if !filter.IsInScope(targetURL, s.Scope) {
					continue
				}

				wg.Add(1)
				sem <- struct{}{}

				go func(targetMethod, u string) {
					defer wg.Done()
					defer func() { <-sem }()

					req, err := http.NewRequestWithContext(ctx, targetMethod, u, nil)
					if err != nil {
						return
					}
					req.Header.Set("User-Agent", "MOHAMMED-API-Auditor/1.0")
					req.Header.Set("Accept", "application/json")

					resp, err := client.Do(req)
					if err != nil {
						return
					}
					defer resp.Body.Close()

					// Check if privileged endpoint returns 200 OK without authentication
					if resp.StatusCode == http.StatusOK {
						cType := resp.Header.Get("Content-Type")
						body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
						if err != nil {
							return
						}

						// Validate response is actual JSON data object and not a generic login redirect/HTML
						if strings.Contains(cType, "application/json") && len(body) > 2 {
							trimmed := strings.TrimSpace(string(body))
							if (strings.HasPrefix(trimmed, "{") && strings.HasSuffix(trimmed, "}")) ||
								(strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]")) {
								
								// Ensure not generic error or login prompt
								if !strings.Contains(trimmed, `"login"`) && !strings.Contains(trimmed, `"unauthorized"`) {
									parsedURL, _ := url.Parse(u)
									findingPath := u
									if parsedURL != nil {
										findingPath = parsedURL.Path
									}

									s.AddFinding(map[string]interface{}{
										"title":      fmt.Sprintf("Broken Authentication / Unprotected Management Endpoint: %s", findingPath),
										"severity":   "High",
										"url":        u,
										"evidence":   fmt.Sprintf("Status: 200 OK | Content-Type: %s | Response payload length: %d bytes", cType, len(body)),
										"tool":       "api_schema_auditor",
										"confidence": 85,
										"http_confirmed": true,
									})
								}
							}
						}
					}
				}(upperMethod, targetURL)
				break // probe one method per route
			}
		}
	}
	wg.Wait()
}
