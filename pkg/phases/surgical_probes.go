package phases

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/mohammed-v3/core/pkg/engine"
	"github.com/mohammed-v3/core/pkg/filter"
	"github.com/mohammed-v3/core/pkg/governor"
	"github.com/mohammed-v3/core/pkg/validation"
)

// SurgicalProbesPhase executes native, lightweight, single-request probes
// for critical high-impact surfaces without running heavy third-party scanners.
type SurgicalProbesPhase struct{}

func (p *SurgicalProbesPhase) Name() string { return "Native Surgical Probes" }
func (p *SurgicalProbesPhase) Description() string {
	return "Direct, single-request high-impact checks (.env, .git, actuator, swagger, web.config) with <=2 concurrency & governor pacing"
}

type surgicalProbeTarget struct {
	Path        string
	Type        string
	Severity    string
	RequiredSig string
}

var surgicalProbeList = []surgicalProbeTarget{
	{Path: "/.env", Type: "Exposed Environment File", Severity: "Critical", RequiredSig: "APP_KEY="},
	{Path: "/.env.production", Type: "Exposed Production Env", Severity: "Critical", RequiredSig: "APP_KEY="},
	{Path: "/.git/HEAD", Type: "Exposed Git Repository", Severity: "High", RequiredSig: "ref: refs/heads/"},
	{Path: "/.git/config", Type: "Exposed Git Configuration", Severity: "High", RequiredSig: "[core]"},
	{Path: "/actuator/health", Type: "Exposed Spring Actuator Diagnostic", Severity: "High", RequiredSig: `"status":"UP"`},
	{Path: "/swagger-ui.html", Type: "Exposed Swagger UI Documentation", Severity: "Medium", RequiredSig: "swagger-ui"},
	{Path: "/web.config", Type: "Exposed IIS Web Configuration", Severity: "High", RequiredSig: "<configuration>"},
}

func (p *SurgicalProbesPhase) Execute(ctx context.Context, s *engine.State) error {
	if len(s.LiveHosts) == 0 {
		s.Printf("│  Surgical Probes: SKIP (no live hosts)\n")
		return nil
	}

	// Always prioritize staging, dev, and internal hosts first
	hosts := filter.PrioritizeLiveTargets(s.LiveHosts)
	s.Printf("│  Surgical Probes: running native checks across %d live hosts (concurrency <= 2, 500ms floor)\n", len(hosts))

	// Enterprise governor: max 2 requests/sec, concurrency <= 2, 200-400ms jitter
	gov := governor.NewGovernor(2,
		governor.WithMaxRPS(2.0),
		governor.WithConcurrency(2),
		governor.WithJitter(200*time.Millisecond, 400*time.Millisecond),
	)

	client := gov.WrapClient(&http.Client{
		Timeout: 10 * time.Second,
	})

	validator := validation.NewFPValidator(func(rawURL string) bool {
		return filter.IsInScope(rawURL, s.Scope)
	})

	var wg sync.WaitGroup
	sem := make(chan struct{}, 2) // Concurrency bounded strictly <= 2

	for _, host := range hosts {
		baseURL := host
		if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
			baseURL = "https://" + baseURL
		}
		baseURL = strings.TrimRight(baseURL, "/")

		// Calibrate soft-404 baseline for this origin
		_, _ = validation.DefaultBaselineValidator().Calibrate(ctx, baseURL, client)

		for _, probe := range surgicalProbeList {
			select {
			case <-ctx.Done():
				return nil
			default:
			}

			probeURL := baseURL + probe.Path
			if !filter.IsInScope(probeURL, s.Scope) {
				continue
			}

			wg.Add(1)
			sem <- struct{}{}

			go func(u string, target surgicalProbeTarget) {
				defer wg.Done()
				defer func() { <-sem }()

				req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
				if err != nil {
					return
				}
				req.Header.Set("User-Agent", "MOHAMMED-Safe-SurgicalProbe/1.0")
				req.Header.Set("Accept", "*/*")

				resp, err := client.Do(req)
				if err != nil {
					return
				}
				defer resp.Body.Close()

				if resp.StatusCode != http.StatusOK {
					return
				}

				bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
				if err != nil {
					return
				}

				// Soft-404 verification
				if validation.DefaultBaselineValidator().IsSoft404(resp.StatusCode, bodyBytes, u) {
					return
				}

				// Exact token and content-type verification
				contentType := resp.Header.Get("Content-Type")
				ok, _ := validation.ExactTokenCheck(target.Type, u, resp.StatusCode, bodyBytes, contentType)
				if !ok {
					return
				}

				// Check required signature substring
				if target.RequiredSig != "" && !strings.Contains(string(bodyBytes), target.RequiredSig) {
					return
				}

				cand := validation.Candidate{
					Type:                   target.Type,
					URL:                    u,
					Evidence:               fmt.Sprintf("Status: 200 OK | Signature match: %q", target.RequiredSig),
					InScope:                true,
					RequiresExploitability: true,
					Exploitable:            true,
					SkipReproduce:          false,
				}

				verdict := validator.Validate(ctx, cand)
				if verdict.Passed {
					s.AddFinding(map[string]interface{}{
						"title":          target.Type,
						"severity":       target.Severity,
						"url":            u,
						"evidence":       cand.Evidence,
						"tool":           "native_surgical_probe",
						"http_confirmed": true,
					})
					s.Printf("│  [!] CONFIRMED VULNERABILITY (%s): %s\n", target.Severity, u)
				}
			}(probeURL, probe)
		}
	}

	wg.Wait()
	return nil
}
