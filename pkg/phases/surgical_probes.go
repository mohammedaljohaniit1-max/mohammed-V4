package phases

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
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
	return "Direct, single-request high-impact checks with strict magic bytes, regex invariants and zero catch-all tolerance"
}

type surgicalProbeTarget struct {
	Path        string
	Type        string
	Severity    string
	RequiredSig string
	Validator   func(body []byte) bool
}

var (
	envRegex      = regexp.MustCompile(`(?m)^(?:APP_KEY|DB_PASSWORD|SECRET_KEY|DATABASE_URL|AWS_SECRET_ACCESS_KEY)=`)
	htpasswdRegex = regexp.MustCompile(`(?m)^[a-zA-Z0-9_\-\.]+:(?:\$apr1\$|\$2[ayb]\$|[a-zA-Z0-9\.\/]{13})`)
	zipMagicBytes = []byte{0x50, 0x4b, 0x03, 0x04} // PK\x03\x04
)

var surgicalProbeList = []surgicalProbeTarget{
	{
		Path:        "/.env",
		Type:        "Exposed Environment File",
		Severity:    "Critical",
		RequiredSig: "APP_KEY=",
		Validator: func(body []byte) bool {
			return envRegex.Match(body)
		},
	},
	{
		Path:        "/.env.production",
		Type:        "Exposed Production Env",
		Severity:    "Critical",
		RequiredSig: "APP_KEY=",
		Validator: func(body []byte) bool {
			return envRegex.Match(body)
		},
	},
	{
		Path:        "/.git/HEAD",
		Type:        "Exposed Git Repository",
		Severity:    "High",
		RequiredSig: "ref: refs/heads/",
		Validator: func(body []byte) bool {
			s := strings.TrimSpace(string(body))
			return strings.HasPrefix(s, "ref: refs/heads/") || strings.HasPrefix(s, "ref: refs/")
		},
	},
	{
		Path:        "/.git/config",
		Type:        "Exposed Git Configuration",
		Severity:    "High",
		RequiredSig: "[core]",
		Validator: func(body []byte) bool {
			return strings.Contains(string(body), "[core]") && strings.Contains(string(body), "repositoryformatversion")
		},
	},
	{
		Path:        "/.htpasswd",
		Type:        "Exposed Apache Htpasswd File",
		Severity:    "High",
		RequiredSig: ":$",
		Validator: func(body []byte) bool {
			return htpasswdRegex.Match(body)
		},
	},
	{
		Path:        "/backup.zip",
		Type:        "Exposed Archive Backup",
		Severity:    "High",
		RequiredSig: "PK",
		Validator: func(body []byte) bool {
			return len(body) >= 4 && bytes.Equal(body[:4], zipMagicBytes)
		},
	},
	{
		Path:        "/actuator/health",
		Type:        "Exposed Spring Actuator Diagnostic",
		Severity:    "High",
		RequiredSig: `"status":"UP"`,
		Validator: func(body []byte) bool {
			s := string(body)
			return (strings.Contains(s, `"status":"UP"`) || strings.Contains(s, `"status":"UNKNOWN"`)) &&
				strings.HasPrefix(strings.TrimSpace(s), "{")
		},
	},
	{
		Path:        "/swagger-ui.html",
		Type:        "Exposed Swagger UI Documentation",
		Severity:    "Medium",
		RequiredSig: "swagger-ui",
		Validator: func(body []byte) bool {
			s := string(body)
			return strings.Contains(s, "swagger-ui") && (strings.Contains(s, "SwaggerUIBundle") || strings.Contains(s, "swagger-ui.css"))
		},
	},
	{
		Path:        "/web.config",
		Type:        "Exposed IIS Web Configuration",
		Severity:    "High",
		RequiredSig: "<configuration>",
		Validator: func(body []byte) bool {
			s := string(body)
			return strings.Contains(s, "<configuration>") && strings.Contains(s, "<system.webServer>")
		},
	},
}

func (p *SurgicalProbesPhase) Execute(ctx context.Context, s *engine.State) error {
	if len(s.LiveHosts) == 0 {
		s.Printf("│  Surgical Probes: SKIP (no live hosts)\n")
		return nil
	}

	hosts := filter.PrioritizeLiveTargets(s.LiveHosts)
	s.Printf("│  Surgical Probes: running zero-tolerance checks across %d live hosts (concurrency <= 2, governor gated)\n", len(hosts))

	gov := governor.NewGovernor(2,
		governor.WithMaxRPS(2.0),
		governor.WithConcurrency(2),
		governor.WithJitter(150*time.Millisecond, 300*time.Millisecond),
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
				req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
				req.Header.Set("Accept", "*/*")

				resp, err := client.Do(req)
				if err != nil {
					return
				}
				defer resp.Body.Close()

				// Non-200 OK is immediately dropped
				if resp.StatusCode != http.StatusOK {
					return
				}

				bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
				if err != nil || len(bodyBytes) == 0 {
					return
				}

				// Soft-404 verification: catch-all 200 responses are SILENTLY DISCARDED
				if validation.DefaultBaselineValidator().IsSoft404(resp.StatusCode, bodyBytes, u) {
					return
				}

				// Exact token and content-type verification
				contentType := resp.Header.Get("Content-Type")
				ok, _ := validation.ExactTokenCheck(target.Type, u, resp.StatusCode, bodyBytes, contentType)
				if !ok {
					return
				}

				// Content Invariant & Magic Byte validation
				if target.Validator != nil {
					if !target.Validator(bodyBytes) {
						// Invariant failed (catch-all or custom error returning 200 OK) -> SILENTLY DISCARD
						return
					}
				} else if target.RequiredSig != "" && !strings.Contains(string(bodyBytes), target.RequiredSig) {
					return
				}

				cand := validation.Candidate{
					Type:                   target.Type,
					URL:                    u,
					Evidence:               fmt.Sprintf("Status: 200 OK | Strict Invariant Verified | Signature: %q", target.RequiredSig),
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
						"confidence":     95,
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
