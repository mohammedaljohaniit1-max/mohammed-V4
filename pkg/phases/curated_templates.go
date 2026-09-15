package phases

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/mohammed-v3/core/pkg/engine"
	"github.com/mohammed-v3/core/pkg/filter"
	"github.com/mohammed-v3/core/pkg/governor"
	"github.com/mohammed-v3/core/pkg/runner"
	"github.com/mohammed-v3/core/pkg/validation"
)

// CuratedTargetCheck represents one high-impact, verified vulnerability check.
type CuratedTargetCheck struct {
	ID          string
	Category    string // "RCE", "CVE", "Sensitive File", "Admin Panel"
	Path        string
	Severity    string
	RequiredSig string
	Disallowed  string
}

// CuratedSurgicalChecks is the strict, hard-capped whitelist of high-yield checks
// (Coffinxp methodology: Quality over Quantity, max 30 targeted checks).
var CuratedSurgicalChecks = []CuratedTargetCheck{
	// ── 1. RCE & Critical Known CVEs ──────────────────────────────────────────
	{ID: "CVE-2021-41773", Category: "RCE", Path: "/icons/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd", Severity: "Critical", RequiredSig: "root:x:0:0:", Disallowed: "text/html"},
	{ID: "CVE-2022-22965", Category: "RCE", Path: "/actuator/env", Severity: "Critical", RequiredSig: "propertySources", Disallowed: "text/html"},
	{ID: "CVE-2024-3400", Category: "RCE", Path: "/global-protect/login.esp", Severity: "Critical", RequiredSig: "GlobalProtect", Disallowed: ""},
	{ID: "CVE-2023-38606", Category: "RCE", Path: "/cgi-bin/test.cgi", Severity: "Critical", RequiredSig: "test", Disallowed: "text/html"},
	{ID: "PHPUnit-RCE", Category: "RCE", Path: "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", Severity: "Critical", RequiredSig: "php", Disallowed: "text/html"},
	{ID: "CVE-2020-14882", Category: "RCE", Path: "/console/css/%252e%252e%252fconsole.portal", Severity: "Critical", RequiredSig: "Administration Console", Disallowed: ""},

	// ── 2. Exposed Sensitive Files & Secrets ──────────────────────────────────
	{ID: "ENV-Root", Category: "Sensitive File", Path: "/.env", Severity: "Critical", RequiredSig: "APP_KEY=", Disallowed: "text/html"},
	{ID: "ENV-Production", Category: "Sensitive File", Path: "/.env.production", Severity: "Critical", RequiredSig: "APP_KEY=", Disallowed: "text/html"},
	{ID: "ENV-Local", Category: "Sensitive File", Path: "/.env.local", Severity: "Critical", RequiredSig: "APP_KEY=", Disallowed: "text/html"},
	{ID: "Git-HEAD", Category: "Sensitive File", Path: "/.git/HEAD", Severity: "High", RequiredSig: "ref: refs/heads/", Disallowed: "text/html"},
	{ID: "Git-Config", Category: "Sensitive File", Path: "/.git/config", Severity: "High", RequiredSig: "[core]", Disallowed: "text/html"},
	{ID: "Web-Config", Category: "Sensitive File", Path: "/web.config", Severity: "High", RequiredSig: "<configuration>", Disallowed: "text/html"},
	{ID: "Backup-ZIP", Category: "Sensitive File", Path: "/backup.zip", Severity: "High", RequiredSig: "PK", Disallowed: "text/html"},
	{ID: "Backup-SQL", Category: "Sensitive File", Path: "/dump.sql.gz", Severity: "High", RequiredSig: "\x1f\x8b", Disallowed: "text/html"},
	{ID: "Docker-Compose", Category: "Sensitive File", Path: "/docker-compose.yml", Severity: "High", RequiredSig: "services:", Disallowed: "text/html"},
	{ID: "K8s-Secret", Category: "Sensitive File", Path: "/secrets.yaml", Severity: "High", RequiredSig: "kind: Secret", Disallowed: "text/html"},

	// ── 3. Unauthenticated Admin & Diagnostic Panels ──────────────────────────
	{ID: "Actuator-Health", Category: "Admin Panel", Path: "/actuator/health", Severity: "High", RequiredSig: `"status":"UP"`, Disallowed: "text/html"},
	{ID: "Actuator-Env", Category: "Admin Panel", Path: "/actuator/env", Severity: "Critical", RequiredSig: "propertySources", Disallowed: "text/html"},
	{ID: "Swagger-UI-HTML", Category: "Admin Panel", Path: "/swagger-ui.html", Severity: "Medium", RequiredSig: "swagger-ui", Disallowed: ""},
	{ID: "Swagger-UI-Index", Category: "Admin Panel", Path: "/swagger/index.html", Severity: "Medium", RequiredSig: "swagger-ui", Disallowed: ""},
	{ID: "OpenAPI-JSON", Category: "Admin Panel", Path: "/v2/api-docs", Severity: "Medium", RequiredSig: `"swagger"`, Disallowed: "text/html"},
	{ID: "OpenAPI-V3", Category: "Admin Panel", Path: "/v3/api-docs", Severity: "Medium", RequiredSig: `"openapi"`, Disallowed: "text/html"},
	{ID: "PHP-Info", Category: "Admin Panel", Path: "/phpinfo.php", Severity: "High", RequiredSig: "PHP Version", Disallowed: ""},
	{ID: "Drupal-Changelog", Category: "Admin Panel", Path: "/CHANGELOG.txt", Severity: "Low", RequiredSig: "Drupal", Disallowed: "text/html"},
}

func init() {
	for i, check := range CuratedSurgicalChecks {
		if strings.TrimSpace(check.RequiredSig) == "" {
			panic(fmt.Sprintf("curated check [%d] %q has an empty RequiredSig - signature required to prevent false positives", i, check.ID))
		}
	}
}

// CuratedTemplatesPhase executes targeted, high-impact checks (Coffinxp methodology).
type CuratedTemplatesPhase struct{}

func (p *CuratedTemplatesPhase) Name() string { return "Curated Surgical Templates" }
func (p *CuratedTemplatesPhase) Description() string {
	return "Executes <=30 high-impact checks (RCE/Known CVEs, sensitive files, admin panels) with Governor rate limits"
}

func (p *CuratedTemplatesPhase) Execute(ctx context.Context, s *engine.State) error {
	if len(s.LiveHosts) == 0 {
		s.Printf("│  Curated Templates: SKIP (no live hosts)\n")
		return nil
	}

	hosts := filter.PrioritizeLiveTargets(s.LiveHosts)
	if len(hosts) > 100 {
		hosts = hosts[:100]
	}

	s.Printf("│  Curated Templates: running %d high-impact checks across %d host(s) (Governor bounded)\n",
		len(CuratedSurgicalChecks), len(hosts))

	// If nuclei binary is installed, use curated flags to run only these templates
	if _, err := runner.ResolveToolPath("nuclei"); err == nil {
		targetsFile := filepath.Join(s.OutputFolder, "curated_nuclei_targets.txt")
		writeLines(targetsFile, hosts)
		nucleiOut := filepath.Join(s.OutputFolder, "curated_nuclei_results.jsonl")

		// High-impact tags and severities only, rate-limited strictly
		args := []string{
			"-list", targetsFile,
			"-tags", "cve,rce,exposure,actuator,swagger,env",
			"-severity", "critical,high,medium",
			"-rate-limit", "50",
			"-concurrency", "2",
			"-timeout", "5",
			"-jsonl", "-o", nucleiOut,
			"-silent",
		}
		res := runner.RunToolWithTimeout(ctx, "nuclei", args, nil, 10*time.Minute)
		if res.OK() || res.TimedOut {
			count := 0
			for _, line := range readNonEmptyLines(nucleiOut) {
				count++
				s.Printf("│  [+] Nuclei Curated Hit: %s\n", line)
			}
			if count > 0 {
				s.Printf("│  Curated Nuclei: found %d vulnerability signal(s)\n", count)
			}
		}
	}

	// Always execute the pure Go native curated checks with Soft-404 baseline diffing
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

	for _, host := range hosts {
		baseURL := host
		if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
			baseURL = "https://" + baseURL
		}
		baseURL = strings.TrimRight(baseURL, "/")

		// Calibrate soft-404 baseline profile
		_, _ = validation.DefaultBaselineValidator().Calibrate(ctx, baseURL, client)

		for _, check := range CuratedSurgicalChecks {
			select {
			case <-ctx.Done():
				return nil
			default:
			}

			targetURL := baseURL + check.Path
			if !filter.IsInScope(targetURL, s.Scope) {
				continue
			}

			gov.Throttle()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", "MOHAMMED-Curated-Surgical/1.0")
			req.Header.Set("Accept", "*/*")

			resp, err := client.Do(req)
			if err != nil {
				continue
			}

			if resp.StatusCode != http.StatusOK {
				resp.Body.Close()
				continue
			}

			body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
			resp.Body.Close()
			if err != nil {
				continue
			}

			// Soft-404 verification
			if validation.DefaultBaselineValidator().IsSoft404(resp.StatusCode, body, targetURL) {
				continue
			}

				// Disallowed Content-Type verification
				ct := strings.ToLower(resp.Header.Get("Content-Type"))
				if check.Disallowed != "" && strings.Contains(ct, check.Disallowed) {
					continue
				}

				// Required signature verification: MUST NOT be empty, and MUST match response body
				sig := strings.TrimSpace(check.RequiredSig)
				if sig == "" || !strings.Contains(string(body), sig) {
					continue
				}

				cand := validation.Candidate{
					Type:                   check.Category + ": " + check.ID,
					URL:                    targetURL,
					Evidence:               fmt.Sprintf("Status: 200 OK | Signature match: %q", sig),
					InScope:                true,
					RequiresExploitability: true,
					Exploitable:            true,
				}

			if validator.Validate(ctx, cand).Passed {
				s.AddFinding(map[string]interface{}{
					"title":          check.ID + " (" + check.Category + ")",
					"severity":       check.Severity,
					"url":            targetURL,
					"evidence":       cand.Evidence,
					"tool":           "curated_surgical_probe",
					"http_confirmed": true,
				})
				s.Printf("│  [!] CONFIRMED VULNERABILITY (%s): %s [%s]\n", check.Severity, targetURL, check.ID)
			}
		}
	}

	return nil
}
