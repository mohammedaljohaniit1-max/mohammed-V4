package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mohammed-v3/core/pkg/engine"
)

// SARIFReport represents the root OASIS SARIF v2.1.0 standard schema.
type SARIFReport struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool      SARIFTool     `json:"tool"`
	Results   []SARIFResult `json:"results"`
	Artifacts []SARIFArtifact `json:"artifacts,omitempty"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []SARIFRule `json:"rules"`
}

type SARIFRule struct {
	ID               string              `json:"id"`
	Name             string              `json:"name"`
	ShortDescription SARIFMessage        `json:"shortDescription"`
	DefaultConfig    SARIFRuleConfig     `json:"defaultConfiguration"`
	Properties       map[string]string   `json:"properties,omitempty"`
}

type SARIFRuleConfig struct {
	Level string `json:"level"` // "error", "warning", "note"
}

type SARIFMessage struct {
	Text string `json:"text"`
}

type SARIFResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   SARIFMessage    `json:"message"`
	Locations []SARIFLocation `json:"locations,omitempty"`
}

type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
}

type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

type SARIFArtifact struct {
	Location SARIFArtifactLocation `json:"location"`
}

// MapSeverityToSARIFLevel converts finding severities to SARIF standard levels.
func MapSeverityToSARIFLevel(sev string) string {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

// GenerateSARIFReport serializes engine state findings into OASIS SARIF v2.1.0.
func GenerateSARIFReport(s *engine.State) ([]byte, error) {
	driver := SARIFDriver{
		Name:           "MOHAMMED-V4",
		Version:        "12.6.0",
		InformationURI: "https://github.com/mohammedaljohaniit1-max/mohammed-V4",
		Rules:          make([]SARIFRule, 0),
	}

	results := make([]SARIFResult, 0)
	ruleMap := make(map[string]bool)

	for _, f := range s.Findings {
		title := fmt.Sprintf("%v", f["title"])
		urlStr := fmt.Sprintf("%v", f["url"])
		sev := fmt.Sprintf("%v", f["severity"])
		tool := fmt.Sprintf("%v", f["tool"])
		ev := fmt.Sprintf("%v", f["evidence"])

		ruleID := strings.ReplaceAll(strings.ToLower(title), " ", "-")
		if !ruleMap[ruleID] {
			ruleMap[ruleID] = true
			driver.Rules = append(driver.Rules, SARIFRule{
				ID:   ruleID,
				Name: title,
				ShortDescription: SARIFMessage{
					Text: fmt.Sprintf("%s discovered by %s", title, tool),
				},
				DefaultConfig: SARIFRuleConfig{
					Level: MapSeverityToSARIFLevel(sev),
				},
			})
		}

		results = append(results, SARIFResult{
			RuleID: ruleID,
			Level:  MapSeverityToSARIFLevel(sev),
			Message: SARIFMessage{
				Text: fmt.Sprintf("[%s] %s at %s. Evidence: %s", sev, title, urlStr, ev),
			},
			Locations: []SARIFLocation{
				{
					PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{
							URI: urlStr,
						},
					},
				},
			},
		})
	}

	report := SARIFReport{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: driver,
				},
				Results: results,
			},
		},
	}

	return json.MarshalIndent(report, "", "  ")
}

// ExportSARIFAndMarkdown exports results.sarif and executive_summary.md alongside standard json.
func ExportSARIFAndMarkdown(s *engine.State, outDir string) error {
	sarifData, err := GenerateSARIFReport(s)
	if err != nil {
		return err
	}

	sarifPath := filepath.Join(outDir, "results.sarif")
	if err := os.WriteFile(sarifPath, sarifData, 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", sarifPath, err)
	}

	// Generate executive_summary.md
	var md strings.Builder
	md.WriteString("# MOHAMMED-V4 Executive Security Assessment Report\n\n")
	md.WriteString(fmt.Sprintf("**Assessment Date:** %s\n", time.Now().UTC().Format(time.RFC3339)))
	md.WriteString(fmt.Sprintf("**Target Scope:** %s\n", strings.Join(s.Scope.Domains, ", ")))
	md.WriteString(fmt.Sprintf("**Total Findings:** %d\n\n", len(s.Findings)))
	md.WriteString("## Vulnerability Inventory\n\n")
	md.WriteString("| Severity | Title | Endpoint | Tool | Evidence |\n")
	md.WriteString("|---|---|---|---|---|\n")

	for _, f := range s.Findings {
		title := fmt.Sprintf("%v", f["title"])
		urlStr := fmt.Sprintf("%v", f["url"])
		sev := fmt.Sprintf("%v", f["severity"])
		tool := fmt.Sprintf("%v", f["tool"])
		ev := fmt.Sprintf("%v", f["evidence"])
		md.WriteString(fmt.Sprintf("| %s | %s | %s | %s | `%s` |\n", sev, title, urlStr, tool, ev))
	}

	mdPath := filepath.Join(outDir, "executive_summary.md")
	return os.WriteFile(mdPath, []byte(md.String()), 0644)
}
