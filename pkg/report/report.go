package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/mohammed-v3/core/pkg/engine"
)

type ReportSummary struct {
	Target       string                   `json:"target"`
	Timestamp    string                   `json:"timestamp"`
	Profile      string                   `json:"profile"`
	BurpProxy    string                   `json:"burp_proxy"`
	SubdomainCount int                    `json:"subdomain_count"`
	LiveHostCount  int                    `json:"live_host_count"`
	URLCount       int                    `json:"url_count"`
	ParamCount     int                    `json:"param_count"`
	FindingCount   int                    `json:"finding_count"`
	Findings     []map[string]interface{} `json:"findings"`
}

func GenerateMarkdown(state *engine.State) string {
	target := "Unknown"
	if len(state.Scope.Domains) > 0 {
		target = state.Scope.Domains[0]
	}

	counts := map[string]int{"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
	for _, f := range state.Findings {
		sev := fmt.Sprintf("%v", f["severity"])
		counts[sev]++
	}

	md := "# 🛡️ MOHAMMED v3 Security Audit Report\n\n"
	md += fmt.Sprintf("**Target:** `%s`  \n", target)
	md += fmt.Sprintf("**Date:** `%s`  \n", time.Now().Format(time.RFC1123))
	md += fmt.Sprintf("**Profile:** `%s`  \n", state.Config.Profile)
	if state.Proxy.Active {
		md += fmt.Sprintf("**Proxy:** `%s`  \n", state.Proxy.ProxyURL)
	}
	md += "\n---\n\n"

	md += "## 📊 Reconnaissance Statistics\n\n"
	md += "| Metric | Count |\n|---|---:|\n"
	md += fmt.Sprintf("| Discovered Subdomains | %d |\n", len(state.Subdomains))
	md += fmt.Sprintf("| Verified Live Hosts | %d |\n", len(state.LiveHosts))
	md += fmt.Sprintf("| Collected URLs | %d |\n", len(state.URLs))
	md += fmt.Sprintf("| Discovered Parameters | %d |\n", len(state.Parameters))
	md += fmt.Sprintf("| **Total Findings** | **%d** |\n\n", len(state.Findings))

	md += "## 🚨 Vulnerability Summary\n\n"
	md += "| Severity | Count |\n|---|---:|\n"
	md += fmt.Sprintf("| 🔴 Critical | %d |\n", counts["Critical"])
	md += fmt.Sprintf("| 🟠 High | %d |\n", counts["High"])
	md += fmt.Sprintf("| 🟡 Medium | %d |\n", counts["Medium"])
	md += fmt.Sprintf("| 🔵 Low | %d |\n", counts["Low"])
	md += fmt.Sprintf("| ⚪ Info | %d |\n\n", counts["Info"])

	md += "## 🔍 Detailed Vulnerability Findings\n\n"
	for _, sev := range []string{"Critical", "High", "Medium", "Low", "Info"} {
		hasSev := false
		for _, f := range state.Findings {
			if fmt.Sprintf("%v", f["severity"]) == sev {
				if !hasSev {
					md += fmt.Sprintf("### Severity: %s\n\n", sev)
					hasSev = true
				}
				md += fmt.Sprintf("#### 📌 %v\n", f["title"])
				md += fmt.Sprintf("- **URL/Target:** `%v`\n", f["url"])
				md += fmt.Sprintf("- **Detector Tool:** `%v`\n", f["tool"])
				md += fmt.Sprintf("- **Evidence/Proof:** `%v`\n\n", f["evidence"])
			}
		}
	}

	return md
}

func GenerateJSON(state *engine.State) string {
	target := "Unknown"
	if len(state.Scope.Domains) > 0 {
		target = state.Scope.Domains[0]
	}

	summary := ReportSummary{
		Target:         target,
		Timestamp:      time.Now().Format(time.RFC3339),
		Profile:        state.Config.Profile,
		BurpProxy:      state.Proxy.ProxyURL,
		SubdomainCount: len(state.Subdomains),
		LiveHostCount:  len(state.LiveHosts),
		URLCount:       len(state.URLs),
		ParamCount:     len(state.Parameters),
		FindingCount:   len(state.Findings),
		Findings:       state.Findings,
	}

	data, _ := json.MarshalIndent(summary, "", "  ")
	return string(data)
}

func SaveReports(state *engine.State) error {
	mdContent := GenerateMarkdown(state)
	jsonContent := GenerateJSON(state)

	mdFile := filepath.Join(state.OutputFolder, "report.md")
	jsonFile := filepath.Join(state.OutputFolder, "report.json")

	if err := os.WriteFile(mdFile, []byte(mdContent), 0644); err != nil {
		return err
	}
	return os.WriteFile(jsonFile, []byte(jsonContent), 0644)
}
