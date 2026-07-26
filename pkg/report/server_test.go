package report

import (
	"strings"
	"testing"
)

// TestBuildViewSortsAndGeneratesReports verifies EXPANSION 5 dashboard view
// construction: findings are ordered Critical→Info and every finding gets a
// HackerOne report body (its own h1_report, or a generated fallback).
func TestBuildViewSortsAndGeneratesReports(t *testing.T) {
	rd := &ReportData{
		Subdomains: 10, LiveHosts: 5, URLs: 100,
		Counts: map[string]int{"Critical": 1, "Info": 1, "Medium": 1},
		Findings: []map[string]interface{}{
			{"title": "info finding", "severity": "Info", "url": "http://x", "tool": "t", "evidence": "e"},
			{"title": "crit finding", "severity": "Critical", "url": "http://y", "tool": "t2", "evidence": "e2"},
			{"title": "med w/ report", "severity": "Medium", "url": "z", "tool": "email_check",
				"evidence": "e3", "h1_report": "CUSTOM-H1-BODY"},
		},
	}
	v := buildView(rd)

	if v.Total != 3 {
		t.Fatalf("Total = %d, want 3", v.Total)
	}
	// Ordering: Critical first, Info last.
	if v.Findings[0].Severity != "Critical" {
		t.Errorf("first finding severity = %q, want Critical", v.Findings[0].Severity)
	}
	if v.Findings[len(v.Findings)-1].Severity != "Info" {
		t.Errorf("last finding severity = %q, want Info", v.Findings[len(v.Findings)-1].Severity)
	}
	// Every finding must carry a non-empty HackerOne report body.
	for _, f := range v.Findings {
		if strings.TrimSpace(f.H1Report) == "" {
			t.Errorf("finding %q has empty H1Report", f.Title)
		}
	}
	// The finding that shipped its own report must keep it verbatim.
	var found bool
	for _, f := range v.Findings {
		if f.Title == "med w/ report" {
			found = true
			if f.H1Report != "CUSTOM-H1-BODY" {
				t.Errorf("custom h1_report not preserved: %q", f.H1Report)
			}
		}
	}
	if !found {
		t.Error("custom-report finding missing from view")
	}
}

// TestSeverityRank guards the dashboard ordering contract.
func TestSeverityRank(t *testing.T) {
	if severityRank("Critical") >= severityRank("High") {
		t.Error("Critical must rank before High")
	}
	if severityRank("Low") >= severityRank("Info") {
		t.Error("Low must rank before Info")
	}
	if severityRank("unknown") != severityRank("Info") {
		t.Error("unknown severity should rank as Info")
	}
}
