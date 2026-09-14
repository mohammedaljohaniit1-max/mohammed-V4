package report

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mohammed-v3/core/pkg/engine"
)

// FIX #9 — Confirmed-vs-Review exporter.
//
// The whatnot.com incident buried 6 catastrophic false positives inside a
// single flat report. Zero-FP architecture demands a hard split between what
// is SAFE to act on and what still needs a human:
//
//   • CONFIRMED_VULNS.txt — Confidence ≥ 70 AND (AI verdict REAL OR
//     HTTP-confirmed). These are ready to submit / route to Burp evidence.
//   • MANUAL_REVIEW.txt    — Confidence 40–69, OR the AI layer was offline so
//     the finding could not be positively confirmed. Requires a human look.
//
// Anything below the review floor is already discarded upstream by
// filter.ApplyConfidencePolicy and never reaches the report.

// confidenceOf extracts the integer confidence written by filter.ScoreFinding.
func confidenceOf(f map[string]interface{}) int {
	switch v := f["confidence"].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	}
	return 0
}

// boolOf reads a bool-ish finding field.
func boolOf(f map[string]interface{}, key string) bool {
	switch v := f[key].(type) {
	case bool:
		return v
	case string:
		return v == "true"
	}
	return false
}

// aiReal reports whether the AI explicitly confirmed the finding as REAL
// (not merely "offline / fail-open").
func aiReal(f map[string]interface{}) bool {
	if boolOf(f, "ai_confirmed") {
		return true
	}
	verdict := strings.ToLower(fmt.Sprintf("%v", f["ai_verdict"]))
	return verdict != "" && verdict != "ollama_offline" && verdict != "ollama_empty_response" &&
		!strings.Contains(verdict, "false")
}

// isConfirmed decides whether a finding belongs in CONFIRMED_VULNS.txt.
func isConfirmed(f map[string]interface{}) bool {
	// ── V12.0 OMEGA · BUG #2 GUARD ────────────────────────────────────────
	// Informational findings (notably demoted tlsx hostname mismatches) must
	// NEVER enter CONFIRMED_VULNS.txt regardless of any other signal.
	if sev, ok := f["severity"].(string); ok {
		switch strings.ToLower(strings.TrimSpace(sev)) {
		case "informational", "info", "none":
			return false
		}
	}
	if confidenceOf(f) < 70 {
		return false
	}
	if boolOf(f, "ai_offline") {
		return false // AI could not positively confirm → review, not confirmed
	}
	return aiReal(f) || boolOf(f, "http_confirmed")
}

// IsReportableFinding filters out internal pipeline events or empty/malformed findings.
func IsReportableFinding(f map[string]interface{}) bool {
	title := sanitizeField(f["title"])
	if title == "" || title == "<nil>" || title == "nil" {
		title = sanitizeField(f["type"])
	}
	if title == "" || title == "<nil>" || title == "nil" {
		return false
	}

	// Filter internal milestone logs that aren't actual vulnerabilities
	lowerTitle := strings.ToLower(title)
	if strings.Contains(lowerTitle, "target classification") ||
		strings.Contains(lowerTitle, "autonomous session bootstrap") ||
		strings.Contains(lowerTitle, "pipeline event") ||
		strings.Contains(lowerTitle, "internal status") {
		return false
	}

	return true
}

func sanitizeField(v interface{}) string {
	if v == nil {
		return ""
	}
	s := strings.TrimSpace(fmt.Sprintf("%v", v))
	if s == "<nil>" || s == "nil" {
		return ""
	}
	return s
}

// formatFinding renders a single finding block for a text export.
func formatFinding(f map[string]interface{}) string {
	title := sanitizeField(f["title"])
	if title == "" {
		title = sanitizeField(f["type"])
	}
	if title == "" {
		title = "Security Observation"
	}

	tool := sanitizeField(f["tool"])
	if tool == "" {
		tool = "mohammed-engine"
	}

	severity := sanitizeField(f["severity"])
	if severity == "" {
		severity = "Info"
	}

	rawURL := sanitizeField(f["url"])
	if rawURL == "" {
		rawURL = "N/A"
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("[%s] %s\n", severity, title))
	b.WriteString(fmt.Sprintf("  URL       : %s\n", rawURL))
	b.WriteString(fmt.Sprintf("  Tool      : %s\n", tool))
	b.WriteString(fmt.Sprintf("  Confidence: %d\n", confidenceOf(f)))
	if v, ok := f["ai_verdict"]; ok && sanitizeField(v) != "" {
		b.WriteString(fmt.Sprintf("  AI Verdict: %v\n", v))
	}
	b.WriteString(fmt.Sprintf("  Evidence  : %v\n", f["evidence"]))
	// EXPANSION 3: email-spoofing findings carry a ready-to-paste HackerOne
	// report snippet — surface it inline so MANUAL_REVIEW.txt is submit-ready.
	if r, ok := f["h1_report"].(string); ok && strings.TrimSpace(r) != "" {
		b.WriteString("  HackerOne Report:\n")
		b.WriteString(r)
		b.WriteString("\n")
	}
	b.WriteString("\n")
	return b.String()
}

// ExportTieredReports writes CONFIRMED_VULNS.txt and MANUAL_REVIEW.txt.
// Returns (confirmedCount, reviewCount, error).
func ExportTieredReports(state *engine.State) (int, int, error) {
	target := "Unknown"
	if len(state.Scope.Domains) > 0 {
		target = state.Scope.Domains[0]
	}
	header := func(title string) string {
		return fmt.Sprintf("# MOHAMMED v4 — %s\n# Target: %s\n# Generated: %s\n\n",
			title, target, time.Now().Format(time.RFC1123))
	}

	var confirmed, review strings.Builder
	confirmed.WriteString(header("CONFIRMED VULNERABILITIES (Confidence >= 70, AI REAL or HTTP-confirmed)"))
	review.WriteString(header("MANUAL REVIEW (Confidence 40-69, or AI offline / unconfirmed)"))

	cCount, rCount := 0, 0
	for _, f := range state.Findings {
		if !IsReportableFinding(f) {
			continue
		}
		if isConfirmed(f) {
			confirmed.WriteString(formatFinding(f))
			cCount++
		} else {
			review.WriteString(formatFinding(f))
			rCount++
		}
	}
	if cCount == 0 {
		confirmed.WriteString("(no confirmed findings — nothing cleared the confidence + confirmation gate)\n")
	}
	if rCount == 0 {
		review.WriteString("(no findings pending manual review)\n")
	}

	confirmedFile := filepath.Join(state.OutputFolder, "CONFIRMED_VULNS.txt")
	reviewFile := filepath.Join(state.OutputFolder, "MANUAL_REVIEW.txt")
	if err := os.WriteFile(confirmedFile, []byte(confirmed.String()), 0644); err != nil {
		return cCount, rCount, err
	}
	if err := os.WriteFile(reviewFile, []byte(review.String()), 0644); err != nil {
		return cCount, rCount, err
	}
	return cCount, rCount, nil
}
