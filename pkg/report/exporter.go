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
	if confidenceOf(f) < 70 {
		return false
	}
	if boolOf(f, "ai_offline") {
		return false // AI could not positively confirm → review, not confirmed
	}
	return aiReal(f) || boolOf(f, "http_confirmed")
}

// formatFinding renders a single finding block for a text export.
func formatFinding(f map[string]interface{}) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("[%v] %v\n", f["severity"], f["title"]))
	b.WriteString(fmt.Sprintf("  URL       : %v\n", f["url"]))
	b.WriteString(fmt.Sprintf("  Tool      : %v\n", f["tool"]))
	b.WriteString(fmt.Sprintf("  Confidence: %d\n", confidenceOf(f)))
	if v, ok := f["ai_verdict"]; ok {
		b.WriteString(fmt.Sprintf("  AI Verdict: %v\n", v))
	}
	b.WriteString(fmt.Sprintf("  Evidence  : %v\n", f["evidence"]))
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
		return fmt.Sprintf("# MOHAMMED v3 — %s\n# Target: %s\n# Generated: %s\n\n",
			title, target, time.Now().Format(time.RFC1123))
	}

	var confirmed, review strings.Builder
	confirmed.WriteString(header("CONFIRMED VULNERABILITIES (Confidence >= 70, AI REAL or HTTP-confirmed)"))
	review.WriteString(header("MANUAL REVIEW (Confidence 40-69, or AI offline / unconfirmed)"))

	cCount, rCount := 0, 0
	for _, f := range state.Findings {
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
