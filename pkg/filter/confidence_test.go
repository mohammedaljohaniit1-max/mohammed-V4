package filter

import "testing"

func TestCalculateConfidence(t *testing.T) {
	// Fully-verified in-scope finding: 25+20+20+15+10+10 = 100.
	full := ConfidenceInputs{
		InScope: true, HTTPConfirmed: true, AIConfirmed: true,
		MultiToolAgree: true, SpecificPattern: true, NoWAFInterference: true,
	}
	if got := CalculateConfidence(full); got != 100 {
		t.Errorf("full confidence = %d, want 100", got)
	}

	// In scope + HTTP only: 25+20 = 45 → review band.
	partial := ConfidenceInputs{InScope: true, HTTPConfirmed: true}
	if got := CalculateConfidence(partial); got != 45 {
		t.Errorf("partial confidence = %d, want 45", got)
	}

	// Out of scope, AI offline, requires AI: 0 - 20 clamped to 0.
	weak := ConfidenceInputs{AIOffline: true, RequiresAI: true}
	if got := CalculateConfidence(weak); got != 0 {
		t.Errorf("weak confidence = %d, want 0 (clamped)", got)
	}
}

func TestClassifyConfidence(t *testing.T) {
	if ClassifyConfidence(85) != VerdictReport {
		t.Error("85 should be VerdictReport")
	}
	if ClassifyConfidence(55) != VerdictReview {
		t.Error("55 should be VerdictReview")
	}
	if ClassifyConfidence(20) != VerdictDiscard {
		t.Error("20 should be VerdictDiscard")
	}
}

// FIX #7 — offline AI must downgrade an unconfirmed Critical to Info.
func TestApplyConfidencePolicyAIOffline(t *testing.T) {
	scope := scopeWhatnot()
	f := map[string]interface{}{
		"title":          "SQL Injection",
		"severity":       "Critical",
		"url":            "https://api.whatnot.com/v1?id=1",
		"ai_verdict":     "ollama_offline",
		"requires_ai":    true,
		"http_confirmed": false,
	}
	keep := ApplyConfidencePolicy(f, scope)
	if !keep {
		t.Fatal("finding should be kept (as Info), not discarded")
	}
	if f["severity"] != "Info" {
		t.Errorf("severity = %v, want Info (downgraded)", f["severity"])
	}
	if f["unverified"] != true {
		t.Error("finding should be marked unverified")
	}
}

// A confident, in-scope, HTTP+AI confirmed finding keeps its severity.
func TestApplyConfidencePolicyReport(t *testing.T) {
	scope := scopeWhatnot()
	f := map[string]interface{}{
		"title":          "SQL Injection",
		"severity":       "Critical",
		"url":            "https://api.whatnot.com/v1?id=1",
		"ai_verdict":     "confirmed real",
		"ai_confirmed":   true,
		"http_confirmed": true,
		"multi_tool":     true,
	}
	keep := ApplyConfidencePolicy(f, scope)
	if !keep {
		t.Fatal("high-confidence finding must be kept")
	}
	if f["severity"] != "Critical" {
		t.Errorf("severity = %v, want Critical (unchanged)", f["severity"])
	}
}

// An out-of-scope, low-signal finding is discarded entirely.
func TestApplyConfidencePolicyDiscard(t *testing.T) {
	scope := scopeWhatnot()
	f := map[string]interface{}{
		"title":    "CORS Misconfiguration",
		"severity": "High",
		"url":      "https://www.grillservice-famholler.at/",
	}
	if ApplyConfidencePolicy(f, scope) {
		t.Error("out-of-scope low-confidence finding must be discarded")
	}
}
