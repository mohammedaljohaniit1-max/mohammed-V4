package filter

// FIX #3 — Confidence scoring for every finding.
//
// Findings in MOHAMMED are carried as map[string]interface{} (see
// engine.State.Findings), so the scorer operates on that shape. The score is
// a 0-100 integer; the caller uses ClassifyConfidence to decide whether a
// finding is reported, downgraded to Info, or discarded entirely.

import (
	"fmt"
	"strings"

	"github.com/mohammed-v3/core/pkg/config"
)

// Confidence thresholds (FIX #3).
const (
	ConfidenceReport  = 70 // >= 70 → report at real severity
	ConfidenceReview  = 40 // 40-69 → downgrade to Info, manual review
	AIOfflinePenalty  = 20 // ollama_offline subtracts this much
)

// ConfidenceInputs are the signals used by CalculateConfidence. A phase fills
// in whatever it can prove; unknown signals stay false and simply score 0.
type ConfidenceInputs struct {
	InScope          bool // hostname verified in scope (+25)
	HTTPConfirmed    bool // real 200 response with real content (+20)
	AIConfirmed      bool // Ollama verdict == REAL (+20)
	MultiToolAgree   bool // two independent tools agree, e.g. sqlmap+ghauri (+15)
	SpecificPattern  bool // specific pattern vs generic (+10)
	NoWAFInterference bool // no WAF block observed during test (+10)
	AIOffline        bool // Ollama was offline (-20, requires-AI findings)
	RequiresAI       bool // this finding type needs AI confirmation
}

// CalculateConfidence implements the FIX #3 additive scoring algorithm,
// clamped to [0,100].
func CalculateConfidence(in ConfidenceInputs) int {
	score := 0
	if in.InScope {
		score += 25
	}
	if in.HTTPConfirmed {
		score += 20
	}
	if in.AIConfirmed {
		score += 20
	}
	if in.MultiToolAgree {
		score += 15
	}
	if in.SpecificPattern {
		score += 10
	}
	if in.NoWAFInterference {
		score += 10
	}
	if in.AIOffline && in.RequiresAI {
		score -= AIOfflinePenalty
	}
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return score
}

// Verdict is the reporting decision derived from a confidence score.
type Verdict int

const (
	VerdictReport  Verdict = iota // real finding, keep severity
	VerdictReview                 // downgrade to Info, manual review
	VerdictDiscard                // do not write to report at all
)

// ClassifyConfidence maps a confidence score to a reporting Verdict.
func ClassifyConfidence(score int) Verdict {
	switch {
	case score >= ConfidenceReport:
		return VerdictReport
	case score >= ConfidenceReview:
		return VerdictReview
	default:
		return VerdictDiscard
	}
}

// ScoreFinding computes a confidence score for a finding map, deriving the
// input signals from the fields the phases already populate:
//
//	url               → hostname scope check
//	http_confirmed    → bool
//	ai_confirmed      → bool (set by engine.State.Triage)
//	ai_verdict        → "ollama_offline" means AI was down
//	multi_tool        → bool
//	specific_pattern  → bool
//	waf_detected      → bool (inverted into NoWAFInterference)
//	requires_ai       → bool
//
// It writes the resulting "confidence" (int) back into the map and returns it.
func ScoreFinding(f map[string]interface{}, scope *config.Scope) int {
	getBool := func(key string) bool {
		if v, ok := f[key]; ok {
			if b, ok := v.(bool); ok {
				return b
			}
		}
		return false
	}

	urlStr := fmt.Sprintf("%v", f["url"])
	aiVerdict := strings.ToLower(fmt.Sprintf("%v", f["ai_verdict"]))
	aiOffline := strings.Contains(aiVerdict, "ollama_offline") || strings.Contains(aiVerdict, "offline")

	in := ConfidenceInputs{
		InScope:           scope != nil && IsInScope(urlStr, scope),
		HTTPConfirmed:     getBool("http_confirmed"),
		AIConfirmed:       getBool("ai_confirmed"),
		MultiToolAgree:    getBool("multi_tool"),
		SpecificPattern:   getBool("specific_pattern"),
		NoWAFInterference: !getBool("waf_detected"),
		AIOffline:         aiOffline,
		RequiresAI:        getBool("requires_ai"),
	}
	score := CalculateConfidence(in)
	f["confidence"] = score
	return score
}

// ApplyConfidencePolicy scores a finding, records the verdict, and mutates the
// finding's severity per FIX #3 / FIX #7:
//
//   - Verdict Report  → severity unchanged.
//   - Verdict Review  → severity downgraded to "Info", note added.
//   - Verdict Discard → returns keep=false (caller must NOT store it).
//
// When AI is offline AND the finding is an unconfirmed Critical/High that
// requires AI, it is downgraded to "Unverified-<sev> [AI offline]" at Info.
func ApplyConfidencePolicy(f map[string]interface{}, scope *config.Scope) (keep bool) {
	score := ScoreFinding(f, scope)
	verdict := ClassifyConfidence(score)

	sev := fmt.Sprintf("%v", f["severity"])
	aiVerdict := strings.ToLower(fmt.Sprintf("%v", f["ai_verdict"]))
	aiOffline := strings.Contains(aiVerdict, "ollama_offline") || strings.Contains(aiVerdict, "offline")
	httpConfirmed := false
	if v, ok := f["http_confirmed"].(bool); ok {
		httpConfirmed = v
	}

	// FIX #7: an unconfirmed Critical/High while AI is offline can NEVER be
	// reported at its original severity. It becomes an Info-level
	// "Unverified-*" flagged for manual review.
	isHigh := sev == "Critical" || sev == "High"
	if aiOffline && isHigh && !httpConfirmed {
		f["original_severity"] = sev
		f["severity"] = "Info"
		f["unverified"] = true
		f["review_reason"] = "AI offline and no HTTP confirmation — manual review required"
		f["title"] = fmt.Sprintf("Unverified-%s [AI offline]: %v", sev, f["title"])
		return true
	}

	switch verdict {
	case VerdictReport:
		return true
	case VerdictReview:
		f["original_severity"] = sev
		f["severity"] = "Info"
		f["unverified"] = true
		f["review_reason"] = "Unverified — manual review needed (confidence " +
			fmt.Sprintf("%d", score) + "/100)"
		return true
	default: // VerdictDiscard
		return false
	}
}
