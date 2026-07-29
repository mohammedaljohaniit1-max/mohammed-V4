package validation

import (
	"strings"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────────────
// V8.0 GAP 2 — fuzzy baseline unit tests (pure, deterministic).
// ─────────────────────────────────────────────────────────────────────────────

func TestSimHash_NearDuplicatesCloserThanDifferentDocs(t *testing.T) {
	// SimHash on longer, realistic bodies: near-duplicates must be strictly
	// closer than clearly-different documents.
	base := strings.Repeat("The application dashboard shows account activity, recent orders, "+
		"billing history, and support tickets for the current user session. ", 4)
	nearDup := base + "One extra sentence at the end changes very little overall."
	different := strings.Repeat("Fatal error: uncaught exception with stack trace in module handler "+
		"at line 42; the request could not be completed due to a server fault. ", 4)

	nearDist := HammingDistance(SimHash(base), SimHash(nearDup))
	diffDist := HammingDistance(SimHash(base), SimHash(different))
	if nearDist >= diffDist {
		t.Fatalf("near-duplicate distance (%d) must be smaller than different-doc distance (%d)", nearDist, diffDist)
	}
}

func TestLevenshteinSimilarity_Bounds(t *testing.T) {
	if s := LevenshteinSimilarity("identical", "identical"); s != 1.0 {
		t.Fatalf("identical strings must score 1.0, got %v", s)
	}
	if s := LevenshteinSimilarity("abcdef", "zyxwvu"); s > 0.3 {
		t.Fatalf("disjoint strings must score low, got %v", s)
	}
}

func TestFuzzyCompare_SameTemplateRequiresBothSignals(t *testing.T) {
	base := "<html><body><h1>Not Found</h1><p>The page /a does not exist.</p></body></html>"
	same := "<html><body><h1>Not Found</h1><p>The page /b does not exist.</p></body></html>"
	fv := FuzzyCompare(base, same)
	if !fv.SameTemplate {
		t.Fatalf("two near-identical error templates must be SameTemplate, got %+v", fv)
	}

	diff := "<html><body><h1>Welcome, admin</h1><p>Your private account balance is $4200.</p></body></html>"
	fv2 := FuzzyCompare(base, diff)
	if fv2.SameTemplate {
		t.Fatalf("clearly different content must NOT be SameTemplate, got %+v", fv2)
	}
}

func TestLooksLikeWAFChallenge(t *testing.T) {
	waf := strings.ToLower("Attention Required! | Cloudflare — Please enable cookies. Checking your browser before accessing.")
	if !looksLikeWAFChallenge(waf) {
		t.Fatalf("cloudflare challenge body must be detected as WAF challenge")
	}
	normal := strings.ToLower("<html><body><h1>Product catalog</h1></body></html>")
	if looksLikeWAFChallenge(normal) {
		t.Fatalf("normal page must NOT be flagged as WAF challenge")
	}
}
