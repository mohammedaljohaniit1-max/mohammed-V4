package phases

import "testing"

// TestWaybackTargetsIncludesAllScope is the regression guard for BUG #3: the
// URL-archive query set MUST include every in-scope subdomain, not just the
// apex. The apex-only version returned 0 URLs for whatnot.com because the
// Wayback/CommonCrawl indexes live on the subdomains (api., live-service.).
func TestWaybackTargetsIncludesAllScope(t *testing.T) {
	scope := []string{
		"whatnot.com",
		"www.whatnot.com",
		"api.whatnot.com",
		"live-service.whatnot.com",
		"auction-service.whatnot.com",
	}
	got := waybackTargets(scope)

	set := make(map[string]bool)
	for _, g := range got {
		set[g] = true
	}

	// Every scope entry must be present — the whole point of the fix.
	for _, want := range scope {
		if !set[want] {
			t.Errorf("waybackTargets dropped in-scope domain %q (apex-only regression!)", want)
		}
	}
	// The apex must also be present (it always is, but guard it).
	if !set["whatnot.com"] {
		t.Errorf("waybackTargets missing apex whatnot.com")
	}
	// No duplicates.
	if len(got) != len(set) {
		t.Errorf("waybackTargets returned duplicates: %v", got)
	}
}

// TestAppendUnique guards the URL-merge helper used by the httpx fallback and
// wayback aggregation (IMPROVEMENT #4).
func TestAppendUnique(t *testing.T) {
	a := []string{"https://a.com", "https://b.com"}
	b := []string{"https://b.com", "https://c.com"}
	got := appendUnique(a, b)
	if len(got) != 3 {
		t.Fatalf("expected 3 unique URLs, got %d: %v", len(got), got)
	}
	seen := map[string]int{}
	for _, u := range got {
		seen[u]++
	}
	for u, n := range seen {
		if n != 1 {
			t.Errorf("URL %q appears %d times (dedup failed)", u, n)
		}
	}
}
