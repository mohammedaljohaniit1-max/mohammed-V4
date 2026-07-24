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

// TestFilterHostsUnderApex is the regression guard for FLAW #3: the parallel
// OSINT harvesters return raw, noisy data (wildcards, trailing dots, HTML
// tokens, out-of-scope hosts). The central filter MUST normalize, dedupe, and
// keep only real hosts under the queried apex.
func TestFilterHostsUnderApex(t *testing.T) {
	raw := []string{
		"API.WhatNot.com",           // uppercase → normalized
		"*.whatnot.com",             // wildcard prefix stripped → apex
		"live-service.whatnot.com.", // trailing dot stripped
		"api.whatnot.com",           // dup of first after normalize
		"evil.com",                  // out of scope → dropped
		"attacker.whatnot.com.evil.com", // sneaky suffix → dropped
		"",                          // empty → dropped
		"foo=bar whatnot.com",       // dirty token → dropped
		"whatnot.com",               // the apex itself → kept
	}
	got := filterHostsUnderApex("whatnot.com", raw)

	want := map[string]bool{
		"api.whatnot.com":          true,
		"whatnot.com":              true,
		"live-service.whatnot.com": true,
	}
	if len(got) != len(want) {
		t.Fatalf("filterHostsUnderApex returned %d hosts, want %d: %v", len(got), len(want), got)
	}
	seen := map[string]int{}
	for _, h := range got {
		seen[h]++
		if !want[h] {
			t.Errorf("unexpected host kept: %q", h)
		}
	}
	for h, n := range seen {
		if n != 1 {
			t.Errorf("host %q returned %d times (dedup failed)", h, n)
		}
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

// TestExtractSecretEvidence guards BUG #8 (audit): a confirmed JS secret must
// carry the ACTUAL matched value + context, not just the pattern label.
func TestExtractSecretEvidence(t *testing.T) {
	body := `window.env = {};` + "\n" +
		`const STRIPE_KEY = "pk_live_abc123DEF456";` + "\n" +
		`window.next = 1;`
	pattern := "pk_live"
	idx := indexOf(body, pattern)
	if idx < 0 {
		t.Fatalf("test setup: pattern %q not in body", pattern)
	}
	matchLine, context, value := extractSecretEvidence(body, idx, pattern)

	if matchLine == "" || matchLine == "pattern: "+pattern {
		t.Errorf("matchLine should contain the source line, got %q", matchLine)
	}
	if value != "pk_live_abc123DEF456" {
		t.Errorf("value should be the extracted key, got %q", value)
	}
	if context == "" {
		t.Errorf("context should be non-empty")
	}
}

// TestExtractSecretEvidenceOutOfRange proves the helper never panics on a bad
// index (defensive — the curl body can be empty or the offset stale).
func TestExtractSecretEvidenceOutOfRange(t *testing.T) {
	ml, _, _ := extractSecretEvidence("short", -1, "api_key")
	if ml == "" {
		t.Errorf("out-of-range index should still return a non-empty fallback")
	}
	ml2, _, _ := extractSecretEvidence("short", 999, "api_key")
	if ml2 == "" {
		t.Errorf("beyond-length index should still return a non-empty fallback")
	}
}

// indexOf is a tiny test helper mirroring strings.Index without importing it
// into the test's top-level (keeps the test self-contained/readable).
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
