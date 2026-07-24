package filter

import (
	"strings"
	"testing"

	"github.com/mohammed-v3/core/pkg/config"
)

func scopeWhatnot() *config.Scope {
	return &config.Scope{Domains: []string{"whatnot.com"}}
}

// FIX #1 — Cloudflare challenge tokens must never be testable.
func TestIsCloudflareChallenge(t *testing.T) {
	cases := map[string]bool{
		"https://www.whatnot.com/user/x?__cf_chl_rt_tk=QZWOkzxUk8jRBwlQhmzWaS": true,
		"https://help.whatnot.com/hc/en-us/requests/new?__cf_chl_tk=abc":       true,
		"https://www.whatnot.com/search?q=shoes":                              false,
		"https://api.whatnot.com/v1/items?id=42":                              false,
	}
	for u, want := range cases {
		if got := IsCloudflareChallenge(u); got != want {
			t.Errorf("IsCloudflareChallenge(%q)=%v want %v", u, got, want)
		}
	}
}

func TestStripNoisyParams(t *testing.T) {
	// A URL whose ONLY param is a CF challenge token → not testable.
	cleaned, testable := StripNoisyParams(
		"https://www.whatnot.com/user/philly?__cf_chl_rt_tk=QZWOkz")
	if testable {
		t.Errorf("CF-only URL must NOT be testable, got cleaned=%q testable=true", cleaned)
	}
	if strings.Contains(cleaned, "__cf_chl_rt_tk") {
		t.Errorf("cleaned URL still contains CF token: %q", cleaned)
	}

	// Analytics-only URL → not testable.
	_, testable = StripNoisyParams("https://www.whatnot.com/p?utm_source=x&gclid=y")
	if testable {
		t.Error("analytics-only URL must NOT be testable")
	}

	// Real injectable param survives → testable.
	cleaned, testable = StripNoisyParams("https://api.whatnot.com/v1/items?id=42&utm_source=x")
	if !testable {
		t.Errorf("URL with real param must be testable, got %q", cleaned)
	}
	if strings.Contains(cleaned, "utm_source") {
		t.Errorf("analytics param not stripped: %q", cleaned)
	}
	if !strings.Contains(cleaned, "id=42") {
		t.Errorf("real param wrongly stripped: %q", cleaned)
	}
}

func TestStripNoisyParamsAuthOnly(t *testing.T) {
	res := StripNoisyParamsDetailed("https://www.whatnot.com/reset?token=abc123")
	if res.Testable {
		t.Error("auth-token-only URL must NOT be SQLi-testable")
	}
	if len(res.AuthParams) != 1 || res.AuthParams[0] != "token" {
		t.Errorf("expected auth param 'token', got %v", res.AuthParams)
	}
}

// FIX #2 — strict scope enforcement against the exact FPs from the prompt.
func TestIsInScope(t *testing.T) {
	scope := scopeWhatnot()
	in := []string{
		"https://api.whatnot.com/v1",
		"https://www.whatnot.com/",
		"https://live-service.whatnot.com/ws",
		"whatnot.com",
	}
	out := []string{
		"https://assets.squarespace.com/universal/scripts/x.js",
		"https://dka575ofm4ao0.cloudfront.net/packs/common.js",
		"https://www.grillservice-famholler.at/",
		"https://cdn.jquery.com/jquery.min.js",
		"https://evil-whatnot.com.attacker.net/",
	}
	for _, u := range in {
		if !IsInScope(u, scope) {
			t.Errorf("IsInScope(%q) = false, want true", u)
		}
	}
	for _, u := range out {
		if IsInScope(u, scope) {
			t.Errorf("IsInScope(%q) = true, want false (OUT OF SCOPE)", u)
		}
	}
}

func TestScopeExcludeWins(t *testing.T) {
	scope := &config.Scope{
		Domains:        []string{"whatnot.com"},
		ExcludeDomains: []string{"blog.whatnot.com"},
	}
	if IsInScope("https://blog.whatnot.com/post", scope) {
		t.Error("explicit exclude must override in-scope subdomain match")
	}
	if !IsInScope("https://api.whatnot.com", scope) {
		t.Error("non-excluded subdomain should stay in scope")
	}
}

func TestFilterInScopeURLs(t *testing.T) {
	scope := scopeWhatnot()
	urls := []string{
		"https://api.whatnot.com/a",
		"https://assets.squarespace.com/x.js",
		"https://www.whatnot.com/b",
		"https://www.grillservice-famholler.at/",
	}
	kept, removed := FilterInScopeURLs(urls, scope)
	if len(kept) != 2 {
		t.Errorf("expected 2 kept, got %d (%v)", len(kept), kept)
	}
	if removed != 2 {
		t.Errorf("expected 2 removed, got %d", removed)
	}
}

func TestIsStaticAsset(t *testing.T) {
	static := []string{
		"https://x.whatnot.com/logo.png",
		"https://x.whatnot.com/app.css",
		"https://x.whatnot.com/font.woff2",
	}
	dynamic := []string{
		"https://x.whatnot.com/api?id=1",
		"https://x.whatnot.com/app.js", // JS scanned for secrets, not "static"
		"https://x.whatnot.com/search",
	}
	for _, u := range static {
		if !IsStaticAsset(u) {
			t.Errorf("IsStaticAsset(%q)=false want true", u)
		}
	}
	for _, u := range dynamic {
		if IsStaticAsset(u) {
			t.Errorf("IsStaticAsset(%q)=true want false", u)
		}
	}
}

func TestDeduplicateByBehavior(t *testing.T) {
	urls := []string{"a", "b", "c", "d"}
	// a,b,c share hash "H1"; d has "H2".
	hashOf := func(u string) string {
		if u == "d" {
			return "H2"
		}
		return "H1"
	}
	got := DeduplicateByBehavior(urls, hashOf)
	if len(got) != 2 {
		t.Errorf("expected 2 unique behaviours, got %d (%v)", len(got), got)
	}
}

func TestDeduplicateByParamSignature(t *testing.T) {
	urls := []string{
		"https://x.whatnot.com/p?id=1",
		"https://x.whatnot.com/p?id=2",
		"https://x.whatnot.com/p?id=3",
		"https://x.whatnot.com/q?name=a",
	}
	got := DeduplicateByParamSignature(urls)
	if len(got) != 2 {
		t.Errorf("expected 2 signatures, got %d (%v)", len(got), got)
	}
}
