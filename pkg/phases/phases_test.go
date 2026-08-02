package phases

import (
	"testing"

	"github.com/mohammed-v3/core/pkg/config"
	"github.com/mohammed-v3/core/pkg/engine"
)

// TestV123_PassiveEnumConcurrentFanOut is the V12.3 FAILURE #1/#3 proof: the
// legacy sequential per-apex loop (with the broken OWASP enumerator) has been
// replaced by a concurrent fan-out. dedupHosts and filterUnderApex are the pure
// building blocks of that fan-out and are asserted here without needing any
// external binary installed.
func TestV123_PassiveEnumConcurrentFanOut(t *testing.T) {
	// filterUnderApex keeps only the apex and its subdomains, drops noise.
	raw := []string{
		"gitlab.com",
		"WWW.GitLab.com\r",         // case + CRLF normalized
		"registry.gitlab.com",
		"evil.com",                 // out of apex → dropped
		"docs.gitlab.com.evil.net", // suffix trick → dropped (not "."+apex)
		"",                         // empty → dropped
	}
	got := filterUnderApex(raw, "gitlab.com")
	want := map[string]bool{"gitlab.com": true, "www.gitlab.com": true, "registry.gitlab.com": true}
	if len(got) != len(want) {
		t.Fatalf("filterUnderApex: got %d hosts %v, want %d %v", len(got), got, len(want), want)
	}
	for _, h := range got {
		if !want[h] {
			t.Errorf("filterUnderApex wrongly kept %q", h)
		}
	}
	// dedupHosts collapses duplicates + case.
	dd := dedupHosts([]string{"a.gitlab.com", "A.GitLab.com", "b.gitlab.com", "a.gitlab.com"})
	if len(dd) != 2 {
		t.Fatalf("dedupHosts: got %d unique %v want 2", len(dd), dd)
	}
}

// TestPrepareSQLiURLs_CapAndFunnel is the V12.1 FIX #2 proof. It asserts (a) the
// cap is honoured at the mandated 20, (b) parameterized high-value URLs are kept
// over parameterless noise, and (c) the elimination funnel accounts for every
// dropped URL by an exact reason.
func TestPrepareSQLiURLs_CapAndFunnel(t *testing.T) {
	scope := &config.Scope{Domains: []string{"example.com"}}
	raw := []string{
		// 3 high-value in-scope parameterized URLs (must be kept, prioritized).
		"https://example.com/item?id=1",
		"https://example.com/user?user_id=2",
		"https://example.com/search?query=abc",
		// out-of-scope (must be counted OutOfScope).
		"https://evil.com/item?id=9",
		// no injectable parameter (must be counted NoParam).
		"https://example.com/about",
		// duplicate parameter signature of the first (must be counted DupSignature).
		"https://example.com/item?id=999",
	}
	targets, elim := PrepareSQLiURLsVerbose(raw, scope, 20)

	if elim.Raw != len(raw) {
		t.Fatalf("Raw tally wrong: got %d want %d", elim.Raw, len(raw))
	}
	if len(targets) == 0 {
		t.Fatal("expected at least the 3 in-scope parameterized URLs, got 0")
	}
	if elim.OutOfScope < 1 {
		t.Errorf("expected >=1 out-of-scope elimination, got %d", elim.OutOfScope)
	}
	if elim.NoParam < 1 {
		t.Errorf("expected >=1 no-param elimination, got %d", elim.NoParam)
	}
	if elim.DupSignature < 1 {
		t.Errorf("expected >=1 dup-signature elimination, got %d", elim.DupSignature)
	}
	// The funnel must be conservation-of-URLs correct: kept + all eliminations
	// == raw.
	sum := elim.Kept + elim.CFChallenge + elim.NoParam + elim.OutOfScope +
		elim.DupSignature + elim.CappedOff
	if sum != elim.Raw {
		t.Fatalf("funnel does not conserve URLs: kept+eliminated=%d want raw=%d (%s)", sum, elim.Raw, elim.String())
	}
	t.Logf("SQLi funnel: %s", elim.String())
}

// TestPartitionCORSByWAF is the V12.1 FIX #3 proof. Root cause: Phase 17 used
// only curl, so WAF-protected hosts (Cloudflare/Akamai) that block/modify the
// ACAO header for non-browser clients returned 0 while the CDP-based Phase 56
// found 13. The fix routes WAF-protected hosts to the real Chrome (CDP) path and
// keeps non-WAF hosts on the fast curl path. This asserts that pure routing
// contract: WAF host → CDP bucket, non-WAF host → curl bucket, non-http dropped.
func TestPartitionCORSByWAF(t *testing.T) {
	s := &engine.State{WAFProtected: map[string]bool{}}
	s.MarkWAFProtected("waf.example.com")

	targets := []string{
		"https://waf.example.com/api/data", // WAF-protected → CDP
		"https://waf.example.com/api/user", // WAF-protected → CDP
		"https://plain.example.com/api",    // non-WAF → curl
		"http://open.example.com/x",        // non-WAF → curl
		"ftp://skip.example.com/x",         // non-http → dropped
		"not-a-url",                        // non-http → dropped
	}
	waf, plain := partitionCORSByWAF(s, targets)

	if len(waf) != 2 {
		t.Fatalf("expected 2 WAF→CDP targets, got %d: %v", len(waf), waf)
	}
	if len(plain) != 2 {
		t.Fatalf("expected 2 non-WAF→curl targets, got %d: %v", len(plain), plain)
	}
	for _, u := range waf {
		if !s.IsWAFProtected(u) {
			t.Errorf("non-WAF host %q wrongly routed to CDP bucket", u)
		}
	}
	for _, u := range plain {
		if s.IsWAFProtected(u) {
			t.Errorf("WAF host %q wrongly routed to curl bucket", u)
		}
	}
	t.Logf("FIX #3 routing OK: %d WAF→CDP, %d non-WAF→curl (2 non-http dropped)", len(waf), len(plain))
}

// TestUpgrade_PrioritizeDiscovered is the V12.1 UPGRADE Phase 33-35 proof: the
// intrusive IDOR/Race/BizLogic phases must consume the endpoints discovered by
// the JS analyzer first. PriorityTargets (discovered /admin, /internal, API)
// come first, then API-shaped URLs, then the rest — deduped and scope-filtered.
func TestUpgrade_PrioritizeDiscovered(t *testing.T) {
	s := &engine.State{
		Scope:           &config.Scope{Domains: []string{"example.com"}},
		PriorityTargets: []string{"https://example.com/admin/panel", "https://evil.com/x"},
	}
	corpus := []string{
		"https://example.com/home",          // plain page (last)
		"https://example.com/api/v1/orders", // API-shaped (middle)
		"https://example.com/admin/panel",   // dup of a priority target
	}
	out := prioritizeDiscovered(s, corpus)

	if len(out) == 0 {
		t.Fatal("expected a non-empty prioritized list")
	}
	// First element must be the in-scope priority target.
	if out[0] != "https://example.com/admin/panel" {
		t.Errorf("priority target must be first, got %q", out[0])
	}
	// Out-of-scope priority target must be dropped.
	for _, u := range out {
		if u == "https://evil.com/x" {
			t.Error("out-of-scope priority target must be filtered")
		}
	}
	// The API-shaped URL must appear before the plain /home page.
	api, home := -1, -1
	for i, u := range out {
		if u == "https://example.com/api/v1/orders" {
			api = i
		}
		if u == "https://example.com/home" {
			home = i
		}
	}
	if api == -1 || home == -1 || api >= home {
		t.Errorf("API URL must precede plain page: api=%d home=%d (%v)", api, home, out)
	}
	// No duplicates.
	seen := map[string]bool{}
	for _, u := range out {
		if seen[u] {
			t.Errorf("duplicate in prioritized list: %q", u)
		}
		seen[u] = true
	}
}

// TestFix5_CDNSmugglingDemotion is the V12.1 FIX #5 proof. A smuggling finding
// on a CDN-fronted host (Cloudflare/Fastly/Akamai/CloudFront) MUST be demoted to
// Informational; a direct-origin host MUST keep its Critical severity.
func TestFix5_CDNSmugglingDemotion(t *testing.T) {
	cases := []struct {
		name       string
		headerBlob string
		body       string
		wantVendor string
		wantSev    string
		wantInfo   bool
	}{
		{"cloudflare", "CF-RAY: 8ab...\nServer: cloudflare\n", "", "Cloudflare", "Informational", true},
		{"fastly", "X-Served-By: cache-lax-1234\nVia: 1.1 varnish\n", "", "Fastly", "Informational", true},
		{"akamai", "Server: AkamaiGHost\nX-Akamai-Request-ID: abc\n", "", "Akamai", "Informational", true},
		{"cloudfront", "X-Amz-Cf-Id: abc==\nX-Amz-Cf-Pop: IAD79\n", "", "CloudFront", "Informational", true},
		{"direct-nginx", "Server: nginx/1.24\nContent-Type: text/html\n", "", "", "Critical", false},
		{"direct-apache", "Server: Apache/2.4.57\n", "", "", "Critical", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			vendor := cdnVendorFromHeaders(tc.headerBlob, tc.body)
			if vendor != tc.wantVendor {
				t.Fatalf("vendor: got %q want %q", vendor, tc.wantVendor)
			}
			sev, info := smugglingSeverity("Critical", vendor)
			if sev != tc.wantSev {
				t.Errorf("severity: got %q want %q", sev, tc.wantSev)
			}
			if info != tc.wantInfo {
				t.Errorf("informational: got %v want %v", info, tc.wantInfo)
			}
		})
	}
}

// TestPrepareSQLiURLs_CapEnforced proves the cap is a hard bound: 40 unique
// in-scope parameterized URLs with a cap of 20 must yield exactly 20 kept and 20
// over-cap.
func TestPrepareSQLiURLs_CapEnforced(t *testing.T) {
	scope := &config.Scope{Domains: []string{"example.com"}}
	var raw []string
	for i := 0; i < 40; i++ {
		raw = append(raw, "https://example.com/p"+itoa(i)+"?id="+itoa(i))
	}
	targets, elim := PrepareSQLiURLsVerbose(raw, scope, 20)
	if len(targets) != 20 {
		t.Fatalf("cap not enforced: got %d candidates want 20", len(targets))
	}
	if elim.CappedOff != 20 {
		t.Fatalf("over-cap tally wrong: got %d want 20", elim.CappedOff)
	}
}
