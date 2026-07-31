package config

import (
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// TestExtractApexDomains is the regression guard for FLAW #1: a scope full of
// subdomains under the same root MUST collapse to a single apex so passive
// enumerators run exactly once per root domain (never per leaf host).
func TestExtractApexDomains(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "whatnot subdomains collapse to one apex",
			in: []string{
				"whatnot.com", "www.whatnot.com", "api.whatnot.com",
				"live-service.whatnot.com", "auction-service.whatnot.com",
			},
			want: []string{"whatnot.com"},
		},
		{
			name: "multiple distinct apexes preserved",
			in:   []string{"api.foo.com", "cdn.bar.io", "foo.com"},
			want: []string{"bar.io", "foo.com"},
		},
		{
			name: "two-part TLD handled",
			in:   []string{"api.example.co.uk", "example.co.uk"},
			want: []string{"example.co.uk"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ExtractApexDomains(tc.in)
			sort.Strings(got)
			sort.Strings(tc.want)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ExtractApexDomains(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestApexOf(t *testing.T) {
	cases := map[string]string{
		"auction-service.whatnot.com": "whatnot.com",
		"www.whatnot.com":             "whatnot.com",
		"whatnot.com":                 "whatnot.com",
		"a.b.c.example.co.uk":         "example.co.uk",
		"example.com":                 "example.com",
	}
	for in, want := range cases {
		if got := ApexOf(in); got != want {
			t.Errorf("ApexOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsApexDomain(t *testing.T) {
	if IsApexDomain("api.whatnot.com") {
		t.Error("api.whatnot.com should NOT be apex")
	}
	if !IsApexDomain("whatnot.com") {
		t.Error("whatnot.com should be apex")
	}
	if !IsApexDomain("example.co.uk") {
		t.Error("example.co.uk should be apex")
	}
}

// TestResolveAPIKeysEnvPrecedence guards EXPANSION 1: OS environment variables
// (Tier 1) override config.yaml values (Tier 2); an empty env var never
// clobbers a non-empty config value.
func TestResolveAPIKeysEnvPrecedence(t *testing.T) {
	t.Setenv("SHODAN_API_KEY", "env-shodan")
	t.Setenv("VIRUSTOTAL_API_KEY", "") // empty must not clobber config

	base := APIKeys{
		Shodan:     "cfg-shodan",
		VirusTotal: "cfg-vt",
		Chaos:      "cfg-chaos",
	}
	got := ResolveAPIKeys(base)

	if got.Shodan != "env-shodan" {
		t.Errorf("Shodan = %q, want env-shodan (Tier 1 wins)", got.Shodan)
	}
	if got.VirusTotal != "cfg-vt" {
		t.Errorf("VirusTotal = %q, want cfg-vt (empty env must not clobber)", got.VirusTotal)
	}
	if got.Chaos != "cfg-chaos" {
		t.Errorf("Chaos = %q, want cfg-chaos (config fallthrough)", got.Chaos)
	}
}

// TestActiveKeyNames verifies only non-empty keys are listed and no key
// material is returned.
func TestActiveKeyNames(t *testing.T) {
	names := ActiveKeyNames(APIKeys{Shodan: "x", GitHub: "y"})
	if len(names) != 2 {
		t.Fatalf("ActiveKeyNames len = %d, want 2 (%v)", len(names), names)
	}
	joined := ""
	for _, n := range names {
		joined += n + " "
	}
	if !contains(joined, "shodan") || !contains(joined, "github") {
		t.Errorf("expected shodan+github in %q", joined)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (indexOf(haystack, needle) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// ═══════════════════════════════════════════════════════════════════════════
// V12.2 PROCESS CRISIS · FAILURE #6 — Scope Pollution regression tests
// ---------------------------------------------------------------------------
// The live GitLab scope file marks out-of-scope targets with a leading '!'.
// V12.1's parser only recognized '-', so `!service-now.com` was stored as a
// TARGET and enumerated (6,879 out-of-scope subdomains, 3-hour Phase 12). These
// tests lock in that '!' excludes are parsed and NEVER enter enumeration.
// ═══════════════════════════════════════════════════════════════════════════

func TestV122_LoadScope_BangExcludes(t *testing.T) {
	dir := t.TempDir()
	scopePath := dir + "/scope_gitlab.txt"
	content := `# GitLab scope
gitlab.com
*.gitlab.org
*.gitlab.net
!us-federal-gitlab.com
!gitlabtraining.cloud
!*.service-now.com
!*.gitlab.cn
!*.gitlab-private.org
-legacy-exclude.com
`
	if err := os.WriteFile(scopePath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	sc, err := LoadScope(scopePath)
	if err != nil {
		t.Fatalf("LoadScope: %v", err)
	}

	// The '!' lines must be EXCLUDES, not target domains.
	for _, d := range sc.Domains {
		if strings.HasPrefix(d, "!") || strings.Contains(d, "service-now") ||
			strings.Contains(d, "gitlab.cn") || strings.Contains(d, "gitlabtraining") {
			t.Fatalf("excluded/out-of-scope domain leaked into targets: %q (Domains=%v)", d, sc.Domains)
		}
	}

	wantExcluded := []string{
		"us-federal-gitlab.com", "gitlabtraining.cloud", "service-now.com",
		"gitlab.cn", "gitlab-private.org", "legacy-exclude.com",
	}
	for _, w := range wantExcluded {
		if !IsExcludedHost(w, sc.ExcludeDomains) {
			t.Fatalf("expected %q to be excluded, ExcludeDomains=%v", w, sc.ExcludeDomains)
		}
	}
	// Wildcard exclude must cover subdomains too.
	if !IsExcludedHost("foo.service-now.com", sc.ExcludeDomains) {
		t.Fatalf("subdomain of excluded apex must be excluded")
	}
	// In-scope target must NOT be excluded.
	if IsExcludedHost("gitlab.com", sc.ExcludeDomains) {
		t.Fatalf("gitlab.com must remain in scope")
	}
}

func TestV122_ApexDomainsForEnum_DropsExcluded(t *testing.T) {
	// Simulates the exact GitLab log: in-scope apexes PLUS out-of-scope apexes
	// that leaked in via derived/OSINT hosts. Only the in-scope apexes may be
	// fed to the enumeration tools.
	domains := []string{
		"gitlab.com", "registry.gitlab.com", "docs.gitlab.com",
		"service-now.com", "biterg.io", "gitlab.cn", "gitlab-private.org",
	}
	excludes := []string{"service-now.com", "biterg.io", "gitlab.cn", "gitlab-private.org"}

	got := ApexDomainsForEnum(domains, excludes)
	for _, g := range got {
		if IsExcludedHost(g, excludes) {
			t.Fatalf("excluded apex %q was returned for enumeration: %v", g, got)
		}
	}
	// gitlab.com must survive.
	found := false
	for _, g := range got {
		if g == "gitlab.com" {
			found = true
		}
	}
	if !found {
		t.Fatalf("in-scope apex gitlab.com missing from enum list: %v", got)
	}
}

func TestV122_FilterExcluded(t *testing.T) {
	hosts := []string{
		"api.gitlab.com", "foo.service-now.com", "gitlab.com",
		"x.gitlab.cn", "docs.gitlab.com",
	}
	excludes := []string{"service-now.com", "gitlab.cn"}
	got := FilterExcluded(hosts, excludes)
	for _, g := range got {
		if strings.Contains(g, "service-now") || strings.Contains(g, "gitlab.cn") {
			t.Fatalf("excluded host survived FilterExcluded: %q", g)
		}
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 in-scope hosts, got %d (%v)", len(got), got)
	}
}
