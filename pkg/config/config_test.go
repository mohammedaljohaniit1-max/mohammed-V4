package config

import (
	"reflect"
	"sort"
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
