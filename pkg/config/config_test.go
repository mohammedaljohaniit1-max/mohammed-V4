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
