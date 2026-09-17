package canonical

import (
	"testing"
)

func TestCanonicalizeRoute(t *testing.T) {
	tests := []struct {
		url      string
		expected string
	}{
		{
			url:      "https://example.com/catalog/product?productId=17&view=grid&utm_source=twitter",
			expected: "GET example.com/catalog/product?productId={INT}&view={ALPHA}",
		},
		{
			url:      "https://example.com/api/v1/users/42/details",
			expected: "GET example.com/api/v1/users/{INT}/details",
		},
		{
			url:      "https://example.com/blog/post?postId=99&ref=home",
			expected: "GET example.com/blog/post?postId={INT}",
		},
	}

	for _, tc := range tests {
		got, err := CanonicalizeRoute("GET", tc.url)
		if err != nil {
			t.Fatalf("unexpected error for %s: %v", tc.url, err)
		}
		if got != tc.expected {
			t.Errorf("CanonicalizeRoute(%q) = %q; want %q", tc.url, got, tc.expected)
		}
	}
}

func TestRouteDeduplicator(t *testing.T) {
	d := NewRouteDeduplicator()

	// First permutation should probe
	if !d.ShouldProbe("bola", "GET", "https://example.com/catalog/product?productId=17") {
		t.Errorf("expected first probe to be accepted")
	}

	// Identical route schema should NOT probe again
	if d.ShouldProbe("bola", "GET", "https://example.com/catalog/product?productId=13") {
		t.Errorf("expected duplicate route schema productId=13 to be discarded")
	}

	// Different phase should probe once
	if !d.ShouldProbe("sqli", "GET", "https://example.com/catalog/product?productId=13") {
		t.Errorf("expected sqli phase to evaluate the schema once")
	}
}
