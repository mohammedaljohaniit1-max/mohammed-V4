package filter

import (
	"testing"
)

func TestShouldSkipFuzzParam(t *testing.T) {
	cases := []struct {
		param string
		skip  bool
	}{
		// Analytics / Marketing
		{"utm_source", true},
		{"utm_medium", true},
		{"utm_campaign", true},
		{"pk_campaign", true},
		{"pk_kwd", true},
		{"ga_source", true},
		{"hsLang", true},
		{"_hsenc", true},
		{"gclid", true},
		{"fbclid", true},

		// CMS Pagination
		{"page", true},
		{"PAGE", true},
		{"p", true},
		{"pno", true},
		{"paged", true},
		{"pg", true},
		{"offset", true},

		// Static Display
		{"lang", true},
		{"category", true},
		{"article", true},
		{"sort", true},
		{"order", true},

		// Real Attack Vectors (Must NOT skip)
		{"id", false},
		{"user_id", false},
		{"search", false},
		{"query", false},
		{"redirect", false},
		{"file", false},
		{"token", false},
		{"email", false},
		{"password", false},
	}

	for _, tc := range cases {
		got := ShouldSkipFuzzParam(tc.param)
		if got != tc.skip {
			t.Errorf("ShouldSkipFuzzParam(%q) = %v; want %v", tc.param, got, tc.skip)
		}
	}
}

func TestHasFuzzableParams(t *testing.T) {
	// Only noisy CMS/marketing params -> must return false
	noisyURL := "https://www.yeswehack.com/blog?page=17&hsLang=en&pk_campaign=spring2026"
	if HasFuzzableParams(noisyURL) {
		t.Fatalf("expected HasFuzzableParams to return false for noisy URL: %s", noisyURL)
	}

	// Mixed with a real vulnerable parameter -> must return true
	mixedURL := "https://www.yeswehack.com/blog?page=17&search=test&hsLang=en"
	if !HasFuzzableParams(mixedURL) {
		t.Fatalf("expected HasFuzzableParams to return true for mixed URL containing 'search': %s", mixedURL)
	}

	// Clean parameter -> must return true
	cleanURL := "https://api.zid.sa/v1/products?category_id=42"
	if !HasFuzzableParams(cleanURL) {
		t.Fatalf("expected HasFuzzableParams to return true for 'category_id': %s", cleanURL)
	}
}
