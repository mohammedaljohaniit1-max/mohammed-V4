package filter

import (
	"net/url"
	"strings"
)

// IgnoredParamExactNames is the set of query parameter keys commonly used
// for CMS pagination, static display, or marketing/analytics that cause
// severe fuzzer bloat and false positives when tested for SQLi/XSS.
var IgnoredParamExactNames = map[string]bool{
	// CMS pagination & navigation
	"page":   true,
	"p":      true,
	"pno":    true,
	"paged":  true,
	"pg":     true,
	"offset": true,
	"limit":  true,
	"size":   true,

	// Static display & language selectors
	"lang":     true,
	"hslang":   true,
	"language": true,
	"category": true,
	"article":  true,
	"sort":     true,
	"order":    true,
	"dir":      true,
	"view":     true,
	"mode":     true,
	"format":   true,

	// Tracking & attribution tokens
	"gclid":   true,
	"fbclid":  true,
	"msclkid": true,
	"dclid":   true,
	"wbraid":  true,
	"gbraid":  true,
	"_ga":     true,
	"_gid":    true,
}

// IgnoredParamPrefixes matches marketing, analytics, and CRM query parameters.
var IgnoredParamPrefixes = []string{
	"utm_", // Google Analytics UTM parameters
	"pk_",  // Matomo / Piwik tracking parameters
	"ga_",  // Google Analytics parameters
	"_hs",  // HubSpot analytics parameters
}

// ShouldSkipFuzzParam returns true if paramName is a marketing, pagination,
// language, or tracking parameter that should be excluded from intensive fuzzing.
func ShouldSkipFuzzParam(paramName string) bool {
	key := strings.ToLower(strings.TrimSpace(paramName))
	if key == "" {
		return true
	}

	if IgnoredParamExactNames[key] {
		return true
	}

	for _, prefix := range IgnoredParamPrefixes {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}

	return false
}

// ShouldSkipFuzzURL returns true if the URL has no query parameters OR all of its
// query parameters are ignored CMS/pagination/marketing parameters.
func ShouldSkipFuzzURL(rawURL string) bool {
	return !HasFuzzableParams(rawURL)
}

// FilterFuzzableParams filters a slice of parameter names, keeping only
// parameters that should be fuzzed (dropping CMS/marketing/pagination noise).
func FilterFuzzableParams(params []string) []string {
	var keep []string
	for _, p := range params {
		if !ShouldSkipFuzzParam(p) {
			keep = append(keep, p)
		}
	}
	return keep
}

// HasFuzzableParams inspects a raw URL and returns true if it contains at least
// one query parameter that is NOT an ignored marketing/pagination parameter.
func HasFuzzableParams(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		// Fallback to manual string parsing
		idx := strings.Index(rawURL, "?")
		if idx < 0 {
			return false
		}
		query := rawURL[idx+1:]
		for _, part := range strings.Split(query, "&") {
			k := part
			if eq := strings.Index(part, "="); eq >= 0 {
				k = part[:eq]
			}
			if !ShouldSkipFuzzParam(k) {
				return true
			}
		}
		return false
	}

	q := u.Query()
	for k := range q {
		if !ShouldSkipFuzzParam(k) {
			return true
		}
	}
	return false
}
