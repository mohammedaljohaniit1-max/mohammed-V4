package scope

import (
	"net/url"
	"regexp"
	"strings"
)

// Contains reports whether a raw URL or host is inside the program scope.
// Out-of-scope patterns are checked FIRST (an explicit exclusion always wins).
// Wildcards ("*.example.com", "*-sa-dev-*.nearpay.io") are supported.
func (sf *ScopeFile) Contains(raw string) bool {
	host := hostOf(raw)
	if host == "" {
		return false
	}
	for _, pat := range sf.OutOfScope {
		if matchHostPattern(pat, host, raw) {
			return false
		}
	}
	for _, pat := range sf.InScope {
		if matchHostPattern(pat, host, raw) {
			return true
		}
	}
	return false
}

// hostOf extracts a lower-cased host from a URL or a bare host string.
func hostOf(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil && u.Host != "" {
			return strings.ToLower(u.Hostname())
		}
	}
	// bare host (maybe with path); strip any path.
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	return strings.ToLower(s)
}

// matchHostPattern matches a scope pattern against a host. A pattern may be:
//   - a URL prefix ("https://ehub.ejada.com/") -> compared against the raw URL
//   - a wildcard host ("*.flagyard.com", "*-sa-dev-*.nearpay.io")
//   - an exact host ("zain.app")
func matchHostPattern(pat, host, raw string) bool {
	pat = strings.TrimSpace(pat)
	if pat == "" {
		return false
	}
	// URL-prefix pattern: match against the full raw URL (case-insensitive).
	if strings.Contains(pat, "://") {
		return strings.HasPrefix(strings.ToLower(strings.TrimSpace(raw)), strings.ToLower(pat)) ||
			hostOf(pat) == host
	}
	pat = strings.ToLower(pat)
	if !strings.Contains(pat, "*") {
		return pat == host
	}
	return compilePattern(pat).MatchString(host)
}

// compilePattern builds the anchored regexp deterministically. '*' -> one or
// more host-label chars. Result is cached per-pattern.
func compilePattern(pat string) *regexp.Regexp {
	if re, ok := patternCache[pat]; ok {
		return re
	}
	segments := strings.Split(pat, "*")
	var b strings.Builder
	b.WriteString("^")
	for i, seg := range segments {
		b.WriteString(regexp.QuoteMeta(seg))
		if i < len(segments)-1 {
			b.WriteString(`[a-z0-9.-]+`)
		}
	}
	b.WriteString("$")
	re := regexp.MustCompile(b.String())
	patternCache[pat] = re
	return re
}

var patternCache = map[string]*regexp.Regexp{}
