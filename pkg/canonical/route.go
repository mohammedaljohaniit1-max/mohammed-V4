package canonical

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

var trackingParams = map[string]bool{
	"utm_source":   true,
	"utm_medium":   true,
	"utm_campaign": true,
	"utm_term":     true,
	"utm_content":  true,
	"ref":          true,
	"sessionid":    true,
	"cachebuster":  true,
	"cb":           true,
	"_":            true,
	"timestamp":    true,
}

var (
	uuidRegex = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	hexRegex  = regexp.MustCompile(`^[0-9a-fA-F]{16,}$`)
	alphaRegex = regexp.MustCompile(`^[a-zA-Z]+$`)
	alphanumRegex = regexp.MustCompile(`^[a-zA-Z0-9]+$`)
)

// ClassifyValueType converts arbitrary parameter values into abstract schema types.
func ClassifyValueType(v string) string {
	if v == "" {
		return "{EMPTY}"
	}
	if _, err := strconv.ParseInt(v, 10, 64); err == nil {
		return "{INT}"
	}
	if _, err := strconv.ParseFloat(v, 64); err == nil {
		return "{FLOAT}"
	}
	if uuidRegex.MatchString(v) {
		return "{UUID}"
	}
	if hexRegex.MatchString(v) {
		return "{HEX}"
	}
	if alphaRegex.MatchString(v) {
		return "{ALPHA}"
	}
	if alphanumRegex.MatchString(v) {
		return "{ALPHANUM}"
	}
	return "{STR}"
}

// RouteDeduplicator tracks evaluated route signatures to discard redundant permutations.
type RouteDeduplicator struct {
	mu       sync.RWMutex
	seenKeys sync.Map // map[string]struct{}
}

// NewRouteDeduplicator initializes a structural deduplicator.
func NewRouteDeduplicator() *RouteDeduplicator {
	return &RouteDeduplicator{}
}

// CanonicalizeRoute converts a raw URL into a normalized schema representation:
// e.g., /catalog/product?productId=17&view=grid -> GET /catalog/product?productId={INT}&view={ALPHA}
func CanonicalizeRoute(method, rawURL string) (string, error) {
	if method == "" {
		method = "GET"
	}
	method = strings.ToUpper(method)

	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return "", err
	}

	host := strings.ToLower(u.Hostname())
	path := u.Path
	if path == "" {
		path = "/"
	}

	// Collapse numeric IDs in path: /users/123/profile -> /users/{INT}/profile
	parts := strings.Split(path, "/")
	for i, p := range parts {
		if _, err := strconv.ParseInt(p, 10, 64); err == nil {
			parts[i] = "{INT}"
		} else if uuidRegex.MatchString(p) {
			parts[i] = "{UUID}"
		}
	}
	canonicalPath := strings.Join(parts, "/")

	// Strip tracking tokens and classify remaining parameters
	q := u.Query()
	var sortedKeys []string
	for k := range q {
		if !trackingParams[strings.ToLower(k)] {
			sortedKeys = append(sortedKeys, k)
		}
	}
	sort.Strings(sortedKeys)

	var paramParts []string
	for _, k := range sortedKeys {
		vals := q[k]
		typeStr := "{EMPTY}"
		if len(vals) > 0 {
			typeStr = ClassifyValueType(vals[0])
		}
		paramParts = append(paramParts, fmt.Sprintf("%s=%s", k, typeStr))
	}

	querySig := strings.Join(paramParts, "&")
	if querySig != "" {
		return fmt.Sprintf("%s %s%s?%s", method, host, canonicalPath, querySig), nil
	}
	return fmt.Sprintf("%s %s%s", method, host, canonicalPath), nil
}

// ShouldProbe checks if a route schema has already been visited for a phase/class.
// Returns true if this is a NEW structural schema, and records it.
func (d *RouteDeduplicator) ShouldProbe(phaseOrClass, method, rawURL string) bool {
	sig, err := CanonicalizeRoute(method, rawURL)
	if err != nil {
		return true // fallback to probe on unparseable URL
	}

	compositeKey := fmt.Sprintf("%s::%s", phaseOrClass, sig)
	_, loaded := d.seenKeys.LoadOrStore(compositeKey, struct{}{})
	return !loaded
}
