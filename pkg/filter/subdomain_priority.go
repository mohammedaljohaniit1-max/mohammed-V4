package filter

import (
	"sort"
	"strings"
)

// HighPriorityKeywords are keywords in hostnames indicating staging, dev, testing,
// internal, administrative, or API environments where critical vulnerabilities frequently reside.
var HighPriorityKeywords = []string{
	"staging",
	"stage",
	"stg",
	"dev",
	"devel",
	"test",
	"testing",
	"qa",
	"uat",
	"internal",
	"intranet",
	"corp",
	"admin",
	"portal",
	"api",
	"backend",
	"vpn",
}

// LowPriorityPrefixes are edge, public, or CDN prefixes that are typically fortified
// and should be scanned after dev/internal assets.
var LowPriorityPrefixes = []string{
	"www.",
	"static.",
	"cdn.",
	"assets.",
	"media.",
	"img.",
}

// PrioritizeLiveTargets sorts a list of hostnames/subdomains so that:
//  1. High-value staging/dev/internal/api/admin targets appear at the front (index 0..N).
//  2. Standard hostnames appear in the middle.
//  3. Generic 'www' and apex/root domains appear at the end.
//
// This non-destructive ordering ensures every subsequent scan phase tests high-value
// targets first without altering the overall phase sequence.
func PrioritizeLiveTargets(hosts []string) []string {
	if len(hosts) <= 1 {
		return hosts
	}

	var high []string
	var standard []string
	var low []string

	for _, raw := range hosts {
		h := strings.ToLower(strings.TrimSpace(raw))
		if h == "" {
			continue
		}

		// Check for high-priority keywords
		isHigh := false
		for _, kw := range HighPriorityKeywords {
			if strings.Contains(h, kw) {
				isHigh = true
				break
			}
		}

		if isHigh {
			high = append(high, raw)
			continue
		}

		// Check for low-priority (www, cdn, static, or pure apex domain)
		isLow := false
		for _, lp := range LowPriorityPrefixes {
			if strings.HasPrefix(h, lp) {
				isLow = true
				break
			}
		}
		// A host with no subdomains (e.g. "zid.sa" with only 1 dot) is apex/root
		if !isLow && strings.Count(h, ".") <= 1 {
			isLow = true
		}

		if isLow {
			low = append(low, raw)
		} else {
			standard = append(standard, raw)
		}
	}

	// Sort stably within groups for deterministic reproducibility
	sort.Strings(high)
	sort.Strings(standard)
	sort.Strings(low)

	result := make([]string, 0, len(hosts))
	result = append(result, high...)
	result = append(result, standard...)
	result = append(result, low...)
	return result
}
