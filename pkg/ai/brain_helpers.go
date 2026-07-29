// brain_helpers.go — small stdlib-only helpers for the V10 cognitive Brain.
// Kept in a separate file so brain.go stays focused on the three cognitive
// responsibilities. All helpers are pure and deterministic (unit-testable).
package ai

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// formatPrompt is a thin wrapper around fmt.Sprintf so the prompt constants read
// cleanly and a future switch to a template engine only touches this one spot.
func formatPrompt(tmpl string, args ...interface{}) string {
	return fmt.Sprintf(tmpl, args...)
}

// extractInt pulls the first integer out of a string (e.g. "CONFIDENCE: 82" → 82).
// Returns 0 when no integer is present. Clamps to [0,100] for confidence use.
func extractInt(s string) int {
	var digits strings.Builder
	started := false
	for _, r := range s {
		if r >= '0' && r <= '9' {
			digits.WriteRune(r)
			started = true
		} else if started {
			break
		}
	}
	if digits.Len() == 0 {
		return 0
	}
	n, err := strconv.Atoi(digits.String())
	if err != nil {
		return 0
	}
	if n < 0 {
		n = 0
	}
	if n > 100 {
		n = 100
	}
	return n
}

// firstNonEmptyLine returns the first trimmed non-empty line of a block, capped
// so a rambling model reply cannot become a giant reason string.
func firstNonEmptyLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		l := strings.TrimSpace(line)
		if l != "" {
			if len(l) > 160 {
				l = l[:160]
			}
			return l
		}
	}
	return ""
}

// caseFlip inverts the case of every ASCII letter — a classic, zero-cost filter
// bypass for case-insensitive signature matchers.
func caseFlip(s string) string {
	b := []rune(s)
	for i, r := range b {
		switch {
		case r >= 'a' && r <= 'z':
			b[i] = r - 32
		case r >= 'A' && r <= 'Z':
			b[i] = r + 32
		}
	}
	return string(b)
}

// urlEncodeAll percent-encodes every byte of the payload (full over-encoding),
// which slips past filters that only decode once before matching.
func urlEncodeAll(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		fmt.Fprintf(&b, "%%%02X", s[i])
	}
	return b.String()
}

// doubleURLEncode URL-encodes the payload twice — defeats single-decode WAFs.
func doubleURLEncode(s string) string {
	return url.QueryEscape(url.QueryEscape(s))
}
