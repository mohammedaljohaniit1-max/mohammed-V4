// Package osint provides SEPARATE, phone- and email-specific OSINT primitives
// (operator request #4). The existing pkg/phases OSINT is DOMAIN-level only
// (subdomains, breach intel for a domain); nothing here duplicates it.
//
// HONESTY / LEGALITY MANDATE (must never be violated):
//
//   - This package NEVER fabricates results. Offline it only produces
//     *candidate* artefacts (normalised identifiers + deterministic account /
//     dork URLs). A candidate URL is a PLACE TO LOOK, not proof an account
//     exists. Proof requires the live existence check (checker.go, gated behind
//     an explicit -live flag and a real network).
//   - It does NOT attempt to bypass CAPTCHA, auth walls, or rate limits, and it
//     does NOT scrape sites whose terms forbid automation. It builds URLs a
//     human (or a gentle HEAD probe) can open.
//   - No API keys are embedded. Sources needing a key are simply skipped.
//
// The design mirrors the real, well-known tools the operator referenced:
//   - email  -> account-existence enumeration (holehe-style)
//   - phone  -> validation + carrier/region + search dorks (phoneinfoga-style)
//   - username -> account enumeration across platforms (maigret/sherlock-style)
//
// Everything in normalize.go / email.go / phone.go / username.go is PURE and
// fully unit-tested offline. Only checker.go touches the network.
package osint

import "strings"

// Identity is the normalised subject of an OSINT run. Exactly one of
// Email / Phone / Username is the primary lead; the others may be derived.
type Identity struct {
	Email    string `json:"email,omitempty"`
	Phone    string `json:"phone,omitempty"`  // E.164 when normalisation succeeds
	Username string `json:"username,omitempty"`
}

// Candidate is a single lead to investigate. It is explicitly NOT a confirmed
// finding — Confirmed stays false until a live existence check proves it.
type Candidate struct {
	Platform  string `json:"platform"`  // e.g. "github", "gravatar", "twitter"
	Kind      string `json:"kind"`      // "account" | "dork" | "breach-check" | "gravatar"
	URL       string `json:"url"`       // the place to look
	Method    string `json:"method"`    // suggested probe: "GET" | "HEAD" | "manual"
	Note      string `json:"note,omitempty"`
	Confirmed bool   `json:"confirmed"` // set true ONLY by a live check
	Status    int    `json:"status,omitempty"` // HTTP status from a live check, if run
}

// Report is the full deterministic output of an offline run.
type Report struct {
	Input      string      `json:"input"`
	Identity   Identity    `json:"identity"`
	Candidates []Candidate `json:"candidates"`
	// Notes records honest caveats (e.g. "offline: URLs are candidates, not proof").
	Notes []string `json:"notes"`
}

// dedupCandidates removes exact URL duplicates while preserving order.
func dedupCandidates(in []Candidate) []Candidate {
	seen := map[string]bool{}
	out := make([]Candidate, 0, len(in))
	for _, c := range in {
		key := c.Platform + "|" + c.URL
		if key == "|" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, c)
	}
	return out
}

// trimLower is a small shared helper.
func trimLower(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
