package osint

import (
	"fmt"
	"net/url"
	"strings"
)

// EmailCandidates builds the holehe-style lead set for an email:
//   - a Gravatar existence URL (privacy-respecting, public by design),
//   - deterministic account URLs on platforms whose PUBLIC profile URL is
//     derivable from the derived username,
//   - a have-i-been-pwned MANUAL breach-check pointer (no key, no scraping),
//   - search-engine dorks for the raw email.
//
// Every entry is a CANDIDATE (Confirmed=false). Nothing here proves an account
// exists; that is the job of the live checker.
func EmailCandidates(email string) []Candidate {
	email, ok := NormalizeEmail(email)
	if !ok {
		return nil
	}
	user := UsernameFromEmail(email)

	out := []Candidate{
		{
			Platform: "gravatar",
			Kind:     "gravatar",
			URL:      "https://www.gravatar.com/avatar/" + md5Hex(email) + "?d=404",
			Method:   "GET",
			Note:     "200 => a Gravatar (and likely a public profile) exists for this email",
		},
		{
			Platform: "haveibeenpwned",
			Kind:     "breach-check",
			URL:      "https://haveibeenpwned.com/account/" + url.PathEscape(email),
			Method:   "manual",
			Note:     "manual: HIBP account search (API requires a key; do not scrape)",
		},
	}

	// Username-derived public profiles (only platforms with a stable public URL).
	out = append(out, usernameProfileCandidates(user, "derived from email local-part")...)

	// Search dorks (manual): a human opens these; we never auto-scrape engines.
	out = append(out, dorkCandidates(email)...)

	return dedupCandidates(out)
}

// UsernameCandidates builds the maigret/sherlock-style lead set for a bare
// username across platforms with derivable public profile URLs.
func UsernameCandidates(username string) []Candidate {
	u := sanitizeUsername(username)
	if u == "" {
		return nil
	}
	out := usernameProfileCandidates(u, "direct username lookup")
	out = append(out, dorkCandidates(u)...)
	return dedupCandidates(out)
}

// platform holds a public-profile URL template. %s is the username.
type platform struct {
	name   string
	tmpl   string
	method string
}

// publicProfilePlatforms lists ONLY sites whose public profile URL is
// deterministic and whose existence can be inferred from an HTTP status without
// authentication or scraping private data.
var publicProfilePlatforms = []platform{
	{"github", "https://github.com/%s", "HEAD"},
	{"gitlab", "https://gitlab.com/%s", "HEAD"},
	{"twitter", "https://twitter.com/%s", "GET"},
	{"instagram", "https://www.instagram.com/%s/", "GET"},
	{"reddit", "https://www.reddit.com/user/%s", "GET"},
	{"keybase", "https://keybase.io/%s", "GET"},
	{"gravatar", "https://gravatar.com/%s", "GET"},
	{"telegram", "https://t.me/%s", "GET"},
	{"medium", "https://medium.com/@%s", "GET"},
	{"pinterest", "https://www.pinterest.com/%s/", "GET"},
	{"tiktok", "https://www.tiktok.com/@%s", "GET"},
	{"npm", "https://www.npmjs.com/~%s", "GET"},
}

func usernameProfileCandidates(user, note string) []Candidate {
	if user == "" {
		return nil
	}
	out := make([]Candidate, 0, len(publicProfilePlatforms))
	for _, p := range publicProfilePlatforms {
		out = append(out, Candidate{
			Platform: p.name,
			Kind:     "account",
			URL:      fmt.Sprintf(p.tmpl, url.PathEscape(user)),
			Method:   p.method,
			Note:     note,
		})
	}
	return out
}

// dorkCandidates produces manual search-engine dorks. We do not auto-query
// engines (that violates their terms); a human clicks these.
func dorkCandidates(term string) []Candidate {
	q := url.QueryEscape(`"` + term + `"`)
	return []Candidate{
		{Platform: "google", Kind: "dork", URL: "https://www.google.com/search?q=" + q, Method: "manual", Note: "manual OSINT dork"},
		{Platform: "bing", Kind: "dork", URL: "https://www.bing.com/search?q=" + q, Method: "manual", Note: "manual OSINT dork"},
	}
}

// sanitizeUsername keeps only characters valid across the common platforms and
// strips a leading '@'. It lower-cases for determinism.
func sanitizeUsername(raw string) string {
	u := strings.TrimSpace(raw)
	u = strings.TrimPrefix(u, "@")
	u = trimLower(u)
	var b strings.Builder
	for _, r := range u {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' {
			b.WriteRune(r)
		}
	}
	return b.String()
}
