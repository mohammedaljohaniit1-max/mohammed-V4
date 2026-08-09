package session

import (
	"sort"
	"strings"
)

// This file implements the TESTABLE core of the "interactive browser login"
// flow the operator asked for (idea #1):
//
//	1. The tool opens a REAL browser at the login page (done by pkg/browser via
//	   go-rod — that part needs Chrome and is not unit-testable in the sandbox).
//	2. The HUMAN logs in manually — solving CAPTCHA / 2FA themselves, which no
//	   automated tool can lawfully bypass. THIS is why interactive login beats
//	   automated bootstrap on hardened/gov targets.
//	3. The tool reads the browser's cookie jar and converts it into the Cookie
//	   header string the scan engines + the session Keeper consume.
//	4. LoginDetected() decides, from the post-login cookies/URL, whether the
//	   login actually succeeded, so we don't start scanning while still logged out.
//
// The go-rod glue lives in the caller (or a build-tagged file); everything HERE
// is pure and fully tested, so the cookie-serialisation and success-detection
// logic is verified without a live browser.

// BrowserCookie mirrors the subset of a go-rod / CDP cookie we need. The caller
// maps rod's proto.NetworkCookie into this before handing it over, so this
// package stays free of any browser dependency.
type BrowserCookie struct {
	Name     string
	Value    string
	Domain   string
	Path     string
	Secure   bool
	HTTPOnly bool
	// Expires is a unix timestamp (0 = session cookie).
	Expires float64
}

// CookiesToHeader converts a browser cookie jar into a single Cookie header
// value ("a=1; b=2"), filtered to the given host when host != "".
//
// It is deterministic (sorted by name) so tests and heartbeats are stable, and
// it skips empty-named cookies. Session cookies (Expires == 0) are KEPT — those
// are exactly the auth cookies we care about.
func CookiesToHeader(cookies []BrowserCookie, host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	filtered := make([]BrowserCookie, 0, len(cookies))
	for _, c := range cookies {
		if strings.TrimSpace(c.Name) == "" {
			continue
		}
		if host != "" && !domainMatches(c.Domain, host) {
			continue
		}
		filtered = append(filtered, c)
	}
	sort.Slice(filtered, func(i, j int) bool { return filtered[i].Name < filtered[j].Name })

	parts := make([]string, 0, len(filtered))
	seen := map[string]bool{}
	for _, c := range filtered {
		if seen[c.Name] {
			continue // first (sorted) wins; avoids duplicate cookie names
		}
		seen[c.Name] = true
		parts = append(parts, c.Name+"="+c.Value)
	}
	return strings.Join(parts, "; ")
}

// domainMatches reports whether a cookie domain applies to host. Handles the
// leading-dot convention (".example.com" matches "app.example.com").
func domainMatches(cookieDomain, host string) bool {
	cd := strings.ToLower(strings.TrimSpace(cookieDomain))
	cd = strings.TrimPrefix(cd, ".")
	if cd == "" {
		return true // host-only cookie with no domain: accept
	}
	return host == cd || strings.HasSuffix(host, "."+cd)
}

// LoginDetected decides whether a manual login succeeded, from the post-login
// signals. This gates the transition "browser open → start scanning".
//
// Heuristics (any strong positive wins; a clear negative overrides):
//   - A recognised session cookie is present  -> success.
//   - The final URL is NOT a login page        -> supports success.
//   - The final URL IS still a login page       -> failure (still logged out).
func LoginDetected(finalURL string, cookies []BrowserCookie) (ok bool, reason string) {
	lower := strings.ToLower(finalURL)
	onLoginPage := strings.Contains(lower, "/login") ||
		strings.Contains(lower, "/signin") ||
		strings.Contains(lower, "/sign-in") ||
		strings.Contains(lower, "/sign_in") ||
		strings.Contains(lower, "/sso")

	hasSession := false
	for _, c := range cookies {
		if looksLikeSessionCookie(c.Name) && strings.TrimSpace(c.Value) != "" {
			hasSession = true
			break
		}
	}

	switch {
	case hasSession && !onLoginPage:
		return true, "session cookie present and off the login page"
	case hasSession && onLoginPage:
		// A session cookie can exist pre-login on some apps; require leaving the
		// login page to be safe.
		return false, "session cookie present but still on login page"
	case !hasSession && onLoginPage:
		return false, "no session cookie and still on login page"
	default:
		// Off the login page but no obvious session cookie: weak success. Accept
		// but flag it so the heartbeat verifies quickly.
		return true, "left login page (no obvious session cookie; heartbeat will confirm)"
	}
}

// looksLikeSessionCookie recognises common framework session-cookie names.
func looksLikeSessionCookie(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	needles := []string{
		"session", "sess", "sid", "auth", "token", "jwt",
		"_gitlab_session", "phpsessid", "jsessionid", "connect.sid",
		"laravel_session", "csrftoken", "remember",
	}
	for _, s := range needles {
		if strings.Contains(n, s) {
			return true
		}
	}
	return false
}
