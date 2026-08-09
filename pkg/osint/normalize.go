package osint

import (
	"regexp"
	"strings"
)

// ---- Email normalisation ----------------------------------------------------

var emailRe = regexp.MustCompile(`^[a-zA-Z0-9.!#$%&'*+/=?^_` + "`" + `{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$`)

// NormalizeEmail lower-cases and trims an email and validates its shape.
// It returns ("", false) for anything that is not a syntactically valid email.
func NormalizeEmail(raw string) (string, bool) {
	e := trimLower(raw)
	if !emailRe.MatchString(e) {
		return "", false
	}
	return e, true
}

// EmailParts splits a validated email into (local, domain).
func EmailParts(email string) (local, domain string) {
	i := strings.LastIndex(email, "@")
	if i < 0 {
		return email, ""
	}
	return email[:i], email[i+1:]
}

// UsernameFromEmail derives a plausible username from the local part, stripping
// a "+tag" gmail-style suffix and dots. It is a heuristic lead, never a fact.
func UsernameFromEmail(email string) string {
	local, _ := EmailParts(email)
	if i := strings.IndexByte(local, '+'); i >= 0 {
		local = local[:i]
	}
	local = strings.ReplaceAll(local, ".", "")
	return local
}

// ---- Phone normalisation ----------------------------------------------------

var nonDigit = regexp.MustCompile(`[^\d+]`)

// NormalizePhone produces a best-effort E.164 string. defaultCC (e.g. "966" for
// Saudi Arabia) is prepended ONLY when the number has no leading '+' and starts
// with a national trunk '0' or is a bare national number. It returns
// ("", false) when the result is not a plausible E.164 (7..15 digits).
//
// This is deliberately conservative: it does not claim carrier/validity, only a
// normalised form. Real validity requires the live checker or a libphonenumber
// integration the operator can add later.
func NormalizePhone(raw, defaultCC string) (string, bool) {
	s := nonDigit.ReplaceAllString(strings.TrimSpace(raw), "")
	if s == "" {
		return "", false
	}
	defaultCC = strings.TrimPrefix(strings.TrimSpace(defaultCC), "+")

	switch {
	case strings.HasPrefix(s, "+"):
		// already international
	case strings.HasPrefix(s, "00"):
		s = "+" + s[2:]
	case strings.HasPrefix(s, "0") && defaultCC != "":
		s = "+" + defaultCC + s[1:]
	case defaultCC != "":
		s = "+" + defaultCC + s
	default:
		return "", false
	}

	digits := strings.TrimPrefix(s, "+")
	if len(digits) < 7 || len(digits) > 15 {
		return "", false
	}
	for _, r := range digits {
		if r < '0' || r > '9' {
			return "", false
		}
	}
	return "+" + digits, true
}

// PhoneCountryCode returns the leading country-code guess for a normalised
// E.164 number using a small built-in table (extended by the operator as
// needed). It returns ("", "") when unknown — it never guesses wildly.
func PhoneCountryCode(e164 string) (cc, region string) {
	d := strings.TrimPrefix(e164, "+")
	// Longest-prefix match over a small, explicit table.
	for _, e := range ccTable {
		if strings.HasPrefix(d, e.code) {
			return e.code, e.region
		}
	}
	return "", ""
}

type ccEntry struct{ code, region string }

// ccTable is intentionally small and explicit (Gulf/MENA + a few majors),
// ordered longest-first so multi-digit codes win. Operators extend this.
var ccTable = []ccEntry{
	{"971", "United Arab Emirates"},
	{"973", "Bahrain"},
	{"974", "Qatar"},
	{"965", "Kuwait"},
	{"968", "Oman"},
	{"966", "Saudi Arabia"},
	{"962", "Jordan"},
	{"961", "Lebanon"},
	{"212", "Morocco"},
	{"216", "Tunisia"},
	{"20", "Egypt"},
	{"90", "Turkey"},
	{"44", "United Kingdom"},
	{"1", "North America"},
}
