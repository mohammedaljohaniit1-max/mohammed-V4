package osint

import (
	"net/url"
	"strings"
)

// PhoneCandidates builds the phoneinfoga-style lead set for a phone number:
//   - the normalised E.164 form + a country/region guess (validation.go-level),
//   - manual search-engine dorks in several formats (E.164, national, spaced),
//   - manual pointers to public reverse-lookup / messaging-app profile pages.
//
// It NEVER claims the number is valid/active or names a real owner — that is
// impossible to prove offline and often illegal to assert. Everything is a
// candidate lead for a human to verify.
func PhoneCandidates(raw, defaultCC string) []Candidate {
	e164, ok := NormalizePhone(raw, defaultCC)
	if !ok {
		return nil
	}
	cc, region := PhoneCountryCode(e164)

	national := strings.TrimPrefix(e164, "+")
	if cc != "" {
		national = strings.TrimPrefix(national, cc)
	}

	out := []Candidate{}

	// Messaging-app profile pointers (public deep links; human confirms).
	out = append(out, Candidate{
		Platform: "whatsapp",
		Kind:     "account",
		URL:      "https://wa.me/" + strings.TrimPrefix(e164, "+"),
		Method:   "manual",
		Note:     "manual: opens WhatsApp if the number is registered",
	})
	out = append(out, Candidate{
		Platform: "telegram",
		Kind:     "account",
		URL:      "https://t.me/+" + strings.TrimPrefix(e164, "+"),
		Method:   "manual",
		Note:     "manual: Telegram deep link",
	})

	// Region note carried as a dork-less informational candidate.
	regionNote := "country code unknown"
	if cc != "" {
		regionNote = "CC +" + cc
		if region != "" {
			regionNote += " (" + region + ")"
		}
	}
	out = append(out, Candidate{
		Platform: "meta",
		Kind:     "info",
		URL:      "",
		Method:   "manual",
		Note:     "normalised " + e164 + "; " + regionNote,
	})

	// Search dorks in the formats people actually store numbers in.
	for _, form := range phoneSearchForms(e164, national) {
		q := url.QueryEscape(`"` + form + `"`)
		out = append(out,
			Candidate{Platform: "google", Kind: "dork", URL: "https://www.google.com/search?q=" + q, Method: "manual", Note: "phone dork"},
			Candidate{Platform: "bing", Kind: "dork", URL: "https://www.bing.com/search?q=" + q, Method: "manual", Note: "phone dork"},
		)
	}

	return dedupCandidates(out)
}

// phoneSearchForms returns the common textual representations of a number so
// dorks catch listings that store it differently.
func phoneSearchForms(e164, national string) []string {
	forms := map[string]bool{e164: true}
	if national != "" {
		forms[national] = true
		// A spaced variant helps match "05x xxx xxxx" style listings.
		if len(national) > 3 {
			forms[national[:3]+" "+national[3:]] = true
		}
	}
	out := make([]string, 0, len(forms))
	for f := range forms {
		if strings.TrimSpace(f) != "" {
			out = append(out, f)
		}
	}
	// Deterministic order for stable tests: E.164 first, then the rest sorted.
	stableStrings(out, e164)
	return out
}

// stableStrings sorts out with `first` pinned to index 0 and the rest sorted.
func stableStrings(s []string, first string) {
	// simple insertion: pull `first` to front, sort remainder
	rest := make([]string, 0, len(s))
	hasFirst := false
	for _, v := range s {
		if v == first {
			hasFirst = true
			continue
		}
		rest = append(rest, v)
	}
	for i := 1; i < len(rest); i++ {
		for j := i; j > 0 && rest[j-1] > rest[j]; j-- {
			rest[j-1], rest[j] = rest[j], rest[j-1]
		}
	}
	idx := 0
	if hasFirst {
		s[0] = first
		idx = 1
	}
	for _, v := range rest {
		s[idx] = v
		idx++
	}
}
