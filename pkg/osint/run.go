package osint

import "strings"

// InputKind classifies a raw operator input as an email, phone or username.
type InputKind string

const (
	KindEmail    InputKind = "email"
	KindPhone    InputKind = "phone"
	KindUsername InputKind = "username"
)

// Classify decides what a raw input is, deterministically:
//   - contains '@' and validates as email -> email
//   - after stripping punctuation it is mostly digits (>=7) -> phone
//   - otherwise -> username
func Classify(raw string) InputKind {
	s := strings.TrimSpace(raw)
	if strings.Contains(s, "@") {
		if _, ok := NormalizeEmail(s); ok {
			return KindEmail
		}
	}
	digits := 0
	for _, r := range s {
		if r >= '0' && r <= '9' {
			digits++
		}
	}
	// A leading '+' or many digits and few letters => phone.
	letters := 0
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			letters++
		}
	}
	if digits >= 7 && letters == 0 {
		return KindPhone
	}
	return KindUsername
}

// BuildReport produces the deterministic, OFFLINE report for a raw input.
// defaultCC is used only for phone normalisation (e.g. "966"). No network is
// touched here; every candidate is Confirmed=false until a Checker runs.
func BuildReport(raw, defaultCC string) Report {
	raw = strings.TrimSpace(raw)
	rep := Report{Input: raw}
	rep.Notes = append(rep.Notes,
		"OFFLINE: every URL below is a CANDIDATE (a place to look), NOT proof an account exists.",
		"Confirmation requires the optional live existence check (--live), which only does gentle GET/HEAD.",
		"Dork/manual candidates are for a human to open; they are never auto-queried (search-engine ToS).",
	)

	switch Classify(raw) {
	case KindEmail:
		email, _ := NormalizeEmail(raw)
		rep.Identity = Identity{Email: email, Username: UsernameFromEmail(email)}
		rep.Candidates = EmailCandidates(raw)
	case KindPhone:
		e164, ok := NormalizePhone(raw, defaultCC)
		if ok {
			rep.Identity = Identity{Phone: e164}
		}
		rep.Candidates = PhoneCandidates(raw, defaultCC)
		if len(rep.Candidates) == 0 {
			rep.Notes = append(rep.Notes, "phone could not be normalised to E.164 (pass a valid number and/or -cc).")
		}
	default:
		rep.Identity = Identity{Username: sanitizeUsername(raw)}
		rep.Candidates = UsernameCandidates(raw)
	}
	return rep
}

// ProbeCount reports how many candidates a live check would actually probe
// (account/gravatar with GET/HEAD) — useful so operators see the network cost
// before running --live.
func ProbeCount(cands []Candidate) int {
	n := 0
	for _, c := range cands {
		if isProbable(c) {
			n++
		}
	}
	return n
}
