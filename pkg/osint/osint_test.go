package osint

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestNormalizeEmail(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"  User@Example.COM ", "user@example.com", true},
		{"a.b+tag@gmail.com", "a.b+tag@gmail.com", true},
		{"not-an-email", "", false},
		{"@nope.com", "", false},
		{"foo@bar", "", false}, // no TLD
		{"", "", false},
	}
	for _, c := range cases {
		got, ok := NormalizeEmail(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("NormalizeEmail(%q)=%q,%v want %q,%v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestUsernameFromEmail(t *testing.T) {
	cases := map[string]string{
		"john.doe@gmail.com":   "johndoe",
		"john.doe+spam@x.com":  "johndoe",
		"a_b@x.io":             "a_b",
	}
	for in, want := range cases {
		e, _ := NormalizeEmail(in)
		if got := UsernameFromEmail(e); got != want {
			t.Errorf("UsernameFromEmail(%q)=%q want %q", in, got, want)
		}
	}
}

func TestNormalizePhone(t *testing.T) {
	cases := []struct {
		raw, cc, want string
		ok            bool
	}{
		{"+966 50 123 4567", "", "+966501234567", true},
		{"0501234567", "966", "+966501234567", true},
		{"00966501234567", "", "+966501234567", true},
		{"501234567", "966", "+966501234567", true},
		{"123", "966", "", false},       // too short after CC? 966123 = 6 digits -> invalid
		{"abc", "966", "", false},
		{"", "966", "", false},
	}
	for _, c := range cases {
		got, ok := NormalizePhone(c.raw, c.cc)
		if ok != c.ok || got != c.want {
			t.Errorf("NormalizePhone(%q,%q)=%q,%v want %q,%v", c.raw, c.cc, got, ok, c.want, c.ok)
		}
	}
}

func TestPhoneCountryCode(t *testing.T) {
	cc, region := PhoneCountryCode("+966501234567")
	if cc != "966" || !strings.Contains(region, "Saudi") {
		t.Errorf("PhoneCountryCode Saudi = %q,%q", cc, region)
	}
	cc, _ = PhoneCountryCode("+971501234567")
	if cc != "971" {
		t.Errorf("PhoneCountryCode UAE cc = %q", cc)
	}
	// Unknown code stays empty (no wild guessing).
	if cc, _ := PhoneCountryCode("+999123456"); cc != "" {
		t.Errorf("unknown CC should be empty, got %q", cc)
	}
}

func TestClassify(t *testing.T) {
	cases := map[string]InputKind{
		"user@example.com": KindEmail,
		"+966501234567":    KindPhone,
		"0501234567":       KindPhone,
		"john_doe":         KindUsername,
		"@handle":          KindUsername,
	}
	for in, want := range cases {
		if got := Classify(in); got != want {
			t.Errorf("Classify(%q)=%q want %q", in, got, want)
		}
	}
}

func TestEmailCandidates_HasGravatarAndAccounts(t *testing.T) {
	cands := EmailCandidates("john.doe@example.com")
	if len(cands) == 0 {
		t.Fatal("expected candidates")
	}
	var hasGravatar, hasGithub, hasHIBP bool
	for _, c := range cands {
		if c.Confirmed {
			t.Errorf("offline candidate must not be pre-confirmed: %+v", c)
		}
		switch {
		case c.Platform == "gravatar" && c.Kind == "gravatar":
			hasGravatar = true
			if !strings.Contains(c.URL, md5Hex("john.doe@example.com")) {
				t.Errorf("gravatar avatar URL missing md5 hash: %s", c.URL)
			}
		case c.Platform == "github":
			hasGithub = true
			if !strings.Contains(c.URL, "johndoe") {
				t.Errorf("github URL should use derived username: %s", c.URL)
			}
		case c.Platform == "haveibeenpwned":
			hasHIBP = true
			if c.Method != "manual" {
				t.Errorf("HIBP must be manual (no scraping): %+v", c)
			}
		}
	}
	if !hasGravatar || !hasGithub || !hasHIBP {
		t.Errorf("missing expected platforms gravatar=%v github=%v hibp=%v", hasGravatar, hasGithub, hasHIBP)
	}
}

func TestPhoneCandidates_MessagingAndDorks(t *testing.T) {
	cands := PhoneCandidates("0501234567", "966")
	if len(cands) == 0 {
		t.Fatal("expected phone candidates")
	}
	var hasWA, hasDork bool
	for _, c := range cands {
		if c.Platform == "whatsapp" {
			hasWA = true
			if !strings.Contains(c.URL, "966501234567") {
				t.Errorf("wa.me URL wrong: %s", c.URL)
			}
		}
		if c.Kind == "dork" {
			hasDork = true
			if c.Method != "manual" {
				t.Errorf("dork must be manual: %+v", c)
			}
		}
	}
	if !hasWA || !hasDork {
		t.Errorf("missing wa=%v dork=%v", hasWA, hasDork)
	}
}

func TestBuildReport_EmailOffline(t *testing.T) {
	rep := BuildReport("Jane.Roe@Example.com", "")
	if rep.Identity.Email != "jane.roe@example.com" {
		t.Errorf("identity email = %q", rep.Identity.Email)
	}
	if len(rep.Notes) == 0 {
		t.Error("report must carry honesty notes")
	}
	for _, c := range rep.Candidates {
		if c.Confirmed {
			t.Errorf("no candidate may be confirmed offline: %+v", c)
		}
	}
}

func TestUsernameCandidates_SanitizesHandle(t *testing.T) {
	cands := UsernameCandidates("@John_Doe!!")
	for _, c := range cands {
		if strings.Contains(c.URL, "!") {
			t.Errorf("username not sanitised in URL: %s", c.URL)
		}
	}
}

// ---- checker (injected prober, no network) ---------------------------------

type fakeProber struct {
	statuses map[string]int // url -> status
	errs     map[string]bool
	calls    int
}

func (f *fakeProber) probe(ctx context.Context, method, u string) (int, error) {
	f.calls++
	if f.errs[u] {
		return 0, context.DeadlineExceeded
	}
	if s, ok := f.statuses[u]; ok {
		return s, nil
	}
	return 404, nil
}

func TestChecker_ConfirmsOn2xxOnly(t *testing.T) {
	cands := []Candidate{
		{Platform: "github", Kind: "account", URL: "https://github.com/exists", Method: "HEAD"},
		{Platform: "gitlab", Kind: "account", URL: "https://gitlab.com/missing", Method: "HEAD"},
		{Platform: "google", Kind: "dork", URL: "https://google.com/search?q=x", Method: "manual"},
	}
	fp := &fakeProber{statuses: map[string]int{
		"https://github.com/exists":  200,
		"https://gitlab.com/missing": 404,
	}}
	out := checkWith(context.Background(), fp, 0, cands)

	if !out[0].Confirmed || out[0].Status != 200 {
		t.Errorf("github should be confirmed 200: %+v", out[0])
	}
	if out[1].Confirmed || out[1].Status != 404 {
		t.Errorf("gitlab should be unconfirmed 404: %+v", out[1])
	}
	if out[2].Confirmed || out[2].Status != 0 {
		t.Errorf("dork must NOT be probed: %+v", out[2])
	}
	if fp.calls != 2 {
		t.Errorf("only account candidates should be probed, calls=%d", fp.calls)
	}
}

func TestChecker_NetworkErrorNeverConfirms(t *testing.T) {
	cands := []Candidate{{Platform: "github", Kind: "account", URL: "https://x/y", Method: "HEAD"}}
	fp := &fakeProber{errs: map[string]bool{"https://x/y": true}}
	out := checkWith(context.Background(), fp, 0, cands)
	if out[0].Confirmed {
		t.Errorf("network error must never confirm: %+v", out[0])
	}
}

func TestChecker_RespectsContextCancel(t *testing.T) {
	cands := []Candidate{
		{Platform: "a", Kind: "account", URL: "https://a", Method: "HEAD"},
		{Platform: "b", Kind: "account", URL: "https://b", Method: "HEAD"},
	}
	fp := &fakeProber{statuses: map[string]int{"https://a": 200, "https://b": 200}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled
	out := checkWith(ctx, fp, 10*time.Millisecond, cands)
	// With a delay and cancelled ctx, the second probe's wait aborts.
	if out[1].Confirmed {
		t.Errorf("cancelled context should stop before second confirm: %+v", out[1])
	}
}

func TestProbeCount(t *testing.T) {
	cands := BuildReport("user@example.com", "").Candidates
	n := ProbeCount(cands)
	if n == 0 {
		t.Error("expected some probable candidates for an email")
	}
	if n > len(cands) {
		t.Error("probe count cannot exceed total")
	}
}

func TestIsProbable_MethodGuard(t *testing.T) {
	if isProbable(Candidate{Kind: "account", URL: "https://x", Method: "manual"}) {
		t.Error("manual method must not be probed")
	}
	if !isProbable(Candidate{Kind: "account", URL: "https://x", Method: http.MethodGet}) {
		t.Error("GET account should be probable")
	}
}
