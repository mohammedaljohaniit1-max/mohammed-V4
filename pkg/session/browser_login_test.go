package session

import "testing"

func TestCookiesToHeader_SortedAndFiltered(t *testing.T) {
	cookies := []BrowserCookie{
		{Name: "b", Value: "2", Domain: "app.example.com"},
		{Name: "a", Value: "1", Domain: ".example.com"},
		{Name: "", Value: "skip", Domain: "app.example.com"}, // empty name dropped
		{Name: "other", Value: "x", Domain: "other.com"},     // filtered by host
	}
	got := CookiesToHeader(cookies, "app.example.com")
	want := "a=1; b=2"
	if got != want {
		t.Fatalf("CookiesToHeader = %q, want %q", got, want)
	}
}

func TestCookiesToHeader_NoHostKeepsAll(t *testing.T) {
	cookies := []BrowserCookie{
		{Name: "x", Value: "1"},
		{Name: "y", Value: "2"},
	}
	if got := CookiesToHeader(cookies, ""); got != "x=1; y=2" {
		t.Fatalf("got %q", got)
	}
}

func TestDomainMatches(t *testing.T) {
	cases := []struct {
		domain, host string
		want         bool
	}{
		{".example.com", "app.example.com", true},
		{"example.com", "example.com", true},
		{"example.com", "app.example.com", true},
		{"other.com", "app.example.com", false},
		{"", "anything.com", true}, // host-only cookie
	}
	for _, c := range cases {
		if got := domainMatches(c.domain, c.host); got != c.want {
			t.Errorf("domainMatches(%q,%q)=%v want %v", c.domain, c.host, got, c.want)
		}
	}
}

func TestLoginDetected_SuccessWithSessionOffLogin(t *testing.T) {
	ok, reason := LoginDetected("https://gitlab.test/dashboard",
		[]BrowserCookie{{Name: "_gitlab_session", Value: "abc"}})
	if !ok {
		t.Fatalf("expected login success, got failure: %s", reason)
	}
}

func TestLoginDetected_FailStillOnLoginPage(t *testing.T) {
	ok, _ := LoginDetected("https://gitlab.test/users/sign_in",
		[]BrowserCookie{{Name: "_gitlab_session", Value: "abc"}})
	if ok {
		t.Fatal("expected failure while still on login page")
	}
}

func TestLoginDetected_FailNoSessionOnLogin(t *testing.T) {
	ok, _ := LoginDetected("https://x.test/login", nil)
	if ok {
		t.Fatal("expected failure: no session and on login page")
	}
}

func TestLoginDetected_WeakSuccessOffLoginNoCookie(t *testing.T) {
	ok, reason := LoginDetected("https://x.test/home", nil)
	if !ok {
		t.Fatalf("expected weak success off login page, got failure: %s", reason)
	}
	if reason == "" {
		t.Fatal("expected a reason explaining the weak success")
	}
}

func TestLooksLikeSessionCookie(t *testing.T) {
	yes := []string{"_gitlab_session", "PHPSESSID", "JSESSIONID", "auth_token", "connect.sid", "jwt"}
	no := []string{"theme", "locale", "consent", "cf_clearance_x"}
	for _, n := range yes {
		if !looksLikeSessionCookie(n) {
			t.Errorf("%q should be recognised as a session cookie", n)
		}
	}
	for _, n := range no {
		if looksLikeSessionCookie(n) {
			t.Errorf("%q should NOT be a session cookie", n)
		}
	}
}
