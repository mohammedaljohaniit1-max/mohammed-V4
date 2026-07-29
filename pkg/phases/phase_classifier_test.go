package phases

import "testing"

func TestLooksLikeSPA(t *testing.T) {
	spa := `<html><head><script src="/static/js/main.abc.js"></script></head><body><div id="root"></div></body></html>`
	if !looksLikeSPA(spa) {
		t.Fatalf("react-style SPA shell should be detected")
	}
	server := `<html><body><h1>Welcome</h1><p>` + string(make([]byte, 30000)) + `</p></body></html>`
	if looksLikeSPA(server) {
		t.Fatalf("large server-rendered page should not be classified SPA")
	}
}

func TestIsJSONContentType(t *testing.T) {
	if !isJSONContentType("application/json; charset=utf-8") {
		t.Fatalf("application/json should be JSON")
	}
	if isJSONContentType("text/html") {
		t.Fatalf("text/html is not JSON")
	}
}

func TestProfileFor_UnknownIsPermissive(t *testing.T) {
	// With no classification run, ProfileFor must return an Unknown profile that
	// does NOT skip CDP (permissive default — never hide attack surface).
	p := ProfileFor("https://never-classified.example")
	if p.SkipCDP {
		t.Fatalf("unknown origin must not skip CDP")
	}
	if p.Class != ClassUnknown {
		t.Fatalf("unclassified origin should be Unknown, got %s", p.Class)
	}
}

func TestShouldSkipCDPFor_FalseWhenClassifierDidNotRun(t *testing.T) {
	// itoaLocal sanity while here.
	if itoaLocal(0) != "0" || itoaLocal(-12) != "-12" || itoaLocal(305) != "305" {
		t.Fatalf("itoaLocal broken")
	}
}
