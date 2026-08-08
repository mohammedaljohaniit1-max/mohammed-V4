package scope

import "testing"

func testScope() *ScopeFile {
	return &ScopeFile{
		Program:    "t",
		InScope:    []string{"*.flagyard.com", "zain.app", "https://ehub.ejada.com/"},
		OutOfScope: []string{"blog.flagyard.com"},
		Automation: AutoReportsRejected,
	}
}

func TestContains_Wildcard(t *testing.T) {
	sf := testScope()
	cases := map[string]bool{
		"https://app.flagyard.com/login": true,
		"api.flagyard.com":               true,
		"flagyard.com":                   false, // wildcard requires a subdomain
		"https://blog.flagyard.com/x":    false, // explicit out-of-scope wins
		"zain.app":                       true,
		"https://zain.app/account":       true,
		"evil.com":                       false,
		"https://ehub.ejada.com/x":       true, // URL-prefix pattern
		"ehub.ejada.com":                 true,
	}
	for in, want := range cases {
		if got := sf.Contains(in); got != want {
			t.Errorf("Contains(%q)=%v want %v", in, got, want)
		}
	}
}

func TestContains_NearpayDevWildcard(t *testing.T) {
	sf := &ScopeFile{Program: "np", InScope: []string{"*-sa-dev-*.nearpay.io"}, Automation: AutoReportsRejected}
	if !sf.Contains("https://foo-sa-dev-bar.nearpay.io/") {
		t.Error("expected nearpay dev wildcard to match")
	}
	if sf.Contains("https://prod.nearpay.io/") {
		t.Error("prod must not match dev-only wildcard")
	}
}

func TestClassOf(t *testing.T) {
	cases := map[string]ToolClass{
		"subfinder": ClassPassive,
		"httpx":     ClassProbe,
		"katana":    ClassActive,
		"nuclei":    ClassAggressive,
		"nmap":      ClassAggressive,
		"ffuf":      ClassAggressive,
		"unknown-x": ClassAggressive, // safe default
	}
	for tool, want := range cases {
		if got := ClassOf(tool); got != want {
			t.Errorf("ClassOf(%q)=%q want %q", tool, got, want)
		}
	}
}

func TestToolAllowed_Forbidden_PassiveOnly(t *testing.T) {
	sf := &ScopeFile{Program: "ejada", InScope: []string{"x.com"}, Automation: AutoForbidden}
	if ok, _ := sf.ToolAllowed("subfinder"); !ok {
		t.Error("passive subfinder should be allowed even when automation forbidden")
	}
	for _, agg := range []string{"nuclei", "nmap", "ffuf", "naabu", "dalfox"} {
		if ok, reason := sf.ToolAllowed(agg); ok {
			t.Errorf("%s must be DENIED under AutoForbidden (%s)", agg, reason)
		}
	}
	if ok, _ := sf.ToolAllowed("katana"); ok {
		t.Error("active katana must be denied under AutoForbidden")
	}
}

func TestToolAllowed_ReportsRejected_NoAggressive(t *testing.T) {
	sf := &ScopeFile{Program: "flagyard", InScope: []string{"*.flagyard.com"}, Automation: AutoReportsRejected}
	if ok, _ := sf.ToolAllowed("katana"); !ok {
		t.Error("active crawler allowed when only tool-only reports are rejected")
	}
	if ok, _ := sf.ToolAllowed("nuclei"); ok {
		t.Error("aggressive nuclei must be denied")
	}
}

func TestToolAllowed_SensitiveGovPassiveOnly(t *testing.T) {
	sf := &ScopeFile{Program: "nournet", InScope: []string{"eservices.nour.net.sa"}, Automation: AutoRateLimited, MaxRPS: 100, SensitiveGov: true}
	if ok, _ := sf.ToolAllowed("subfinder"); !ok {
		t.Error("passive allowed on sensitive gov")
	}
	// Even probe/active/aggressive denied on sensitive gov.
	for _, tl := range []string{"httpx", "katana", "nuclei", "nmap"} {
		if ok, reason := sf.ToolAllowed(tl); ok {
			t.Errorf("%s must be denied on sensitive gov (%s)", tl, reason)
		}
	}
}

func TestToolAllowed_RateLimitedNeedsCeiling(t *testing.T) {
	// aggressive tool denied when no max_rps set
	sf := &ScopeFile{Program: "z", InScope: []string{"zain.app"}, Automation: AutoRateLimited, MaxRPS: 0}
	if ok, _ := sf.ToolAllowed("nuclei"); ok {
		t.Error("aggressive tool must need an explicit max_rps")
	}
	sf.MaxRPS = 100
	if ok, _ := sf.ToolAllowed("nuclei"); !ok {
		t.Error("aggressive tool allowed once max_rps set")
	}
}

func TestAllowedTools_Summary(t *testing.T) {
	sf := &ScopeFile{Program: "ejada", InScope: []string{"x"}, Automation: AutoForbidden}
	allowed, denied := sf.AllowedTools([]string{"subfinder", "nuclei", "katana"})
	if len(allowed) != 1 || allowed[0] != "subfinder" {
		t.Errorf("allowed=%v want [subfinder]", allowed)
	}
	if _, ok := denied["nuclei"]; !ok {
		t.Error("nuclei should be in denied map")
	}
}

func TestValidate_Defaults(t *testing.T) {
	sf := &ScopeFile{Program: "p", InScope: []string{"x"}}
	if err := sf.Validate(); err != nil {
		t.Fatal(err)
	}
	if sf.Automation != AutoForbidden {
		t.Errorf("unspecified automation must default to safest (forbidden), got %q", sf.Automation)
	}
}

func TestValidate_Errors(t *testing.T) {
	if err := (&ScopeFile{InScope: []string{"x"}}).Validate(); err == nil {
		t.Error("missing program should error")
	}
	if err := (&ScopeFile{Program: "p"}).Validate(); err == nil {
		t.Error("missing in_scope should error")
	}
	if err := (&ScopeFile{Program: "p", InScope: []string{"x"}, Automation: "bogus"}).Validate(); err == nil {
		t.Error("bad automation should error")
	}
}
