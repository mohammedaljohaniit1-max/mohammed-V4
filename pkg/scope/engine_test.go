package scope

import (
	"reflect"
	"testing"
)

func TestWildcardBounty_ToolAllowed_FullAutomation(t *testing.T) {
	sf := &ScopeFile{
		Program: "ICI", InScope: []string{"*.iciparisxl.nl"},
		Automation: AutoWildcardBounty, MaxRPS: 5,
	}
	if err := sf.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	// Every class, including aggressive, is allowed under wildcard_bounty.
	for _, tool := range []string{"subfinder", "httpx", "katana", "nuclei", "ffuf", "dalfox", "naabu"} {
		ok, reason := sf.ToolAllowed(tool)
		if !ok {
			t.Errorf("wildcard_bounty should allow %q, denied: %s", tool, reason)
		}
	}
}

func TestWildcardBounty_RequiresMaxRPS(t *testing.T) {
	sf := &ScopeFile{Program: "x", InScope: []string{"a"}, Automation: AutoWildcardBounty}
	if err := sf.Validate(); err == nil {
		t.Error("wildcard_bounty with max_rps=0 must fail validation")
	}
	sf2 := &ScopeFile{Program: "x", InScope: []string{"a"}, Automation: AutoRateLimited}
	if err := sf2.Validate(); err == nil {
		t.Error("rate_limited with max_rps=0 must fail validation")
	}
}

func TestFullPlan_WildcardBounty(t *testing.T) {
	sf := &ScopeFile{
		Program: "ICI", InScope: []string{"*.iciparisxl.nl"},
		Automation: AutoWildcardBounty, MaxRPS: 5, RequiredUA: "@intigriti.me",
	}
	_ = sf.Validate()
	p := sf.FullPlan()
	if p.Profile != "large" {
		t.Errorf("profile=%q want large", p.Profile)
	}
	if !p.WAFBypass {
		t.Error("wildcard_bounty full plan should enable waf-bypass")
	}
	if p.PassiveOnly {
		t.Error("wildcard_bounty must not be passive-only")
	}
	// 5 rps -> 5*60*0.9 = 270 rpm, must stay <= 5*60=300.
	if p.RatePerMin != 270 {
		t.Errorf("RatePerMin=%d want 270 (90%% of 300)", p.RatePerMin)
	}
	if p.UserAgent != "@intigriti.me" {
		t.Errorf("UserAgent=%q want @intigriti.me", p.UserAgent)
	}
}

func TestFullPlan_ForbiddenIsPassive(t *testing.T) {
	sf := &ScopeFile{Program: "ejada", InScope: []string{"https://ehub.ejada.com/"}, Automation: AutoForbidden}
	_ = sf.Validate()
	p := sf.FullPlan()
	if p.Profile != "passive" || !p.PassiveOnly {
		t.Errorf("forbidden FullPlan must be passive-only, got profile=%q passiveOnly=%v", p.Profile, p.PassiveOnly)
	}
	if p.WAFBypass {
		t.Error("forbidden target must never enable waf-bypass")
	}
}

func TestFullPlan_SensitiveGovIsPassive_EvenIfRateLimited(t *testing.T) {
	sf := &ScopeFile{
		Program: "zain", InScope: []string{"https://zain.app"},
		Automation: AutoRateLimited, MaxRPS: 100, SensitiveGov: true,
	}
	_ = sf.Validate()
	p := sf.FullPlan()
	if p.Profile != "passive" || !p.PassiveOnly {
		t.Errorf("sensitive_gov must pin passive even when rate_limited, got %q", p.Profile)
	}
}

func TestFullPlan_ReportsRejectedIsSmall(t *testing.T) {
	sf := &ScopeFile{Program: "flag", InScope: []string{"*.flagyard.com"}, Automation: AutoReportsRejected}
	_ = sf.Validate()
	p := sf.FullPlan()
	if p.Profile != "small" {
		t.Errorf("reports_rejected FullPlan profile=%q want small", p.Profile)
	}
	if p.WAFBypass {
		t.Error("reports_rejected must not enable waf-bypass")
	}
}

func TestPassivePlan_AlwaysPassive(t *testing.T) {
	sf := &ScopeFile{
		Program: "ICI", InScope: []string{"*.iciparisxl.nl"},
		Automation: AutoWildcardBounty, MaxRPS: 5,
	}
	_ = sf.Validate()
	p := sf.PassivePlan()
	if p.Profile != "passive" || !p.PassiveOnly || p.WAFBypass {
		t.Errorf("PassivePlan must be passive-only with no waf-bypass, got %+v", p)
	}
}

func TestRPSToRPM_NeverExceedsCeiling(t *testing.T) {
	cases := map[int]int{0: 60, 1: 54, 5: 270, 100: 5400}
	for rps, want := range cases {
		if got := rpsToRPM(rps); got != want {
			t.Errorf("rpsToRPM(%d)=%d want %d", rps, got, want)
		}
		if rps > 0 && rpsToRPM(rps) > rps*60 {
			t.Errorf("rpsToRPM(%d) exceeded ceiling %d", rps, rps*60)
		}
	}
}

func TestScopeHosts_WildcardAndURLReduction(t *testing.T) {
	sf := &ScopeFile{
		Program: "x", InScope: []string{
			"https://api.example.com/path?q=1",
			"*.example.com",
			"www.example.com",
		},
		OutOfScope: []string{"*.internal.example.com"},
		Automation: AutoReportsRejected,
	}
	_ = sf.Validate()
	got := sf.ScopeHosts()
	want := []string{"!internal.example.com", "api.example.com", "example.com", "www.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ScopeHosts()=%v\nwant %v", got, want)
	}
}

func TestHostForScope(t *testing.T) {
	cases := map[string]string{
		"https://api.example.com/":  "api.example.com",
		"*.example.com":             "example.com",
		"WWW.Example.COM":           "www.example.com",
		"http://x.io:8443/a/b":      "x.io",
		"":                          "",
	}
	for in, want := range cases {
		if got := hostForScope(in); got != want {
			t.Errorf("hostForScope(%q)=%q want %q", in, got, want)
		}
	}
}
