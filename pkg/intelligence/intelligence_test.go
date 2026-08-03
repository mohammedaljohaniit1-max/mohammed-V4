package intelligence

import (
	"encoding/json"
	"sync"
	"testing"
)

func TestClassify_UltraHardenedByReportCount(t *testing.T) {
	ic := NewCore("gitlab.com")
	got := ic.Classify(ClassifyInput{ResolvedReports: 1500, HasBugBountyProgram: true})
	if got != ClassA {
		t.Fatalf("1500 resolved reports => want ClassA, got %s", got)
	}
	s := ic.Strategy()
	if s.RunGenericNuclei || s.RunAutomatedXSS {
		t.Fatalf("ClassA must disable generic nuclei/XSS, got %+v", s)
	}
	if !s.FocusBusinessLogic || s.ManualPercent != 70 {
		t.Fatalf("ClassA strategy wrong: %+v", s)
	}
}

func TestClassify_KnownUltraHardenedOverridesEverything(t *testing.T) {
	ic := NewCore("meta.com")
	got := ic.Classify(ClassifyInput{KnownUltraHardened: true, ResolvedReports: 0})
	if got != ClassA {
		t.Fatalf("KnownUltraHardened => want ClassA, got %s", got)
	}
}

func TestClassify_WellHardened(t *testing.T) {
	ic := NewCore("midsize.example")
	if got := ic.Classify(ClassifyInput{ResolvedReports: 250, HasBugBountyProgram: true}); got != ClassB {
		t.Fatalf("250 reports => want ClassB, got %s", got)
	}
}

func TestClassify_PartiallySecured(t *testing.T) {
	ic := NewCore("startup.example")
	if got := ic.Classify(ClassifyInput{ResolvedReports: 12, HasBugBountyProgram: true}); got != ClassC {
		t.Fatalf("12 reports => want ClassC, got %s", got)
	}
}

func TestClassify_LegacyUnprotectedIsD(t *testing.T) {
	ic := NewCore("legacy.example")
	got := ic.Classify(ClassifyInput{
		ResolvedReports:     -1,
		HasBugBountyProgram: false,
		LegacyStack:         true,
		WAFVendor:           "",
	})
	if got != ClassD {
		t.Fatalf("legacy + no program + no WAF => want ClassD, got %s", got)
	}
	if ic.Strategy().AutomationPercent != 90 {
		t.Fatalf("ClassD should be automation-heavy, got %+v", ic.Strategy())
	}
}

func TestClassify_NoProgramButWAFIsNotSoft(t *testing.T) {
	// Absence of a program must NOT be read as "soft target".
	ic := NewCore("noprogram.example")
	got := ic.Classify(ClassifyInput{HasBugBountyProgram: false, WAFVendor: "Cloudflare"})
	if got != ClassC {
		t.Fatalf("no program but WAF present => want ClassC (not D), got %s", got)
	}
	present, vendor := ic.WAF()
	if !present || vendor != "Cloudflare" {
		t.Fatalf("Classify should record WAF vendor, got present=%v vendor=%q", present, vendor)
	}
}

func TestFingerprint_RailsFromRuntimeHeader(t *testing.T) {
	ic := NewCore("app.example")
	ic.Fingerprint(Signals{
		Headers: map[string]string{"X-Runtime": "0.123", "Server": "nginx"},
	})
	if ic.Tech().Language != "ruby_on_rails" {
		t.Fatalf("X-Runtime => want ruby_on_rails, got %q", ic.Tech().Language)
	}
	if _, ok := ic.Tech().Evidence["language=ruby_on_rails"]; !ok {
		t.Fatalf("evidence map should justify the language claim: %+v", ic.Tech().Evidence)
	}
}

func TestFingerprint_DjangoFromCookie(t *testing.T) {
	ic := NewCore("app.example")
	ic.Fingerprint(Signals{SetCookie: "csrftoken=abc; sessionid=xyz"})
	if ic.Tech().Language != "python_django" {
		t.Fatalf("django cookies => want python_django, got %q", ic.Tech().Language)
	}
}

func TestFingerprint_WAFCloudflareHeader(t *testing.T) {
	ic := NewCore("app.example")
	ic.Fingerprint(Signals{Headers: map[string]string{"CF-RAY": "abc-LHR", "Server": "cloudflare"}})
	present, vendor := ic.WAF()
	if !present || vendor != "Cloudflare" {
		t.Fatalf("CF-Ray => want Cloudflare, got present=%v vendor=%q", present, vendor)
	}
}

func TestFingerprint_GraphQLProtocol(t *testing.T) {
	ic := NewCore("app.example")
	ic.Fingerprint(Signals{URL: "https://app.example/api/graphql", Body: `{"data":{}}`})
	found := false
	for _, p := range ic.Protocols() {
		if p == ProtoGraphQL {
			found = true
		}
	}
	if !found {
		t.Fatalf("/api/graphql => want ProtoGraphQL in %v", ic.Protocols())
	}
}

func TestFingerprint_JWTAuth(t *testing.T) {
	ic := NewCore("app.example")
	// realistic-looking JWT (header.payload.signature)
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.abcDEF123"
	ic.Fingerprint(Signals{Headers: map[string]string{"Authorization": "Bearer " + jwt}})
	got := ic.AuthMechanisms()
	if len(got) == 0 || got[0] != AuthJWT {
		t.Fatalf("Bearer JWT => want AuthJWT, got %v", got)
	}
}

func TestFingerprint_NoFalseTechWhenSilent(t *testing.T) {
	// A bland response must not produce a language guess. Over-claiming is the
	// exact failure mode we are avoiding.
	ic := NewCore("app.example")
	ic.Fingerprint(Signals{Headers: map[string]string{"Server": "nginx"}})
	if ic.Tech().Language != "" {
		t.Fatalf("bland response must not guess a language, got %q", ic.Tech().Language)
	}
}

func TestLearn_IgnoresEmptyAndMalformed(t *testing.T) {
	ic := NewCore("app.example")
	ic.Learn(Discovery{})                                   // empty kind
	ic.Learn(Discovery{Kind: DiscTech, Value: "no-equals"}) // malformed KV
	ic.Learn(Discovery{Kind: DiscTech, Value: "language="}) // empty value
	if ic.Tech().Language != "" {
		t.Fatalf("malformed discoveries must not set language, got %q", ic.Tech().Language)
	}
	// empty-kind discovery must not even be recorded
	if ic.DiscoveryCount() != 2 {
		t.Fatalf("want 2 recorded (malformed KV + empty value), got %d", ic.DiscoveryCount())
	}
}

func TestProfile_JSONRoundTrip(t *testing.T) {
	ic := NewCore("gitlab.com")
	ic.Classify(ClassifyInput{KnownUltraHardened: true})
	ic.Fingerprint(Signals{
		Headers:   map[string]string{"X-Runtime": "0.1", "CF-RAY": "x"},
		SetCookie: "_session_id=deadbeef",
		URL:       "https://gitlab.com/api/graphql",
		Body:      `{"data":{}}`,
	})
	ic.Learn(Discovery{Kind: DiscSession, Value: "reporter"})
	ic.Learn(Discovery{Kind: DiscEndpoint, Value: "/api/v4/users"})
	ic.Learn(Discovery{Kind: DiscParam, Value: "id"})

	p := ic.Profile()
	b, err := p.MarshalIndent()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back Profile
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Class != ClassA {
		t.Fatalf("round-trip class = %s", back.Class)
	}
	if back.Tech.Language != "ruby_on_rails" {
		t.Fatalf("round-trip language = %s", back.Tech.Language)
	}
	if !back.WAFPresent || back.WAFVendor != "Cloudflare" {
		t.Fatalf("round-trip WAF = %v/%s", back.WAFPresent, back.WAFVendor)
	}
	if len(back.Sessions) != 1 || back.Sessions[0] != "reporter" {
		t.Fatalf("round-trip sessions = %v", back.Sessions)
	}
	if back.SchemaVersion != ProfileSchemaVersion {
		t.Fatalf("schema version = %d", back.SchemaVersion)
	}
}

// TestCore_ConcurrentLearn is run under -race in CI to prove thread safety.
func TestCore_ConcurrentLearn(t *testing.T) {
	ic := NewCore("app.example")
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			ic.Learn(Discovery{Kind: DiscEndpoint, Value: "/e" + string(rune('a'+n%26))})
			ic.Fingerprint(Signals{Headers: map[string]string{"X-Runtime": "1"}})
			_ = ic.Profile()
		}(i)
	}
	wg.Wait()
	if ic.Tech().Language != "ruby_on_rails" {
		t.Fatalf("concurrent fingerprint lost the language signal")
	}
}
