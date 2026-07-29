package engine

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestBypassEngine_RateLimitFloorClamped(t *testing.T) {
	// Even asking for 1000 rps must clamp to the ethical ≤10 rps floor.
	e := NewBypassEngine(true, 1000)
	if e.minInterRequest < 100*time.Millisecond {
		t.Fatalf("min inter-request %v below 10rps floor (100ms)", e.minInterRequest)
	}
	p := e.Plan(WAFCloudflare)
	if p.MinInterRequest < 100*time.Millisecond {
		t.Fatalf("plan MinInterRequest %v below floor", p.MinInterRequest)
	}
}

func TestBypassEngine_DisabledIsNoOp(t *testing.T) {
	e := NewBypassEngine(false, 10)
	p := e.Plan(WAFCloudflare)
	if len(p.Techniques) != 0 {
		t.Fatalf("disabled engine must apply no techniques, got %v", p.Techniques)
	}
	if got := p.TransformPayload("' OR '1'='1"); got != "' OR '1'='1" {
		t.Fatalf("disabled engine must use identity payload, got %q", got)
	}
}

func TestBypassEngine_BehavioralRequiresBrowser(t *testing.T) {
	e := NewBypassEngine(true, 10)
	for _, v := range []WAFVendor{WAFDataDome, WAFPerimeterX, WAFArkose} {
		p := e.Plan(v)
		if !p.RequiresBrowser {
			t.Fatalf("%s plan must require a browser (behavioral)", v)
		}
		if p.MaxInterRequest < 4*time.Second {
			t.Fatalf("%s plan human jitter max %v too fast (<4.7s window)", v, p.MaxInterRequest)
		}
	}
}

func TestBypassEngine_CloudflarePrefersHTTP2(t *testing.T) {
	e := NewBypassEngine(true, 10)
	p := e.Plan(WAFCloudflare)
	if !p.PreferHTTP2 {
		t.Fatalf("cloudflare plan should prefer HTTP/2 multiplexing")
	}
	if !hasTechnique(p, TechCFClearanceEmulate) {
		t.Fatalf("cloudflare plan should emulate cf_clearance")
	}
}

func TestBypassEngine_AWSJSONAndEncoding(t *testing.T) {
	e := NewBypassEngine(true, 10)
	p := e.Plan(WAFAWS)
	if !p.PreferJSONBody {
		t.Fatalf("AWS plan should prefer JSON body")
	}
	out := p.TransformPayload("select * from users where id='1'")
	if !strings.Contains(out, "%25") {
		t.Fatalf("AWS payload should be double-URL-encoded, got %q", out)
	}
}

func TestDoubleURLEncode(t *testing.T) {
	got := doubleURLEncode("'")
	if got != "%2527" {
		t.Fatalf("double-encode of ' should be %%2527, got %q", got)
	}
}

func TestAlternatingCase(t *testing.T) {
	if got := alternatingCase("select"); got != "SeLeCt" {
		t.Fatalf("alternatingCase(select)=%q want SeLeCt", got)
	}
}

func TestPlanForResponse_DataDome(t *testing.T) {
	e := NewBypassEngine(true, 10)
	h := http.Header{}
	h.Set("Set-Cookie", "datadome=abc123; Path=/")
	fp, plan := e.PlanForResponse(403, h, "px-captcha please verify")
	if !fp.Detected {
		t.Fatalf("expected WAF detected for datadome cookie")
	}
	if !plan.RequiresBrowser {
		t.Fatalf("datadome plan must require a browser")
	}
}

func TestApplyPlanHeaders_CookieMerge(t *testing.T) {
	plan := BypassPlan{Headers: map[string]string{"Cookie": "cf_clearance="}}
	out := ApplyPlanHeaders(map[string]string{"Cookie": "session=1"}, plan)
	if !strings.Contains(out["Cookie"], "session=1") || !strings.Contains(out["Cookie"], "cf_clearance=") {
		t.Fatalf("cookie merge failed: %q", out["Cookie"])
	}
}

func TestIsBehavioralWAF(t *testing.T) {
	if !IsBehavioralWAF(WAFDataDome) || !IsBehavioralWAF(WAFPerimeterX) || !IsBehavioralWAF(WAFArkose) {
		t.Fatalf("DataDome/PerimeterX/Arkose must be behavioral")
	}
	if IsBehavioralWAF(WAFCloudflare) {
		t.Fatalf("Cloudflare is not behavioral")
	}
}

func hasTechnique(p BypassPlan, want BypassTechnique) bool {
	for _, tq := range p.Techniques {
		if tq == want {
			return true
		}
	}
	return false
}
