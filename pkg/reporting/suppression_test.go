package reporting

import (
	"strings"
	"testing"
)

func f(fields ...interface{}) Finding {
	m := Finding{}
	for i := 0; i+1 < len(fields); i += 2 {
		m[fields[i].(string)] = fields[i+1]
	}
	return m
}

func TestSuppress_MissingSecurityHeaders(t *testing.T) {
	s := NewDefault()
	res := s.Apply([]Finding{
		f("title", "Missing Security Header: Content-Security-Policy", "severity", "low", "confidence", 30),
	})
	if res.SuppressedCount() != 1 {
		t.Fatalf("expected 1 suppressed, got %d", res.SuppressedCount())
	}
	if res.Suppressed[0].RuleID != "SUP-MISSING-HEADERS" {
		t.Errorf("ruleID = %s, want SUP-MISSING-HEADERS", res.Suppressed[0].RuleID)
	}
}

func TestSuppress_SelfXSS(t *testing.T) {
	s := NewDefault()
	res := s.Apply([]Finding{
		f("title", "Self-XSS in profile bio (victim must paste into console)", "severity", "low"),
	})
	if res.SuppressedCount() != 1 || res.Suppressed[0].RuleID != "SUP-SELF-XSS" {
		t.Fatalf("self-XSS not suppressed correctly: %+v", res.Suppressed)
	}
}

func TestSuppress_Clickjacking(t *testing.T) {
	s := NewDefault()
	res := s.Apply([]Finding{
		f("title", "Clickjacking possible: X-Frame-Options not set", "severity", "low"),
	})
	if res.SuppressedCount() != 1 || res.Suppressed[0].RuleID != "SUP-CLICKJACKING-NO-ACTION" {
		t.Fatalf("clickjacking not suppressed: %+v", res.Suppressed)
	}
}

func TestSuppress_VersionBanner(t *testing.T) {
	s := NewDefault()
	res := s.Apply([]Finding{
		f("title", "Server version disclosure via X-Powered-By header", "severity", "info"),
	})
	if res.SuppressedCount() != 1 || res.Suppressed[0].RuleID != "SUP-VERSION-BANNER" {
		t.Fatalf("version banner not suppressed: %+v", res.Suppressed)
	}
}

func TestSuppress_NoRateLimit(t *testing.T) {
	s := NewDefault()
	res := s.Apply([]Finding{
		f("title", "No rate limiting on login (brute force possible)", "severity", "medium"),
	})
	if res.SuppressedCount() != 1 || res.Suppressed[0].RuleID != "SUP-NO-RATE-LIMIT" {
		t.Fatalf("no-rate-limit not suppressed: %+v", res.Suppressed)
	}
}

func TestSuppress_CookieFlags(t *testing.T) {
	s := NewDefault()
	res := s.Apply([]Finding{
		f("title", "Session cookie missing HttpOnly flag", "severity", "low"),
	})
	if res.SuppressedCount() != 1 || res.Suppressed[0].RuleID != "SUP-COOKIE-FLAGS" {
		t.Fatalf("cookie-flags not suppressed: %+v", res.Suppressed)
	}
}

func TestSuppress_WeakTLS(t *testing.T) {
	s := NewDefault()
	res := s.Apply([]Finding{
		f("title", "Weak cipher / TLS 1.0 supported", "severity", "low"),
	})
	if res.SuppressedCount() != 1 || res.Suppressed[0].RuleID != "SUP-WEAK-TLS-CONFIG" {
		t.Fatalf("weak-TLS not suppressed: %+v", res.Suppressed)
	}
}

// THE MOST IMPORTANT TEST: the suppressor must NEVER silently drop a real,
// high-impact finding, even if its wording overlaps a rejected class.
func TestSuppress_NeverDropsHighImpact(t *testing.T) {
	s := NewDefault()
	findings := []Finding{
		// Critical SQLi — must survive.
		f("title", "SQL injection in /api/reports id parameter", "severity", "critical", "confidence", 95),
		// High IDOR — must survive.
		f("title", "IDOR: access other users' private repos", "severity", "high", "confidence", 90),
		// A finding that MENTIONS a header but is actually a real high-severity issue.
		f("title", "CSP bypass enabling stored XSS", "severity", "high", "confidence", 88),
		// SSRF — must survive.
		f("title", "SSRF to internal metadata endpoint 169.254.169.254", "severity", "critical", "confidence", 92),
	}
	res := s.Apply(findings)
	if res.SuppressedCount() != 0 {
		t.Fatalf("high-impact findings must never be suppressed, but %d were: %+v",
			res.SuppressedCount(), res.Suppressed)
	}
	if res.KeptCount() != len(findings) {
		t.Fatalf("kept %d, want %d", res.KeptCount(), len(findings))
	}
}

// A missing-header finding that some stage rated HIGH must be kept (severity
// gate overrides wording).
func TestSuppress_SeverityGateOverridesWording(t *testing.T) {
	s := NewDefault()
	res := s.Apply([]Finding{
		f("title", "Missing Content-Security-Policy header", "severity", "high", "confidence", 80),
	})
	if res.SuppressedCount() != 0 {
		t.Fatalf("high-severity finding suppressed despite severity gate: %+v", res.Suppressed)
	}
}

// SPF: suppress the bare best-practice finding, but KEEP one that carries a
// working spoof PoC.
func TestSuppress_SPFOnlyWithoutPoC(t *testing.T) {
	s := NewDefault()
	res := s.Apply([]Finding{
		f("title", "Missing DMARC record", "severity", "low"),
		f("title", "Missing SPF record", "severity", "low", "evidence", "spoofed email delivered, PoC attached"),
	})
	if res.KeptCount() != 1 {
		t.Fatalf("expected exactly the PoC finding kept, got kept=%d suppressed=%d",
			res.KeptCount(), res.SuppressedCount())
	}
	if !strings.Contains(str(res.Kept[0], "title"), "SPF") {
		t.Errorf("wrong finding kept: %+v", res.Kept[0])
	}
}

// Directory listing: suppress the empty one, keep the one exposing secrets.
func TestSuppress_DirListingKeepsSecrets(t *testing.T) {
	s := NewDefault()
	res := s.Apply([]Finding{
		f("title", "Directory listing enabled on /static/", "severity", "info"),
		f("title", "Directory listing enabled on /backup/ exposing .env credentials", "severity", "medium"),
	})
	if res.KeptCount() != 1 {
		t.Fatalf("expected 1 kept (the secret one), got %d", res.KeptCount())
	}
	if !strings.Contains(strings.ToLower(str(res.Kept[0], "title")), "backup") {
		t.Errorf("kept wrong dir-listing finding: %+v", res.Kept[0])
	}
}

func TestSuppress_NilAndEmptyAreKept(t *testing.T) {
	s := NewDefault()
	res := s.Apply([]Finding{nil, {}})
	if res.SuppressedCount() != 0 {
		t.Fatalf("nil/empty should be kept, got %d suppressed", res.SuppressedCount())
	}
}

func TestSuppress_FirstMatchWins(t *testing.T) {
	s := NewDefault()
	// wording matches both self-xss and (loosely) header text; ensure a single
	// decision, not a double count.
	res := s.Apply([]Finding{
		f("title", "Self-XSS; also missing X-Frame-Options header", "severity", "low"),
	})
	if res.SuppressedCount() != 1 {
		t.Fatalf("expected exactly 1 suppression decision, got %d", res.SuppressedCount())
	}
}

func TestSuppressionLog_RendersReasons(t *testing.T) {
	s := NewDefault()
	res := s.Apply([]Finding{
		f("title", "Missing HSTS header", "severity", "low", "url", "https://x.test/"),
	})
	log := res.SuppressionLog()
	for _, want := range []string{"SUP-MISSING-HEADERS", "reason", "policy", "https://x.test/"} {
		if !strings.Contains(log, want) {
			t.Errorf("suppression log missing %q:\n%s", want, log)
		}
	}
}

func TestSuppressionLog_EmptyWhenNothingSuppressed(t *testing.T) {
	s := NewDefault()
	res := s.Apply([]Finding{
		f("title", "SQL injection", "severity", "critical", "confidence", 99),
	})
	if !strings.Contains(res.SuppressionLog(), "nothing suppressed") {
		t.Errorf("expected 'nothing suppressed' log, got:\n%s", res.SuppressionLog())
	}
}

func TestDefaultRules_AllHaveIDReasonPolicy(t *testing.T) {
	for _, r := range DefaultRules() {
		if strings.TrimSpace(r.ID) == "" || strings.TrimSpace(r.Reason) == "" ||
			strings.TrimSpace(r.Policy) == "" || r.match == nil {
			t.Errorf("incomplete rule: %+v", r)
		}
	}
}
