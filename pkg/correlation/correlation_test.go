package correlation

import "testing"

// TestSessionTheftChain: XSS + weak session cookie on the same host promote to
// a Critical "XSS → Session Hijack" chain.
func TestSessionTheftChain(t *testing.T) {
	findings := []Finding{
		{"type": "XSS", "target": "app.target.com", "url": "https://app.target.com/s?q=x", "evidence": "reflected <script> executed"},
		{"type": "Weak Session Cookie", "target": "app.target.com", "url": "https://app.target.com/", "evidence": "session cookie missing HttpOnly"},
	}
	chains := New().Correlate(findings)
	if !hasChain(chains, "XSS → Session Hijack", "Critical") {
		t.Fatalf("expected session-theft chain, got %+v", chains)
	}
}

// TestAccountTakeoverChain: IDOR + verb-tampering → Critical takeover chain.
func TestAccountTakeoverChain(t *testing.T) {
	findings := []Finding{
		{"type": "IDOR", "target": "api.target.com", "url": "https://api.target.com/u?id=2", "evidence": "distinct object"},
		{"type": "API: verb-tampering", "class": "verb-tampering", "target": "api.target.com", "url": "https://api.target.com/u/1", "evidence": "PUT accepted"},
	}
	chains := New().Correlate(findings)
	if !hasChain(chains, "IDOR/BOLA → Account Takeover", "Critical") {
		t.Fatalf("expected account-takeover chain, got %+v", chains)
	}
}

// TestNoChainWithoutBothComponents: a lone finding must NOT produce a chain.
func TestNoChainWithoutBothComponents(t *testing.T) {
	findings := []Finding{
		{"type": "XSS", "target": "app.target.com", "url": "https://app.target.com/s?q=x", "evidence": "reflected"},
	}
	chains := New().Correlate(findings)
	for _, c := range chains {
		if c.Title == "XSS → Session Hijack" {
			t.Fatalf("must not chain a single finding: %+v", c)
		}
	}
}

// TestChainsAreHostScoped: findings on DIFFERENT hosts must not be chained.
func TestChainsAreHostScoped(t *testing.T) {
	findings := []Finding{
		{"type": "XSS", "target": "a.target.com", "url": "https://a.target.com/s?q=x", "evidence": "reflected"},
		{"type": "Weak Session Cookie", "target": "b.target.com", "url": "https://b.target.com/", "evidence": "missing HttpOnly"},
	}
	chains := New().Correlate(findings)
	if len(chains) != 0 {
		t.Fatalf("cross-host findings must not chain, got %+v", chains)
	}
}

// TestSSTIRCEEscalatesWithTechFingerprint.
func TestSSTIRCEEscalatesWithTechFingerprint(t *testing.T) {
	findings := []Finding{
		{"type": "SSTI", "target": "x.target.com", "url": "https://x.target.com/p?q=1", "evidence": "template evaluated"},
		{"type": "Tech Fingerprint", "target": "x.target.com", "url": "https://x.target.com/", "evidence": "Jinja2 stack disclosed"},
	}
	chains := New().Correlate(findings)
	if !hasChain(chains, "SSTI → Template RCE", "Critical") {
		t.Fatalf("SSTI + tech fingerprint should escalate to Critical, got %+v", chains)
	}
}

// TestAsFindingsShape verifies the chain → finding conversion.
func TestAsFindingsShape(t *testing.T) {
	e := New()
	chains := e.Correlate([]Finding{
		{"type": "SSTI", "target": "x.target.com", "url": "https://x.target.com/p?q=1", "evidence": "evaluated"},
	})
	out := e.AsFindings(chains)
	for _, f := range out {
		if f["type"] != "Correlated Attack Chain" {
			t.Fatalf("finding type wrong: %+v", f)
		}
		if _, ok := f["chain_title"].(string); !ok {
			t.Fatalf("missing chain_title: %+v", f)
		}
	}
}

func hasChain(chains []Chain, title, severity string) bool {
	for _, c := range chains {
		if c.Title == title && c.Severity == severity {
			return true
		}
	}
	return false
}
