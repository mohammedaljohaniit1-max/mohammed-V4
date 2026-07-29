package report

import (
	"strings"
	"testing"
)

func TestClassifyFinding(t *testing.T) {
	cases := []struct {
		f    map[string]interface{}
		want string
	}{
		{map[string]interface{}{"type": "SQL Injection"}, "sqli"},
		{map[string]interface{}{"type": "Blind RCE via ping"}, "rce"},
		{map[string]interface{}{"type": "SSRF to metadata"}, "ssrf"},
		{map[string]interface{}{"type": "IDOR differential"}, "idor"},
		{map[string]interface{}{"type": "Path Traversal /etc/passwd"}, "path-traversal"},
		{map[string]interface{}{"type": "Reflected XSS"}, "xss"},
		{map[string]interface{}{"type": "Privilege Escalation via param pollution"}, "privilege-escalation"},
		{map[string]interface{}{"type": "2FA bypass"}, "2fa-bypass"},
		{map[string]interface{}{"type": "OAuth code interception"}, "oauth"},
		{map[string]interface{}{"type": "Something odd"}, "generic"},
	}
	for _, c := range cases {
		if got := classifyFinding(c.f); got != c.want {
			t.Fatalf("classifyFinding(%v)=%q want %q", c.f["type"], got, c.want)
		}
	}
}

func TestGenerateH1Report_HasAllSections(t *testing.T) {
	f := map[string]interface{}{
		"type":     "SQL Injection",
		"title":    "Time-based SQLi in id param",
		"url":      "https://t.example/api/items?id=1",
		"severity": "Critical",
		"evidence": "response delayed 5.02s vs 0.03s baseline",
		"confidence": 92,
		"ai_verdict": "REAL",
		"ai_confirmed": true,
	}
	md := GenerateH1Report(f, "sqli_t-example_001")
	for _, section := range []string{
		"## Summary", "## Steps to Reproduce", "## Proof of Concept",
		"## Impact", "## Severity", "## Remediation", "CVSS:3.1/",
	} {
		if !strings.Contains(md, section) {
			t.Fatalf("H1 report missing section %q\n%s", section, md)
		}
	}
	if !strings.Contains(md, "CVSS 3.1 Base Score") {
		t.Fatalf("H1 report must include a CVSS 3.1 base score")
	}
}

func TestVulnID_Stable(t *testing.T) {
	f := map[string]interface{}{"type": "SQL Injection", "target": "app.example.com"}
	id := vulnID(f, 3)
	if !strings.HasPrefix(id, "sqli_") || !strings.HasSuffix(id, "_003") {
		t.Fatalf("unexpected vuln id %q", id)
	}
}

func TestProfileFor_KnownClassHasVector(t *testing.T) {
	p := profileFor(map[string]interface{}{"type": "RCE", "severity": "Critical"})
	if !strings.HasPrefix(p.Vector, "CVSS:3.1/") {
		t.Fatalf("RCE profile must have a CVSS 3.1 vector, got %q", p.Vector)
	}
	if p.Score < 9.0 {
		t.Fatalf("RCE should be near-max CVSS, got %.1f", p.Score)
	}
}
