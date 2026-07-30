package report

// h1_report.go — MOHAMMED V11.0 FINAL SOVEREIGN — FLAW #8 fix.
//
// V10.0 emitted raw text findings that a researcher had to hand-rewrite into a
// HackerOne submission. This module auto-generates a fully-structured,
// submit-ready HackerOne markdown report for EVERY confirmed vulnerability:
//
//   /output/{target}/reports/{vuln_id}_h1_report.md
//
// Each report carries the standard H1 sections — Summary, Steps to Reproduce,
// Impact, Proof of Concept, Severity (with a computed CVSS 3.1 vector + score),
// and Remediation — populated from the finding's structured fields plus a
// vulnerability-class knowledge base.
//
// It is driven only by CONFIRMED findings (isConfirmed) so an operator never
// files a false positive; MANUAL_REVIEW findings stay in the tiered text
// export until a human clears them.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/mohammed-v3/core/pkg/engine"
)

// cvssProfile is the per-class CVSS 3.1 base vector + remediation knowledge.
type cvssProfile struct {
	Vector      string
	Score       float64
	Rating      string
	Impact      string
	Remediation string
}

// classProfiles maps a normalized vulnerability class to its CVSS 3.1 base
// profile. Vectors are conservative, defensible base-metric choices per class.
var classProfiles = map[string]cvssProfile{
	"rce": {
		Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", Score: 10.0, Rating: "Critical",
		Impact:      "Remote code execution grants an attacker arbitrary command execution on the target host, leading to full compromise of confidentiality, integrity and availability, and pivoting into the internal network.",
		Remediation: "Never pass user input to a shell/interpreter. Use parameterized APIs, strict allowlists, and drop to least privilege. Patch the vulnerable component and add egress monitoring.",
	},
	"sqli": {
		Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:N/C:H/I:H/A:H", Score: 9.8, Rating: "Critical",
		Impact:      "SQL injection allows reading and modifying arbitrary database records, authentication bypass, and in many configurations code execution via stacked queries or file primitives.",
		Remediation: "Use parameterized queries / prepared statements exclusively. Apply least-privilege DB accounts, input validation, and a WAF as defense-in-depth (not a primary control).",
	},
	"ssrf": {
		Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:L", Score: 9.1, Rating: "Critical",
		Impact:      "Server-side request forgery lets an attacker make the server issue requests to internal services and cloud metadata endpoints (e.g. 169.254.169.254), often yielding cloud credentials and internal RCE.",
		Remediation: "Enforce an egress allowlist, block link-local/metadata ranges, disable unused URL schemes, require DNS-rebind-safe resolution, and use IMDSv2 on AWS.",
	},
	"idor": {
		Vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:N/C:H/I:L/A:N", Score: 8.1, Rating: "High",
		Impact:      "Insecure direct object reference / BOLA allows an authenticated attacker to read (and sometimes modify) other users' records by manipulating an object identifier, breaching tenant isolation.",
		Remediation: "Enforce per-object authorization on every request server-side (not just at the UI). Use unguessable identifiers as defense-in-depth and add access-control tests to CI.",
	},
	"bola": {
		Vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:N/C:H/I:L/A:N", Score: 8.1, Rating: "High",
		Impact:      "Broken object-level authorization allows a low-privileged user to access resources belonging to other users/tenants, breaching data isolation.",
		Remediation: "Perform object-level authorization checks on every API operation server-side, keyed on the authenticated principal, and cover them with automated tests.",
	},
	"path-traversal": {
		Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:N/C:H/I:N/A:N", Score: 7.5, Rating: "High",
		Impact:      "Path traversal lets an attacker read files outside the intended directory (e.g. /etc/passwd, application secrets, source), disclosing credentials and enabling further attacks.",
		Remediation: "Canonicalize and validate file paths against a strict allowlist, reject '..' sequences and absolute paths, and serve files from a sandboxed directory with least privilege.",
	},
	"xss": {
		Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", Score: 6.1, Rating: "Medium",
		Impact:      "Cross-site scripting executes attacker-controlled JavaScript in a victim's authenticated session, enabling session/token theft, account takeover, and phishing within the trusted origin.",
		Remediation: "Context-aware output encoding, a strict Content-Security-Policy, HttpOnly/SameSite cookies, and framework auto-escaping. Validate and sanitize all reflected/stored input.",
	},
	"privilege-escalation": {
		Vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:N/C:H/I:H/A:N", Score: 8.8, Rating: "High",
		Impact:      "Privilege escalation lets a low-privileged account gain administrative rights, compromising confidentiality and integrity of all tenant data and configuration.",
		Remediation: "Never trust client-supplied role/privilege fields. Enforce authorization server-side against the session principal, reject mass-assignment of protected attributes, and audit role changes.",
	},
	"2fa-bypass": {
		Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:N/C:H/I:H/A:N", Score: 8.1, Rating: "High",
		Impact:      "Bypassing two-factor authentication defeats a critical account-protection control, enabling account takeover using only first-factor credentials.",
		Remediation: "Enforce the 2FA step server-side before issuing any authenticated session/token; never expose protected resources on a partially-authenticated (interim) session.",
	},
	"oauth": {
		Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N", Score: 8.5, Rating: "High",
		Impact:      "OAuth authorization-code interception (open redirect_uri) allows an attacker to capture a victim's authorization code and exchange it for an access token, taking over the account.",
		Remediation: "Strictly validate redirect_uri against a pre-registered exact-match allowlist, use PKCE, bind the code to the client, and never allow attacker-controlled callback hosts.",
	},
	"generic": {
		Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:N/C:L/I:L/A:N", Score: 5.3, Rating: "Medium",
		Impact:      "The identified issue weakens the application's security posture and may be chained with other findings to achieve a higher-impact compromise.",
		Remediation: "Review the affected component against secure-coding guidance, apply least privilege, and add a regression test covering the reported behaviour.",
	},
}

// severityToProfile is a fallback when the class is unknown: map the finding's
// own severity to a coarse CVSS profile.
var severityToProfile = map[string]cvssProfile{
	"critical": {Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", Score: 9.8, Rating: "Critical"},
	"high":     {Vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:N/C:H/I:L/A:N", Score: 8.1, Rating: "High"},
	"medium":   {Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:N/C:L/I:L/A:N", Score: 5.3, Rating: "Medium"},
	"low":      {Vector: "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:N/C:L/I:N/A:N", Score: 3.1, Rating: "Low"},
	"info":     {Vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:N/C:N/I:N/A:N", Score: 0.0, Rating: "Informational"},
}

var nonAlnum = regexp.MustCompile(`[^a-z0-9]+`)

// containsWord reports whether word appears in s as a whole token (bounded by
// non-alphanumeric characters), so "rce" does NOT match "inte**rce**ption".
func containsWord(s, word string) bool {
	idx := 0
	for {
		i := strings.Index(s[idx:], word)
		if i < 0 {
			return false
		}
		start := idx + i
		end := start + len(word)
		leftOK := start == 0 || !isAlnumByte(s[start-1])
		rightOK := end == len(s) || !isAlnumByte(s[end])
		if leftOK && rightOK {
			return true
		}
		idx = start + 1
		if idx >= len(s) {
			return false
		}
	}
}

func isAlnumByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// classifyFinding normalizes a finding's type/title into a knowledge-base key.
func classifyFinding(f map[string]interface{}) string {
	blob := strings.ToLower(fmt.Sprintf("%v %v %v",
		f["type"], f["title"], f["phase"]))
	switch {
	case containsWord(blob, "rce") || strings.Contains(blob, "command inj") || strings.Contains(blob, "remote code") || strings.Contains(blob, "code execution"):
		return "rce"
	case strings.Contains(blob, "sql"):
		return "sqli"
	case strings.Contains(blob, "ssrf") || strings.Contains(blob, "server-side request"):
		return "ssrf"
	case strings.Contains(blob, "privilege") || strings.Contains(blob, "param pollution") || strings.Contains(blob, "mass assignment"):
		return "privilege-escalation"
	case strings.Contains(blob, "2fa") || strings.Contains(blob, "two-factor") || strings.Contains(blob, "mfa"):
		return "2fa-bypass"
	case strings.Contains(blob, "oauth") || strings.Contains(blob, "authorization code"):
		return "oauth"
	case strings.Contains(blob, "bola"):
		return "bola"
	case strings.Contains(blob, "idor") || strings.Contains(blob, "direct object"):
		return "idor"
	case strings.Contains(blob, "traversal") || strings.Contains(blob, "lfi") || strings.Contains(blob, "file read"):
		return "path-traversal"
	case strings.Contains(blob, "xss") || strings.Contains(blob, "cross-site script"):
		return "xss"
	default:
		return "generic"
	}
}

// profileFor selects the CVSS profile for a finding: class knowledge base first,
// severity fallback second.
func profileFor(f map[string]interface{}) cvssProfile {
	class := classifyFinding(f)
	if p, ok := classProfiles[class]; ok && class != "generic" {
		return p
	}
	sev := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", f["severity"])))
	if p, ok := severityToProfile[sev]; ok {
		// Borrow the generic remediation/impact text but keep the severity vector.
		g := classProfiles["generic"]
		p.Impact = g.Impact
		p.Remediation = g.Remediation
		return p
	}
	return classProfiles["generic"]
}

// vulnID builds a stable, filesystem-safe identifier for a finding.
func vulnID(f map[string]interface{}, idx int) string {
	class := classifyFinding(f)
	host := nonAlnum.ReplaceAllString(strings.ToLower(fmt.Sprintf("%v", f["target"])), "-")
	host = strings.Trim(host, "-")
	if host == "" {
		host = "target"
	}
	return fmt.Sprintf("%s_%s_%03d", class, host, idx)
}

// GenerateH1Report renders a single HackerOne-ready markdown report for a
// confirmed finding. Exposed for unit testing.
func GenerateH1Report(f map[string]interface{}, id string) string {
	prof := profileFor(f)
	title := firstNonEmpty(fmt.Sprintf("%v", f["title"]), fmt.Sprintf("%v", f["type"]), "Security Vulnerability")
	url := fmt.Sprintf("%v", f["url"])
	evidence := fmt.Sprintf("%v", f["evidence"])
	class := classifyFinding(f)

	var b strings.Builder
	b.WriteString(fmt.Sprintf("# %s\n\n", title))
	b.WriteString(fmt.Sprintf("_Report ID: `%s` — generated by MOHAMMED V12.0 OMEGA on %s_\n\n",
		id, time.Now().UTC().Format(time.RFC1123)))

	// Summary.
	b.WriteString("## Summary\n\n")
	b.WriteString(fmt.Sprintf("A **%s** vulnerability (%s) was confirmed at `%s`. %s\n\n",
		prof.Rating, humanClass(class), url, prof.Impact))

	// Steps to Reproduce.
	b.WriteString("## Steps to Reproduce\n\n")
	for i, step := range reproSteps(f, class, url) {
		b.WriteString(fmt.Sprintf("%d. %s\n", i+1, step))
	}
	b.WriteString("\n")

	// Proof of Concept.
	b.WriteString("## Proof of Concept\n\n")
	b.WriteString("The following non-destructive proof was captured (MOHAMMED operates on a strict\n")
	b.WriteString("\"prove, don't exploit\" boundary — see RESPONSIBLE_DISCLOSURE.md):\n\n")
	b.WriteString("```\n")
	b.WriteString(strings.TrimSpace(evidence))
	b.WriteString("\n```\n\n")
	if poc, ok := f["poc"].(string); ok && strings.TrimSpace(poc) != "" {
		b.WriteString("Reproduction request/marker:\n\n```\n")
		b.WriteString(strings.TrimSpace(poc))
		b.WriteString("\n```\n\n")
	}

	// Impact.
	b.WriteString("## Impact\n\n")
	b.WriteString(prof.Impact)
	b.WriteString("\n\n")

	// Severity (CVSS 3.1).
	b.WriteString("## Severity\n\n")
	b.WriteString(fmt.Sprintf("- **Rating:** %s\n", prof.Rating))
	b.WriteString(fmt.Sprintf("- **CVSS 3.1 Base Score:** %.1f\n", prof.Score))
	b.WriteString(fmt.Sprintf("- **CVSS 3.1 Vector:** `%s`\n\n", prof.Vector))

	// Remediation.
	b.WriteString("## Remediation\n\n")
	b.WriteString(prof.Remediation)
	b.WriteString("\n\n")

	// Footer.
	b.WriteString("---\n")
	b.WriteString(fmt.Sprintf("_Confidence: %d/100 · AI verdict: %v · Confirmed: %v_\n",
		confidenceOf(f), f["ai_verdict"], isConfirmed(f)))
	return b.String()
}

// reproSteps builds class-appropriate, non-destructive reproduction steps.
func reproSteps(f map[string]interface{}, class, url string) []string {
	base := []string{
		fmt.Sprintf("Navigate/authenticate to the target application in scope: `%s`.", url),
	}
	switch class {
	case "idor", "bola":
		base = append(base,
			"Authenticate as a low-privileged user (User B) and capture their session token.",
			fmt.Sprintf("Issue the request to `%s`, substituting another user's (User A) object identifier.", url),
			"Observe that User A's data is returned even though it belongs to a different principal.")
	case "sqli":
		base = append(base,
			fmt.Sprintf("Send a time-based payload to the injectable parameter at `%s`.", url),
			"Observe the response time increases by the injected delay, confirming query control (no data was extracted).")
	case "ssrf":
		base = append(base,
			fmt.Sprintf("Set the vulnerable parameter at `%s` to a unique out-of-band (OOB) callback host.", url),
			"Observe the DNS/HTTP interaction arriving at the OOB listener, proving server-side request control.")
	case "rce":
		base = append(base,
			fmt.Sprintf("Inject a benign timing command (e.g. `sleep`) into the vulnerable parameter at `%s`.", url),
			"Observe the response is delayed by the injected duration, proving command execution (no destructive command was run).")
	case "path-traversal":
		base = append(base,
			fmt.Sprintf("Request `%s` with a traversal sequence targeting `/etc/hostname`.", url),
			"Observe the file contents in the response, confirming out-of-directory read.")
	case "xss":
		base = append(base,
			fmt.Sprintf("Submit the payload `<img src=x onerror=alert(document.domain)>` to the reflected sink at `%s`.", url),
			"Observe the JavaScript executes in the page origin (alert shows the target domain).")
	case "2fa-bypass":
		base = append(base,
			"Complete only the first authentication factor to obtain an interim session.",
			fmt.Sprintf("Access the protected resource at `%s` using the interim session, without completing 2FA.", url),
			"Observe protected data is returned, proving the 2FA step is not enforced server-side.")
	case "oauth":
		base = append(base,
			fmt.Sprintf("Begin the OAuth flow at `%s` with an attacker-controlled `redirect_uri`.", url),
			"Observe the authorization code is delivered to the attacker callback, enabling token exchange.")
	case "privilege-escalation":
		base = append(base,
			fmt.Sprintf("As a low-privileged user, send the profile-update request to `%s` including a protected role field (e.g. `role=admin`).", url),
			"Refresh the profile and observe the elevated role persisted, proving mass-assignment privilege escalation.")
	default:
		base = append(base,
			fmt.Sprintf("Reproduce the reported behaviour against `%s` using the evidence below.", url))
	}
	return base
}

func humanClass(class string) string {
	switch class {
	case "rce":
		return "Remote Code Execution"
	case "sqli":
		return "SQL Injection"
	case "ssrf":
		return "Server-Side Request Forgery"
	case "idor":
		return "Insecure Direct Object Reference"
	case "bola":
		return "Broken Object-Level Authorization"
	case "path-traversal":
		return "Path Traversal"
	case "xss":
		return "Cross-Site Scripting"
	case "privilege-escalation":
		return "Privilege Escalation"
	case "2fa-bypass":
		return "Two-Factor Authentication Bypass"
	case "oauth":
		return "OAuth Authorization-Code Interception"
	default:
		return "Security Vulnerability"
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		v = strings.TrimSpace(v)
		if v != "" && v != "<nil>" {
			return v
		}
	}
	return ""
}

// ExportH1Reports writes one HackerOne-ready markdown report per CONFIRMED
// finding into <OutputFolder>/reports/. Returns the number of reports written.
func ExportH1Reports(state *engine.State) (int, error) {
	reportsDir := filepath.Join(state.OutputFolder, "reports")
	if err := os.MkdirAll(reportsDir, 0o755); err != nil {
		return 0, err
	}
	written := 0
	for i, f := range state.Findings {
		if !isConfirmed(f) {
			continue
		}
		id := vulnID(f, i+1)
		md := GenerateH1Report(f, id)
		path := filepath.Join(reportsDir, id+"_h1_report.md")
		if err := os.WriteFile(path, []byte(md), 0o644); err != nil {
			return written, err
		}
		written++
	}
	return written, nil
}
