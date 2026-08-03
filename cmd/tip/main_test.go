package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mohammed-v3/core/pkg/intelligence"
)

// writeSignals writes a fixtures file into a temp dir and returns its path.
func writeSignals(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "signals.json")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("write signals: %v", err)
	}
	return p
}

func readProfile(t *testing.T, path string) intelligence.Profile {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read profile: %v", err)
	}
	var p intelligence.Profile
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatalf("unmarshal profile: %v", err)
	}
	return p
}

func TestRun_RequiresTarget(t *testing.T) {
	var out bytes.Buffer
	err := run([]string{}, &out)
	if err == nil {
		t.Fatal("expected error when -target missing")
	}
	if !strings.Contains(err.Error(), "target") {
		t.Fatalf("expected target error, got %v", err)
	}
}

func TestRun_HardenedRailsClassA(t *testing.T) {
	sig := writeSignals(t, `{
		"responses": [
			{"url":"https://gitlab.test/","headers":{"X-Runtime":"0.01","CF-Ray":"abc"},"set_cookie":"_session_id=x"},
			{"url":"https://gitlab.test/api/graphql","headers":{"Content-Type":"application/json"},"body":"{\"data\":{}}"}
		],
		"known_ultra_hardened": true
	}`)
	outBase := t.TempDir()
	var out bytes.Buffer
	err := run([]string{"-target", "gitlab.test", "-signals", sig, "-out", outBase}, &out)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	p := readProfile(t, filepath.Join(outBase, "gitlab.test", "intelligence_profile.json"))

	if p.Class != intelligence.ClassA {
		t.Errorf("class = %q, want A", p.Class)
	}
	if p.Strategy.RunGenericNuclei {
		t.Error("Class A must NOT run generic nuclei")
	}
	if !p.Strategy.FocusBusinessLogic {
		t.Error("Class A must focus on business logic")
	}
	if p.Tech.Language != "ruby_on_rails" {
		t.Errorf("language = %q, want ruby_on_rails", p.Tech.Language)
	}
	if !p.WAFPresent || p.WAFVendor != "Cloudflare" {
		t.Errorf("WAF = (%v,%q), want (true,Cloudflare)", p.WAFPresent, p.WAFVendor)
	}
	if !containsProto(p.Protocols, intelligence.ProtoGraphQL) {
		t.Errorf("protocols = %v, want graphql present", p.Protocols)
	}
	// Summary should mention the class and the profile path.
	if !strings.Contains(out.String(), "Class:") || !strings.Contains(out.String(), "intelligence_profile.json") {
		t.Errorf("summary missing key lines:\n%s", out.String())
	}
}

func TestRun_LegacyNoProgramClassD(t *testing.T) {
	sig := writeSignals(t, `{
		"responses": [
			{"url":"https://old.test/","headers":{"Server":"Apache/2.2.15","X-Powered-By":"PHP/5.3.3"},"set_cookie":"PHPSESSID=x"}
		],
		"legacy_stack": true
	}`)
	outBase := t.TempDir()
	var out bytes.Buffer
	if err := run([]string{"-target", "old.test", "-signals", sig, "-out", outBase}, &out); err != nil {
		t.Fatalf("run: %v", err)
	}
	p := readProfile(t, filepath.Join(outBase, "old.test", "intelligence_profile.json"))
	if p.Class != intelligence.ClassD {
		t.Errorf("class = %q, want D", p.Class)
	}
	if !p.Strategy.RunGenericNuclei {
		t.Error("Class D should run generic nuclei")
	}
	if p.Tech.Language != "php" {
		t.Errorf("language = %q, want php", p.Tech.Language)
	}
	if p.WAFPresent {
		t.Error("no WAF should be detected for the legacy target")
	}
}

// A program with an unknown report count must NOT be treated as soft: it should
// land in Class C (partially secured), never D. This is the exact mistake the
// V13 mandate exists to prevent.
func TestRun_ProgramUnknownCountIsClassC(t *testing.T) {
	sig := writeSignals(t, `{
		"responses": [{"url":"https://prog.test/","headers":{"Content-Type":"application/json"}}],
		"has_bug_bounty_program": true
	}`)
	outBase := t.TempDir()
	var out bytes.Buffer
	if err := run([]string{"-target", "prog.test", "-signals", sig, "-out", outBase}, &out); err != nil {
		t.Fatalf("run: %v", err)
	}
	p := readProfile(t, filepath.Join(outBase, "prog.test", "intelligence_profile.json"))
	if p.Class != intelligence.ClassC {
		t.Errorf("class = %q, want C (program present, count unknown -> not soft)", p.Class)
	}
}

// Flags must override fixtures-file classification facts.
func TestRun_FlagsOverrideFixtures(t *testing.T) {
	sig := writeSignals(t, `{
		"responses": [{"url":"https://x.test/","headers":{}}],
		"has_bug_bounty_program": false
	}`)
	outBase := t.TempDir()
	var out bytes.Buffer
	if err := run([]string{"-target", "x.test", "-signals", sig, "-out", outBase, "-known-ultra-hardened"}, &out); err != nil {
		t.Fatalf("run: %v", err)
	}
	p := readProfile(t, filepath.Join(outBase, "x.test", "intelligence_profile.json"))
	if p.Class != intelligence.ClassA {
		t.Errorf("class = %q, want A (flag override)", p.Class)
	}
}

func TestRun_RejectsUnknownSignalFields(t *testing.T) {
	sig := writeSignals(t, `{"responses":[],"totally_unknown_field":true}`)
	outBase := t.TempDir()
	var out bytes.Buffer
	err := run([]string{"-target", "x.test", "-signals", sig, "-out", outBase}, &out)
	if err == nil {
		t.Fatal("expected error on unknown signal field")
	}
}

func TestSanitizeTarget(t *testing.T) {
	cases := map[string]string{
		"example.com":        "example.com",
		"host:8443":          "host_8443",
		"a/b":                "a_b",
		"weird *?name":       "weird___name",
	}
	for in, want := range cases {
		if got := sanitizeTarget(in); got != want {
			t.Errorf("sanitizeTarget(%q) = %q, want %q", in, got, want)
		}
	}
}

func containsProto(list []intelligence.Protocol, want intelligence.Protocol) bool {
	for _, p := range list {
		if p == want {
			return true
		}
	}
	return false
}
