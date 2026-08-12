package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeScope creates a temp scope JSON and returns its path.
func writeScope(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "prog.json")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPreset_RequiresFile(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := run(nil, &out, &errOut); err == nil {
		t.Error("expected error when -file is missing")
	}
}

func TestPreset_WildcardBountyFullCommand(t *testing.T) {
	sf := writeScope(t, `{
		"program":"ICI","platform":"intigriti.com",
		"automation":"wildcard_bounty","max_rps":5,"required_ua":"@intigriti.me",
		"in_scope":["*.iciparisxl.nl","https://api.iciparisxl.nl/"]
	}`)
	outDir := t.TempDir()
	var out, errOut bytes.Buffer
	err := run([]string{"-file", sf, "-mode", "full", "-outdir", outDir}, &out, &errOut)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	s := out.String()
	for _, want := range []string{"--profile large", "--rate 270", "--waf-bypass", "@intigriti.me"} {
		if !strings.Contains(s, want) {
			t.Errorf("full command missing %q\n%s", want, s)
		}
	}
	// scope.txt must have been written with reduced hosts.
	txt, err := os.ReadFile(filepath.Join(outDir, "prog.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(txt), "iciparisxl.nl") {
		t.Errorf("scope.txt missing host:\n%s", txt)
	}
}

func TestPreset_ForbiddenAutoPassive(t *testing.T) {
	sf := writeScope(t, `{
		"program":"ejada","automation":"forbidden",
		"in_scope":["https://ehub.ejada.com/"]
	}`)
	var out, errOut bytes.Buffer
	if err := run([]string{"-file", sf, "-mode", "full", "-outdir", t.TempDir()}, &out, &errOut); err != nil {
		t.Fatalf("run: %v", err)
	}
	s := out.String()
	if !strings.Contains(s, "--profile passive") {
		t.Errorf("forbidden target must be forced passive:\n%s", s)
	}
	if strings.Contains(s, "--waf-bypass") {
		t.Errorf("forbidden target must never get --waf-bypass:\n%s", s)
	}
}

func TestPreset_PassiveMode(t *testing.T) {
	sf := writeScope(t, `{
		"program":"ICI","automation":"wildcard_bounty","max_rps":5,
		"in_scope":["*.iciparisxl.nl"]
	}`)
	var out, errOut bytes.Buffer
	if err := run([]string{"-file", sf, "-mode", "passive", "-outdir", t.TempDir()}, &out, &errOut); err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(out.String(), "--profile passive") {
		t.Errorf("passive mode must use --profile passive:\n%s", out.String())
	}
}
