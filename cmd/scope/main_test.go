package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestScopeRun_RequiresFile(t *testing.T) {
	var buf bytes.Buffer
	if err := run([]string{}, &buf); err == nil {
		t.Fatal("expected error without -file")
	}
}

func TestScopeRun_EjadaForbidden(t *testing.T) {
	var buf bytes.Buffer
	if err := run([]string{"-file", "../../scope/ejada.json"}, &buf); err != nil {
		t.Fatal(err)
	}
	s := buf.String()
	if !strings.Contains(s, "forbidden") {
		t.Errorf("ejada should show forbidden automation:\n%s", s)
	}
	if !strings.Contains(s, "[DENY ] nuclei") {
		t.Errorf("nuclei must be denied for ejada:\n%s", s)
	}
	if !strings.Contains(s, "[ALLOW] subfinder") {
		t.Errorf("subfinder must be allowed for ejada:\n%s", s)
	}
}

func TestScopeRun_URLInScope(t *testing.T) {
	var buf bytes.Buffer
	if err := run([]string{"-file", "../../scope/flagyard.json", "-url", "https://app.flagyard.com/x"}, &buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "IN SCOPE") {
		t.Errorf("expected in-scope verdict:\n%s", buf.String())
	}
}

func TestScopeRun_ToolCheck(t *testing.T) {
	var buf bytes.Buffer
	if err := run([]string{"-file", "../../scope/nournet.json", "-tool", "nmap"}, &buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "DENIED") {
		t.Errorf("nmap must be denied for sensitive gov nournet:\n%s", buf.String())
	}
}
