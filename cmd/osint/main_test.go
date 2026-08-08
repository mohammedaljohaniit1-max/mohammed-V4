package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/mohammed-v3/core/pkg/osint"
)

func TestRun_RequiresInput(t *testing.T) {
	var buf bytes.Buffer
	if err := run([]string{}, &buf); err == nil {
		t.Fatal("expected error when -input missing")
	}
}

func TestRun_EmailHumanOutput(t *testing.T) {
	var buf bytes.Buffer
	if err := run([]string{"-input", "John.Doe@example.com"}, &buf); err != nil {
		t.Fatal(err)
	}
	s := buf.String()
	if !strings.Contains(s, "john.doe@example.com") {
		t.Errorf("output missing normalised email:\n%s", s)
	}
	if !strings.Contains(s, "CANDIDATES") {
		t.Errorf("output missing candidates section:\n%s", s)
	}
	if !strings.Contains(s, "NOT proof") {
		t.Errorf("output must carry honesty caveat:\n%s", s)
	}
}

func TestRun_JSONIsValidAndOffline(t *testing.T) {
	var buf bytes.Buffer
	if err := run([]string{"-input", "0501234567", "-cc", "966", "-json"}, &buf); err != nil {
		t.Fatal(err)
	}
	var rep osint.Report
	if err := json.Unmarshal(buf.Bytes(), &rep); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if rep.Identity.Phone != "+966501234567" {
		t.Errorf("phone not normalised in JSON: %q", rep.Identity.Phone)
	}
	for _, c := range rep.Candidates {
		if c.Confirmed {
			t.Errorf("offline JSON must not confirm any candidate: %+v", c)
		}
	}
}

func TestRun_UsernameJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := run([]string{"-input", "@Ninja_X", "-json"}, &buf); err != nil {
		t.Fatal(err)
	}
	var rep osint.Report
	if err := json.Unmarshal(buf.Bytes(), &rep); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if rep.Identity.Username != "ninja_x" {
		t.Errorf("username not sanitised: %q", rep.Identity.Username)
	}
}
