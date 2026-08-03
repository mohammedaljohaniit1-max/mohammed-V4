package intelligence

import (
	"path/filepath"
	"runtime"
	"testing"
)

// playbookDir resolves the repo-root playbooks/ dir relative to this test file,
// so the test works regardless of the working directory.
func playbookDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve caller path")
	}
	// pkg/intelligence/playbook_test.go -> ../../playbooks
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "playbooks")
}

func TestLoadPlaybooks_AllFiveStacks(t *testing.T) {
	lib, err := LoadPlaybooks(playbookDir(t))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	want := []string{"golang", "java_spring", "nodejs_express", "python_django", "ruby_on_rails"}
	for _, lang := range want {
		if _, ok := lib.For(lang); !ok {
			t.Fatalf("missing playbook for %q (have %v)", lang, lib.Languages())
		}
	}
	if lib.Len() < 5 {
		t.Fatalf("expected >=5 playbooks, got %d", lib.Len())
	}
}

func TestPlaybook_ContentIsPopulated(t *testing.T) {
	lib, err := LoadPlaybooks(playbookDir(t))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	pb, ok := lib.For("ruby_on_rails")
	if !ok {
		t.Fatal("rails playbook missing")
	}
	if pb.Technology == "" || len(pb.CommonVulnerabilities) == 0 ||
		len(pb.HighValueSurface) == 0 || len(pb.CustomChecks) == 0 {
		t.Fatalf("rails playbook under-populated: %+v", pb)
	}
	// spot-check a known high-value surface
	found := false
	for _, s := range pb.HighValueSurface {
		if s == "/rails/info/properties" {
			found = true
		}
	}
	if !found {
		t.Fatalf("rails playbook missing /rails/info/properties: %v", pb.HighValueSurface)
	}
}

func TestSelectFor_UsesDetectedLanguage(t *testing.T) {
	lib, err := LoadPlaybooks(playbookDir(t))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	ic := NewCore("app.example")
	// Before fingerprinting, no language -> no playbook.
	if _, ok := lib.SelectFor(ic); ok {
		t.Fatal("should not select a playbook before language is known")
	}
	ic.Fingerprint(Signals{Headers: map[string]string{"X-Runtime": "0.1"}})
	pb, ok := lib.SelectFor(ic)
	if !ok || pb.MatchLanguage != "ruby_on_rails" {
		t.Fatalf("after Rails fingerprint, want rails playbook, got ok=%v pb=%q", ok, pb.MatchLanguage)
	}
}

func TestLoadPlaybooks_BadDir(t *testing.T) {
	if _, err := LoadPlaybooks(filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
		t.Fatal("expected error for missing dir")
	}
}
