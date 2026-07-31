package config

import (
	"os"
	"path/filepath"
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════
// V12.2 §2.4 REGRESSION TESTS — Built-in embedded scopes (--scope gitlab)
// ---------------------------------------------------------------------------
// Proves the embedded gitlab/github scopes load, that '!' lines are parsed as
// EXCLUDES (FAILURE #6 guard: service-now.com / gitlab.cn must NOT appear as
// targets), and that ResolveScope disambiguates a built-in name from a path.
// ═══════════════════════════════════════════════════════════════════════════

func TestV122_BuiltinScopes_Available(t *testing.T) {
	names := BuiltinScopeNames()
	want := map[string]bool{"gitlab": true, "github": true}
	for _, n := range names {
		delete(want, n)
	}
	if len(want) != 0 {
		t.Fatalf("missing built-in scopes: %v (got %v)", want, names)
	}
	if !IsBuiltinScope("gitlab") || !IsBuiltinScope("GITLAB") {
		t.Fatal("IsBuiltinScope must be case-insensitive for 'gitlab'")
	}
	if IsBuiltinScope("./gitlab.txt") {
		t.Fatal("a path-looking argument must not be treated as a built-in name")
	}
}

func TestV122_LoadBuiltinScope_GitlabExcludesOutOfScope(t *testing.T) {
	sc, err := LoadBuiltinScope("gitlab")
	if err != nil {
		t.Fatalf("LoadBuiltinScope(gitlab): %v", err)
	}
	if len(sc.Domains) == 0 {
		t.Fatal("gitlab scope has no in-scope domains")
	}

	// gitlab.com must be IN scope.
	if !containsStr(sc.Domains, "gitlab.com") {
		t.Fatalf("gitlab.com must be an in-scope domain, got %v", sc.Domains)
	}

	// FAILURE #6 guard: the out-of-scope markers must be EXCLUDES, never targets.
	for _, bad := range []string{"service-now.com", "gitlab.cn"} {
		if containsStr(sc.Domains, bad) {
			t.Fatalf("%s must NOT be an in-scope target (scope pollution)", bad)
		}
		if !containsStr(sc.ExcludeDomains, bad) {
			t.Fatalf("%s must be recorded as an exclude", bad)
		}
	}

	// '!' prefix must never survive into any field.
	for _, d := range append(append([]string{}, sc.Domains...), sc.ExcludeDomains...) {
		if len(d) > 0 && (d[0] == '!' || d[0] == '-') {
			t.Fatalf("scope entry retains exclude prefix: %q", d)
		}
	}
}

func TestV122_ResolveScope_NameVsPath(t *testing.T) {
	// Built-in name.
	sc, builtin, err := ResolveScope("github")
	if err != nil || !builtin || len(sc.Domains) == 0 {
		t.Fatalf("ResolveScope(github) should load built-in: builtin=%v err=%v", builtin, err)
	}

	// Filesystem path.
	dir := t.TempDir()
	p := filepath.Join(dir, "myscope.txt")
	if err := os.WriteFile(p, []byte("example.com\n!evil.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	sc2, builtin2, err := ResolveScope(p)
	if err != nil || builtin2 {
		t.Fatalf("ResolveScope(path) should load file, not built-in: builtin=%v err=%v", builtin2, err)
	}
	if !containsStr(sc2.Domains, "example.com") || !containsStr(sc2.ExcludeDomains, "evil.com") {
		t.Fatalf("path scope parsed wrong: %+v", sc2)
	}
}

func containsStr(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
