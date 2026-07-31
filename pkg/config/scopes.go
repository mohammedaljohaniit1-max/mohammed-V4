package config

// ═══════════════════════════════════════════════════════════════════════════
// V12.2 §2.4 — Built-in named scopes (//go:embed)
// ---------------------------------------------------------------------------
// The operator can now say `--scope gitlab` instead of hunting for a scope
// file. Named scopes ship compiled into the single `mohammed` binary via
// //go:embed, so there is nothing to download or place on disk. Crucially the
// built-in GitLab scope encodes the correct OUT-OF-SCOPE excludes ('!' lines)
// that the 8-hour crash proved were being enumerated — so the reference scope
// itself is now a regression guard against FAILURE #6 (scope pollution).
// ═══════════════════════════════════════════════════════════════════════════

import (
	"embed"
	"fmt"
	"sort"
	"strings"
)

//go:embed scopes/*.txt
var embeddedScopes embed.FS

// IsBuiltinScope reports whether name (case-insensitive) resolves to a built-in
// embedded scope such as "gitlab" or "github". A value containing a path
// separator, a dot, or a slash is treated as a filesystem path, never a name.
func IsBuiltinScope(name string) bool {
	n := normalizeScopeName(name)
	if n == "" {
		return false
	}
	_, err := embeddedScopes.ReadFile("scopes/" + n + ".txt")
	return err == nil
}

// BuiltinScopeNames returns the sorted list of available built-in scope names
// (without the .txt extension), for help text and error messages.
func BuiltinScopeNames() []string {
	entries, err := embeddedScopes.ReadDir("scopes")
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if strings.HasSuffix(n, ".txt") {
			names = append(names, strings.TrimSuffix(n, ".txt"))
		}
	}
	sort.Strings(names)
	return names
}

// LoadBuiltinScope parses the embedded named scope (e.g. "gitlab", "github").
func LoadBuiltinScope(name string) (*Scope, error) {
	n := normalizeScopeName(name)
	data, err := embeddedScopes.ReadFile("scopes/" + n + ".txt")
	if err != nil {
		return nil, fmt.Errorf("no built-in scope %q (available: %s)", name, strings.Join(BuiltinScopeNames(), ", "))
	}
	return ParseScope(strings.NewReader(string(data)))
}

// ResolveScope loads a scope from either a built-in name (--scope gitlab) or a
// filesystem path (--scope ./scope.txt). Resolution order:
//  1. If the argument names a built-in scope AND does not look like a path
//     (no '/', no '.', no os separator), load the embedded scope.
//  2. Otherwise treat it as a filesystem path and LoadScope it.
//
// This lets `--scope gitlab` and `--scope /tmp/my.txt` coexist unambiguously.
func ResolveScope(arg string) (*Scope, bool, error) {
	looksLikePath := strings.ContainsAny(arg, "/\\.")
	if !looksLikePath && IsBuiltinScope(arg) {
		sc, err := LoadBuiltinScope(arg)
		return sc, true, err
	}
	sc, err := LoadScope(arg)
	return sc, false, err
}

// normalizeScopeName lowercases and trims a candidate built-in scope name.
func normalizeScopeName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}
