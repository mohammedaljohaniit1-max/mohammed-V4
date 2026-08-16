package phases

import (
	"testing"
)

// V12.6 regression tests: DNS native-fallback helpers + URL de-bloat.
// These are pure (no network) so they run in CI/sandbox.

func TestCollapseURLPatterns_CollapsesValuePermutations(t *testing.T) {
	in := []string{
		"https://x.com/product?id=1",
		"https://x.com/product?id=2",
		"https://x.com/product?id=3",
		"https://x.com/product?id=9999",
		"https://x.com/search?q=a",
		"https://x.com/search?q=b",
	}
	out := collapseURLPatterns(in, 25000)
	// id=* collapses to 1 signature, q=* collapses to 1 signature → 2 total.
	if len(out) != 2 {
		t.Fatalf("expected 2 collapsed patterns, got %d: %v", len(out), out)
	}
}

func TestCollapseURLPatterns_CollapsesNumericPathIDs(t *testing.T) {
	in := []string{
		"https://x.com/user/1/profile",
		"https://x.com/user/2/profile",
		"https://x.com/user/384726/profile",
	}
	out := collapseURLPatterns(in, 25000)
	if len(out) != 1 {
		t.Fatalf("expected 1 collapsed numeric-path pattern, got %d: %v", len(out), out)
	}
}

func TestCollapseURLPatterns_PreservesDistinctEndpoints(t *testing.T) {
	in := []string{
		"https://x.com/a",
		"https://x.com/b",
		"https://x.com/c?x=1",
		"https://x.com/c?y=1", // different param KEY → distinct
	}
	out := collapseURLPatterns(in, 25000)
	if len(out) != 4 {
		t.Fatalf("expected 4 distinct endpoints preserved, got %d: %v", len(out), out)
	}
}

func TestCollapseURLPatterns_EnforcesHardCap(t *testing.T) {
	var in []string
	for i := 0; i < 100; i++ {
		// each has a distinct path segment (non-numeric) → distinct signature
		in = append(in, "https://x.com/path"+string(rune('a'+i%26))+"/x"+itoa(i))
	}
	out := collapseURLPatterns(in, 10)
	if len(out) > 10 {
		t.Fatalf("cap not enforced: got %d (>10)", len(out))
	}
	_ = out
}

func TestCollapseURLPatterns_KeepsConcreteExample(t *testing.T) {
	in := []string{
		"https://x.com/product?id=42",
		"https://x.com/product?id=43",
	}
	out := collapseURLPatterns(in, 25000)
	if len(out) != 1 {
		t.Fatalf("expected 1, got %d", len(out))
	}
	// The kept URL must be a real, replayable example (has a concrete value).
	if out[0] != "https://x.com/product?id=42" {
		t.Fatalf("expected first concrete example kept, got %q", out[0])
	}
}

func TestSortStrings(t *testing.T) {
	s := []string{"c", "a", "b", "a"}
	sortStrings(s)
	for i := 1; i < len(s); i++ {
		if s[i-1] > s[i] {
			t.Fatalf("not sorted: %v", s)
		}
	}
}

func TestFirstResolverIP_ParsesFile(t *testing.T) {
	// firstResolverIP reads a resolvers file; feed it an inline temp file.
	dir := t.TempDir()
	p := dir + "/r.txt"
	writeLines(p, []string{"# comment", "", "not-an-ip", "8.8.8.8", "1.1.1.1"})
	got := firstResolverIP(p)
	if got != "8.8.8.8" {
		t.Fatalf("expected first valid IP 8.8.8.8, got %q", got)
	}
}
