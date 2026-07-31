package phases

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestV122_IngestAmassFile_ReadsOutputFile is the FAILURE #1 regression test.
// It proves the Method-1 fix: amass's -o OUTPUT FILE is read and every in-scope
// host is ingested — the exact path that finally captures amass v5 output that
// never reaches stdout (the 7-version-old "0 subdomains" bug). It also proves a
// missing file is a harmless 0 (no crash), and that out-of-scope lines are
// rejected by the ingest closure.
func TestV122_IngestAmassFile_ReadsOutputFile(t *testing.T) {
	dir := t.TempDir()
	amFile := filepath.Join(dir, "amass_raw_gitlab_com.txt")

	// Simulate what amass v5 writes to its -o file.
	content := "gitlab.com\nregistry.gitlab.com\ndocs.gitlab.com\nevil.example.org\n"
	if err := os.WriteFile(amFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	domain := "gitlab.com"
	suffix := "." + domain
	found := map[string]bool{}
	ingest := func(line string) int {
		added := 0
		for _, tok := range strings.Fields(strings.ToLower(line)) {
			tok = strings.Trim(tok, ".,()<>\"'[]")
			if tok == domain || strings.HasSuffix(tok, suffix) {
				if len(tok) < 255 && !found[tok] {
					found[tok] = true
					added++
				}
			}
		}
		return added
	}

	got := ingestAmassFile(amFile, ingest)
	if got != 3 {
		t.Fatalf("ingestAmassFile added %d in-scope hosts, want 3 (found=%v)", got, found)
	}
	for _, want := range []string{"gitlab.com", "registry.gitlab.com", "docs.gitlab.com"} {
		if !found[want] {
			t.Fatalf("expected %q to be ingested from amass -o file", want)
		}
	}
	if found["evil.example.org"] {
		t.Fatalf("out-of-scope host must NOT be ingested")
	}

	// A missing file must be a harmless no-op, never a crash.
	if n := ingestAmassFile(filepath.Join(dir, "does_not_exist.txt"), ingest); n != 0 {
		t.Fatalf("missing amass file should add 0, got %d", n)
	}
}

// TestV122_AmassGiveUpThreshold guards Method 2: amass must be auto-removed
// after a small number of consecutive zero-results so it can never again burn
// ~97 minutes failing on every apex (the GitLab log: 0/12).
func TestV122_AmassGiveUpThreshold(t *testing.T) {
	if amassGiveUpAfter < 1 || amassGiveUpAfter > 3 {
		t.Fatalf("amassGiveUpAfter = %d, want a small give-up threshold (1..3)", amassGiveUpAfter)
	}
}
