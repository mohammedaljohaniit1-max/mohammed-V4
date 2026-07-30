package phases

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/mohammed-v3/core/pkg/engine"
	"github.com/mohammed-v3/core/pkg/runner"
)

// ─────────────────────────────────────────────────────────────────────────────
// V12.1 SECTION 3 — Modern tool integrations
//
// Each tool gets a small, PURE parser helper (unit-tested with no process
// execution) plus a thin runner wrapper that skips gracefully when the binary
// is absent. The parsers are the ZERO-TOLERANCE proof that our ingestion of each
// tool's real output format is correct.
// ─────────────────────────────────────────────────────────────────────────────

// parseHostLines normalizes a tool's newline-separated host output, lowercasing,
// trimming, dropping blanks/comments, and keeping only hosts in-scope for the
// given apex (host == apex or *.apex). Used by chaos, uncover, and alterx result
// ingestion so every subdomain source is filtered identically.
func parseHostLines(stdout, apex string) []string {
	apex = strings.ToLower(strings.TrimSpace(apex))
	suffix := "." + apex
	seen := map[string]bool{}
	var out []string
	for _, line := range strings.Split(stdout, "\n") {
		h := strings.ToLower(strings.TrimSpace(strings.ReplaceAll(line, "\r", "")))
		if h == "" || strings.HasPrefix(h, "#") {
			continue
		}
		// uncover may emit host:port — keep only the host part.
		if i := strings.IndexByte(h, ':'); i > 0 && !strings.Contains(h, "://") {
			h = h[:i]
		}
		if len(h) >= 255 {
			continue
		}
		if apex != "" && h != apex && !strings.HasSuffix(h, suffix) {
			continue
		}
		if seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, h)
	}
	return out
}

// runUncover queries uncover (unified Shodan/Censys/FOFA/Hunter) for hosts that
// belong to the target apex and merges in-scope results into `found`. Returns the
// count of NEW hosts added. Skips silently when the binary or API keys are
// missing (uncover exits non-zero without keys). V12.1 Section 3.
func runUncover(ctx context.Context, s *engine.State, apex string, found map[string]bool) int {
	if _, err := runner.ResolveToolPath("uncover"); err != nil {
		return 0
	}
	// -silent → hosts only; the query targets the apex across every engine.
	res := runner.RunTool(ctx, "uncover", []string{"-q", apex, "-silent"}, nil)
	if !res.OK() && !res.TimedOut {
		return 0
	}
	added := 0
	for _, h := range parseHostLines(res.Stdout, apex) {
		if !found[h] {
			found[h] = true
			added++
		}
	}
	return added
}

// runAlterxPermutations feeds the currently-known subdomains to alterx to
// generate pattern-based permutations, writing them to alterx_perms.txt so the
// active bruteforce phase can resolve them. It returns the number of permutations
// generated. alterx is a wordlist generator — it does NOT resolve — so its
// output is a candidate list, not confirmed hosts. V12.1 Section 3.
func runAlterxPermutations(ctx context.Context, s *engine.State, subsFile, outFile string) int {
	if _, err := runner.ResolveToolPath("alterx"); err != nil {
		return 0
	}
	if _, n := fileHasContent(subsFile); n == 0 {
		return 0
	}
	res := runner.RunTool(ctx, "alterx", []string{"-l", subsFile, "-silent"}, nil)
	if !res.OK() && !res.TimedOut {
		return 0
	}
	perms := strings.TrimSpace(res.Stdout)
	if perms == "" {
		return 0
	}
	_ = os.WriteFile(outFile, []byte(perms), 0644)
	return len(strings.Split(perms, "\n"))
}

// cariddiFinding is one JSON record emitted by `cariddi -json`. cariddi crawls a
// host and reports endpoints, parameters, secrets, and errors.
type cariddiFinding struct {
	URL     string `json:"url"`
	Method  string `json:"method"`
	Secrets []struct {
		Name  string `json:"name"`
		Match string `json:"match"`
	} `json:"secrets"`
	Endpoints []struct {
		Name string `json:"parameters"`
	} `json:"endpoints"`
}

// parseCariddiJSON extracts discovered URLs and secret matches from cariddi's
// JSON output (one object per line OR a JSON array). Returns (urls, secrets).
// PURE — unit-tested against cariddi's documented schema. V12.1 Section 3.
func parseCariddiJSON(out string) (urls []string, secrets []string) {
	out = strings.TrimSpace(out)
	if out == "" {
		return nil, nil
	}
	ingest := func(f cariddiFinding) {
		if u := strings.TrimSpace(f.URL); u != "" {
			urls = append(urls, u)
		}
		for _, sec := range f.Secrets {
			if m := strings.TrimSpace(sec.Match); m != "" {
				label := sec.Name
				if label == "" {
					label = "secret"
				}
				secrets = append(secrets, label+": "+m)
			}
		}
	}
	// Try a top-level array first.
	if strings.HasPrefix(out, "[") {
		var arr []cariddiFinding
		if json.Unmarshal([]byte(out), &arr) == nil {
			for _, f := range arr {
				ingest(f)
			}
			return dedupeStrings(urls), dedupeStrings(secrets)
		}
	}
	// Fall back to newline-delimited JSON objects.
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var f cariddiFinding
		if json.Unmarshal([]byte(line), &f) == nil {
			ingest(f)
		}
	}
	return dedupeStrings(urls), dedupeStrings(secrets)
}

// trufflehogResult is one verified-secret record from `trufflehog --json`.
type trufflehogResult struct {
	DetectorName string `json:"DetectorName"`
	Verified     bool   `json:"Verified"`
	Raw          string `json:"Raw"`
	Redacted     string `json:"Redacted"`
	SourceName   string `json:"SourceName"`
}

// parseTrufflehogJSON extracts secrets from trufflehog's NDJSON output, marking
// which were cryptographically VERIFIED (trufflehog actually tested the
// credential against the live provider). Returns (all, verifiedOnly). PURE.
// V12.1 Section 3.
func parseTrufflehogJSON(out string) (all []string, verified []string) {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var r trufflehogResult
		if json.Unmarshal([]byte(line), &r) != nil {
			continue
		}
		if r.DetectorName == "" {
			continue
		}
		shown := r.Redacted
		if shown == "" {
			shown = r.Raw
		}
		label := r.DetectorName + ": " + shown
		all = append(all, label)
		if r.Verified {
			verified = append(verified, label)
		}
	}
	return dedupeStrings(all), dedupeStrings(verified)
}

// runTrufflehog scans a filesystem path (the scan output folder, which holds
// crawled JS/HTML) for verified secrets. Returns (allCount, verifiedCount) and
// writes the raw report to trufflehog.json. Skips when the binary is missing.
// V12.1 Section 3.
func runTrufflehog(ctx context.Context, s *engine.State, scanPath string) (int, int) {
	if _, err := runner.ResolveToolPath("trufflehog"); err != nil {
		return 0, 0
	}
	res := runner.RunTool(ctx, "trufflehog", []string{"filesystem", scanPath, "--json", "--no-update"}, nil)
	if !res.OK() && !res.TimedOut {
		return 0, 0
	}
	all, verified := parseTrufflehogJSON(res.Stdout)
	if len(all) > 0 {
		_ = os.WriteFile(filepath.Join(s.OutputFolder, "trufflehog.json"), []byte(res.Stdout), 0644)
	}
	return len(all), len(verified)
}

// parsePPmapOutput reports whether ppmap flagged a URL as prototype-pollution
// vulnerable. ppmap prints "<url> might be vulnerable" / "is vulnerable" lines.
// PURE. V12.1 Section 3.
func parsePPmapOutput(out string) bool {
	l := strings.ToLower(out)
	return strings.Contains(l, "vulnerable") && !strings.Contains(l, "not vulnerable")
}

// runPPmap probes a single URL for prototype pollution. Returns true when ppmap
// confirms the sink. Skips when the binary is missing. V12.1 Section 3.
func runPPmap(ctx context.Context, url string) bool {
	if _, err := runner.ResolveToolPath("ppmap"); err != nil {
		return false
	}
	res := runner.RunTool(ctx, "ppmap", []string{url}, nil)
	if !res.OK() && !res.TimedOut {
		return false
	}
	return parsePPmapOutput(res.Stdout)
}

// dedupeStrings returns xs with duplicates removed, preserving first-seen order.
func dedupeStrings(xs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range xs {
		if x == "" || seen[x] {
			continue
		}
		seen[x] = true
		out = append(out, x)
	}
	return out
}
