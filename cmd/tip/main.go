// Command tip is the V13 Target Intelligence Profiler (mandate §1.1).
//
// It builds an intelligence profile for a target from observable signals and
// caller-supplied facts, runs the deterministic A/B/C/D classifier, selects the
// matching per-technology playbook, and writes:
//
//	output/{target}/intelligence_profile.json
//
// HONESTY / SANDBOX NOTE:
//   - There is deliberately NO fabricated "seed" data and NO invented
//     improvement percentage. The profile only ever contains what a signal
//     actually proved.
//   - Signals come from a fixtures JSON file (-signals) so the run is fully
//     deterministic and unit-testable offline. A single, optional, passive
//     live GET (-fetch) is supported when a network is available; if the fetch
//     fails, tip degrades honestly (records nothing) rather than guessing.
//   - Classification facts the operator knows (program size, whether a paid
//     program exists, "known ultra-hardened") are passed explicitly as flags.
//     The classifier never phones home.
package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/mohammed-v3/core/pkg/intelligence"
)

// signalsFile is the on-disk fixtures shape. Every field maps 1:1 onto
// intelligence.Signals; it exists so operators can capture a target's response
// once and re-run the profiler deterministically.
type signalsFile struct {
	// One or more observed responses. Each entry is fingerprinted in order; the
	// core accumulates everything learned across them.
	Responses []responseFixture `json:"responses"`

	// Classification facts (operator-supplied; -1 / false when unknown).
	ResolvedReports     int    `json:"resolved_reports"`
	HasBugBountyProgram bool   `json:"has_bug_bounty_program"`
	RateLimited         bool   `json:"rate_limited"`
	LegacyStack         bool   `json:"legacy_stack"`
	KnownUltraHardened  bool   `json:"known_ultra_hardened"`
	WAFVendorOverride   string `json:"waf_vendor_override,omitempty"`
}

type responseFixture struct {
	URL         string            `json:"url,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	SetCookie   string            `json:"set_cookie,omitempty"`
	Body        string            `json:"body,omitempty"`
	CertIssuer  string            `json:"cert_issuer,omitempty"`
	CertSubject string            `json:"cert_subject,omitempty"`
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "tip: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("tip", flag.ContinueOnError)
	fs.SetOutput(out)

	var (
		target       = fs.String("target", "", "target host (required), e.g. example.com")
		signalsPath  = fs.String("signals", "", "path to a signals fixtures JSON file (offline, deterministic)")
		outDir       = fs.String("out", "output", "base output directory")
		playbooksDir = fs.String("playbooks", "", "playbooks directory (default: repo playbooks/ resolved from source)")
		doFetch      = fs.Bool("fetch", false, "perform ONE passive live GET of https://<target>/ to collect signals (best-effort)")
		fetchTimeout = fs.Duration("fetch-timeout", 8*time.Second, "timeout for the optional live fetch")
		insecure     = fs.Bool("insecure", false, "skip TLS verification on the optional live fetch")

		resolvedReports = fs.Int("resolved-reports", -1, "known resolved-report count for the program (-1 = unknown)")
		hasProgram      = fs.Bool("has-program", false, "a formal paid bug-bounty program exists")
		rateLimited     = fs.Bool("rate-limited", false, "target returned 429s under light probing")
		legacyStack     = fs.Bool("legacy-stack", false, "signals indicate an EOL/legacy stack")
		ultraHardened   = fs.Bool("known-ultra-hardened", false, "operator asserts a top-tier program (GitLab/Google/…) -> Class A")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	t := strings.TrimSpace(*target)
	if t == "" {
		fs.Usage()
		return fmt.Errorf("-target is required")
	}

	core := intelligence.NewCore(t)

	// Load fixtures if provided (may also carry classification facts).
	var sf *signalsFile
	if *signalsPath != "" {
		loaded, err := loadSignals(*signalsPath)
		if err != nil {
			return err
		}
		sf = loaded
		for _, r := range sf.Responses {
			core.Fingerprint(intelligence.Signals{
				Headers:     r.Headers,
				SetCookie:   r.SetCookie,
				Body:        r.Body,
				CertIssuer:  r.CertIssuer,
				CertSubject: r.CertSubject,
				URL:         firstNonEmptyURL(r.URL, "https://"+t+"/"),
			})
		}
	}

	// Optional single passive live GET. Best-effort: failure is reported and the
	// run continues on whatever fixtures provided.
	if *doFetch {
		if sig, err := passiveFetch(t, *fetchTimeout, *insecure); err != nil {
			fmt.Fprintf(out, "warning: live fetch failed, continuing with fixtures only: %v\n", err)
		} else {
			core.Fingerprint(sig)
		}
	}

	// Merge classification facts: fixtures file supplies defaults, explicit flags
	// override when set to a non-default value.
	ci := intelligence.ClassifyInput{
		ResolvedReports:     -1,
		HasBugBountyProgram: false,
	}
	if sf != nil {
		ci.ResolvedReports = sf.ResolvedReports
		ci.HasBugBountyProgram = sf.HasBugBountyProgram
		ci.RateLimited = sf.RateLimited
		ci.LegacyStack = sf.LegacyStack
		ci.KnownUltraHardened = sf.KnownUltraHardened
		ci.WAFVendor = strings.TrimSpace(sf.WAFVendorOverride)
	}
	if *resolvedReports != -1 {
		ci.ResolvedReports = *resolvedReports
	}
	if *hasProgram {
		ci.HasBugBountyProgram = true
	}
	if *rateLimited {
		ci.RateLimited = true
	}
	if *legacyStack {
		ci.LegacyStack = true
	}
	if *ultraHardened {
		ci.KnownUltraHardened = true
	}
	// If a WAF was detected by fingerprinting, feed it to the classifier so a
	// no-program-but-WAF target is not mis-ranked as soft.
	if ci.WAFVendor == "" {
		if present, vendor := core.WAF(); present {
			ci.WAFVendor = vendor
		}
	}

	class := core.Classify(ci)

	// Playbook selection based on detected language.
	pbDir := resolvePlaybooksDir(*playbooksDir)
	var selectedPlaybook string
	if lib, err := intelligence.LoadPlaybooks(pbDir); err != nil {
		fmt.Fprintf(out, "warning: playbooks not loaded (%v)\n", err)
	} else if pb, ok := lib.SelectFor(core); ok {
		selectedPlaybook = pb.Technology
	}

	// Build and write the profile.
	profile := core.Profile()
	blob, err := profile.MarshalIndent()
	if err != nil {
		return fmt.Errorf("marshal profile: %w", err)
	}
	dir := filepath.Join(*outDir, sanitizeTarget(t))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create output dir %q: %w", dir, err)
	}
	path := filepath.Join(dir, "intelligence_profile.json")
	if err := os.WriteFile(path, blob, 0o644); err != nil {
		return fmt.Errorf("write profile %q: %w", path, err)
	}

	printSummary(out, profile, class, selectedPlaybook, path)
	return nil
}

func loadSignals(path string) (*signalsFile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read signals %q: %w", path, err)
	}
	var sf signalsFile
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&sf); err != nil {
		return nil, fmt.Errorf("parse signals %q: %w", path, err)
	}
	if sf.ResolvedReports == 0 {
		// Distinguish "absent" from "explicitly zero": JSON absence decodes to 0,
		// but a program with literally 0 resolved reports is meaningful. We treat
		// a bare 0 with no program as unknown to avoid over-classifying.
		if !sf.HasBugBountyProgram {
			sf.ResolvedReports = -1
		}
	}
	return &sf, nil
}

// passiveFetch performs ONE GET and extracts signals. It never follows more than
// the default redirect chain and reads a bounded body. It is intentionally
// minimal: it does not probe, fuzz, or authenticate.
func passiveFetch(target string, timeout time.Duration, insecure bool) (intelligence.Signals, error) {
	url := "https://" + target + "/"
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure}, //nolint:gosec // operator opt-in via -insecure
		},
	}
	resp, err := client.Get(url)
	if err != nil {
		return intelligence.Signals{}, err
	}
	defer resp.Body.Close()

	headers := map[string]string{}
	for k := range resp.Header {
		headers[k] = resp.Header.Get(k)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

	var issuer, subject string
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		c := resp.TLS.PeerCertificates[0]
		issuer = c.Issuer.String()
		subject = c.Subject.String()
	}
	return intelligence.Signals{
		Headers:     headers,
		SetCookie:   strings.Join(resp.Header.Values("Set-Cookie"), "; "),
		Body:        string(body),
		CertIssuer:  issuer,
		CertSubject: subject,
		URL:         url,
	}, nil
}

// resolvePlaybooksDir picks the playbooks directory: explicit flag wins, else it
// resolves repo-root/playbooks relative to this source file (works from any cwd),
// else falls back to ./playbooks.
func resolvePlaybooksDir(flagVal string) string {
	if strings.TrimSpace(flagVal) != "" {
		return flagVal
	}
	if _, file, _, ok := runtime.Caller(0); ok {
		// cmd/tip/main.go -> repo root is two levels up.
		root := filepath.Dir(filepath.Dir(filepath.Dir(file)))
		cand := filepath.Join(root, "playbooks")
		if fi, err := os.Stat(cand); err == nil && fi.IsDir() {
			return cand
		}
	}
	return "playbooks"
}

func printSummary(out io.Writer, p intelligence.Profile, class intelligence.TargetClass, playbook, path string) {
	fmt.Fprintf(out, "=== Target Intelligence Profile: %s ===\n", p.Target)
	fmt.Fprintf(out, "  Class:            %s\n", class)
	fmt.Fprintf(out, "  Strategy:         manual=%d%% auto=%d%% nuclei=%v xss/sqli=%v focus-BL=%v\n",
		p.Strategy.ManualPercent, p.Strategy.AutomationPercent,
		p.Strategy.RunGenericNuclei, p.Strategy.RunAutomatedXSS, p.Strategy.FocusBusinessLogic)
	fmt.Fprintf(out, "  Rationale:        %s\n", p.Strategy.Description)
	if p.Tech.Language != "" {
		fmt.Fprintf(out, "  Language:         %s\n", p.Tech.Language)
	} else {
		fmt.Fprintf(out, "  Language:         (not detected)\n")
	}
	if p.WAFPresent {
		fmt.Fprintf(out, "  WAF/CDN:          %s\n", p.WAFVendor)
	} else {
		fmt.Fprintf(out, "  WAF/CDN:          (none detected)\n")
	}
	fmt.Fprintf(out, "  Auth mechanisms:  %s\n", joinAuth(p.AuthMechanisms))
	fmt.Fprintf(out, "  Protocols:        %s\n", joinProto(p.Protocols))
	if playbook != "" {
		fmt.Fprintf(out, "  Playbook:         %s\n", playbook)
	} else {
		fmt.Fprintf(out, "  Playbook:         (none matched)\n")
	}
	fmt.Fprintf(out, "  Discoveries:      %d\n", p.DiscoveryCount)
	fmt.Fprintf(out, "  Written:          %s\n", path)
}

func joinAuth(a []intelligence.AuthType) string {
	if len(a) == 0 {
		return "(none detected)"
	}
	parts := make([]string, len(a))
	for i, v := range a {
		parts[i] = string(v)
	}
	return strings.Join(parts, ", ")
}

func joinProto(p []intelligence.Protocol) string {
	if len(p) == 0 {
		return "(none detected)"
	}
	parts := make([]string, len(p))
	for i, v := range p {
		parts[i] = string(v)
	}
	return strings.Join(parts, ", ")
}

func firstNonEmptyURL(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

// sanitizeTarget makes a filesystem-safe directory name from a host.
func sanitizeTarget(t string) string {
	r := strings.NewReplacer("/", "_", ":", "_", "\\", "_", " ", "_", "*", "_", "?", "_")
	return r.Replace(strings.TrimSpace(t))
}
