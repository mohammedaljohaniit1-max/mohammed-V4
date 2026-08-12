// Command preset is the BRIDGE that drives the REAL MOHAMMED engine for one
// bug-bounty program, at the legally-correct intensity for that program.
//
// It replaces the old recon/*.sh bash (which bypassed the engine entirely and
// only queried crt.sh). Instead, preset:
//
//  1. loads the program's scope JSON (the legal guard-rail),
//  2. computes an EnginePlan (profile / rate / threads / UA) from the policy,
//  3. writes a mohammed-compatible scope.txt (in-scope hosts + '!' excludes),
//  4. prints the EXACT `mohammed scan ...` command to run (or runs it with -run).
//
// Two modes:
//
//	preset -file scope/iciparisxl.json                 # FULL plan (max legal intensity)
//	preset -file scope/iciparisxl.json -mode passive   # PASSIVE plan (OSINT only)
//	preset -file scope/ejada.json                      # forbidden -> auto-pinned PASSIVE
//	preset -file scope/iciparisxl.json -run            # actually execute the scan
//
// The FULL plan is SAFE on forbidden/sensitive targets: it auto-downgrades to
// passive, so you can never accidentally send active traffic to ejada/Mobily.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/mohammed-v3/core/pkg/scope"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "preset: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, out, errOut io.Writer) error {
	fs := flag.NewFlagSet("preset", flag.ContinueOnError)
	fs.SetOutput(out)
	var (
		file    = fs.String("file", "", "path to a scope JSON file (required)")
		mode    = fs.String("mode", "full", "scan mode: full | passive")
		outDir  = fs.String("outdir", "recon/scopes", "where to write the generated scope.txt")
		binPath = fs.String("bin", "./bin/mohammed", "path to the mohammed binary (for -run and the printed command)")
		doRun   = fs.Bool("run", false, "actually execute the mohammed scan (default: just print the command)")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*file) == "" {
		fmt.Fprintln(out, "usage: preset -file scope/<program>.json [-mode full|passive] [-run]")
		return fmt.Errorf("-file is required")
	}

	sf, err := scope.Load(*file)
	if err != nil {
		return err
	}

	var plan scope.EnginePlan
	switch strings.ToLower(*mode) {
	case "passive":
		plan = sf.PassivePlan()
	case "full", "":
		plan = sf.FullPlan()
	default:
		return fmt.Errorf("unknown -mode %q (use full|passive)", *mode)
	}

	// Write the mohammed scope.txt for this program.
	slug := strings.TrimSuffix(filepath.Base(*file), ".json")
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", *outDir, err)
	}
	scopeTxt := filepath.Join(*outDir, slug+".txt")
	if err := writeScopeTxt(scopeTxt, sf, plan); err != nil {
		return err
	}

	// Build the mohammed argument vector.
	outPath := filepath.Join("recon", "out-engine", slug+"-"+strings.ToLower(*mode))
	margs := []string{
		"scan",
		"-s", scopeTxt,
		"--profile", plan.Profile,
		"--rate", fmt.Sprintf("%d", plan.RatePerMin),
		"--threads", fmt.Sprintf("%d", plan.Threads),
		"--output", outPath,
	}
	if plan.WAFBypass {
		margs = append(margs, "--waf-bypass")
	}

	// ---- report -------------------------------------------------------------
	fmt.Fprintf(out, "== %s ==\n", sf.Program)
	fmt.Fprintf(out, "  platform    : %s\n", sf.Platform)
	fmt.Fprintf(out, "  automation  : %s\n", sf.Automation)
	if sf.MaxRPS > 0 {
		fmt.Fprintf(out, "  max_rps     : %d req/s (program limit)\n", sf.MaxRPS)
	}
	if sf.SensitiveGov {
		fmt.Fprintf(out, "  sensitive   : YES (gov/limited infra)\n")
	}
	fmt.Fprintf(out, "  mode        : %s\n", strings.ToUpper(*mode))
	fmt.Fprintf(out, "  plan        : profile=%s rate=%d/min threads=%d waf-bypass=%v passive-only=%v\n",
		plan.Profile, plan.RatePerMin, plan.Threads, plan.WAFBypass, plan.PassiveOnly)
	fmt.Fprintf(out, "  rationale   : %s\n", plan.Rationale)
	if plan.UserAgent != "" {
		fmt.Fprintf(out, "  REQUIRED UA : %s  (set this in config.yaml / engine User-Agent)\n", plan.UserAgent)
	}
	fmt.Fprintf(out, "  scope file  : %s (%d line(s))\n", scopeTxt, len(sf.ScopeHosts()))
	if strings.ToLower(*mode) == "full" && !plan.PassiveOnly && sf.Automation != scope.AutoWildcardBounty && sf.Automation != scope.AutoRateLimited {
		fmt.Fprintf(out, "  note        : aggressive vuln-scan phases are OFF for this policy; recon+probe only.\n")
	}
	fmt.Fprintln(out)

	cmdline := *binPath + " " + strings.Join(margs, " ")
	fmt.Fprintf(out, "RUN THIS:\n  %s\n", cmdline)
	if plan.UserAgent != "" {
		fmt.Fprintf(out, "  (ensure User-Agent contains %q — mandated by the program)\n", plan.UserAgent)
	}

	if !*doRun {
		return nil
	}

	// -run: execute the real engine.
	fmt.Fprintf(errOut, "\n[preset] executing: %s\n", cmdline)
	cmd := exec.Command(*binPath, margs...) //nolint:gosec // operator-driven
	cmd.Stdout = out
	cmd.Stderr = errOut
	return cmd.Run()
}

// writeScopeTxt emits the mohammed scope file: a header comment block (policy
// summary) followed by the in-scope hosts and '!' out-of-scope excludes.
func writeScopeTxt(path string, sf *scope.ScopeFile, plan scope.EnginePlan) error {
	var b strings.Builder
	fmt.Fprintf(&b, "# MOHAMMED scope — generated by cmd/preset (do not hand-edit)\n")
	fmt.Fprintf(&b, "# program   : %s (%s)\n", sf.Program, sf.Platform)
	fmt.Fprintf(&b, "# automation: %s   max_rps: %d   sensitive_gov: %v\n", sf.Automation, sf.MaxRPS, sf.SensitiveGov)
	fmt.Fprintf(&b, "# plan      : profile=%s rate=%d/min threads=%d passive-only=%v\n", plan.Profile, plan.RatePerMin, plan.Threads, plan.PassiveOnly)
	if plan.UserAgent != "" {
		fmt.Fprintf(&b, "# REQUIRED User-Agent substring: %s\n", plan.UserAgent)
	}
	b.WriteString("#\n")
	for _, line := range sf.ScopeHosts() {
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return os.WriteFile(path, []byte(b.String()), 0o644) //nolint:gosec // scope file is not secret
}
