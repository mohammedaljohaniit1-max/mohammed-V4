// Command scope is the PRE-FLIGHT guard-rail for MOHAMMED. Before touching any
// bug-bounty target, run it to see (a) whether a URL is in scope and (b) which
// of the 25 integrated tools you are ALLOWED to run under that program's rules.
//
// This exists because Saudi programs (bugbounty.sa) frequently forbid automated
// scanning outright — some warn of "legal action". The scanner must refuse to
// run forbidden tooling; this command shows the operator that decision up front.
//
// Examples:
//
//	scope -file scope/ejada.json                  # show policy + allowed tools
//	scope -file scope/flagyard.json -url https://app.flagyard.com/login
//	scope -file scope/nournet.json -tool nuclei   # is this one tool allowed?
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/mohammed-v3/core/pkg/scope"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "scope: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("scope", flag.ContinueOnError)
	fs.SetOutput(out)
	var (
		file = fs.String("file", "", "path to a scope JSON file (required)")
		url  = fs.String("url", "", "check whether this URL/host is in scope")
		tool = fs.String("tool", "", "check whether this single tool is allowed")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *file == "" {
		fs.Usage()
		return fmt.Errorf("-file is required")
	}
	sf, err := scope.Load(*file)
	if err != nil {
		return err
	}

	fmt.Fprintf(out, "== %s ==\n", sf.Program)
	fmt.Fprintf(out, "platform:     %s\n", sf.Platform)
	fmt.Fprintf(out, "automation:   %s\n", sf.Automation)
	fmt.Fprintf(out, "sensitive_gov: %v\n", sf.SensitiveGov)
	if sf.MaxRPS > 0 {
		fmt.Fprintf(out, "max_rps:      %d\n", sf.MaxRPS)
	}
	if sf.EmailConvention != "" {
		fmt.Fprintf(out, "email conv.:  %s\n", sf.EmailConvention)
	}
	fmt.Fprintln(out)

	if *url != "" {
		in := sf.Contains(*url)
		verdict := "OUT OF SCOPE"
		if in {
			verdict = "IN SCOPE"
		}
		fmt.Fprintf(out, "URL check: %s -> %s\n\n", *url, verdict)
	}

	if *tool != "" {
		ok, reason := sf.ToolAllowed(*tool)
		state := "DENIED"
		if ok {
			state = "ALLOWED"
		}
		fmt.Fprintf(out, "tool check: %s -> %s (%s)\n\n", *tool, state, reason)
		return nil
	}

	// Full tool matrix.
	tools := scope.AllKnownTools()
	sort.Strings(tools)
	fmt.Fprintln(out, "-- TOOL MATRIX (per this program) --")
	for _, t := range tools {
		ok, reason := sf.ToolAllowed(t)
		mark := "DENY "
		if ok {
			mark = "ALLOW"
		}
		fmt.Fprintf(out, "  [%s] %-12s %-11s %s\n", mark, t, scope.ClassOf(t), reason)
	}

	fmt.Fprintln(out, "\n-- POLICY NOTES --")
	for _, n := range sf.Notes {
		fmt.Fprintf(out, "  * %s\n", n)
	}
	return nil
}
