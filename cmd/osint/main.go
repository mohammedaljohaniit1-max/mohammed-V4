// Command osint is a SEPARATE phone/email/username OSINT tool (operator
// request #4), distinct from the domain-level OSINT in pkg/phases.
//
// It is honest by construction:
//   - OFFLINE (default) it prints CANDIDATE leads only — normalised identifiers
//     plus deterministic account/dork URLs. A candidate is a place to look,
//     never a claim that an account exists.
//   - --live runs an OPTIONAL, gentle GET/HEAD existence check over the
//     account-type candidates only (never dorks/manual). A 2xx marks the
//     candidate confirmed; anything else stays unconfirmed. Network errors
//     never fabricate a positive.
//   - It never bypasses CAPTCHA/auth/rate limits and never scrapes search
//     engines (dorks are for a human to click).
//
// Examples:
//
//	osint -input user@example.com
//	osint -input 0501234567 -cc 966
//	osint -input john_doe -json
//	osint -input user@example.com -live -delay 2s   # gentle, polite probing
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/mohammed-v3/core/pkg/osint"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "osint: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("osint", flag.ContinueOnError)
	fs.SetOutput(out)

	var (
		input     = fs.String("input", "", "email, phone, or username to investigate (required)")
		cc        = fs.String("cc", "", "default country code for bare phone numbers, e.g. 966 (Saudi Arabia)")
		asJSON    = fs.Bool("json", false, "emit the full report as JSON")
		live      = fs.Bool("live", false, "run the OPTIONAL gentle existence check over account candidates")
		delay     = fs.Duration("delay", 2*time.Second, "min gap between live probes (politeness / anti-ban)")
		timeout   = fs.Duration("timeout", 8*time.Second, "per-probe HTTP timeout for --live")
		userAgent = fs.String("ua", "", "User-Agent for --live probes (default: honest identifying UA)")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *input == "" {
		fs.Usage()
		return fmt.Errorf("-input is required")
	}

	rep := osint.BuildReport(*input, *cc)

	if *live {
		n := osint.ProbeCount(rep.Candidates)
		if !*asJSON {
			fmt.Fprintf(out, "[live] gently probing %d account candidate(s) with delay=%s ...\n", n, delay.String())
		}
		checker := osint.NewChecker(*timeout, *delay, *userAgent)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		rep.Candidates = checker.Check(ctx, rep.Candidates)
		rep.Notes = append(rep.Notes, "live: a 'confirmed' result means an HTTP 2xx was observed for that public URL — verify manually before reporting.")
	}

	if *asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(rep)
	}

	printHuman(out, rep, *live)
	return nil
}

func printHuman(out io.Writer, rep osint.Report, live bool) {
	fmt.Fprintf(out, "== OSINT report for %q ==\n", rep.Input)
	if rep.Identity.Email != "" {
		fmt.Fprintf(out, "email:    %s\n", rep.Identity.Email)
	}
	if rep.Identity.Phone != "" {
		fmt.Fprintf(out, "phone:    %s\n", rep.Identity.Phone)
	}
	if rep.Identity.Username != "" {
		fmt.Fprintf(out, "username: %s\n", rep.Identity.Username)
	}
	fmt.Fprintln(out)

	confirmed := 0
	for _, c := range rep.Candidates {
		if c.Confirmed {
			confirmed++
		}
	}

	if live {
		fmt.Fprintf(out, "-- CONFIRMED (HTTP 2xx observed) : %d --\n", confirmed)
		for _, c := range rep.Candidates {
			if c.Confirmed {
				fmt.Fprintf(out, "  [%d] %-12s %s\n", c.Status, c.Platform, c.URL)
			}
		}
		fmt.Fprintln(out)
	}

	fmt.Fprintln(out, "-- CANDIDATES (places to look, NOT proof) --")
	for _, c := range rep.Candidates {
		mark := " "
		if c.Confirmed {
			mark = "✓"
		}
		status := ""
		if c.Status != 0 {
			status = fmt.Sprintf(" (%d)", c.Status)
		}
		fmt.Fprintf(out, "  %s %-14s %-6s %s%s\n", mark, c.Platform, c.Kind, c.URL, status)
		if c.Note != "" {
			fmt.Fprintf(out, "      note: %s\n", c.Note)
		}
	}

	fmt.Fprintln(out, "\n-- NOTES --")
	for _, n := range rep.Notes {
		fmt.Fprintf(out, "  * %s\n", n)
	}
}
