package runner

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

// ─────────────────────────────────────────
// Result holds the output of a tool run
// ─────────────────────────────────────────
type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Duration time.Duration
	// Err is non-nil ONLY for real failures: binary not found, failed to
	// start, timeout, or scan cancellation. A plain non-zero exit code (many
	// tools exit 1 when they simply found nothing) does NOT set Err — that is
	// reported via ExitCode and TimedOut/Killed flags instead.
	Err error
	// TimedOut is true when the tool was killed because it exceeded its timeout.
	TimedOut bool
	// Cancelled is true when the parent scan context was cancelled.
	Cancelled bool
}

// OK reports whether the tool ran to completion without a real failure.
// A non-zero exit code is tolerated (treated as "ran, maybe no results").
func (r *Result) OK() bool {
	return r != nil && r.Err == nil
}

// ─────────────────────────────────────────
// Per-tool timeout overrides
// Tools that can take a long time get more, fast tools get less
// ─────────────────────────────────────────
var toolTimeouts = map[string]time.Duration{
	// ── Heavy recon tools — generous but bounded ──────────────────────
	// bbot passive enum realistically needs 5-10 min per root domain; the old
	// 3-minute cap killed it before any results (BUG #2). Bumped to 8m.
	"bbot": 8 * time.Minute,
	// amass passive can spend minutes contacting sources.
	"amass": 6 * time.Minute,
	// nuclei full-template scans on many hosts are long-running.
	"nuclei": 20 * time.Minute,
	// sqlmap per-URL deep tests.
	"sqlmap": 8 * time.Minute,
	"ghauri": 8 * time.Minute,
	// ffuf per-target directory brute force.
	"ffuf":        5 * time.Minute,
	"feroxbuster": 5 * time.Minute,
	"dirsearch":   5 * time.Minute,
	// katana deep crawl across many live endpoints.
	"katana":      8 * time.Minute,
	"gospider":    6 * time.Minute,
	"hakrawler":   4 * time.Minute,
	"dalfox":      8 * time.Minute,
	"smuggler":    4 * time.Minute,
	"naabu":       6 * time.Minute,
	"nmap":        15 * time.Minute,
	"subfinder":   4 * time.Minute,
	"findomain":   3 * time.Minute,
	"assetfinder": 2 * time.Minute,
	"subzy":       4 * time.Minute,
	"httpx":       8 * time.Minute,
	"dnsx":        5 * time.Minute,
	"puredns":     8 * time.Minute,
	"shuffledns":  5 * time.Minute,
	// gau historical mining can be slow per domain (BUG #10) — allow 4m.
	"gau":         4 * time.Minute,
	"waybackurls": 3 * time.Minute,
	"tlsx":        3 * time.Minute,
	"crlfuzz":     3 * time.Minute,
	"kxss":        3 * time.Minute,
	"arjun":       3 * time.Minute,
	"paramspider": 3 * time.Minute,
	"getJS":       2 * time.Minute,
	"dontgo403":   90 * time.Second,
	"kr":          5 * time.Minute,
	"cloud_enum":  4 * time.Minute,
	"s3scanner":   3 * time.Minute,
	"dnsgen":      3 * time.Minute,
	// ── Fast system tools ─────────────────────────────────────────────
	"curl": 45 * time.Second,
	"dig":  15 * time.Second,
	"git":  60 * time.Second,
	"bash": 60 * time.Second,
}

// ─────────────────────────────────────────
// ResolveToolPath: finds binary across common install locations
// ─────────────────────────────────────────
func ResolveToolPath(toolName string) (string, error) {
	// First try system PATH
	path, err := exec.LookPath(toolName)
	if err == nil {
		return path, nil
	}

	// Check common installation directories
	homeDir, _ := os.UserHomeDir()
	candidates := []string{
		filepath.Join(homeDir, ".local", "bin", toolName),
		filepath.Join(homeDir, "go", "bin", toolName),
		filepath.Join("/usr/local/bin", toolName),
		filepath.Join("/usr/bin", toolName),
		filepath.Join("/snap/bin", toolName),
		filepath.Join("/opt/homebrew/bin", toolName),
	}

	for _, cand := range candidates {
		if info, err := os.Stat(cand); err == nil && !info.IsDir() {
			return cand, nil
		}
	}

	return "", fmt.Errorf("tool %q not found in system PATH or common locations", toolName)
}

// ─────────────────────────────────────────
// RunTool: run a tool with per-tool timeout and proper process group kill
// ─────────────────────────────────────────
func RunTool(ctx context.Context, toolName string, args []string, env map[string]string) *Result {
	timeout, ok := toolTimeouts[toolName]
	if !ok {
		timeout = 5 * time.Minute // default fallback
	}
	return runToolInternal(ctx, toolName, args, env, timeout)
}

// ─────────────────────────────────────────
// RunToolWithTimeout: explicitly override timeout for special cases
// ─────────────────────────────────────────
func RunToolWithTimeout(ctx context.Context, toolName string, args []string, env map[string]string, timeout time.Duration) *Result {
	return runToolInternal(ctx, toolName, args, env, timeout)
}

// ─────────────────────────────────────────
// runToolInternal: core execution with Setpgid for correct child kill
// ─────────────────────────────────────────
func runToolInternal(ctx context.Context, toolName string, args []string, env map[string]string, timeout time.Duration) *Result {
	start := time.Now()

	binaryPath, err := ResolveToolPath(toolName)
	if err != nil {
		return &Result{
			ExitCode: -1,
			Duration: time.Since(start),
			Err:      err,
		}
	}

	// Create a context with timeout layered on top of parent context
	toolCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.Command(binaryPath, args...)

	// CRITICAL: Setpgid=true ensures all child processes share the same process group.
	// When we kill the parent, we can kill the entire group (fixes amass/bbot hanging).
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	// Build environment: inherit system env + append overrides
	cmd.Env = os.Environ()
	for k, v := range env {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err = cmd.Start(); err != nil {
		return &Result{
			ExitCode: -1,
			Duration: time.Since(start),
			Err:      fmt.Errorf("failed to start %s: %w", toolName, err),
		}
	}

	// Wait for process to finish OR context/timeout to expire
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	res := &Result{}

	select {
	case waitErr := <-done:
		// Process finished. waitErr is an *exec.ExitError for any non-zero exit.
		// We deliberately do NOT treat a non-zero exit as a failure — see below.
		if waitErr != nil {
			if _, isExit := waitErr.(*exec.ExitError); !isExit {
				// A non-ExitError (e.g. I/O problem) IS a real failure.
				err = waitErr
			}
		}
	case <-toolCtx.Done():
		// Timeout or cancellation — kill the ENTIRE process group so orphaned
		// children (amass/bbot spawn many) are reaped, not just the parent.
		if cmd.Process != nil {
			pgid, pgErr := syscall.Getpgid(cmd.Process.Pid)
			if pgErr == nil {
				_ = syscall.Kill(-pgid, syscall.SIGKILL)
			} else {
				_ = cmd.Process.Kill()
			}
		}
		<-done // wait for goroutine to finish after kill

		if ctx.Err() != nil {
			res.Cancelled = true
			err = fmt.Errorf("scan cancelled")
		} else {
			res.TimedOut = true
			err = fmt.Errorf("tool %s exceeded timeout of %v", toolName, timeout)
		}
	}

	res.Stdout = stdout.String()
	res.Stderr = stderr.String()
	res.Duration = time.Since(start)
	res.Err = err
	if cmd.ProcessState != nil {
		res.ExitCode = cmd.ProcessState.ExitCode()
	}

	return res
}
