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
	Err      error
}

// ─────────────────────────────────────────
// Per-tool timeout overrides
// Tools that can take a long time get more, fast tools get less
// ─────────────────────────────────────────
var toolTimeouts = map[string]time.Duration{
	// Heavy recon tools — generous but bounded
	"amass":        4 * time.Minute,
	"bbot":         3 * time.Minute,
	"nuclei":       15 * time.Minute,
	"sqlmap":       5 * time.Minute,
	"ghauri":       5 * time.Minute,
	"ffuf":         3 * time.Minute,
	"feroxbuster":  3 * time.Minute,
	"dirsearch":    3 * time.Minute,
	"katana":       5 * time.Minute,
	"gospider":     5 * time.Minute,
	"hakrawler":    3 * time.Minute,
	"dalfox":       5 * time.Minute,
	"smuggler":     3 * time.Minute,
	"naabu":        5 * time.Minute,
	"nmap":         10 * time.Minute,
	"subfinder":    3 * time.Minute,
	"findomain":    2 * time.Minute,
	"assetfinder":  90 * time.Second,
	"subzy":        3 * time.Minute,
	"httpx":        5 * time.Minute,
	"dnsx":         3 * time.Minute,
	"puredns":      5 * time.Minute,
	"shuffledns":   3 * time.Minute,
	"gau":          3 * time.Minute,
	"waybackurls":  2 * time.Minute,
	"tlsx":         2 * time.Minute,
	"crlfuzz":      2 * time.Minute,
	"kxss":         2 * time.Minute,
	"arjun":        2 * time.Minute,
	"paramspider":  2 * time.Minute,
	"getJS":        90 * time.Second,
	"dontgo403":    30 * time.Second,
	"kr":           3 * time.Minute,
	"cloud_enum":   2 * time.Minute,
	"s3scanner":    2 * time.Minute,
	// Fast system tools
	"curl":         15 * time.Second,
	"dig":          10 * time.Second,
	"git":          30 * time.Second,
	"bash":         30 * time.Second,
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

	select {
	case err = <-done:
		// Process finished normally (or with non-zero exit)
	case <-toolCtx.Done():
		// Timeout or cancellation — kill the entire process group
		if cmd.Process != nil {
			pgid, pgErr := syscall.Getpgid(cmd.Process.Pid)
			if pgErr == nil {
				// Kill the entire process group (negative pgid = kill group)
				_ = syscall.Kill(-pgid, syscall.SIGKILL)
			} else {
				// Fallback: kill just the process
				_ = cmd.Process.Kill()
			}
		}
		<-done // wait for goroutine to finish after kill

		if ctx.Err() != nil {
			err = fmt.Errorf("scan cancelled")
		} else {
			err = fmt.Errorf("tool %s exceeded timeout of %v", toolName, timeout)
		}
	}

	res := &Result{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		Duration: time.Since(start),
		Err:      err,
	}

	if cmd.ProcessState != nil {
		res.ExitCode = cmd.ProcessState.ExitCode()
	}

	// A non-zero exit code alone is not always an error (some tools exit 1 when no results)
	// Preserve the actual error for the caller to decide
	return res
}
