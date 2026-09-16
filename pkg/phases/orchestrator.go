package phases

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os/exec"
	"regexp"
	"strings"
	"sync"

	"github.com/mohammed-v3/core/pkg/config"
	"github.com/mohammed-v3/core/pkg/engine"
	"github.com/mohammed-v3/core/pkg/governor"
)

// OrchestrationEngine coordinates parallel asset discovery tools,
// streaming results in-memory via channels and Unix pipes while enforcing scope boundaries.
type OrchestrationEngine struct {
	mu           sync.RWMutex
	scope        *config.Scope
	gov          *governor.Governor
	seenAssets   map[string]struct{}
	outOfScopeRx []*regexp.Regexp
}

// NewOrchestrationEngine initializes the asset graph with scope constraints.
func NewOrchestrationEngine(scope *config.Scope, gov *governor.Governor) *OrchestrationEngine {
	oe := &OrchestrationEngine{
		scope:      scope,
		gov:        gov,
		seenAssets: make(map[string]struct{}),
	}

	if scope != nil {
		for _, exc := range scope.ExcludeDomains {
			cleaned := strings.TrimSpace(strings.TrimPrefix(exc, "*."))
			if cleaned != "" {
				pattern := fmt.Sprintf(`(?i)(^|\.)%s$`, regexp.QuoteMeta(cleaned))
				if rx, err := regexp.Compile(pattern); err == nil {
					oe.outOfScopeRx = append(oe.outOfScopeRx, rx)
				}
			}
		}
	}

	return oe
}

// CanonicalizeAsset normalizes URLs or hostnames, stripping fragments, port 80/443 defaults,
// and sorting query parameters to prevent duplicate analysis.
func (oe *OrchestrationEngine) CanonicalizeAsset(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}

	// Hostname or URL check
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		// Pure hostname
		host := strings.ToLower(raw)
		if idx := strings.Index(host, "/"); idx != -1 {
			host = host[:idx]
		}
		if idx := strings.Index(host, ":"); idx != -1 {
			host = host[:idx]
		}

		if oe.isOutOfScope(host) {
			return "", false
		}
		return host, true
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "", false
	}

	host := strings.ToLower(u.Hostname())
	if oe.isOutOfScope(host) {
		return "", false
	}

	// Normalize scheme and port
	scheme := strings.ToLower(u.Scheme)
	port := u.Port()
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}

	hostPort := host
	if port != "" {
		hostPort = fmt.Sprintf("%s:%s", host, port)
	}

	// Clean path and query params
	cleanPath := u.Path
	if cleanPath == "" {
		cleanPath = "/"
	}

	q := u.Query()
	cleanQuery := q.Encode()

	canonicalURL := fmt.Sprintf("%s://%s%s", scheme, hostPort, cleanPath)
	if cleanQuery != "" {
		canonicalURL = fmt.Sprintf("%s?%s", canonicalURL, cleanQuery)
	}

	return canonicalURL, true
}

func (oe *OrchestrationEngine) isOutOfScope(host string) bool {
	if oe.scope == nil {
		return false
	}

	for _, rx := range oe.outOfScopeRx {
		if rx.MatchString(host) {
			return true
		}
	}
	return false
}

// StreamToolExecution executes a command and streams its stdout line-by-line into an asset channel.
func (oe *OrchestrationEngine) StreamToolExecution(ctx context.Context, cmdName string, args []string, input io.Reader) (<-chan string, error) {
	cmd := exec.CommandContext(ctx, cmdName, args...)
	if input != nil {
		cmd.Stdin = input
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start %s: %w", cmdName, err)
	}

	outChan := make(chan string, 100)

	go func() {
		defer close(outChan)
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}

			// Try JSON decode first if line looks like JSON (e.g. httpx, subfinder)
			if strings.HasPrefix(line, "{") && strings.HasSuffix(line, "}") {
				var jsonPayload map[string]interface{}
				if err := json.Unmarshal([]byte(line), &jsonPayload); err == nil {
					if u, ok := jsonPayload["url"].(string); ok && u != "" {
						line = u
					} else if h, ok := jsonPayload["host"].(string); ok && h != "" {
						line = h
					}
				}
			}

			if canonical, valid := oe.CanonicalizeAsset(line); valid {
				oe.mu.Lock()
				if _, exists := oe.seenAssets[canonical]; !exists {
					oe.seenAssets[canonical] = struct{}{}
					oe.mu.Unlock()
					select {
					case outChan <- canonical:
					case <-ctx.Done():
						_ = cmd.Process.Kill()
						return
					}
				} else {
					oe.mu.Unlock()
				}
			}
		}
		_ = cmd.Wait()
	}()

	return outChan, nil
}

// IngestIntoState feeds deduplicated assets into the central engine state in real time.
func (oe *OrchestrationEngine) IngestIntoState(s *engine.State, assetStream <-chan string) int {
	ingested := 0
	for asset := range assetStream {
		if strings.HasPrefix(asset, "http://") || strings.HasPrefix(asset, "https://") {
			s.AddURL(asset)
		} else {
			s.AddURL(asset)
		}
		ingested++
	}
	return ingested
}
