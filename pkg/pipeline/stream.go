package pipeline

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

// StreamAsset represents a streaming discovery asset passed in memory between phases.
type StreamAsset struct {
	Type     string `json:"type"` // "subdomain", "url", "parameter", "secret"
	Value    string `json:"value"`
	Source   string `json:"source"`
	Origin   string `json:"origin"`
	Captured time.Time `json:"captured"`
}

// BoundedExecutor manages child CLI tool execution with dynamic context timeouts
// and process-group SIGKILL termination to completely eliminate hung background tasks.
type BoundedExecutor struct {
	MaxPhaseCap time.Duration
	BasePerURL  time.Duration
	MinFloor    time.Duration
}

// NewBoundedExecutor creates an executor with safe enterprise timeout ceilings.
func NewBoundedExecutor(maxPhaseCap time.Duration) *BoundedExecutor {
	if maxPhaseCap <= 0 {
		maxPhaseCap = 15 * time.Minute
	}
	return &BoundedExecutor{
		MaxPhaseCap: maxPhaseCap,
		BasePerURL:  1500 * time.Millisecond, // 1.5s per target
		MinFloor:    45 * time.Second,
	}
}

// CalculateTimeout computes: min(MaxPhaseCap, max(45s, N_targets * 1.5s))
func (b *BoundedExecutor) CalculateTimeout(targetCount int) time.Duration {
	if targetCount <= 0 {
		targetCount = 1
	}
	scaled := time.Duration(targetCount) * b.BasePerURL
	if scaled < b.MinFloor {
		scaled = b.MinFloor
	}
	if scaled > b.MaxPhaseCap {
		return b.MaxPhaseCap
	}
	return scaled
}

// StreamCommand runs a child CLI tool in its own process group, streaming lines to a Go channel.
// When context is cancelled or timeout trips, it kills the entire process group (-pgid) via SIGKILL.
func (b *BoundedExecutor) StreamCommand(parentCtx context.Context, targetCount int, cmdName string, args []string, input io.Reader) (<-chan string, error) {
	to := b.CalculateTimeout(targetCount)
	ctx, cancel := context.WithTimeout(parentCtx, to)

	cmd := exec.CommandContext(ctx, cmdName, args...)
	// Set process group ID so children can be killed together
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if input != nil {
		cmd.Stdin = input
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to open stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to start %s: %w", cmdName, err)
	}

	outChan := make(chan string, 100)

	go func() {
		defer cancel()
		defer close(outChan)

		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			select {
			case outChan <- line:
			case <-ctx.Done():
				break
			}
		}

		// Ensure process group termination on exit
		if cmd.Process != nil && cmd.Process.Pid > 0 {
			pgid, err := syscall.Getpgid(cmd.Process.Pid)
			if err == nil {
				_ = syscall.Kill(-pgid, syscall.SIGKILL)
			}
		}
		_ = cmd.Wait()
	}()

	return outChan, nil
}

// ChannelPipeline routes streaming assets into concurrent worker pools in real time.
type ChannelPipeline struct {
	mu      sync.RWMutex
	inChan  chan StreamAsset
	workers int
}

// NewChannelPipeline builds an in-memory streaming asset router.
func NewChannelPipeline(bufferSize, workers int) *ChannelPipeline {
	if bufferSize <= 0 {
		bufferSize = 500
	}
	if workers <= 0 {
		workers = 10
	}
	return &ChannelPipeline{
		inChan:  make(chan StreamAsset, bufferSize),
		workers: workers,
	}
}

// Ingest streams an asset into the pipeline without disk writes.
func (cp *ChannelPipeline) Ingest(asset StreamAsset) {
	if asset.Captured.IsZero() {
		asset.Captured = time.Now()
	}
	cp.inChan <- asset
}

// Process reads from the pipeline with a pool of concurrent handlers.
func (cp *ChannelPipeline) Process(ctx context.Context, handler func(StreamAsset)) {
	var wg sync.WaitGroup
	for i := 0; i < cp.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case asset, ok := <-cp.inChan:
					if !ok {
						return
					}
					handler(asset)
				}
			}
		}()
	}
	wg.Wait()
}

// Close gracefully closes the streaming channel.
func (cp *ChannelPipeline) Close() {
	close(cp.inChan)
}
