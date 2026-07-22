package governor

import (
	"sync"
	"time"
)

type Governor struct {
	mu           sync.Mutex
	Concurrency  int
	CurrentDelay time.Duration
	WAFHits      int
	MaxWAFHits   int
}

func NewGovernor(initialConcurrency int) *Governor {
	return &Governor{
		Concurrency:  initialConcurrency,
		CurrentDelay: 50 * time.Millisecond,
		MaxWAFHits:   5,
	}
}

func (g *Governor) ReportWAF() {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.WAFHits++
	g.Concurrency = max(1, g.Concurrency/2)
	g.CurrentDelay = min(2*time.Second, g.CurrentDelay*2)
}

func (g *Governor) Throttle() {
	g.mu.Lock()
	delay := g.CurrentDelay
	g.mu.Unlock()

	time.Sleep(delay)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
