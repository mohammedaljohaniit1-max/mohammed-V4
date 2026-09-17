package pipeline

import (
	"context"
	"testing"
	"time"
)

func TestBoundedExecutor_TimeoutCalculation(t *testing.T) {
	be := NewBoundedExecutor(10 * time.Minute)

	// Small target count (e.g. 10 targets) -> should floor to 45s
	to10 := be.CalculateTimeout(10)
	if to10 != 45*time.Second {
		t.Errorf("expected 45s floor, got %v", to10)
	}

	// 100 targets -> 150s
	to100 := be.CalculateTimeout(100)
	if to100 != 150*time.Second {
		t.Errorf("expected 150s, got %v", to100)
	}

	// 10,000 targets -> should cap at MaxPhaseCap (10m)
	toHuge := be.CalculateTimeout(10000)
	if toHuge != 10*time.Minute {
		t.Errorf("expected 10m cap, got %v", toHuge)
	}
}

func TestBoundedExecutor_StreamCommand(t *testing.T) {
	be := NewBoundedExecutor(5 * time.Second)
	ctx := context.Background()

	// Execute echo command in process group
	outChan, err := be.StreamCommand(ctx, 1, "echo", []string{"hello\nworld"}, nil)
	if err != nil {
		t.Fatalf("StreamCommand failed: %v", err)
	}

	var lines []string
	for line := range outChan {
		lines = append(lines, line)
	}

	if len(lines) != 2 || lines[0] != "hello" || lines[1] != "world" {
		t.Errorf("unexpected output: %v", lines)
	}
}

func TestChannelPipeline_Streaming(t *testing.T) {
	cp := NewChannelPipeline(10, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var received []string
	done := make(chan struct{})

	go func() {
		cp.Process(ctx, func(asset StreamAsset) {
			received = append(received, asset.Value)
			if len(received) == 2 {
				close(done)
			}
		})
	}()

	cp.Ingest(StreamAsset{Type: "url", Value: "https://example.com/api"})
	cp.Ingest(StreamAsset{Type: "subdomain", Value: "api.example.com"})

	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatalf("timed out waiting for pipeline processing")
	}

	if len(received) != 2 {
		t.Errorf("expected 2 processed assets, got %d", len(received))
	}
	cp.Close()
}
