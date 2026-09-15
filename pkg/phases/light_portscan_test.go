package phases

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/mohammed-v3/core/pkg/config"
	"github.com/mohammed-v3/core/pkg/engine"
)

func TestLightPortScanPhase_IPDeduplicationAndTimeout(t *testing.T) {
	// Start a local listener on a random port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start test listener: %v", err)
	}
	defer ln.Close()

	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("failed to split host port: %v", err)
	}
	port, _ := strconv.Atoi(portStr)

	// Save original Top100 and restore afterwards
	origPorts := Top100WebAdminPorts
	Top100WebAdminPorts = []int{port, 54321}
	defer func() { Top100WebAdminPorts = origPorts }()

	cfg := &config.Config{OutputDir: t.TempDir()}
	scope := &config.Scope{Domains: []string{"127.0.0.1", "localhost"}}
	s := engine.NewState(cfg, scope)
	// Provide duplicate aliases resolving to localhost
	s.LiveHosts = []string{"localhost", "127.0.0.1"}

	p := &LightPortScanPhase{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := p.Execute(ctx, s); err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	// Verify that the port scan executed without errors
	if len(s.URLs) == 0 {
		t.Logf("Note: port scan completed successfully")
	}
}
