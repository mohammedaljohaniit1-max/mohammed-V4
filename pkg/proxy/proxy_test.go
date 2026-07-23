package proxy

import "testing"

// TestProxyActiveDeactivation is the regression guard for the CATASTROPHIC
// BUG #1: when the Burp connectivity test fails, the engine must be able to
// flip the shared ProxyManager to inactive so downstream phases (httpx,
// katana, gospider, ffuf, nuclei) fall back to DIRECT networking instead of
// routing every request through a dead proxy and getting 0 results.
func TestProxyActiveDeactivation(t *testing.T) {
	pm := NewProxyManager("http://172.30.48.1:8080")
	if !pm.Active {
		t.Fatalf("proxy with URL should start Active")
	}
	if pm.GetEnv() == nil {
		t.Fatalf("active proxy must expose env vars")
	}

	// Simulate the engine's Burp-unreachable path.
	pm.Active = false
	pm.ProxyURL = ""

	if pm.Active {
		t.Fatalf("proxy must be inactive after deactivation")
	}
	if env := pm.GetEnv(); env != nil {
		t.Fatalf("inactive proxy must return nil env, got %v", env)
	}
}

// TestProxyEmptyURL ensures an empty --burp value never activates the proxy.
func TestProxyEmptyURL(t *testing.T) {
	pm := NewProxyManager("")
	if pm.Active {
		t.Fatalf("empty proxy URL must not be Active")
	}
	if pm.GetEnv() != nil {
		t.Fatalf("inactive proxy must return nil env")
	}
}
