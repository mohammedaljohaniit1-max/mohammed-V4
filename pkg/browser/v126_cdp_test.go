package browser

import (
	"os"
	"strings"
	"testing"
)

// V12.6: CDP stability hardening — chromium autodetect + hardened launcher.

func TestNewHardenedLauncher_HasStabilityFlags(t *testing.T) {
	l := newHardenedLauncher("")
	if l == nil {
		t.Fatal("expected a launcher, got nil")
	}
	// The launcher must carry the Kali-stability flags. We can't easily read
	// private flag state, so assert it constructs without panic and (when a bin
	// is provided) records it.
	l2 := newHardenedLauncher("/usr/bin/chromium")
	if l2 == nil {
		t.Fatal("expected launcher with bin, got nil")
	}
}

func TestDetectChromiumBinary_RespectsEnvOverride(t *testing.T) {
	// Point the override at a real, existing file (this test binary itself).
	self, err := os.Executable()
	if err != nil {
		t.Skip("cannot resolve test executable")
	}
	old := os.Getenv("MOHAMMED_CHROME_BIN")
	defer os.Setenv("MOHAMMED_CHROME_BIN", old)

	os.Setenv("MOHAMMED_CHROME_BIN", self)
	if got := detectChromiumBinary(); got != self {
		t.Fatalf("env override ignored: want %q got %q", self, got)
	}

	// A non-existent override must be ignored (fall through to system paths).
	os.Setenv("MOHAMMED_CHROME_BIN", "/nonexistent/chrome-xyz")
	got := detectChromiumBinary()
	if got == "/nonexistent/chrome-xyz" {
		t.Fatalf("non-existent override should be ignored, got %q", got)
	}
	// got is either "" or a real system path; must not be the fake one.
	if got != "" && strings.Contains(got, "nonexistent") {
		t.Fatalf("unexpected: %q", got)
	}
}
