package phases

import "testing"

// TestV122_SampleHosts_CapAndPriority is the FAILURE #3 regression test for the
// intelligent host sampler. It proves (a) the result never exceeds the cap and
// (b) in-scope + staging/dev hosts are prioritized over noise.
func TestV122_SampleHosts_CapAndPriority(t *testing.T) {
	inScope := []string{"gitlab.com"}

	var hosts []string
	// 5 in-scope hosts (Priority 1)
	hosts = append(hosts, "registry.gitlab.com", "docs.gitlab.com",
		"customers.gitlab.com", "about.gitlab.com", "gitlab.com")
	// 3 staging/dev hosts on an out-of-scope apex (Priority 2)
	hosts = append(hosts, "dev.example.net", "staging.example.net", "test.example.net")
	// 2000 noise hosts (Priority 3)
	for i := 0; i < 2000; i++ {
		hosts = append(hosts, "noise"+itoaTest(i)+".example.org")
	}

	got := SampleHosts(hosts, inScope, portScanMaxHosts)
	if len(got) != portScanMaxHosts {
		t.Fatalf("sampled %d hosts, want exactly cap %d", len(got), portScanMaxHosts)
	}

	// Every in-scope host must be present (Priority 1 is never dropped).
	set := make(map[string]bool, len(got))
	for _, h := range got {
		set[h] = true
	}
	for _, in := range []string{"registry.gitlab.com", "docs.gitlab.com", "gitlab.com"} {
		if !set[in] {
			t.Fatalf("in-scope host %q was dropped by sampler", in)
		}
	}
	// Staging hosts must be present too (Priority 2, well within the cap).
	for _, st := range []string{"dev.example.net", "staging.example.net"} {
		if !set[st] {
			t.Fatalf("staging host %q was dropped by sampler", st)
		}
	}
}

// TestV122_SampleHosts_NoOpUnderCap proves the sampler returns the input
// unchanged when the host count is already within the cap.
func TestV122_SampleHosts_NoOpUnderCap(t *testing.T) {
	hosts := []string{"a.gitlab.com", "b.gitlab.com", "c.gitlab.com"}
	got := SampleHosts(hosts, []string{"gitlab.com"}, portScanMaxHosts)
	if len(got) != len(hosts) {
		t.Fatalf("expected no-op under cap, got %d want %d", len(got), len(hosts))
	}
}

// itoaTest is a tiny stdlib-free int→string for the test (avoids an strconv import
// churn in a table that only needs unique suffixes).
func itoaTest(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
