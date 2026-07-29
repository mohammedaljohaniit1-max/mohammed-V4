package engine

import (
	"net/http"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────────
// V9.0 ABSOLUTE APEX — WAF/CDN evasion engine tests (Section 1.2).
// ─────────────────────────────────────────────────────────────────────────

func hdr(pairs ...string) http.Header {
	h := http.Header{}
	for i := 0; i+1 < len(pairs); i += 2 {
		h.Add(pairs[i], pairs[i+1])
	}
	return h
}

func TestFingerprintWAF_Cloudflare(t *testing.T) {
	fp := FingerprintWAF(403, hdr("CF-RAY", "8abc123def-LHR", "Server", "cloudflare"),
		`<title>just a moment...</title><div id="__cf_chl_rt_tk">x</div>`)
	if !fp.Detected || fp.Vendor != WAFCloudflare {
		t.Fatalf("Cloudflare not fingerprinted: %+v", fp)
	}
	if !fp.Challenge {
		t.Fatalf("Cloudflare JS challenge (__cf_chl_rt_tk) not flagged as challenge")
	}
}

func TestFingerprintWAF_Akamai(t *testing.T) {
	fp := FingerprintWAF(200, hdr("Server", "AkamaiGHost", "X-Akamai-Transformed", "9 - 0"), "hello")
	if !fp.Detected || fp.Vendor != WAFAkamai {
		t.Fatalf("Akamai not fingerprinted: %+v", fp)
	}
}

func TestFingerprintWAF_Imperva(t *testing.T) {
	fp := FingerprintWAF(200, hdr("X-Iinfo", "1-2-3", "Set-Cookie", "visid_incap_123=abc"),
		"Request unsuccessful. Incapsula incident ID: 1-2")
	if !fp.Detected || fp.Vendor != WAFImperva {
		t.Fatalf("Imperva/Incapsula not fingerprinted: %+v", fp)
	}
}

func TestFingerprintWAF_AWS(t *testing.T) {
	fp := FingerprintWAF(403, hdr("X-Amzn-Waf-Action", "block"), "Request blocked")
	if !fp.Detected || fp.Vendor != WAFAWS {
		t.Fatalf("AWS WAF not fingerprinted: %+v", fp)
	}
	if !fp.Challenge {
		t.Fatalf("AWS WAF block not flagged as challenge")
	}
}

func TestFingerprintWAF_BareBlockStatus(t *testing.T) {
	// A 403 with no vendor evidence is still treated as a generic WAF gate.
	fp := FingerprintWAF(403, http.Header{}, "Forbidden")
	if !fp.Detected || fp.Vendor != WAFGeneric || !fp.Challenge {
		t.Fatalf("bare 403 not treated as generic WAF challenge: %+v", fp)
	}
}

func TestFingerprintWAF_CleanResponseNotFlagged(t *testing.T) {
	fp := FingerprintWAF(200, hdr("Server", "nginx", "Content-Type", "text/html"),
		"<html><body>Welcome to our shop</body></html>")
	if fp.Detected {
		t.Fatalf("clean origin response mis-flagged as WAF: %+v", fp)
	}
}

func TestShouldSkipHeavyFuzzing(t *testing.T) {
	if !ShouldSkipHeavyFuzzing(true, false) {
		t.Fatalf("WAF-protected + no bypass must SKIP heavy fuzzing")
	}
	if ShouldSkipHeavyFuzzing(true, true) {
		t.Fatalf("--waf-bypass must allow heavy fuzzing on protected host")
	}
	if ShouldSkipHeavyFuzzing(false, false) {
		t.Fatalf("unprotected host must never skip fuzzing")
	}
}

func TestHeavyFuzzCategoriesCovered(t *testing.T) {
	want := map[string]bool{"XSS": false, "SQLi": false, "SSTI": false}
	for _, c := range HeavyFuzzCategories {
		if _, ok := want[c]; ok {
			want[c] = true
		}
	}
	for k, seen := range want {
		if !seen {
			t.Fatalf("HeavyFuzzCategories missing mandated class %q", k)
		}
	}
}

func TestMemoryShield_AdaptiveThreads(t *testing.T) {
	// Under normal conditions AdaptiveThreads returns the configured value.
	if got := AdaptiveThreads(30); got != 30 {
		t.Fatalf("AdaptiveThreads(30) = %d under no pressure, want 30", got)
	}
	// Simulate pressure by dropping the budget below current heap usage.
	oldBudget, oldPct := memBudgetBytes, memSoftLimitPct
	memBudgetBytes = 1 // 80% of 1 byte ≈ 0 → always pressured
	memSoftLimitPct = 80
	defer func() { memBudgetBytes, memSoftLimitPct = oldBudget, oldPct }()
	if !MemoryPressure() {
		t.Fatalf("MemoryPressure should report pressure with a 1-byte budget")
	}
	if got := AdaptiveThreads(50); got != 5 {
		t.Fatalf("AdaptiveThreads(50) under pressure = %d, want floor 5", got)
	}
}
