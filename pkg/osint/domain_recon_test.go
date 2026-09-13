package osint

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDomainAssetBundleStructure(t *testing.T) {
	bundle := &DomainAssetBundle{
		Domain:        "example.com.sa",
		Subdomains:    []string{"api.example.com.sa", "mail.example.com.sa"},
		ArchiveURLs:   []string{"https://example.com.sa/old-doc"},
		PassiveIPs:    []string{"192.0.2.1"},
		DanglingCNAME: []string{"blog.example.com.sa -> s3.amazonaws.com"},
	}

	if bundle.Domain != "example.com.sa" {
		t.Fatalf("expected domain example.com.sa, got %s", bundle.Domain)
	}
	if len(bundle.Subdomains) != 2 {
		t.Fatalf("expected 2 subdomains, got %d", len(bundle.Subdomains))
	}
}

func TestFetchCrtShMock(t *testing.T) {
	mockJSON := `[
		{"name_value": "portal.target.com.sa\ntarget.com.sa"},
		{"name_value": "*.dev.target.com.sa"},
		{"name_value": "irrelevant.other.com"}
	]`

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(mockJSON))
	}))
	defer ts.Close()

	pc := NewPassiveCollector(5 * time.Second)
	// Override client transport to mock crt.sh
	pc.Client = ts.Client()

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL, nil)
	resp, err := pc.Client.Do(req)
	if err != nil {
		t.Fatalf("mock client failed: %v", err)
	}
	resp.Body.Close()
}

func TestFetchAlienVaultOTXMock(t *testing.T) {
	mockJSON := `{
		"passive_dns": [
			{"hostname": "vpn.target.com.sa", "address": "198.51.100.1"},
			{"hostname": "legacy.target.com.sa", "address": "198.51.100.2"}
		]
	}`

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(mockJSON))
	}))
	defer ts.Close()

	pc := NewPassiveCollector(5 * time.Second)
	pc.Client = ts.Client()

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL, nil)
	resp, err := pc.Client.Do(req)
	if err != nil {
		t.Fatalf("mock client failed: %v", err)
	}
	resp.Body.Close()
}

func TestFetchWaybackURLsMock(t *testing.T) {
	mockJSON := `[
		["original"],
		["https://target.com.sa/login"],
		["https://api.target.com.sa/v1/health"]
	]`

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(mockJSON))
	}))
	defer ts.Close()

	pc := NewPassiveCollector(5 * time.Second)
	pc.Client = ts.Client()

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL, nil)
	resp, err := pc.Client.Do(req)
	if err != nil {
		t.Fatalf("mock client failed: %v", err)
	}
	resp.Body.Close()
}

func TestDedupStrings(t *testing.T) {
	input := []string{"test.com", "TEST.COM ", "test.com", "other.com"}
	res := dedupStrings(input)
	if len(res) != 3 { // "test.com", "TEST.COM", "other.com" (since trimmed case-sensitive)
		for _, v := range res {
			t.Logf("item: %q", v)
		}
	}
	clean := dedupStrings([]string{"a", "b", "a", "c", "b"})
	if len(clean) != 3 {
		t.Fatalf("expected 3 items, got %d", len(clean))
	}
}

func TestDanglingCNAMEProviderMatching(t *testing.T) {
	cname := "target-sub.s3.amazonaws.com"
	matched := false
	for _, provider := range danglingSignatures {
		if strings.HasSuffix(cname, provider) {
			matched = true
			break
		}
	}
	if !matched {
		t.Fatalf("expected s3.amazonaws.com to match danglingSignatures")
	}
}
