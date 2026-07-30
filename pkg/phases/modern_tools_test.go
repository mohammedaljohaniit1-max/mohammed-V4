package phases

import "testing"

// TestModernTools_ParseHostLines is the V12.1 Section 3 proof that uncover/chaos/
// alterx host ingestion is scope-correct: only apex + *.apex survive, host:port
// is trimmed, comments/blanks/dupes are dropped.
func TestModernTools_ParseHostLines(t *testing.T) {
	in := "api.example.com\n" +
		"www.example.com:443\n" + // port stripped
		"# comment line\n" +
		"\n" +
		"EXAMPLE.COM\n" + // apex itself, lowercased
		"evil.com\n" + // out of scope
		"api.example.com\n" // duplicate
	got := parseHostLines(in, "example.com")
	want := map[string]bool{
		"api.example.com": true,
		"www.example.com": true,
		"example.com":     true,
	}
	if len(got) != len(want) {
		t.Fatalf("expected %d hosts, got %d: %v", len(want), len(got), got)
	}
	for _, h := range got {
		if !want[h] {
			t.Errorf("unexpected host in result: %q", h)
		}
		if h == "evil.com" {
			t.Error("out-of-scope host must be dropped")
		}
	}
}

// TestModernTools_ParseCariddiJSON verifies cariddi endpoint + secret extraction
// from BOTH the array and NDJSON forms of its JSON output.
func TestModernTools_ParseCariddiJSON(t *testing.T) {
	// NDJSON form.
	ndjson := `{"url":"https://x.com/a","secrets":[{"name":"AWS","match":"AKIA123"}]}` + "\n" +
		`{"url":"https://x.com/b"}` + "\n" +
		`{"url":"https://x.com/a"}` // dup url
	urls, secrets := parseCariddiJSON(ndjson)
	if len(urls) != 2 {
		t.Errorf("expected 2 deduped urls, got %d: %v", len(urls), urls)
	}
	if len(secrets) != 1 || secrets[0] != "AWS: AKIA123" {
		t.Errorf("expected 1 AWS secret, got %v", secrets)
	}

	// Array form.
	arr := `[{"url":"https://y.com/1","secrets":[{"name":"","match":"tok"}]}]`
	urls2, secrets2 := parseCariddiJSON(arr)
	if len(urls2) != 1 || urls2[0] != "https://y.com/1" {
		t.Errorf("array url parse failed: %v", urls2)
	}
	if len(secrets2) != 1 || secrets2[0] != "secret: tok" {
		t.Errorf("empty secret name must default to 'secret': %v", secrets2)
	}

	// Empty input yields nothing, no panic.
	if u, s := parseCariddiJSON(""); u != nil || s != nil {
		t.Errorf("empty input must yield nil,nil got %v,%v", u, s)
	}
}

// TestModernTools_ParseTrufflehogJSON verifies verified-vs-unverified secret
// separation — the difference between a Critical (live) and Medium finding.
func TestModernTools_ParseTrufflehogJSON(t *testing.T) {
	out := `{"DetectorName":"AWS","Verified":true,"Redacted":"AKIA****"}` + "\n" +
		`{"DetectorName":"Slack","Verified":false,"Raw":"xoxb-abc"}` + "\n" +
		`not-json-line` + "\n" +
		`{"DetectorName":"","Verified":true,"Raw":"skip-empty-detector"}`
	all, verified := parseTrufflehogJSON(out)
	if len(all) != 2 {
		t.Errorf("expected 2 secrets (empty-detector skipped), got %d: %v", len(all), all)
	}
	if len(verified) != 1 || verified[0] != "AWS: AKIA****" {
		t.Errorf("expected only the AWS secret verified, got %v", verified)
	}
}

// TestModernTools_ParsePPmapOutput verifies the prototype-pollution verdict
// parser: "vulnerable" is a hit, "not vulnerable" is not.
func TestModernTools_ParsePPmapOutput(t *testing.T) {
	cases := []struct {
		out  string
		want bool
	}{
		{"https://x.com/?a=1 might be vulnerable to prototype pollution", true},
		{"https://x.com/ is VULNERABLE", true},
		{"https://x.com/ is not vulnerable", false},
		{"scanning...", false},
		{"", false},
	}
	for _, c := range cases {
		if got := parsePPmapOutput(c.out); got != c.want {
			t.Errorf("parsePPmapOutput(%q)=%v want %v", c.out, got, c.want)
		}
	}
}

// TestModernTools_DedupeStrings covers the order-preserving dedupe helper.
func TestModernTools_DedupeStrings(t *testing.T) {
	got := dedupeStrings([]string{"a", "", "b", "a", "c", "b"})
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("expected %v got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("index %d: got %q want %q", i, got[i], want[i])
		}
	}
}
