package ai

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// mockOllama spins a fake Ollama server. tags is the /api/tags model list;
// genFn produces the /api/generate response body for a given prompt.
func mockOllama(t *testing.T, tags []string, genFn func(prompt string) string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/tags", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var sb strings.Builder
		sb.WriteString(`{"models":[`)
		for i, m := range tags {
			if i > 0 {
				sb.WriteString(",")
			}
			sb.WriteString(`{"name":"` + m + `"}`)
		}
		sb.WriteString(`]}`)
		_, _ = w.Write([]byte(sb.String()))
	})
	mux.HandleFunc("/api/generate", func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		resp := genFn(string(body))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"response":` + jsonString(resp) + `,"done":true}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// jsonString does a minimal JSON string encode for the mock.
func jsonString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return `"` + s + `"`
}

func TestBrain_ProbeResolvesModelAutoFallback(t *testing.T) {
	srv := mockOllama(t, []string{"llama3.2:latest", "gemma:2b"}, func(string) string { return "" })
	b := NewBrain(true, srv.URL, "", 5)
	if !b.Probe(context.Background()) {
		t.Fatal("expected brain online with installed models")
	}
	// gemma:2b appears earlier in DefaultModelPriority than llama3.2, so it must
	// be selected as the active model even though llama was listed first.
	if got := b.ActiveModel(); got != "gemma:2b" {
		t.Fatalf("expected auto-fallback to pick gemma:2b, got %q", got)
	}
}

func TestBrain_ProbeHonoursConfiguredPrimaryModel(t *testing.T) {
	srv := mockOllama(t, []string{"gemma:2b", "qwen2.5-coder:latest"}, func(string) string { return "" })
	b := NewBrain(true, srv.URL, "qwen2.5-coder:latest", 5)
	b.Probe(context.Background())
	if got := b.ActiveModel(); got != "qwen2.5-coder:latest" {
		t.Fatalf("expected configured primary to win, got %q", got)
	}
}

func TestBrain_OfflineFailsOpenSemantic(t *testing.T) {
	// Disabled brain must never touch the network and must return Offline=true.
	b := NewBrain(false, "http://127.0.0.1:1", "", 2)
	v := b.SemanticTriage(context.Background(), "sqli", "GET /x", "you have an error in your SQL syntax near")
	if !v.Offline {
		t.Fatal("expected offline verdict when brain disabled")
	}
	// The offline heuristic must still flag the obvious SQL error as vulnerable.
	if !v.Vulnerable {
		t.Fatalf("offline heuristic should flag SQL error, got %+v", v)
	}
}

func TestBrain_SemanticTriageParsesModelVerdict(t *testing.T) {
	srv := mockOllama(t, []string{"gemma:2b"}, func(string) string {
		return "VERDICT: VULNERABLE\nCONFIDENCE: 88\nREASON: raw stack trace leaked"
	})
	b := NewBrain(true, srv.URL, "", 5)
	b.Probe(context.Background())
	v := b.SemanticTriage(context.Background(), "info-leak", "GET /x", "some ambiguous body")
	if !v.Vulnerable || v.Confidence != 88 {
		t.Fatalf("expected VULNERABLE conf=88, got %+v", v)
	}
}

func TestBrain_MutatePayloadOfflineDeterministic(t *testing.T) {
	b := NewBrain(false, "", "", 2)
	muts := b.MutatePayload(context.Background(), "xss", "<script>alert(1)</script>", "blocked")
	if len(muts) == 0 {
		t.Fatal("offline mutation must still yield deterministic variants")
	}
	// The identity payload must never be returned as a "mutation".
	for _, m := range muts {
		if m == "<script>alert(1)</script>" {
			t.Fatal("mutation set must not contain the original payload")
		}
	}
}

func TestBrain_MutatePayloadUsesModelWhenOnline(t *testing.T) {
	srv := mockOllama(t, []string{"qwen2.5-coder:latest"}, func(string) string {
		return "<ScRiPt>alert(1)</ScRiPt>\n<img src=x onerror=alert(1)>\nHere are some payloads"
	})
	b := NewBrain(true, srv.URL, "", 5)
	b.Probe(context.Background())
	muts := b.MutatePayload(context.Background(), "xss", "<script>alert(1)</script>", "403 blocked")
	if len(muts) < 2 {
		t.Fatalf("expected model mutations, got %v", muts)
	}
	for _, m := range muts {
		if strings.HasPrefix(strings.ToLower(m), "here") {
			t.Fatalf("prose line leaked into mutations: %q", m)
		}
	}
}

func TestBrain_RankIDORCandidatesHeuristicOffline(t *testing.T) {
	b := NewBrain(false, "", "", 2)
	in := []string{
		"https://t/style.css",
		"https://t/api/v1/users/123?id=5",
		"https://t/admin/delete?user_id=9",
		"https://t/home",
	}
	ranked := b.RankIDORCandidates(context.Background(), in)
	if len(ranked) != len(in) {
		t.Fatalf("ranking must preserve all inputs, got %d", len(ranked))
	}
	// The admin/delete endpoint has the highest score and must sort first.
	if !strings.Contains(ranked[0], "admin") {
		t.Fatalf("expected admin endpoint ranked first, got %q", ranked[0])
	}
}

func TestBrain_RankNeverHallucinatesEndpoints(t *testing.T) {
	// Even online, the ranker must only echo endpoints that were in the input.
	srv := mockOllama(t, []string{"gemma:2b"}, func(string) string {
		return "https://evil.invalid/injected\nhttps://t/api/v1/users/1"
	})
	b := NewBrain(true, srv.URL, "", 5)
	b.Probe(context.Background())
	in := []string{"https://t/api/v1/users/1", "https://t/home"}
	ranked := b.RankIDORCandidates(context.Background(), in)
	for _, r := range ranked {
		if r == "https://evil.invalid/injected" {
			t.Fatal("ranker must reject endpoints not present in the input")
		}
	}
}

func TestBrain_HelpersDeterministic(t *testing.T) {
	if extractInt("CONFIDENCE: 73 out of 100") != 73 {
		t.Fatal("extractInt failed")
	}
	if extractInt("CONFIDENCE: 250") != 100 {
		t.Fatal("extractInt must clamp to 100")
	}
	if caseFlip("AbC") != "aBc" {
		t.Fatal("caseFlip failed")
	}
	if urlEncodeAll("A") != "%41" {
		t.Fatalf("urlEncodeAll failed: %q", urlEncodeAll("A"))
	}
}
