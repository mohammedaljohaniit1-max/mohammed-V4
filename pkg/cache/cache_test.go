package cache

import (
	"net/http"
	"testing"
)

func TestEvaluateResponseHeaders(t *testing.T) {
	header := http.Header{}
	header.Set("Cache-Control", "private, no-cache, no-store, must-revalidate")
	header.Set("Vary", "Cookie, Authorization")

	report := EvaluateResponseHeaders(header)
	if !report.IsExplicitPrivate {
		t.Errorf("expected explicit private flag")
	}
	if !report.HasNoStore {
		t.Errorf("expected no-store flag")
	}
	if report.Vary != "Cookie, Authorization" {
		t.Errorf("expected Vary header to match")
	}
}
