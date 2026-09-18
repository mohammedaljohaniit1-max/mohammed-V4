package drift

import (
	"testing"
)

func TestRouteParser_ParseBundle(t *testing.T) {
	js := `
		const u1 = "/api/v1/users";
		const u2 = "/api/v2/orders/status";
		const g1 = "/graphql";
		const v = "/v1/health";
		const ignore = "/static/css/style.css";
	`
	parser := NewRouteParser()
	routes := parser.ParseBundle(js, "bundle.js")

	if len(routes) < 3 {
		t.Fatalf("expected at least 3 routes, got %d", len(routes))
	}

	foundMap := make(map[string]bool)
	for _, r := range routes {
		foundMap[r.Path] = true
	}

	if !foundMap["/api/v1/users"] {
		t.Errorf("missing /api/v1/users")
	}
	if !foundMap["/api/v2/orders/status"] {
		t.Errorf("missing /api/v2/orders/status")
	}
	if foundMap["/static/css/style.css"] {
		t.Errorf("unexpected non-api route matched")
	}
}

func TestRouteParser_ParseSourceMap(t *testing.T) {
	mapJSON := []byte(`{
		"version": 3,
		"file": "bundle.js",
		"sources": [
			"src/api/v1/client.ts",
			"src/components/button.tsx"
		],
		"sourcesContent": [
			"export const getUser = () => fetch('/api/v1/users/me');",
			"export const Button = () => null;"
		]
	}`)

	parser := NewRouteParser()
	routes, sm, err := parser.ParseSourceMap(mapJSON, "bundle.js.map")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if sm == nil || sm.Version != 3 {
		t.Errorf("expected source map version 3")
	}

	if len(routes) == 0 {
		t.Fatalf("expected at least 1 route extracted from source map")
	}

	foundMe := false
	for _, r := range routes {
		if r.Path == "/api/v1/users/me" {
			foundMe = true
		}
	}

	if !foundMe {
		t.Errorf("expected route /api/v1/users/me extracted")
	}
}
