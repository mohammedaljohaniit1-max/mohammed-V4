package drift

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// DiscoveredRoute represents an API route identified during asset parsing.
type DiscoveredRoute struct {
	Path       string `json:"path"`
	SourceFile string `json:"source_file"`
	MethodHint string `json:"method_hint,omitempty"`
}

// SourceMap represents the standard v3 source map format.
type SourceMap struct {
	Version        int      `json:"version"`
	File           string   `json:"file"`
	Sources        []string `json:"sources"`
	SourcesContent []string `json:"sourcesContent,omitempty"`
}

// RouteParser extracts API routes from frontend bundles and source maps for asset auditing.
type RouteParser struct {
	routeRegex *regexp.Regexp
}

// NewRouteParser creates a RouteParser configured with standard API path detection patterns.
func NewRouteParser() *RouteParser {
	pattern := "[\"'](/(?:api/v[0-9]+|api|graphql|v[0-9]+)/[a-zA-Z0-9_\\-\\./]+)[\"']"
	return &RouteParser{
		routeRegex: regexp.MustCompile(pattern),
	}
}

// ParseBundle extracts API route declarations from JavaScript bundle content.
func (p *RouteParser) ParseBundle(content, filename string) []DiscoveredRoute {
	matches := p.routeRegex.FindAllStringSubmatch(content, -1)
	seen := make(map[string]bool)
	var routes []DiscoveredRoute

	for _, match := range matches {
		if len(match) > 1 {
			cleanPath := strings.TrimSpace(match[1])
			if !seen[cleanPath] {
				seen[cleanPath] = true
				routes = append(routes, DiscoveredRoute{
					Path:       cleanPath,
					SourceFile: filename,
				})
			}
		}
	}
	return routes
}

// ParseSourceMap unpacks source map JSON and extracts routes from source file paths and embedded content.
func (p *RouteParser) ParseSourceMap(mapData []byte, mapFilename string) ([]DiscoveredRoute, *SourceMap, error) {
	var sm SourceMap
	if err := json.Unmarshal(mapData, &sm); err != nil {
		return nil, nil, fmt.Errorf("failed to parse source map: %w", err)
	}

	seen := make(map[string]bool)
	var routes []DiscoveredRoute

	// Extract from source file paths
	for _, sourcePath := range sm.Sources {
		if strings.Contains(sourcePath, "api") || strings.Contains(sourcePath, "route") {
			matches := p.routeRegex.FindAllStringSubmatch(sourcePath, -1)
			for _, match := range matches {
				if len(match) > 1 && !seen[match[1]] {
					seen[match[1]] = true
					routes = append(routes, DiscoveredRoute{
						Path:       match[1],
						SourceFile: sourcePath,
					})
				}
			}
		}
	}

	// Extract from embedded source contents if available
	for i, content := range sm.SourcesContent {
		sourceName := fmt.Sprintf("embedded_%d", i)
		if i < len(sm.Sources) {
			sourceName = sm.Sources[i]
		}
		for _, r := range p.ParseBundle(content, sourceName) {
			if !seen[r.Path] {
				seen[r.Path] = true
				routes = append(routes, r)
			}
		}
	}

	return routes, &sm, nil
}
