package cache

import (
	"net/http"
	"strings"
)

// CacheConformanceReport evaluates standard RFC 7234 compliance.
type CacheConformanceReport struct {
	CacheControl      string `json:"cache_control"`
	Vary              string `json:"vary"`
	IsExplicitPrivate bool   `json:"is_explicit_private"`
	HasNoStore        bool   `json:"has_no_store"`
}

// EvaluateResponseHeaders audits standard caching directives for sensitive endpoints.
func EvaluateResponseHeaders(header http.Header) CacheConformanceReport {
	cc := strings.ToLower(header.Get("Cache-Control"))
	vary := header.Get("Vary")

	return CacheConformanceReport{
		CacheControl:      cc,
		Vary:              vary,
		IsExplicitPrivate: strings.Contains(cc, "private"),
		HasNoStore:        strings.Contains(cc, "no-store"),
	}
}
