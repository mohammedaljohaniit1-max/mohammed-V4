package phases

import (
	"context"
	"strings"
	"time"

	"github.com/mohammed-v3/core/pkg/engine"
	"github.com/mohammed-v3/core/pkg/proxy"
)

// ═══════════════════════════════════════════════════════════════
// V12.1 FIX #5 — CDN-aware HTTP-smuggling severity
//
// ROOT CAUSE (mandate Section 1, FIX #5): a live Temu scan "confirmed" 28 HTTP
// request-smuggling findings on a target that is fully fronted by a CDN. On a
// shared CDN edge (Cloudflare / Fastly / Akamai / CloudFront) the front-end and
// back-end are the SAME hardened, RFC-strict proxy fleet — desync between "the
// front-end" and "the back-end" that a raw-socket timing oracle measures is
// almost always an artifact of the edge's own request queueing, NOT an
// exploitable smuggling primitive against the origin. Reporting 28 Criticals on
// such a host is the single loudest false-positive class in the whole scan.
//
// The fix does NOT drop the finding (a genuine edge desync is still worth a
// note); it DEMOTES it to Informational on CDN-fronted hosts and only keeps the
// High/Critical severity on DIRECT (non-CDN) origins where a real front-end↔
// back-end desync is exploitable.
// ═══════════════════════════════════════════════════════════════

// cdnSignatures maps a lower-cased response-header/body marker to the CDN vendor
// it proves. These are the vendor-specific headers the edges add on every
// response — impossible to fake from the origin.
var cdnSignatures = []struct {
	marker string
	vendor string
}{
	{"cf-ray", "Cloudflare"},
	{"cf-cache-status", "Cloudflare"},
	{"cf-mitigated", "Cloudflare"},
	{"server: cloudflare", "Cloudflare"},
	{"__cf", "Cloudflare"},
	{"x-served-by", "Fastly"}, // Fastly edge id (e.g. cache-*)
	{"x-fastly", "Fastly"},    // x-fastly-request-id
	{"fastly-", "Fastly"},     // fastly-io-info etc.
	{"x-akamai", "Akamai"},    // x-akamai-transformed / request-id
	{"akamai", "Akamai"},      // server: AkamaiGHost, akamai-* headers
	{"x-amz-cf-id", "CloudFront"},
	{"x-amz-cf-pop", "CloudFront"},
	{"via: 1.1 varnish", "Fastly"},
	{"server: cloudfront", "CloudFront"},
	{"x-cache: hit from cloudfront", "CloudFront"},
}

// cdnVendorFromHeaders inspects a response header blob (and optional body sample)
// and returns the CDN vendor name if any vendor signature is present, or "" when
// the host looks like a direct origin. Case-insensitive and pure — the unit test
// exercises every branch without a network. FIX #5.
func cdnVendorFromHeaders(headerBlob, bodySample string) string {
	hay := strings.ToLower(headerBlob + "\n" + bodySample)
	for _, sig := range cdnSignatures {
		if strings.Contains(hay, sig.marker) {
			return sig.vendor
		}
	}
	return ""
}

// smugglingSeverity decides the reported severity for an HTTP request-smuggling
// finding given the detected CDN vendor. On a CDN-fronted host the finding is
// demoted to "Informational" (with informational=true so the caller can flag
// http_confirmed=false / suppress the Critical); on a direct origin the original
// severity is preserved. FIX #5. This is the single decision point both
// smuggling phases (Phase 25 curl/smuggler and Phase 49 raw-socket) route
// through, so the demotion policy is identical everywhere.
func smugglingSeverity(originalSeverity, cdnVendor string) (severity string, informational bool) {
	if cdnVendor != "" {
		return "Informational", true
	}
	return originalSeverity, false
}

// detectCDNForHost fetches the response headers for a host and classifies it by
// vendor signature. It is the network-facing wrapper around cdnVendorFromHeaders
// used by the live smuggling phases; it returns "" on any fetch failure so a
// transient error can never accidentally UPGRADE a finding (fail-open toward the
// safer Informational only happens when a vendor IS detected). FIX #5.
func detectCDNForHost(ctx context.Context, s *engine.State, rawURL string) string {
	px := s.PhaseProxy(proxy.ProxyModeDirect) // lightweight header probe, never Burp
	client := httpClientFor(px, 8*time.Second)
	_, body, headerBlob := fetch(ctx, client, rawURL)
	if headerBlob == "" {
		return ""
	}
	// Only sniff a small body slice for server banners embedded in error pages.
	if len(body) > 2048 {
		body = body[:2048]
	}
	return cdnVendorFromHeaders(headerBlob, body)
}
