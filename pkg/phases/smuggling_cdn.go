package phases

import (
	"context"
	"net/http"
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

// cdnVendorFromHTTPHeader is the http.Header-typed convenience wrapper around
// cdnVendorFromHeaders: it flattens the header map into the "key: value" blob
// the signature matcher expects, plus a small body sample. V12.4 FAILURE #9.
func cdnVendorFromHTTPHeader(h http.Header, body string) string {
	if len(h) == 0 && body == "" {
		return ""
	}
	var b strings.Builder
	for k, vs := range h {
		for _, v := range vs {
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteByte('\n')
		}
	}
	sample := body
	if len(sample) > 2048 {
		sample = sample[:2048]
	}
	return cdnVendorFromHeaders(b.String(), sample)
}

// cdnVendorNames are the WAF-fingerprint vendor names that are genuine CDNs
// (front-end and back-end are the same hardened proxy fleet, so a raw-socket
// desync is an edge-queueing artefact, not an origin-exploitable primitive).
// A pure application WAF (e.g. Imperva/F5) is deliberately excluded so it never
// suppresses a real smuggling finding against a direct origin behind it.
var cdnVendorNames = map[string]bool{
	"cloudflare": true, "akamai": true, "cloudfront": true,
	"fastly": true, "amazon cloudfront": true, "aws cloudfront": true,
}

// isCDNVendorName reports whether a WAF-fingerprint vendor name is a genuine CDN.
func isCDNVendorName(vendor string) bool {
	return cdnVendorNames[strings.ToLower(strings.TrimSpace(vendor))]
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
	// V12.4 FAILURE #9: consult the engine's already-known CDN state first. The
	// recon/orchestration phases (ASN=Akamai, CDN classification, WAF/CDN
	// fingerprint) populate State.CDNVendors, so we do not depend on a fragile
	// per-finding live probe that returns "" under load — the exact failure that
	// let 25 CDN-edge desync artefacts be reported as Critical smuggling.
	if v, known := s.CDNVendorFor(rawURL); known {
		return v
	}
	px := s.PhaseProxy(proxy.ProxyModeDirect) // lightweight header probe, never Burp
	client := httpClientFor(px, 8*time.Second)
	_, body, headerBlob := fetch(ctx, client, rawURL)
	if headerBlob == "" {
		// Probe failed — leave the status UNKNOWN (do not cache) so the caller
		// applies the smuggling "unknown ⇒ Informational" safety policy instead
		// of defaulting to a Critical.
		return ""
	}
	// Only sniff a small body slice for server banners embedded in error pages.
	if len(body) > 2048 {
		body = body[:2048]
	}
	vendor := cdnVendorFromHeaders(headerBlob, body)
	s.MarkCDN(rawURL, vendor) // cache positive vendor OR positively-probed direct origin
	return vendor
}
