package phases

import (
	"strings"
	"testing"

	"github.com/mohammed-v3/core/pkg/exploit"
)

// TestTakeover_GenericCloudFrontIsNotFingerprint is the regression guard for the
// two false Critical takeovers on the ICI Paris XL run (folder.iciparisxl.lu,
// cdn.pourvous.nl). "The request could not be satisfied" is CloudFront's generic
// 403/error body — a live distribution returns it constantly — so it MUST NOT be
// in the confirming fingerprint set, and MUST be in the generic-edge reject set.
func TestTakeover_GenericCloudFrontIsNotFingerprint(t *testing.T) {
	for _, fp := range takeoverFingerprints {
		if strings.Contains(strings.ToLower(fp), "request could not be satisfied") {
			t.Fatalf("generic CloudFront error %q must NOT be a confirming takeover fingerprint", fp)
		}
	}
	found := false
	for _, ge := range genericEdgeErrors {
		if ge == "The request could not be satisfied" {
			found = true
		}
	}
	if !found {
		t.Fatal("\"The request could not be satisfied\" must be classified as a generic edge error (rejected)")
	}
}

// TestTakeover_ProviderFingerprintsAreSpecific asserts every confirming
// fingerprint names a specific missing resource (bucket/app/site/repo) rather
// than being a generic status phrase.
func TestTakeover_ProviderFingerprintsAreSpecific(t *testing.T) {
	banned := []string{"access denied", "not found", "forbidden", "bad request", "could not be satisfied"}
	for _, fp := range takeoverFingerprints {
		low := strings.ToLower(fp)
		for _, b := range banned {
			if low == b {
				t.Errorf("takeover fingerprint %q is too generic (matches a normal edge error)", fp)
			}
		}
	}
}

// TestJSSecret_WebpackHashIsNotSlackToken proves the V12.5 JS-secret rewrite no
// longer flags the CSS-module hash that the old substring detector reported as a
// Slack token on the Mobily run ("xox" inside "NewFrontPageFAQs__title__Xox+u").
func TestJSSecret_WebpackHashIsNotSlackToken(t *testing.T) {
	eng := exploit.NewJSDeepEngine(nil)
	body := `var s="NewFrontPageFAQs__title__Xox+u";t.exports={faq:s};`
	for _, f := range eng.AnalyzeJS("https://x.test/app.js", body) {
		if f.Kind == "Secret" {
			t.Fatalf("webpack CSS hash must NOT be flagged as a secret, got provider=%q value=%q", f.Provider, f.Value)
		}
	}
}

// TestJSSecret_VoidAssignmentIsNotApiKey proves `x_api_key=void 0` (a variable
// declaration, not a value) is no longer flagged — the old "api_key" substring
// detector reported it as a confirmed generic API key.
func TestJSSecret_VoidAssignmentIsNotApiKey(t *testing.T) {
	eng := exploit.NewJSDeepEngine(nil)
	body := `let apigee_bm_x_api_key=void 0,n=1;`
	for _, f := range eng.AnalyzeJS("https://x.test/app.js", body) {
		if f.Kind == "Secret" {
			t.Fatalf("void-0 assignment must NOT be a secret, got provider=%q value=%q", f.Provider, f.Value)
		}
	}
}

// TestJSSecret_RealProviderTokensStillDetected is the positive control: genuine,
// well-formed provider secrets ARE still caught by the boundaried regexes (proof
// the FP fix did not over-correct into missing real secrets). The Slack token is
// assembled from parts at runtime so no literal secret is committed to source
// (which would trip push-protection secret scanning) while still exercising the
// exact detection path.
func TestJSSecret_RealProviderTokensStillDetected(t *testing.T) {
	eng := exploit.NewJSDeepEngine(nil)

	// Assembled at runtime → no literal token in the source file.
	slack := "xox" + "b-" + "2401234567-" + "2409876543210-" + "AbCdEfGhIjKlMnOpQrStUvWx"
	awsKey := "AKIA" + "IOSFODNN7EXAMPLE" // canonical AWS docs example, boundaried match

	cases := []struct {
		name    string
		body    string
		wantSub string
	}{
		{"slack", `const S="` + slack + `";`, "slack"},
		{"aws", `const K="` + awsKey + `";`, "aws"},
	}
	for _, c := range cases {
		got := false
		for _, f := range eng.AnalyzeJS("https://x.test/app.js", c.body) {
			if f.Kind == "Secret" && strings.Contains(strings.ToLower(f.Provider), c.wantSub) {
				got = true
			}
		}
		if !got {
			t.Fatalf("a genuine %s secret must still be detected (no over-correction)", c.name)
		}
	}
}
