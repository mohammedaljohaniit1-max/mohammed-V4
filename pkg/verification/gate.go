package verification

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/mohammed-v3/core/pkg/canonical"
	"github.com/mohammed-v3/core/pkg/engine"
	"github.com/mohammed-v3/core/pkg/governor"
	"github.com/mohammed-v3/core/pkg/validation"
)

// Public catalog, static, informational and blog routes that NEVER qualify for unauthenticated BOLA/IDOR.
var PublicRouteExclusionRegex = regexp.MustCompile(`(?i)/(catalog|products?|items?|posts?|blogs?|articles?|news|about|terms|privacy|contact|public|assets|static|css|js|images?|img|fonts?)/?`)

// High-entropy patterns representing sensitive PII, authentication, or financial data.
var SensitiveDataPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`), // Email
	regexp.MustCompile(`(?i)(token|bearer|jwt|api[_-]?key|secret|password|hash|ssn|credit[_-]?card|cvv|auth[_-]?token)["']?\s*[:=]\s*["']?[a-zA-Z0-9_\-\.]{8,}`),
	regexp.MustCompile(`(?i)("balance"|"account_number"|"routing_number"|"total_amount"|"billing_address")\s*:`),
	regexp.MustCompile(`(?i)("tenant_id"|"user_id"|"role"|"permissions")\s*:\s*["']?(admin|superuser|root|internal)`),
}

// AIValidationRequest schema passed to Ollama / Gemini handshake.
type AIValidationRequest struct {
	FindingType      string `json:"finding_type"`
	URL              string `json:"url"`
	Method           string `json:"method"`
	Evidence         string `json:"evidence"`
	ResponseSnippet  string `json:"response_snippet"`
	BaselineSnippet  string `json:"baseline_snippet"`
	SimHashDistance  int    `json:"simhash_distance"`
	LevenshteinRatio float64 `json:"levenshtein_ratio"`
}

// AIValidationResponse strict JSON format expected from AI engine.
type AIValidationResponse struct {
	Confirmed  bool    `json:"confirmed"`
	Confidence float64 `json:"confidence"`
	Reason     string  `json:"reason"`
}

// FindingRecord represents a verified security finding or anomaly.
type FindingRecord struct {
	ID          string                 `json:"id"`
	Title       string                 `json:"title"`
	Severity    string                 `json:"severity"`
	URL         string                 `json:"url"`
	Tool        string                 `json:"tool"`
	Confidence  int                    `json:"confidence"`
	Evidence    string                 `json:"evidence"`
	Details     map[string]interface{} `json:"details,omitempty"`
	Timestamp   string                 `json:"timestamp"`
	IsConfirmed bool                   `json:"is_confirmed"`
}

// ZeroNoiseGate coordinates multi-stage false-positive elimination.
type ZeroNoiseGate struct {
	mu           sync.RWMutex
	client       *http.Client
	gov          *governor.Governor
	outputDir    string
	confirmed    []FindingRecord
	manualReview []FindingRecord
	deduplicator *canonical.RouteDeduplicator
}

// NewZeroNoiseGate creates a verification gate.
func NewZeroNoiseGate(outputDir string, gov *governor.Governor) *ZeroNoiseGate {
	baseClient := &http.Client{
		Timeout: 12 * time.Second,
	}
	var client *http.Client
	if gov != nil {
		client = gov.WrapClient(baseClient)
	} else {
		client = baseClient
	}

	return &ZeroNoiseGate{
		client:       client,
		gov:          gov,
		outputDir:    outputDir,
		deduplicator: canonical.NewRouteDeduplicator(),
	}
}

// ResponseProfile holds baseline structural features of an HTTP response.
type ResponseProfile struct {
	StatusCode    int
	ContentLength int64
	BodyHash      string
	Title         string
	Body          []byte
	SimHash       uint64
	IsCatchAll    bool
}

// CaptureBaseline captures an endpoint's current response profile.
func (g *ZeroNoiseGate) CaptureBaseline(ctx context.Context, targetURL string) (*ResponseProfile, error) {
	// Baseline should probe a randomized non-existent path on target origin to establish error/catch-all fingerprint
	u, err := url.Parse(targetURL)
	baselineURL := targetURL
	if err == nil {
		u.Path = "/_mohammed_nonexistent_" + hex.EncodeToString([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
		u.RawQuery = ""
		baselineURL = u.String()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baselineURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "MOHAMMED-ZeroNoiseGate/2.0")

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return nil, err
	}

	h := sha256.Sum256(body)
	bodyHash := hex.EncodeToString(h[:])
	isCatchAll := validation.DefaultBaselineValidator().IsSoft404(resp.StatusCode, body, targetURL)

	return &ResponseProfile{
		StatusCode:    resp.StatusCode,
		ContentLength: int64(len(body)),
		BodyHash:      bodyHash,
		Title:         extractTitle(body),
		Body:          body,
		SimHash:       computeSimHash64(string(body)),
		IsCatchAll:    isCatchAll,
	}, nil
}

// ValidateBOLA verifies that an endpoint qualifies for BOLA testing.
func (g *ZeroNoiseGate) ValidateBOLA(rawURL string, body []byte, isAuthHeaderPresent bool) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}

	// 1. Public Path Exclusion: never report BOLA on public informational, blog, or catalog pages
	if PublicRouteExclusionRegex.MatchString(u.Path) {
		return false
	}

	// 2. Authentication Requirement: endpoint must either require auth headers or expose private APIs
	isPrivateAPI := strings.Contains(u.Path, "/api/") && (strings.Contains(u.Path, "/user") || strings.Contains(u.Path, "/order") || strings.Contains(u.Path, "/account") || strings.Contains(u.Path, "/me") || strings.Contains(u.Path, "/admin"))
	if !isAuthHeaderPresent && !isPrivateAPI {
		return false
	}

	// 3. Payload Sensitivity: response must contain authentic private data/PII, not generic HTML templates
	hasSensitiveData := false
	for _, p := range SensitiveDataPatterns {
		if p.Match(body) {
			hasSensitiveData = true
			break
		}
	}

	return hasSensitiveData
}

// ValidateCORS ensures reflected CORS is reported ONLY when credentials are confirmed on sensitive session context.
func (g *ZeroNoiseGate) ValidateCORS(respHeaders http.Header, body []byte, isAuthContext bool) bool {
	acac := strings.ToLower(respHeaders.Get("Access-Control-Allow-Credentials"))
	if acac != "true" {
		return false
	}

	// Require both authenticated context and sensitive user data (e.g., CSRF, profile, tokens)
	hasSensitiveData := false
	for _, p := range SensitiveDataPatterns {
		if p.Match(body) {
			hasSensitiveData = true
			break
		}
	}

	return isAuthContext && hasSensitiveData
}

// VerifyDifferential asserts state determinism via SimHash Hamming distance and Levenshtein ratio.
func (g *ZeroNoiseGate) VerifyDifferential(ctx context.Context, candidate FindingRecord, probePath string, requiredSig string) bool {
	// Rule 1: Structural Route Deduplication - discard duplicate route permutations
	if !g.deduplicator.ShouldProbe(candidate.Tool, "GET", candidate.URL) {
		return false
	}

	// Rule 2: Capture origin baseline
	baseline, err := g.CaptureBaseline(ctx, candidate.URL)
	if err == nil && baseline.IsCatchAll {
		return false
	}

	// Rule 3: Execute confirmation probe
	if g.gov != nil {
		g.gov.Throttle()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, candidate.URL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "MOHAMMED-ZeroNoiseGate/2.0")

	resp, err := g.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return false
	}

	// 1. Status code must not be a generic error
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false
	}

	// 2. SimHash distance against baseline error page
	probeSimHash := computeSimHash64(string(body))
	if baseline != nil {
		hammingDist := hammingDistance64(baseline.SimHash, probeSimHash)
		levRatio := computeLevenshteinRatio(string(baseline.Body), string(body))

		// If page is identical template (Hamming < 12 and Levenshtein >= 0.85), reject as catch-all variant
		if hammingDist < 12 && levRatio >= 0.85 {
			return false
		}
	}

	// 3. Required signature match if provided
	if requiredSig != "" && !strings.Contains(string(body), requiredSig) {
		return false
	}

	return true
}

// IngestFinding routes findings to CONFIRMED or MANUAL review based on confidence and confirmation.
func (g *ZeroNoiseGate) IngestFinding(f FindingRecord) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if f.Timestamp == "" {
		f.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}

	if f.IsConfirmed && f.Confidence >= 70 {
		g.confirmed = append(g.confirmed, f)
	} else {
		g.manualReview = append(g.manualReview, f)
	}
}

// ExportArtifacts writes CONFIRMED_FINDINGS.json and MANUAL_ASSESSMENT.json.
func (g *ZeroNoiseGate) ExportArtifacts() error {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if err := os.MkdirAll(g.outputDir, 0755); err != nil {
		return err
	}

	cData, _ := json.MarshalIndent(g.confirmed, "", "  ")
	mData, _ := json.MarshalIndent(g.manualReview, "", "  ")

	_ = os.WriteFile(filepath.Join(g.outputDir, "CONFIRMED_FINDINGS.json"), cData, 0644)
	_ = os.WriteFile(filepath.Join(g.outputDir, "MANUAL_ASSESSMENT.json"), mData, 0644)
	return nil
}

// ProcessEngineFindings filters engine.State findings through zero-noise policies.
func (g *ZeroNoiseGate) ProcessEngineFindings(s *engine.State) {
	for _, f := range s.Findings {
		title := fmt.Sprintf("%v", f["title"])
		urlStr := fmt.Sprintf("%v", f["url"])
		sev := fmt.Sprintf("%v", f["severity"])
		tool := fmt.Sprintf("%v", f["tool"])
		ev := fmt.Sprintf("%v", f["evidence"])

		confidence := 50
		if c, ok := f["confidence"].(int); ok {
			confidence = c
		}

		isConfirmed := false
		if conf, ok := f["http_confirmed"].(bool); ok && conf && confidence >= 70 {
			isConfirmed = true
		}

		rec := FindingRecord{
			ID:          fmt.Sprintf("MOH-%d", time.Now().UnixNano()%100000),
			Title:       title,
			Severity:    sev,
			URL:         urlStr,
			Tool:        tool,
			Confidence:  confidence,
			Evidence:    ev,
			IsConfirmed: isConfirmed,
		}

		g.IngestFinding(rec)
	}
}

// computeSimHash64 computes a 64-bit SimHash of text.
func computeSimHash64(s string) uint64 {
	words := strings.Fields(strings.ToLower(s))
	if len(words) == 0 {
		return 0
	}
	var v [64]int
	for _, word := range words {
		h := sha256.Sum256([]byte(word))
		var hash64 uint64
		for i := 0; i < 8; i++ {
			hash64 = (hash64 << 8) | uint64(h[i])
		}
		for i := 0; i < 64; i++ {
			if (hash64 & (1 << i)) != 0 {
				v[i]++
			} else {
				v[i]--
			}
		}
	}
	var fingerprint uint64
	for i := 0; i < 64; i++ {
		if v[i] > 0 {
			fingerprint |= (1 << i)
		}
	}
	return fingerprint
}

// hammingDistance64 calculates the bitwise difference between two 64-bit integers.
func hammingDistance64(a, b uint64) int {
	x := a ^ b
	dist := 0
	for x > 0 {
		dist += int(x & 1)
		x >>= 1
	}
	return dist
}

// computeLevenshteinRatio calculates string similarity ratio between 0.0 and 1.0.
func computeLevenshteinRatio(s1, s2 string) float64 {
	if s1 == s2 {
		return 1.0
	}
	// Sample up to 1000 characters for performance
	if len(s1) > 1000 {
		s1 = s1[:1000]
	}
	if len(s2) > 1000 {
		s2 = s2[:1000]
	}

	l1, l2 := len(s1), len(s2)
	if l1 == 0 || l2 == 0 {
		return 0.0
	}

	dist := levenshteinDistance(s1, s2)
	maxLen := math.Max(float64(l1), float64(l2))
	return 1.0 - (float64(dist) / maxLen)
}

func levenshteinDistance(s1, s2 string) int {
	d := make([][]int, len(s1)+1)
	for i := range d {
		d[i] = make([]int, len(s2)+1)
		d[i][0] = i
	}
	for j := range d[0] {
		d[0][j] = j
	}

	for i := 1; i <= len(s1); i++ {
		for j := 1; j <= len(s2); j++ {
			cost := 0
			if s1[i-1] != s2[j-1] {
				cost = 1
			}
			d[i][j] = min3(d[i-1][j]+1, d[i][j-1]+1, d[i-1][j-1]+cost)
		}
	}
	return d[len(s1)][len(s2)]
}

func min3(a, b, c int) int {
	if a < b && a < c {
		return a
	}
	if b < c {
		return b
	}
	return c
}

func extractTitle(body []byte) string {
	lower := strings.ToLower(string(body))
	start := strings.Index(lower, "<title>")
	if start == -1 {
		return ""
	}
	end := strings.Index(lower[start:], "</title>")
	if end == -1 {
		return ""
	}
	return strings.TrimSpace(string(body[start+7 : start+end]))
}
