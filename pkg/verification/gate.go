package verification

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/mohammed-v3/core/pkg/engine"
	"github.com/mohammed-v3/core/pkg/governor"
	"github.com/mohammed-v3/core/pkg/validation"
)

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

// ZeroNoiseGate coordinates multi-pass state differential validation to eliminate false positives.
type ZeroNoiseGate struct {
	mu           sync.RWMutex
	client       *http.Client
	gov          *governor.Governor
	outputDir    string
	confirmed    []FindingRecord
	manualReview []FindingRecord
}

// NewZeroNoiseGate creates a verification gate configured with a governor client.
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
		client:    client,
		gov:       gov,
		outputDir: outputDir,
	}
}

// ResponseProfile holds baseline structural features of an HTTP response.
type ResponseProfile struct {
	StatusCode    int
	ContentLength int64
	BodyHash      string
	Title         string
	IsCatchAll    bool
}

// CaptureBaseline captures an endpoint's current response profile.
func (g *ZeroNoiseGate) CaptureBaseline(ctx context.Context, targetURL string) (*ResponseProfile, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "MOHAMMED-ZeroNoiseGate/1.0")

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

	// Check if this behaves as a generic catch-all
	isCatchAll := validation.DefaultBaselineValidator().IsSoft404(resp.StatusCode, body, targetURL)

	return &ResponseProfile{
		StatusCode:    resp.StatusCode,
		ContentLength: int64(len(body)),
		BodyHash:      bodyHash,
		Title:         extractTitle(body),
		IsCatchAll:    isCatchAll,
	}, nil
}

// VerifyDifferential performs multi-pass validation across 3 isolated probes to ensure finding determinism.
func (g *ZeroNoiseGate) VerifyDifferential(ctx context.Context, candidate FindingRecord, probePath string, requiredSig string) bool {
	// 1. If candidate URL is a generic catch-all, reject immediately
	baseline, err := g.CaptureBaseline(ctx, candidate.URL)
	if err == nil && baseline.IsCatchAll {
		return false
	}

	// 2. Execute 2 consecutive verification probes to assert state repeatability
	passCount := 0
	for i := 0; i < 2; i++ {
		select {
		case <-ctx.Done():
			return false
		default:
		}

		if g.gov != nil {
			g.gov.Throttle()
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, candidate.URL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "MOHAMMED-ZeroNoiseGate/1.0")

		resp, err := g.client.Do(req)
		if err != nil {
			continue
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
		resp.Body.Close()
		if err != nil {
			continue
		}

		// Ensure required signature is deterministically present
		if requiredSig != "" && !strings.Contains(string(body), requiredSig) {
			continue
		}

		// Ensure response is not a soft-404 error
		if validation.DefaultBaselineValidator().IsSoft404(resp.StatusCode, body, candidate.URL) {
			continue
		}

		passCount++
	}

	return passCount == 2
}

// IngestFinding places candidate findings into CONFIRMED_FINDINGS or MANUAL_ASSESSMENT.
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

// ExportArtifacts writes CONFIRMED_FINDINGS.json and MANUAL_ASSESSMENT.json to disk.
func (g *ZeroNoiseGate) ExportArtifacts() error {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if err := os.MkdirAll(g.outputDir, 0755); err != nil {
		return err
	}

	confirmedPath := filepath.Join(g.outputDir, "CONFIRMED_FINDINGS.json")
	manualPath := filepath.Join(g.outputDir, "MANUAL_ASSESSMENT.json")

	cData, _ := json.MarshalIndent(g.confirmed, "", "  ")
	mData, _ := json.MarshalIndent(g.manualReview, "", "  ")

	if err := os.WriteFile(confirmedPath, cData, 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", confirmedPath, err)
	}
	if err := os.WriteFile(manualPath, mData, 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", manualPath, err)
	}

	return nil
}

// ProcessEngineFindings processes findings from engine.State through the zero-noise gate.
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

func extractTitle(body []byte) string {
	lower := bytes.ToLower(body)
	start := bytes.Index(lower, []byte("<title>"))
	if start == -1 {
		return ""
	}
	end := bytes.Index(lower[start:], []byte("</title>"))
	if end == -1 {
		return ""
	}
	return strings.TrimSpace(string(body[start+7 : start+end]))
}
