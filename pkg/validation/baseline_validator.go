package validation

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
)

// BaselineProfile holds the fingerprint of a host's response to non-existent paths.
type BaselineProfile struct {
	StatusCode    int
	ContentLength int64
	BodyHash      string
	Title         string
	IsCatchAll    bool
}

// BaselineValidator tracks baseline calibration profiles across origins.
type BaselineValidator struct {
	profiles map[string]*BaselineProfile
	mu       sync.RWMutex
}

var defaultBaselineValidator = NewBaselineValidator()

// DefaultBaselineValidator returns the package-level shared baseline validator.
func DefaultBaselineValidator() *BaselineValidator {
	return defaultBaselineValidator
}

// NewBaselineValidator creates an empty baseline validator.
func NewBaselineValidator() *BaselineValidator {
	return &BaselineValidator{
		profiles: make(map[string]*BaselineProfile),
	}
}

// Calibrate issues a GET request to a randomized non-existent path on the target's origin
// to fingerprint Soft-404 / Catch-all responses.
func (bv *BaselineValidator) Calibrate(ctx context.Context, targetURL string, client *http.Client) (*BaselineProfile, error) {
	origin := extractOrigin(targetURL)
	if origin == "" {
		return nil, fmt.Errorf("invalid URL or origin: %s", targetURL)
	}

	bv.mu.RLock()
	if profile, exists := bv.profiles[origin]; exists {
		bv.mu.RUnlock()
		return profile, nil
	}
	bv.mu.RUnlock()

	// Generate random non-existent path e.g., /.calib-<uuid>
	randomUUID := generateRandomHex(16)
	calibURL := fmt.Sprintf("%s/.calib-%s", origin, randomUUID)

	if client == nil {
		client = baselineClient
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, calibURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "MOHAMMED-Safe-Baseline/1.0")
	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return nil, err
	}

	hash := sha256.Sum256(body)
	bodyHash := hex.EncodeToString(hash[:])
	title := extractHTMLTitle(body)

	profile := &BaselineProfile{
		StatusCode:    resp.StatusCode,
		ContentLength: int64(len(body)),
		BodyHash:      bodyHash,
		Title:         title,
		IsCatchAll:    resp.StatusCode == http.StatusOK,
	}

	bv.mu.Lock()
	bv.profiles[origin] = profile
	bv.mu.Unlock()

	return profile, nil
}

// IsSoft404 checks if a target response matches the calibrated Soft-404 / Catch-all baseline
// for that host (within ±64 bytes length tolerance or identical body hash).
func (bv *BaselineValidator) IsSoft404(respStatusCode int, respBody []byte, targetURL string) bool {
	origin := extractOrigin(targetURL)
	if origin == "" {
		return false
	}

	bv.mu.RLock()
	profile, exists := bv.profiles[origin]
	bv.mu.RUnlock()

	if !exists || profile == nil {
		return false
	}

	// If the server answered 200 OK to the random non-existent path, it's a catch-all / soft-404 server.
	if profile.IsCatchAll {
		// Matching status 200 OK
		if respStatusCode == http.StatusOK {
			// Check exact body hash
			hash := sha256.Sum256(respBody)
			if hex.EncodeToString(hash[:]) == profile.BodyHash {
				return true
			}
			// Check content-length tolerance delta of ±64 bytes
			lengthDiff := int64(len(respBody)) - profile.ContentLength
			if lengthDiff < 0 {
				lengthDiff = -lengthDiff
			}
			if lengthDiff <= 64 {
				return true
			}
			// Check title match if present
			currentTitle := extractHTMLTitle(respBody)
			if profile.Title != "" && currentTitle != "" && profile.Title == currentTitle {
				return true
			}
		}
	}

	// Also catch cases where target status and body hash directly match baseline error page
	if respStatusCode == profile.StatusCode {
		hash := sha256.Sum256(respBody)
		if hex.EncodeToString(hash[:]) == profile.BodyHash {
			return true
		}
	}

	return false
}

// ExactTokenCheck verifies high-impact findings with strict regex tokens and Content-Type validation.
func ExactTokenCheck(findingType, targetURL string, statusCode int, body []byte, contentType string) (bool, string) {
	lowerType := strings.ToLower(findingType)
	lowerBody := string(body)
	lowerContentType := strings.ToLower(contentType)

	// High-impact checks
	isEnv := strings.Contains(lowerType, ".env") || strings.Contains(targetURL, "/.env")
	isGit := strings.Contains(lowerType, ".git") || strings.Contains(targetURL, "/.git/")
	isActuator := strings.Contains(lowerType, "actuator") || strings.Contains(targetURL, "/actuator")

	if !isEnv && !isGit && !isActuator {
		return true, "" // not a specialized exact-token asset
	}

	// Rule 1: A raw credential / configuration file must NOT be an HTML page (WAF/login mask)
	if strings.Contains(lowerContentType, "text/html") && (isEnv || isGit) {
		return false, "rejected: HTML content-type returned for raw sensitive file/repo endpoint"
	}

	// Rule 2: Strict signature verification
	if isEnv {
		envRegex := regexp.MustCompile(`(?m)^[A-Z0-9_]+=(.*)$`)
		if !strings.Contains(lowerBody, "APP_KEY=") && !strings.Contains(lowerBody, "DB_PASSWORD=") && !envRegex.Match(body) {
			return false, "rejected: .env missing mandatory key-value signature (e.g. APP_KEY=)"
		}
	}

	if isGit {
		if !strings.Contains(lowerBody, "ref: refs/heads/") && !strings.Contains(lowerBody, "[core]") {
			return false, "rejected: .git endpoint missing Git repository signature ([core] or ref: refs/heads/)"
		}
	}

	if isActuator {
		if !strings.Contains(lowerBody, `"status":"UP"`) && !strings.Contains(lowerBody, `"status" : "UP"`) && !strings.Contains(lowerBody, `"beans":`) && !strings.Contains(lowerBody, `"health":`) {
			return false, "rejected: actuator endpoint missing Spring Boot Actuator JSON structure"
		}
	}

	return true, ""
}

func extractOrigin(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		if strings.Contains(rawURL, "://") {
			parts := strings.Split(rawURL, "/")
			if len(parts) >= 3 {
				return parts[0] + "//" + parts[2]
			}
		}
		return ""
	}
	return u.Scheme + "://" + u.Host
}

var titleRegexp = regexp.MustCompile(`(?i)<title[^>]*>(.*?)</title>`)

func extractHTMLTitle(body []byte) string {
	matches := titleRegexp.FindSubmatch(body)
	if len(matches) > 1 {
		return strings.TrimSpace(string(bytes.ReplaceAll(matches[1], []byte("\n"), []byte(" "))))
	}
	return ""
}

func generateRandomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
