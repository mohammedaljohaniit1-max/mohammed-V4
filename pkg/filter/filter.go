package filter

import (
	"crypto/sha256"
	"fmt"
	"sync"
)

type Evidence struct {
	Source     string `json:"source"`
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
	BodyHash   string `json:"body_hash"`
}

type EvidenceVerifier struct {
	mu           sync.Mutex
	seenHashes   map[string]bool
	verifiedURLs map[string]*Evidence
}

func NewEvidenceVerifier() *EvidenceVerifier {
	return &EvidenceVerifier{
		seenHashes:   make(map[string]bool),
		verifiedURLs: make(map[string]*Evidence),
	}
}

func HashBody(body []byte) string {
	h := sha256.New()
	h.Write(body)
	return fmt.Sprintf("%x", h.Sum(nil))
}

func (e *EvidenceVerifier) AddEvidence(ev *Evidence) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	key := fmt.Sprintf("%s_%s_%d", ev.URL, ev.BodyHash, ev.StatusCode)
	if e.seenHashes[key] {
		return false // Duplicate evidence rejected
	}

	e.seenHashes[key] = true
	e.verifiedURLs[ev.URL] = ev
	return true
}
