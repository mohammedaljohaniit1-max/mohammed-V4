package beacon

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// TraceToken represents a tracked asynchronous trace or webhook event.
type TraceToken struct {
	ID         string    `json:"id"`
	Origin     string    `json:"origin"`
	CreatedAt  time.Time `json:"created_at"`
	Resolved   bool      `json:"resolved"`
	ResolvedAt time.Time `json:"resolved_at,omitempty"`
}

// Correlator manages active trace tokens in a thread-safe manner.
type Correlator struct {
	tokens sync.Map // map[string]*TraceToken
}

// NewCorrelator creates an initialized Correlator.
func NewCorrelator() *Correlator {
	return &Correlator{}
}

// generateID creates a standard 16-byte random hex identifier.
func generateID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// Register creates and registers a new outgoing trace token.
func (c *Correlator) Register(origin string) (*TraceToken, error) {
	id, err := generateID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate trace ID: %w", err)
	}

	token := &TraceToken{
		ID:        id,
		Origin:    origin,
		CreatedAt: time.Now(),
		Resolved:  false,
	}

	c.tokens.Store(id, token)
	return token, nil
}

// Resolve marks an active token as resolved upon receiving a callback.
func (c *Correlator) Resolve(id string) (*TraceToken, bool) {
	val, ok := c.tokens.Load(id)
	if !ok {
		return nil, false
	}

	token := val.(*TraceToken)
	token.Resolved = true
	token.ResolvedAt = time.Now()
	return token, true
}

// Get retrieves the current status of a token.
func (c *Correlator) Get(id string) (*TraceToken, bool) {
	val, ok := c.tokens.Load(id)
	if !ok {
		return nil, false
	}
	return val.(*TraceToken), true
}
