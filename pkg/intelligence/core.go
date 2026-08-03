// Package intelligence implements the V13 "Intelligence Core": a thread-safe,
// central model of what the scanner has learned about a target, plus a
// deterministic target classifier (A/B/C/D) and a technology fingerprinter.
//
// Design philosophy (deliberately narrow, not "comprehensive"):
//   - Every field is something we can actually populate from observable signals
//     (HTTP headers, JS bundles, TLS certificate metadata, error pages) or from
//     caller-supplied facts (program size, provided sessions).
//   - Nothing here performs active exploitation. It is the read-model that every
//     scanning phase consults and updates via Learn(). Keeping this layer pure
//     and testable is what makes the downstream zero-false-positive gating
//     believable.
//
// This file is standalone: it has no dependency on the rest of the scanner, so
// it can be unit-tested in isolation and reused by cmd/tip.
package intelligence

import (
	"sort"
	"strings"
	"sync"
	"time"
)

// TargetClass is the adaptive hardening classification (mandate §1.2).
type TargetClass string

const (
	ClassA       TargetClass = "A" // Ultra-Hardened (GitLab, Google, Meta …)
	ClassB       TargetClass = "B" // Well-Hardened (mid/large tech, fintech)
	ClassC       TargetClass = "C" // Partially Secured (startups, new programs)
	ClassD       TargetClass = "D" // Unprotected (legacy, no program)
	ClassUnknown TargetClass = "?" // Not yet classified
)

// AuthType enumerates authentication mechanisms we can detect from signals.
type AuthType string

const (
	AuthOAuth2 AuthType = "oauth2"
	AuthOIDC   AuthType = "oidc"
	AuthSAML   AuthType = "saml"
	AuthJWT    AuthType = "jwt"
	AuthCookie AuthType = "cookie_session"
	AuthBasic  AuthType = "http_basic"
	AuthAPIKey AuthType = "api_key"
)

// Protocol enumerates API/transport protocols we can detect.
type Protocol string

const (
	ProtoREST      Protocol = "rest"
	ProtoGraphQL   Protocol = "graphql"
	ProtoGRPC      Protocol = "grpc"
	ProtoWebSocket Protocol = "websocket"
	ProtoSSE       Protocol = "sse"
	ProtoJSONRPC   Protocol = "jsonrpc"
)

// TechStack is the detected technology profile (mandate §1.1 Q1).
// Empty string means "not detected"; we never guess.
type TechStack struct {
	Language string   `json:"language,omitempty"` // e.g. "ruby_on_rails", "golang"
	Database string   `json:"database,omitempty"`
	Infra    string   `json:"infra,omitempty"` // e.g. "kubernetes", "aws"
	CDNorWAF string   `json:"cdn_or_waf,omitempty"`
	Servers  []string `json:"servers,omitempty"` // raw Server/X-Powered-By values seen
	// Evidence maps a claim (e.g. "language=ruby_on_rails") to the concrete
	// signal that justified it (e.g. "header X-Runtime present"). This is what
	// makes the profile auditable rather than magic.
	Evidence map[string]string `json:"evidence,omitempty"`
}

// Strategy holds the per-class strategy flags that downstream phases read
// (mandate §1.2). Percentages are advisory hints, not hard schedulers.
type Strategy struct {
	ManualPercent     int  `json:"manual_percent"`
	AutomationPercent int  `json:"automation_percent"`
	RunGenericNuclei  bool `json:"run_generic_nuclei"`
	RunAutomatedXSS   bool `json:"run_automated_xss_sqli"`
	FocusBusinessLogic bool `json:"focus_business_logic"`
	// Description is a short human-readable rationale, surfaced in the profile.
	Description string `json:"description"`
}

// Discovery is a single fact learned by a phase and fed to the core via Learn.
// Exactly one of the payload fields is expected to be set per Discovery; the
// core is defensive and ignores empty payloads.
type Discovery struct {
	Kind      DiscoveryKind `json:"kind"`
	Source    string        `json:"source"` // which phase/module produced it
	Value     string        `json:"value"`  // the payload (interpretation depends on Kind)
	Detail    string        `json:"detail,omitempty"`
	Timestamp time.Time     `json:"timestamp"`
}

// DiscoveryKind classifies a Discovery payload.
type DiscoveryKind string

const (
	DiscTech     DiscoveryKind = "tech"      // Value = "key=value", e.g. "language=golang"
	DiscWAF      DiscoveryKind = "waf"       // Value = vendor name
	DiscAuth     DiscoveryKind = "auth"      // Value = AuthType
	DiscProtocol DiscoveryKind = "protocol"  // Value = Protocol
	DiscEndpoint DiscoveryKind = "endpoint"  // Value = URL
	DiscParam    DiscoveryKind = "param"     // Value = parameter name
	DiscSession  DiscoveryKind = "session"   // Value = role label
)

// IntelligenceCore is the thread-safe central model (mandate §4.2).
type IntelligenceCore struct {
	mu sync.RWMutex

	target     string
	class      TargetClass
	strategy   Strategy
	tech       TechStack
	wafPresent bool
	wafVendor  string

	auth      map[AuthType]bool
	protocols map[Protocol]bool
	endpoints map[string]bool
	params    map[string]bool
	sessions  map[string]bool // role label -> present

	discoveries []Discovery
}

// NewCore constructs an empty core for a target host.
func NewCore(target string) *IntelligenceCore {
	return &IntelligenceCore{
		target:    strings.TrimSpace(target),
		class:     ClassUnknown,
		auth:      map[AuthType]bool{},
		protocols: map[Protocol]bool{},
		endpoints: map[string]bool{},
		params:    map[string]bool{},
		sessions:  map[string]bool{},
	}
}

// Target returns the target host this core describes.
func (ic *IntelligenceCore) Target() string {
	ic.mu.RLock()
	defer ic.mu.RUnlock()
	return ic.target
}

// Learn ingests a single Discovery and updates the model. It is safe to call
// from many goroutines. Unknown or empty discoveries are ignored (never panics)
// — resilience here is a hard requirement because it is fed by every phase.
func (ic *IntelligenceCore) Learn(d Discovery) {
	if d.Kind == "" {
		return
	}
	if d.Timestamp.IsZero() {
		d.Timestamp = time.Now().UTC()
	}
	ic.mu.Lock()
	defer ic.mu.Unlock()

	ic.discoveries = append(ic.discoveries, d)

	switch d.Kind {
	case DiscTech:
		k, v, ok := splitKV(d.Value)
		if !ok || v == "" {
			return
		}
		if ic.tech.Evidence == nil {
			ic.tech.Evidence = map[string]string{}
		}
		switch k {
		case "language":
			ic.tech.Language = v
		case "database":
			ic.tech.Database = v
		case "infra":
			ic.tech.Infra = v
		case "server":
			ic.tech.Servers = appendUnique(ic.tech.Servers, v)
		}
		ic.tech.Evidence[d.Value] = firstNonEmpty(d.Detail, d.Source)
	case DiscWAF:
		if v := strings.TrimSpace(d.Value); v != "" {
			ic.wafPresent = true
			ic.wafVendor = v
			ic.tech.CDNorWAF = v
		}
	case DiscAuth:
		if a := AuthType(strings.TrimSpace(d.Value)); a != "" {
			ic.auth[a] = true
		}
	case DiscProtocol:
		if p := Protocol(strings.TrimSpace(d.Value)); p != "" {
			ic.protocols[p] = true
		}
	case DiscEndpoint:
		if v := strings.TrimSpace(d.Value); v != "" {
			ic.endpoints[v] = true
		}
	case DiscParam:
		if v := strings.TrimSpace(d.Value); v != "" {
			ic.params[v] = true
		}
	case DiscSession:
		if v := strings.TrimSpace(d.Value); v != "" {
			ic.sessions[v] = true
		}
	}
}

// --- Read accessors (all return copies / snapshots; never expose internal maps) ---

func (ic *IntelligenceCore) Tech() TechStack {
	ic.mu.RLock()
	defer ic.mu.RUnlock()
	return ic.tech.clone()
}

func (ic *IntelligenceCore) Class() TargetClass {
	ic.mu.RLock()
	defer ic.mu.RUnlock()
	return ic.class
}

func (ic *IntelligenceCore) Strategy() Strategy {
	ic.mu.RLock()
	defer ic.mu.RUnlock()
	return ic.strategy
}

func (ic *IntelligenceCore) WAF() (present bool, vendor string) {
	ic.mu.RLock()
	defer ic.mu.RUnlock()
	return ic.wafPresent, ic.wafVendor
}

func (ic *IntelligenceCore) AuthMechanisms() []AuthType {
	ic.mu.RLock()
	defer ic.mu.RUnlock()
	out := make([]AuthType, 0, len(ic.auth))
	for a := range ic.auth {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func (ic *IntelligenceCore) Protocols() []Protocol {
	ic.mu.RLock()
	defer ic.mu.RUnlock()
	out := make([]Protocol, 0, len(ic.protocols))
	for p := range ic.protocols {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func (ic *IntelligenceCore) Sessions() []string {
	ic.mu.RLock()
	defer ic.mu.RUnlock()
	return sortedKeys(ic.sessions)
}

func (ic *IntelligenceCore) Endpoints() []string {
	ic.mu.RLock()
	defer ic.mu.RUnlock()
	return sortedKeys(ic.endpoints)
}

func (ic *IntelligenceCore) Params() []string {
	ic.mu.RLock()
	defer ic.mu.RUnlock()
	return sortedKeys(ic.params)
}

// DiscoveryCount returns how many discoveries have been ingested (for tests/telemetry).
func (ic *IntelligenceCore) DiscoveryCount() int {
	ic.mu.RLock()
	defer ic.mu.RUnlock()
	return len(ic.discoveries)
}

// --- small helpers ---

func (t TechStack) clone() TechStack {
	c := t
	c.Servers = append([]string(nil), t.Servers...)
	if t.Evidence != nil {
		c.Evidence = make(map[string]string, len(t.Evidence))
		for k, v := range t.Evidence {
			c.Evidence[k] = v
		}
	}
	return c
}

func splitKV(s string) (k, v string, ok bool) {
	i := strings.IndexByte(s, '=')
	if i < 0 {
		return "", "", false
	}
	return strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1:]), true
}

func appendUnique(list []string, v string) []string {
	for _, e := range list {
		if strings.EqualFold(e, v) {
			return list
		}
	}
	return append(list, v)
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
