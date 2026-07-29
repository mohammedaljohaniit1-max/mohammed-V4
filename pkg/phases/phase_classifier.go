package phases

// phase_classifier.go — MOHAMMED V11.0 FINAL SOVEREIGN — FLAW #5 fix.
//
// V10.0 ran a FIXED phase order for every target. That wastes budget: a pure
// REST API has no DOM, so the whole headless-Chrome/CDP block (DOM-XSS,
// postMessage, client-side-secret) is dead weight; conversely an SPA is almost
// entirely client-side so CDP must run FIRST. This Phase 0 classifier fixes
// that by spending ≤30s up front issuing cheap HEAD/GET probes to fingerprint
// each in-scope origin, classifying it (Web App / REST API / SPA / Backend),
// and publishing a TARGET-ADAPTIVE phase plan the sovereign phases consult to
// skip or prioritize themselves.
//
// It FAILS OPEN: on any probe error the origin is classified Unknown and the
// full default plan is used, so classification can only ever *save* work, never
// hide a real attack surface.

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/mohammed-v3/core/pkg/engine"
	"github.com/mohammed-v3/core/pkg/exploit"
	"github.com/mohammed-v3/core/pkg/filter"
)

// TargetClass is the classified nature of an origin.
type TargetClass string

const (
	ClassUnknown TargetClass = "Unknown"
	ClassWebApp  TargetClass = "WebApp"  // server-rendered HTML app
	ClassRESTAPI TargetClass = "RESTAPI" // JSON/XML API, no HTML UI
	ClassSPA     TargetClass = "SPA"     // single-page app (React/Vue/Angular)
	ClassBackend TargetClass = "Backend" // raw backend/service (no browser surface)
)

// TargetProfile is the classifier verdict for one origin plus its adaptive plan.
type TargetProfile struct {
	Origin string
	Class  TargetClass
	// SkipCDP is true when this origin has no meaningful DOM (REST/Backend) so
	// the CDP browser phases can be skipped for it.
	SkipCDP bool
	// PrioritizeCDP is true for SPAs where the app logic lives client-side, so
	// the CDP phases should run early/first.
	PrioritizeCDP bool
	// Signals records the evidence strings that drove the classification.
	Signals []string
	// Server / PoweredBy carry fingerprint headers for the report trail.
	Server    string
	PoweredBy string
}

// classifierPlan is the process-wide, single-scan result store (mirrors the
// sovereignBootstrap singleton pattern used elsewhere in this package).
type classifierPlan struct {
	mu       sync.RWMutex
	profiles map[string]TargetProfile
	built    bool
}

var globalClassifierPlan = &classifierPlan{profiles: map[string]TargetProfile{}}

// ProfileFor returns the classification for an origin (or a permissive Unknown
// default when the classifier did not run / did not see it). Safe for
// concurrent reads from later phases.
func ProfileFor(origin string) TargetProfile {
	globalClassifierPlan.mu.RLock()
	defer globalClassifierPlan.mu.RUnlock()
	if p, ok := globalClassifierPlan.profiles[originString(origin)]; ok {
		return p
	}
	// Unknown → permissive default: run everything.
	return TargetProfile{Origin: originString(origin), Class: ClassUnknown}
}

// ClassifierRan reports whether Phase 0 executed this scan.
func ClassifierRan() bool {
	globalClassifierPlan.mu.RLock()
	defer globalClassifierPlan.mu.RUnlock()
	return globalClassifierPlan.built
}

// ShouldSkipCDPFor is the convenience the CDP phases (57/58) call to decide
// whether to skip an origin. Returns false (do not skip) when the classifier
// did not run, so behaviour is unchanged unless Phase 0 has positively
// classified the origin as CDP-irrelevant.
func ShouldSkipCDPFor(origin string) bool {
	if !ClassifierRan() {
		return false
	}
	return ProfileFor(origin).SkipCDP
}

// ─────────────────────────────────────────────────────────────────────────
// Phase 0 — Target Classifier
// ─────────────────────────────────────────────────────────────────────────

// PhaseClassifier is the target-adaptive Phase 0. It runs before the heavy
// phases and populates the global plan.
type PhaseClassifier struct{}

func (p *PhaseClassifier) Name() string { return "Target Classifier (Phase 0)" }
func (p *PhaseClassifier) Description() string {
	return "Phase 0: HEAD/GET fingerprint each in-scope origin, classify WebApp/API/SPA/Backend, build target-adaptive phase plan (≤30s)"
}

func (p *PhaseClassifier) Execute(ctx context.Context, s *engine.State) error {
	origins := apexLiveOrigins(s)
	if len(origins) == 0 {
		s.Printf("│  Phase 0 Classifier: SKIP (no in-scope live origins)\n")
		return nil
	}

	// Hard 30s cap on the entire classification pass (mandate: "Phase 0, 30s max").
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	client := exploit.NewClient(exploit.Options{
		FollowRedirects: false,
		Timeout:         6 * time.Second,
		Stealth:         sharedStealthGovernor(s),
	})

	globalClassifierPlan.mu.Lock()
	globalClassifierPlan.profiles = map[string]TargetProfile{}
	globalClassifierPlan.mu.Unlock()

	var (
		nWeb, nAPI, nSPA, nBackend, nUnknown int
	)

	for _, origin := range budget(origins, 24) {
		select {
		case <-cctx.Done():
			s.Printf("│  Phase 0 Classifier: 30s budget reached — classified %d origins so far\n",
				nWeb+nAPI+nSPA+nBackend+nUnknown)
			goto done
		default:
		}
		prof := classifyOrigin(cctx, client, origin)
		globalClassifierPlan.mu.Lock()
		globalClassifierPlan.profiles[originString(origin)] = prof
		globalClassifierPlan.mu.Unlock()

		switch prof.Class {
		case ClassWebApp:
			nWeb++
		case ClassRESTAPI:
			nAPI++
		case ClassSPA:
			nSPA++
		case ClassBackend:
			nBackend++
		default:
			nUnknown++
		}
	}

done:
	globalClassifierPlan.mu.Lock()
	globalClassifierPlan.built = true
	globalClassifierPlan.mu.Unlock()

	s.Printf("│  Phase 0 Classifier: WebApp=%d REST-API=%d SPA=%d Backend=%d Unknown=%d\n",
		nWeb, nAPI, nSPA, nBackend, nUnknown)
	s.Printf("│  Adaptive plan armed: REST/Backend origins skip CDP DOM phases; SPA origins prioritize CDP\n")

	// Record an Info finding so the plan appears in the report trail.
	s.AddFinding(map[string]interface{}{
		"type":     "Target Classification (Phase 0)",
		"severity": "Info",
		"url":      firstOrigin(origins),
		"target":   filter.HostOf(firstOrigin(origins)),
		"evidence": classificationSummary(nWeb, nAPI, nSPA, nBackend, nUnknown),
		"phase":    "V11-classifier",
	})
	return nil
}

// classifyOrigin issues cheap probes and returns a TargetProfile. It fetches
// the root document with a browser-like Accept header, then inspects the
// Content-Type, headers, and a small body sample.
func classifyOrigin(ctx context.Context, client *exploit.Client, origin string) TargetProfile {
	prof := TargetProfile{Origin: originString(origin), Class: ClassUnknown}

	// GET / — a HEAD often hides the Content-Type/body signals we need, so we
	// GET but rely on the client's 1MiB body cap to stay cheap.
	resp := client.Do(ctx, "GET", origin+"/", nil, map[string]string{
		"Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
	})
	if resp.Err != nil {
		prof.Signals = append(prof.Signals, "root probe error: "+resp.Err.Error())
		return prof
	}

	ct := ""
	if resp.Headers != nil {
		ct = strings.ToLower(resp.Headers.Get("Content-Type"))
		prof.Server = resp.Headers.Get("Server")
		prof.PoweredBy = resp.Headers.Get("X-Powered-By")
	}
	body := resp.Body
	lower := strings.ToLower(body)

	// Also probe a canonical API path to disambiguate API-first backends.
	apiJSON := probeLooksJSON(ctx, client, origin, "/api")

	switch {
	case isJSONContentType(ct) || (apiJSON && !strings.Contains(ct, "html")):
		// JSON root (or /api serves JSON and root is not HTML) → REST API.
		prof.Class = ClassRESTAPI
		prof.SkipCDP = true
		prof.Signals = append(prof.Signals, "JSON content-type / API-first root")
	case looksLikeSPA(lower):
		prof.Class = ClassSPA
		prof.PrioritizeCDP = true
		prof.Signals = append(prof.Signals, "SPA bundle markers (root div + JS framework)")
	case strings.Contains(ct, "html") || strings.Contains(lower, "<html"):
		prof.Class = ClassWebApp
		prof.Signals = append(prof.Signals, "server-rendered HTML document")
	case resp.Status >= 200 && resp.Status < 500 && ct != "" && !strings.Contains(ct, "html"):
		// Responds but not HTML and not JSON UI → raw backend/service.
		prof.Class = ClassBackend
		prof.SkipCDP = true
		prof.Signals = append(prof.Signals, "non-HTML backend response ("+ct+")")
	default:
		prof.Class = ClassUnknown
		prof.Signals = append(prof.Signals, "inconclusive root response")
	}
	if apiJSON {
		prof.Signals = append(prof.Signals, "/api returns JSON")
	}
	return prof
}

// probeLooksJSON GETs a path and reports whether it returned a JSON body.
func probeLooksJSON(ctx context.Context, client *exploit.Client, origin, path string) bool {
	resp := client.Do(ctx, "GET", origin+path, nil, map[string]string{"Accept": "application/json"})
	if resp.Err != nil {
		return false
	}
	ct := ""
	if resp.Headers != nil {
		ct = strings.ToLower(resp.Headers.Get("Content-Type"))
	}
	if isJSONContentType(ct) {
		return true
	}
	trimmed := strings.TrimSpace(resp.Body)
	return len(trimmed) > 1 && (trimmed[0] == '{' || trimmed[0] == '[')
}

func isJSONContentType(ct string) bool {
	return strings.Contains(ct, "application/json") ||
		strings.Contains(ct, "application/vnd.api+json") ||
		strings.Contains(ct, "text/json")
}

// looksLikeSPA detects a single-page-app shell: a near-empty root container plus
// a JS framework bundle reference.
func looksLikeSPA(lowerBody string) bool {
	frameworkMarkers := []string{
		`id="root"`, `id="app"`, `id="__next"`, `data-reactroot`,
		`ng-version`, `__nuxt`, `window.__initial_state__`,
		"/static/js/main.", "vite", "webpackjsonp", "react", "vue.js", "angular",
	}
	hits := 0
	for _, m := range frameworkMarkers {
		if strings.Contains(lowerBody, m) {
			hits++
		}
	}
	// An SPA shell is small: a couple of framework markers with little text.
	return hits >= 1 && len(lowerBody) < 20000 && strings.Contains(lowerBody, "<div")
}

func classificationSummary(w, a, spa, b, u int) string {
	return "Phase-0 target classification — WebApp=" + itoaLocal(w) +
		" REST-API=" + itoaLocal(a) + " SPA=" + itoaLocal(spa) +
		" Backend=" + itoaLocal(b) + " Unknown=" + itoaLocal(u) +
		"; REST/Backend origins skip CDP DOM phases, SPA origins prioritize CDP"
}

func firstOrigin(origins []string) string {
	if len(origins) == 0 {
		return ""
	}
	return origins[0]
}

// itoaLocal is a tiny int→string helper local to this file (the phases package
// has no shared itoa; exploit.itoa is unexported to that package).
func itoaLocal(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
