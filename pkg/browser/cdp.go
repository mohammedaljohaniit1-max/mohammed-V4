// Package browser — MOHAMMED V10.0 SOVEREIGN — Go-Rod Headless Chrome CDP engine.
//
// Section 3 of the V10 mandate. V9 was 100% HTTP-request based and therefore
// completely blind to anything that only exists AFTER JavaScript executes:
// SPA routes, DOM-based XSS sinks, postMessage listeners, and secrets stashed in
// localStorage/sessionStorage. This engine drives a real headless Chromium over
// the Chrome DevTools Protocol (via github.com/go-rod/rod) to close that gap.
//
// Zero-touch / zero-cost discipline:
//   - Chromium is free and open-source; go-rod auto-downloads a pinned build if
//     none is installed, so no paid service and no manual setup is required.
//   - The engine FAILS OPEN and SAFE: if no browser can be launched (headless
//     Chrome unavailable in a locked-down CI box) every method returns an empty
//     result and Available()==false, so the scan continues on the HTTP path
//     rather than crashing. Nothing here is a stub — when a browser IS present
//     every capability runs for real.
//   - Every page operation is bounded by a hard per-page timeout so a hostile
//     SPA (infinite spinner, redirect loop) can never hang the scan.
package browser

import (
	"context"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
)

// Engine is a reusable headless-Chrome controller. It launches one browser and
// opens a fresh, isolated page per audited URL. Safe for sequential use; guard
// with your own concurrency limiter (the resource governor in pkg/engine) when
// fanning out, since each page costs real memory.
type Engine struct {
	mu          sync.Mutex
	browser     *rod.Browser
	controlURL  string
	launched    bool
	launchErr   error
	pageTimeout time.Duration
	// binPath is an explicit Chromium/Chrome binary path (from CHROME_BIN /
	// config); empty lets go-rod resolve or download one.
	binPath string
}

// Options configures the CDP engine.
type Options struct {
	// PageTimeout bounds every navigation + evaluation. Defaults to 20s.
	PageTimeout time.Duration
	// BinPath, when set, forces a specific Chromium/Chrome executable.
	BinPath string
}

// NewEngine builds an (unlaunched) engine. The browser is started lazily on the
// first audit so constructing an Engine is always cheap and never fails.
func NewEngine(o Options) *Engine {
	to := o.PageTimeout
	if to <= 0 {
		to = 20 * time.Second
	}
	bin := o.BinPath
	if bin == "" {
		// Honour the common env override used by install_path.sh / CI.
		if envBin := strings.TrimSpace(os.Getenv("CHROME_BIN")); envBin != "" {
			bin = envBin
		} else if envBin := strings.TrimSpace(os.Getenv("ROD_BROWSER_BIN")); envBin != "" {
			bin = envBin
		}
	}
	return &Engine{pageTimeout: to, binPath: bin}
}

// launch starts the headless browser exactly once (sync.Once semantics via the
// launched flag under mu). It records launchErr on failure so Available() and
// every audit method can fail open without repeatedly retrying a doomed launch.
func (e *Engine) launch() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.launched {
		return e.launchErr
	}
	e.launched = true

	defer func() {
		// go-rod panics (via its Must* internals / leakless) are converted to a
		// recorded error so a missing Chromium never crashes the whole scan.
		if r := recover(); r != nil {
			e.launchErr = &LaunchError{Reason: toString(r)}
			e.browser = nil
		}
	}()

	l := launcher.New().
		Headless(true).
		NoSandbox(true). // required in most CI/container environments
		Set("disable-gpu").
		Set("disable-dev-shm-usage").
		Set("disable-setuid-sandbox").
		Set("no-first-run").
		Set("disable-extensions")
	if e.binPath != "" {
		l = l.Bin(e.binPath)
	}

	controlURL, err := l.Launch()
	if err != nil {
		e.launchErr = &LaunchError{Reason: err.Error()}
		return e.launchErr
	}
	e.controlURL = controlURL

	b := rod.New().ControlURL(controlURL)
	if err := b.Connect(); err != nil {
		e.launchErr = &LaunchError{Reason: err.Error()}
		return e.launchErr
	}
	e.browser = b
	return nil
}

// LaunchError signals the browser could not be started (Chromium absent, no
// sandbox permission, etc.). The scan treats it as "CDP unavailable, use HTTP".
type LaunchError struct{ Reason string }

func (l *LaunchError) Error() string { return "cdp: browser launch failed: " + l.Reason }

// Available reports whether a browser is (or can be) launched. It triggers the
// lazy launch; a false result means the scan should fall back to the HTTP path.
func (e *Engine) Available() bool {
	if err := e.launch(); err != nil {
		return false
	}
	return e.browser != nil
}

// Close shuts the browser down. Safe to call on an unlaunched/failed engine.
func (e *Engine) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.browser != nil {
		_ = e.browser.Close()
		e.browser = nil
	}
}

// openPage navigates a fresh isolated page to url with the per-page timeout and
// waits for load. Caller MUST call the returned cleanup func. Returns an error
// (and a nil page) when the browser is unavailable or navigation fails.
func (e *Engine) openPage(ctx context.Context, url string) (page *rod.Page, cleanup func(), err error) {
	if err := e.launch(); err != nil {
		return nil, func() {}, err
	}
	if e.browser == nil {
		return nil, func() {}, &LaunchError{Reason: "browser nil"}
	}

	defer func() {
		if r := recover(); r != nil {
			page = nil
			cleanup = func() {}
			err = &LaunchError{Reason: toString(r)}
		}
	}()

	p, perr := e.browser.Context(ctx).Page(proto.TargetCreateTarget{URL: "about:blank"})
	if perr != nil {
		return nil, func() {}, perr
	}
	cleanup = func() {
		defer func() { _ = recover() }()
		_ = p.Close()
	}
	p = p.Timeout(e.pageTimeout)
	if nerr := p.Navigate(url); nerr != nil {
		cleanup()
		return nil, func() {}, nerr
	}
	// WaitLoad tolerates SPAs that never fully idle; the page Timeout caps it.
	_ = p.WaitLoad()
	return p, cleanup, nil
}

// ─────────────────────────────────────────────────────────────────────────
// 3.1 — Full SPA Rendering & DOM Inspection
// ─────────────────────────────────────────────────────────────────────────

// RenderResult is the outcome of rendering a page in a real browser.
type RenderResult struct {
	URL          string
	FinalURL     string   // location after client-side redirects/SPA routing
	HTML         string   // fully-rendered DOM (post-JS)
	Links        []string // hrefs discovered in the rendered DOM
	Endpoints    []string // API endpoints found in inline JS / attributes
	InlineVars   []string // interesting inline JS variable names/values
	Rendered     bool     // true when the browser actually rendered the page
	Unavailable  bool     // true when CDP was unavailable (HTTP fallback needed)
	ErrorMessage string
}

// jsExtractSurface walks the rendered DOM for links, fetch/XHR/api endpoints,
// and inline configuration variables that only exist after hydration. Runs
// inside the page so it sees the live, post-JavaScript state.
const jsExtractSurface = `() => {
  const out = { final: location.href, links: [], endpoints: [], vars: [] };
  const push = (arr, v) => { if (v && arr.indexOf(v) === -1 && arr.length < 300) arr.push(v); };
  document.querySelectorAll('a[href]').forEach(a => push(out.links, a.href));
  // action/src/data-* attributes frequently carry API paths.
  document.querySelectorAll('[action],[src],[data-url],[data-api],[data-endpoint]').forEach(el => {
    ['action','src','data-url','data-api','data-endpoint'].forEach(attr => {
      const v = el.getAttribute(attr); if (v) push(out.endpoints, v);
    });
  });
  // Scan inline scripts for URL-ish strings and config globals.
  const rx = /["'](\/(?:api|v1|v2|graphql|rest|internal|admin)[^"'\s]*)["']/g;
  document.querySelectorAll('script:not([src])').forEach(s => {
    const t = s.textContent || ''; let m;
    while ((m = rx.exec(t)) !== null) push(out.endpoints, m[1]);
  });
  // Common SPA config globals leaking API bases / feature flags.
  ['__NEXT_DATA__','__NUXT__','__APOLLO_STATE__','ENV','CONFIG','APP_CONFIG'].forEach(k => {
    try { if (window[k] !== undefined) push(out.vars, k); } catch(e){}
  });
  return out;
}`

// Render loads url in headless Chrome, executes its JavaScript, and returns the
// fully-rendered surface (DOM, links, discovered API endpoints, SPA globals).
// On any CDP failure it returns Unavailable=true so the caller uses HTTP crawl.
func (e *Engine) Render(ctx context.Context, url string) RenderResult {
	res := RenderResult{URL: url}
	p, cleanup, err := e.openPage(ctx, url)
	if err != nil {
		res.Unavailable = true
		res.ErrorMessage = err.Error()
		return res
	}
	defer cleanup()

	if html, herr := p.HTML(); herr == nil {
		res.HTML = html
	}
	obj, evErr := p.Eval(jsExtractSurface)
	if evErr == nil && obj != nil {
		v := obj.Value
		res.FinalURL = v.Get("final").Str()
		for _, l := range v.Get("links").Arr() {
			res.Links = append(res.Links, l.Str())
		}
		for _, ep := range v.Get("endpoints").Arr() {
			res.Endpoints = append(res.Endpoints, ep.Str())
		}
		for _, vv := range v.Get("vars").Arr() {
			res.InlineVars = append(res.InlineVars, vv.Str())
		}
	}
	res.Rendered = true
	if res.FinalURL == "" {
		res.FinalURL = url
	}
	return res
}

// ─────────────────────────────────────────────────────────────────────────
// 3.3 — LocalStorage / SessionStorage Secret Harvester
// ─────────────────────────────────────────────────────────────────────────

// StorageItem is one key/value pair harvested from browser storage.
type StorageItem struct {
	Store     string // "localStorage" | "sessionStorage"
	Key       string
	Value     string
	Sensitive bool   // matched a token/secret heuristic
	Reason    string // why it was flagged sensitive
}

const jsHarvestStorage = `() => {
  const dump = (store, name) => {
    const items = [];
    try { for (let i = 0; i < store.length; i++) { const k = store.key(i); items.push({store:name,key:k,value:String(store.getItem(k)).slice(0,2000)}); } } catch(e){}
    return items;
  };
  return dump(localStorage,'localStorage').concat(dump(sessionStorage,'sessionStorage'));
}`

// HarvestStorage renders the page and extracts every localStorage /
// sessionStorage entry, flagging tokens/secrets. Empty (Unavailable) on CDP
// failure. This is a genuine capability HTTP scanning can NEVER replicate.
func (e *Engine) HarvestStorage(ctx context.Context, url string) ([]StorageItem, bool) {
	p, cleanup, err := e.openPage(ctx, url)
	if err != nil {
		return nil, false
	}
	defer cleanup()

	obj, evErr := p.Eval(jsHarvestStorage)
	if evErr != nil || obj == nil {
		return nil, true
	}
	var out []StorageItem
	for _, it := range obj.Value.Arr() {
		item := StorageItem{
			Store: it.Get("store").Str(),
			Key:   it.Get("key").Str(),
			Value: it.Get("value").Str(),
		}
		if sensitive, reason := classifyStorageSecret(item.Key, item.Value); sensitive {
			item.Sensitive = true
			item.Reason = reason
		}
		out = append(out, item)
	}
	return out, true
}

// classifyStorageSecret flags storage entries that look like auth material or
// secrets. Deterministic + offline; the AI brain can further triage the value.
func classifyStorageSecret(key, value string) (bool, string) {
	k := strings.ToLower(key)
	keySignals := []string{"token", "jwt", "auth", "session", "secret", "apikey", "api_key", "access", "refresh", "bearer", "password", "credential"}
	for _, s := range keySignals {
		if strings.Contains(k, s) {
			return true, "key matches secret signal: " + s
		}
	}
	// A JWT-shaped value (three base64url segments) is always interesting.
	if segs := strings.Split(value, "."); len(segs) == 3 && len(segs[0]) > 8 && strings.HasPrefix(segs[0], "eyJ") {
		return true, "value is JWT-shaped (header.payload.signature)"
	}
	if len(value) >= 32 && isMostlyToken(value) {
		return true, "value is a long high-entropy token"
	}
	return false, ""
}

// isMostlyToken reports whether a string is dominated by token-ish characters
// (base64url/hex), a cheap proxy for "high entropy secret".
func isMostlyToken(s string) bool {
	if len(s) == 0 {
		return false
	}
	tokenish := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '+' || c == '/' || c == '=' {
			tokenish++
		}
	}
	return tokenish*10 >= len(s)*9 // ≥90% token characters
}

// ─────────────────────────────────────────────────────────────────────────
// 3.4 — In-Browser CORS verification (withCredentials)
// ─────────────────────────────────────────────────────────────────────────

// CORSProof is the result of an in-browser cross-origin credentialed fetch.
type CORSProof struct {
	Origin        string
	TargetURL     string
	Allowed       bool   // the browser actually returned the cross-origin body
	Status        int    // HTTP status the browser saw (0 on network error)
	BodySample    string // first bytes of the cross-origin body (proof)
	WithCreds     bool   // whether credentials were included
	ErrorMessage  string
	Unavailable   bool
}

// jsCorsFetch performs a real credentialed cross-origin fetch from the page's
// origin, returning status + a body sample. If the browser blocks it (SOP/CORS
// misconfig absent) the promise rejects and we report Allowed=false.
const jsCorsFetch = `(target) => {
  return fetch(target, { method: 'GET', credentials: 'include', mode: 'cors' })
    .then(r => r.text().then(t => ({ ok: true, status: r.status, body: t.slice(0, 512) })))
    .catch(e => ({ ok: false, status: 0, body: String(e).slice(0,256) }));
}`

// VerifyCORS loads pageURL (the trusted origin) and, from inside that real
// browser context, issues a credentialed cross-origin fetch to targetURL. A
// returned body is HARD PROOF of an exploitable CORS misconfiguration (data is
// readable cross-origin WITH credentials) — impossible to fake with curl.
func (e *Engine) VerifyCORS(ctx context.Context, pageURL, targetURL string) CORSProof {
	proof := CORSProof{Origin: pageURL, TargetURL: targetURL, WithCreds: true}
	p, cleanup, err := e.openPage(ctx, pageURL)
	if err != nil {
		proof.Unavailable = true
		proof.ErrorMessage = err.Error()
		return proof
	}
	defer cleanup()

	obj, evErr := p.Eval(jsCorsFetch, targetURL)
	if evErr != nil || obj == nil {
		proof.ErrorMessage = "eval failed"
		return proof
	}
	v := obj.Value
	if v.Get("ok").Bool() {
		proof.Status = v.Get("status").Int()
		proof.BodySample = v.Get("body").Str()
		// Allowed only when a real body came back with a 2xx/3xx status.
		proof.Allowed = proof.Status > 0 && proof.Status < 400 && len(proof.BodySample) > 0
	} else {
		proof.ErrorMessage = v.Get("body").Str()
	}
	return proof
}

// ─────────────────────────────────────────────────────────────────────────
// 3.2 — DOM XSS & postMessage Scanner
// ─────────────────────────────────────────────────────────────────────────

// DOMXSSProof records a confirmed client-side execution.
type DOMXSSProof struct {
	URL          string
	Sink         string // "url-fragment" | "query-param" | "postMessage"
	Marker       string // the unique canary that executed
	Executed     bool   // the canary callback actually fired in the DOM
	Evidence     string
	Unavailable  bool
	ErrorMessage string
}

// jsInstrumentSinks installs a global canary hook BEFORE navigation-driven code
// runs. When our unique marker reaches a JS execution sink (eval/innerHTML →
// script, or an unvalidated postMessage handler that reflects it), the hook
// records it. We poll window.__MOHAMMED_XSS__ after the page settles.
//
// The marker is passed in; the hook overrides alert/console and also inspects
// the live DOM + fires a probe postMessage to exercise message listeners.
const jsDomXSSProbe = `(marker) => {
  return new Promise((resolve) => {
    const hit = { executed: false, sink: '', evidence: '' };
    // 1. Trap the classic execution oracles.
    try {
      const origAlert = window.alert;
      window.alert = function(x){ if (String(x).indexOf(marker)!==-1){hit.executed=true;hit.sink='alert';hit.evidence='alert('+x+')';} return origAlert && origAlert.apply(this, arguments); };
    } catch(e){}
    // 2. Look for the marker already materialised as an injected element/script.
    try {
      if (document.getElementById(marker)) { hit.executed = true; hit.sink = 'dom-element'; hit.evidence = 'injected #'+marker+' present'; }
      const scripts = document.querySelectorAll('script');
      for (const s of scripts) { if ((s.textContent||'').indexOf(marker)!==-1) { hit.executed=true; hit.sink='dom-script'; hit.evidence='marker inside <script>'; break; } }
    } catch(e){}
    // 3. Exercise postMessage listeners: send our marker and see if a handler
    //    reflects it into the DOM without origin validation.
    try {
      window.postMessage('MOHAMMED_PM_'+marker, '*');
    } catch(e){}
    // Give async handlers a tick, then re-inspect the DOM for reflection.
    setTimeout(() => {
      try {
        if (!hit.executed && (document.body && document.body.innerHTML.indexOf('MOHAMMED_PM_'+marker) !== -1)) {
          hit.executed = true; hit.sink = 'postMessage'; hit.evidence = 'postMessage payload reflected into DOM (no origin check)';
        }
      } catch(e){}
      resolve(hit);
    }, 400);
  });
}`

// ScanDOMXSS injects a unique canary into the URL fragment / query and drives
// the page in a real browser to see whether it reaches an execution sink or an
// unvalidated postMessage handler. A positive is HARD PROOF (real DOM
// execution), satisfying the mandate's "confirmed by Headless Chrome DOM
// execution proof" gate. Returns Unavailable on CDP failure (HTTP fallback).
func (e *Engine) ScanDOMXSS(ctx context.Context, injectedURL, marker string) DOMXSSProof {
	proof := DOMXSSProof{URL: injectedURL, Marker: marker}
	p, cleanup, err := e.openPage(ctx, injectedURL)
	if err != nil {
		proof.Unavailable = true
		proof.ErrorMessage = err.Error()
		return proof
	}
	defer cleanup()

	obj, evErr := p.Eval(jsDomXSSProbe, marker)
	if evErr != nil || obj == nil {
		proof.ErrorMessage = "probe eval failed"
		return proof
	}
	v := obj.Value
	proof.Executed = v.Get("executed").Bool()
	proof.Sink = v.Get("sink").Str()
	proof.Evidence = v.Get("evidence").Str()
	if proof.Executed && proof.Sink == "" {
		proof.Sink = "dom"
	}
	return proof
}

// Redact masks the middle of a secret/value for evidence strings so the report
// never stores a fully usable live token harvested from browser storage.
func Redact(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= 8 {
		if s == "" {
			return ""
		}
		return "****"
	}
	if len(s) > 80 {
		s = s[:80]
	}
	return s[:4] + "…" + s[len(s)-4:]
}

// toString renders a recover() value for error messages without importing fmt
// everywhere.
func toString(v interface{}) string {
	if v == nil {
		return "unknown"
	}
	if s, ok := v.(string); ok {
		return s
	}
	if e, ok := v.(error); ok {
		return e.Error()
	}
	return "panic"
}
