// Package correlation implements the V7 (Section 3) Phase 45 Smart Correlation
// Engine. Individual phases each report atomic findings; a real attack surface
// engine is worth more than the sum of those findings when it can chain them.
// This engine reads the flat finding list, groups by host, and applies a set
// of deterministic correlation rules that promote a *combination* of low/medium
// findings into a single high-severity attack chain — the kind of insight a
// human triager produces and V6 never did.
//
// The engine is pure: it takes []map[string]interface{} (the engine.State
// findings shape) and returns new correlation findings. It never mutates the
// inputs and imports nothing from pkg/engine, so it is unit-testable in
// isolation.
package correlation

import (
	"sort"
	"strings"
)

// Finding is the loosely-typed finding shape used across MOHAMMED. The engine
// only reads a handful of well-known keys ("type", "severity", "url",
// "target", "evidence").
type Finding = map[string]interface{}

// Chain is a correlated multi-finding attack path.
type Chain struct {
	Host       string
	Title      string
	Severity   string
	Confidence string
	Components []string // the finding types that formed the chain
	Evidence   string
	URLs       []string
}

// Engine correlates findings into attack chains.
type Engine struct {
	rules []rule
}

// New builds a correlation engine with the built-in rule set.
func New() *Engine {
	return &Engine{rules: builtinRules()}
}

// Correlate groups findings by host and evaluates every rule against each
// group, returning the chains that fired. Deterministic ordering (host, then
// title) makes the output stable for tests and diffs.
func (e *Engine) Correlate(findings []Finding) []Chain {
	byHost := groupByHost(findings)
	var chains []Chain
	hosts := make([]string, 0, len(byHost))
	for h := range byHost {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	for _, h := range hosts {
		group := byHost[h]
		idx := indexByType(group)
		for _, r := range e.rules {
			if c, ok := r.eval(h, idx); ok {
				chains = append(chains, c)
			}
		}
	}
	sort.SliceStable(chains, func(i, j int) bool {
		if chains[i].Host != chains[j].Host {
			return chains[i].Host < chains[j].Host
		}
		return chains[i].Title < chains[j].Title
	})
	return chains
}

// AsFindings turns chains into the standard finding map shape so they can be
// appended to engine.State.Findings and flow through the normal reporter.
func (e *Engine) AsFindings(chains []Chain) []Finding {
	out := make([]Finding, 0, len(chains))
	for _, c := range chains {
		out = append(out, Finding{
			"type":        "Correlated Attack Chain",
			"chain_title": c.Title,
			"severity":    c.Severity,
			"confidence":  c.Confidence,
			"target":      c.Host,
			"components":  strings.Join(c.Components, " + "),
			"evidence":    c.Evidence,
			"urls":        strings.Join(c.URLs, ", "),
			"phase":       "V7-correlation",
		})
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────────────
// rule engine
// ─────────────────────────────────────────────────────────────────────────────

// typeIndex maps a normalized finding-type substring to the findings that
// matched it on a single host.
type typeIndex map[string][]Finding

// rule evaluates one correlation pattern on a host's finding index.
type rule struct {
	name string
	eval func(host string, idx typeIndex) (Chain, bool)
}

// has reports whether the index contains any finding whose type contains any of
// the given substrings (case-insensitive), returning the first matching URL.
func (idx typeIndex) has(substrs ...string) (Finding, bool) {
	for key, fs := range idx {
		for _, sub := range substrs {
			if strings.Contains(key, sub) && len(fs) > 0 {
				return fs[0], true
			}
		}
	}
	return nil, false
}

func urlOf(f Finding) string {
	if u, ok := f["url"].(string); ok {
		return u
	}
	return ""
}
func evidenceOf(f Finding) string {
	if e, ok := f["evidence"].(string); ok {
		return e
	}
	return ""
}

// builtinRules encodes the correlation knowledge. Each rule requires TWO or
// more independent finding types on the same host and promotes the combination.
func builtinRules() []rule {
	return []rule{
		// 1. Session theft chain: an XSS/reflection + a session cookie missing
		//    HttpOnly means the token is directly stealable.
		{
			name: "session-theft",
			eval: func(host string, idx typeIndex) (Chain, bool) {
				xss, ok1 := idx.has("xss", "reflect", "header injection")
				cookie, ok2 := idx.has("session", "cookie")
				if !ok1 || !ok2 {
					return Chain{}, false
				}
				return Chain{
					Host: host, Title: "XSS → Session Hijack",
					Severity: "Critical", Confidence: "high",
					Components: []string{"XSS/Reflection", "Weak Session Cookie"},
					Evidence:   "Reflected script execution combined with a session cookie lacking HttpOnly permits direct token theft: " + evidenceOf(xss) + " | " + evidenceOf(cookie),
					URLs:       dedupeURLs(urlOf(xss), urlOf(cookie)),
				}, true
			},
		},
		// 2. Account-takeover chain: IDOR/BOLA + missing auth on a mutating verb
		//    lets an attacker both read and write other users' objects.
		{
			name: "account-takeover",
			eval: func(host string, idx typeIndex) (Chain, bool) {
				idor, ok1 := idx.has("idor", "bola")
				verb, ok2 := idx.has("verb-tampering", "mass-assignment")
				if !ok1 || !ok2 {
					return Chain{}, false
				}
				return Chain{
					Host: host, Title: "IDOR/BOLA → Account Takeover",
					Severity: "Critical", Confidence: "high",
					Components: []string{"IDOR/BOLA", "Write Authorization Gap"},
					Evidence:   "Cross-object read via IDOR/BOLA combined with an accepted mutating request enables full account takeover: " + evidenceOf(idor) + " | " + evidenceOf(verb),
					URLs:       dedupeURLs(urlOf(idor), urlOf(verb)),
				}, true
			},
		},
		// 3. RCE-likely chain: SSTI on a host that also leaks a stack/tech
		//    fingerprint raises the confidence of template RCE.
		{
			name: "ssti-rce",
			eval: func(host string, idx typeIndex) (Chain, bool) {
				ssti, ok := idx.has("ssti")
				if !ok {
					return Chain{}, false
				}
				sev := "High"
				comps := []string{"SSTI"}
				ev := evidenceOf(ssti)
				if fp, ok2 := idx.has("tech", "fingerprint", "version"); ok2 {
					sev = "Critical"
					comps = append(comps, "Tech Fingerprint")
					ev += " | server tech disclosed: " + evidenceOf(fp)
				}
				return Chain{
					Host: host, Title: "SSTI → Template RCE",
					Severity: sev, Confidence: "high",
					Components: comps,
					Evidence:   "Server-side template injection confirmed via arithmetic oracle" + tail(ev),
					URLs:       dedupeURLs(urlOf(ssti)),
				}, true
			},
		},
		// 4. Full-read SSRF chain: SSRF + cloud infra finding = metadata theft.
		{
			name: "ssrf-metadata",
			eval: func(host string, idx typeIndex) (Chain, bool) {
				ssrf, ok1 := idx.has("ssrf")
				cloud, ok2 := idx.has("cloud", "metadata", "s3", "bucket")
				if !ok1 || !ok2 {
					return Chain{}, false
				}
				return Chain{
					Host: host, Title: "SSRF → Cloud Metadata Exposure",
					Severity: "Critical", Confidence: "high",
					Components: []string{"SSRF", "Cloud Infrastructure"},
					Evidence:   "SSRF on a cloud-hosted target enables metadata/credential theft: " + evidenceOf(ssrf) + " | " + evidenceOf(cloud),
					URLs:       dedupeURLs(urlOf(ssrf), urlOf(cloud)),
				}, true
			},
		},
		// 5. Payment-abuse chain: business-logic price tampering + race condition
		//    on the same host = repeatable financial abuse.
		{
			name: "payment-abuse",
			eval: func(host string, idx typeIndex) (Chain, bool) {
				biz, ok1 := idx.has("business-logic", "price")
				race, ok2 := idx.has("race")
				if !ok1 || !ok2 {
					return Chain{}, false
				}
				return Chain{
					Host: host, Title: "Price Tampering + Race → Financial Abuse",
					Severity: "Critical", Confidence: "high",
					Components: []string{"Business Logic", "Race Condition"},
					Evidence:   "Price/role parameter tampering combined with a TOCTOU race allows repeatable financial abuse: " + evidenceOf(biz) + " | " + evidenceOf(race),
					URLs:       dedupeURLs(urlOf(biz), urlOf(race)),
				}, true
			},
		},
		// 6. Forged-auth chain: a JWT alg=none/empty-sig on a host exposing an
		//    API surface means the whole API is forgeable.
		{
			name: "jwt-api-forge",
			eval: func(host string, idx typeIndex) (Chain, bool) {
				jwt, ok1 := idx.has("jwt-alg-none", "jwt-empty-sig")
				api, ok2 := idx.has("graphql", "bola", "verb-tampering", "api-version-bypass")
				if !ok1 || !ok2 {
					return Chain{}, false
				}
				return Chain{
					Host: host, Title: "Forgeable JWT → API Compromise",
					Severity: "Critical", Confidence: "high",
					Components: []string{"JWT Signature Bypass", "Exposed API"},
					Evidence:   "A forgeable JWT combined with a reachable API surface allows authenticated-as-anyone API access: " + evidenceOf(jwt) + " | " + evidenceOf(api),
					URLs:       dedupeURLs(urlOf(jwt), urlOf(api)),
				}, true
			},
		},
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// helpers
// ─────────────────────────────────────────────────────────────────────────────

func groupByHost(findings []Finding) map[string][]Finding {
	out := make(map[string][]Finding)
	for _, f := range findings {
		h := hostOf(f)
		if h == "" {
			continue
		}
		out[h] = append(out[h], f)
	}
	return out
}

func indexByType(group []Finding) typeIndex {
	idx := make(typeIndex)
	for _, f := range group {
		t := strings.ToLower(strFrom(f, "type"))
		// Also index by the api sub-class and chain title fields when present.
		keys := []string{t}
		if sub := strings.ToLower(strFrom(f, "class")); sub != "" {
			keys = append(keys, sub)
		}
		for _, k := range keys {
			if k == "" {
				continue
			}
			idx[k] = append(idx[k], f)
		}
	}
	return idx
}

func hostOf(f Finding) string {
	if t := strFrom(f, "target"); t != "" {
		return normHost(t)
	}
	if u := strFrom(f, "url"); u != "" {
		return normHost(hostFromURL(u))
	}
	return ""
}

func strFrom(f Finding, key string) string {
	if v, ok := f[key].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

func normHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.TrimPrefix(h, "www.")
	return h
}

func hostFromURL(rawURL string) string {
	s := rawURL
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/:?#"); i >= 0 {
		s = s[:i]
	}
	return s
}

func dedupeURLs(urls ...string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, u := range urls {
		u = strings.TrimSpace(u)
		if u == "" || seen[u] {
			continue
		}
		seen[u] = true
		out = append(out, u)
	}
	return out
}

func tail(ev string) string {
	if strings.TrimSpace(ev) == "" {
		return ""
	}
	return ": " + ev
}
