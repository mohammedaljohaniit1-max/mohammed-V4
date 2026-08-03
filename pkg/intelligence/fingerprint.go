package intelligence

import (
	"regexp"
	"strings"
)

// Signals is the raw observable input to the fingerprinter. Every field is
// something a passive/light-active phase can collect without exploitation.
// Nil/empty fields are simply skipped.
type Signals struct {
	// Headers is the response header set (canonicalised keys are not required;
	// matching is case-insensitive). Values are the raw header values.
	Headers map[string]string

	// SetCookie is the raw Set-Cookie value(s) joined, inspected for framework
	// session-cookie names (_session_id, PHPSESSID, JSESSIONID, …).
	SetCookie string

	// Body is a bounded slice of a response/JS-bundle/error-page body. The
	// caller is responsible for capping size; the fingerprinter treats it as an
	// opaque string and only runs pre-compiled regexes.
	Body string

	// CertIssuer / CertSubject are TLS certificate metadata strings if available.
	CertIssuer  string
	CertSubject string

	// URL is the request URL that produced these signals (used for protocol and
	// endpoint hints such as /api/graphql).
	URL string
}

// Pre-compiled patterns (mandate §7.2 spirit: pre-compile, never compile in hot
// paths). All matching is case-insensitive.
var (
	reRailsRuntime = regexp.MustCompile(`(?i)^x-runtime$`)
	reRailsCookie  = regexp.MustCompile(`(?i)_session_id=`)
	reDjangoCookie = regexp.MustCompile(`(?i)(csrftoken|sessionid)=`)
	rePHPCookie    = regexp.MustCompile(`(?i)PHPSESSID=`)
	reJavaCookie   = regexp.MustCompile(`(?i)JSESSIONID=`)
	reLaravel      = regexp.MustCompile(`(?i)laravel_session=`)
	reRailsErr     = regexp.MustCompile(`(?i)(actioncontroller|activerecord|<title>action controller)`)
	reDjangoErr    = regexp.MustCompile(`(?i)(django\.core|traceback \(most recent call last\).*\.py)`)
	reSpringErr    = regexp.MustCompile(`(?i)(org\.springframework|whitelabel error page)`)
	reExpressErr   = regexp.MustCompile(`(?i)(cannot get /|at layer\.handle|express)`)
	reGraphQLURL   = regexp.MustCompile(`(?i)/graphql`)
	reGraphQLBody  = regexp.MustCompile(`(?i)"errors"\s*:\s*\[|"data"\s*:\s*\{|graphql`)
	reJWTish       = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*`)
)

// wafSignatures maps a header name (lower) or header-value substring to a WAF
// vendor. Header-name hits are strongest; value substrings are secondary.
var wafHeaderNames = map[string]string{
	"cf-ray":               "Cloudflare",
	"cf-cache-status":      "Cloudflare",
	"x-akamai-transformed": "Akamai",
	"x-iinfo":              "Imperva Incapsula",
	"x-sucuri-id":          "Sucuri",
	"x-amz-cf-id":          "AWS CloudFront",
	"x-fastly-request-id":  "Fastly",
	"x-cache":              "", // ambiguous; only used with a vendor value match
}

var serverWAFHints = []struct {
	needle string
	vendor string
}{
	{"cloudflare", "Cloudflare"},
	{"akamaighost", "Akamai"},
	{"awselb", "AWS ELB"},
	{"cloudfront", "AWS CloudFront"},
	{"fastly", "Fastly"},
	{"imperva", "Imperva"},
	{"incapsula", "Imperva Incapsula"},
	{"sucuri", "Sucuri"},
	{"barracuda", "Barracuda"},
}

// Fingerprint inspects the given signals and emits Discovery records into the
// core via Learn. It returns the list of discoveries it produced (also useful
// for tests). It performs NO network I/O and never panics on malformed input.
func (ic *IntelligenceCore) Fingerprint(s Signals) []Discovery {
	var out []Discovery
	emit := func(kind DiscoveryKind, value, detail string) {
		d := Discovery{Kind: kind, Source: "fingerprint", Value: value, Detail: detail}
		ic.Learn(d)
		out = append(out, d)
	}

	lowerHeaders := lowerKeyMap(s.Headers)

	// --- Server / X-Powered-By raw values ---
	if v := lowerHeaders["server"]; v != "" {
		emit(DiscTech, "server="+v, "Server header")
	}
	if v := lowerHeaders["x-powered-by"]; v != "" {
		emit(DiscTech, "server="+v, "X-Powered-By header")
	}

	// --- Language / framework from headers + cookies + error bodies ---
	lang, langEvidence := detectLanguage(lowerHeaders, s.SetCookie, s.Body)
	if lang != "" {
		emit(DiscTech, "language="+lang, langEvidence)
	}

	// --- WAF / CDN ---
	if vendor, ev := detectWAF(lowerHeaders); vendor != "" {
		emit(DiscWAF, vendor, ev)
	}

	// --- Auth mechanisms ---
	for _, a := range detectAuth(lowerHeaders, s.SetCookie, s.Body) {
		emit(DiscAuth, string(a), "auth signal")
	}

	// --- Protocols ---
	for _, p := range detectProtocols(s.URL, lowerHeaders, s.Body) {
		emit(DiscProtocol, string(p), "protocol signal")
	}

	// --- Infra hints from cert metadata ---
	if infra := detectInfraFromCert(s.CertIssuer, s.CertSubject); infra != "" {
		emit(DiscTech, "infra="+infra, "TLS certificate metadata")
	}

	return out
}

func detectLanguage(h map[string]string, setCookie, body string) (lang, evidence string) {
	// Header-based (strongest).
	for name := range h {
		if reRailsRuntime.MatchString(name) {
			return "ruby_on_rails", "X-Runtime header (Rails)"
		}
	}
	// Cookie-based.
	switch {
	case reRailsCookie.MatchString(setCookie):
		return "ruby_on_rails", "_session_id cookie (Rails)"
	case reLaravel.MatchString(setCookie):
		return "php_laravel", "laravel_session cookie"
	case rePHPCookie.MatchString(setCookie):
		return "php", "PHPSESSID cookie"
	case reJavaCookie.MatchString(setCookie):
		return "java", "JSESSIONID cookie"
	case reDjangoCookie.MatchString(setCookie):
		return "python_django", "csrftoken/sessionid cookie (Django)"
	}
	// Error-page body (secondary, only if nothing stronger matched).
	switch {
	case reRailsErr.MatchString(body):
		return "ruby_on_rails", "Rails error page signature"
	case reDjangoErr.MatchString(body):
		return "python_django", "Django traceback signature"
	case reSpringErr.MatchString(body):
		return "java_spring", "Spring error page signature"
	case reExpressErr.MatchString(body):
		return "nodejs_express", "Express error signature"
	}
	// Header hint: X-AspNet-Version.
	if _, ok := h["x-aspnet-version"]; ok {
		return "dotnet_aspnet", "X-AspNet-Version header"
	}
	return "", ""
}

func detectWAF(h map[string]string) (vendor, evidence string) {
	for name, vend := range wafHeaderNames {
		if _, ok := h[name]; ok && vend != "" {
			return vend, "header " + name + " present"
		}
	}
	// Server header substring hints.
	if srv := h["server"]; srv != "" {
		l := strings.ToLower(srv)
		for _, hint := range serverWAFHints {
			if strings.Contains(l, hint.needle) {
				return hint.vendor, "Server header contains " + hint.needle
			}
		}
	}
	return "", ""
}

func detectAuth(h map[string]string, setCookie, body string) []AuthType {
	set := map[AuthType]bool{}
	if v := h["www-authenticate"]; v != "" {
		l := strings.ToLower(v)
		if strings.Contains(l, "basic") {
			set[AuthBasic] = true
		}
		if strings.Contains(l, "bearer") {
			set[AuthJWT] = true
		}
	}
	if v := h["authorization"]; v != "" && strings.HasPrefix(strings.ToLower(v), "bearer ") {
		set[AuthJWT] = true
	}
	if reJWTish.MatchString(body) || reJWTish.MatchString(setCookie) {
		set[AuthJWT] = true
	}
	if setCookie != "" {
		set[AuthCookie] = true
	}
	// OAuth/OIDC hints from well-known paths surfaced in body/URL are handled by
	// the protocol/endpoint discovery elsewhere; here we only assert what a
	// single response can prove.
	out := make([]AuthType, 0, len(set))
	for a := range set {
		out = append(out, a)
	}
	return out
}

func detectProtocols(url string, h map[string]string, body string) []Protocol {
	set := map[Protocol]bool{}
	if reGraphQLURL.MatchString(url) || reGraphQLBody.MatchString(body) {
		set[ProtoGraphQL] = true
	}
	ct := strings.ToLower(h["content-type"])
	switch {
	case strings.Contains(ct, "application/grpc"):
		set[ProtoGRPC] = true
	case strings.Contains(ct, "text/event-stream"):
		set[ProtoSSE] = true
	case strings.Contains(ct, "application/json") || strings.Contains(ct, "application/xml"):
		set[ProtoREST] = true
	}
	if strings.EqualFold(h["upgrade"], "websocket") {
		set[ProtoWebSocket] = true
	}
	if strings.Contains(strings.ToLower(body), `"jsonrpc"`) {
		set[ProtoJSONRPC] = true
	}
	out := make([]Protocol, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	return out
}

func detectInfraFromCert(issuer, subject string) string {
	l := strings.ToLower(issuer + " " + subject)
	switch {
	case strings.Contains(l, "amazon"):
		return "aws"
	case strings.Contains(l, "google trust services"), strings.Contains(l, "goog"):
		return "gcp"
	case strings.Contains(l, "microsoft"), strings.Contains(l, "azure"):
		return "azure"
	}
	return ""
}

func lowerKeyMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[strings.ToLower(strings.TrimSpace(k))] = v
	}
	return out
}
