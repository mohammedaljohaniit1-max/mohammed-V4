package config

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// ═══════════════════════════════════════════════════════════════
// Config & Scope
// ═══════════════════════════════════════════════════════════════

type Config struct {
	ScopeFile  string
	Profile    string
	BurpProxy  string
	OutputDir  string
	Threads    int
	RateLimit  int
	SkipPhases int
	Verbose    bool
	Debug      bool
	APIKeys    APIKeys
	Ollama     OllamaConfig

	// Zero-false-positive controls (FIX #5/#1/#2/#7).
	SelectiveProxyRouting          bool
	StripCloudflareParams          bool
	EnforceScopeOnJS               bool
	RequireConfirmationForCritical bool
	WAFBypass                      bool // --waf-bypass (Genius #4)
}

type APIKeys struct {
	GitHub         string `yaml:"github"`
	Shodan         string `yaml:"shodan"`
	VirusTotal     string `yaml:"virustotal"`
	AlienVault     string `yaml:"alienvault"`
	SecurityTrails string `yaml:"securitytrails"`
	Chaos          string `yaml:"chaos"`
	Censys         string `yaml:"censys"`
	HaveIBeenPwned string `yaml:"haveibeenpwned"`
}

type OllamaConfig struct {
	Enabled     bool    `yaml:"enabled"`
	Endpoint    string  `yaml:"endpoint"`
	Model       string  `yaml:"model"`
	Temperature float64 `yaml:"temperature"`
	Timeout     int     `yaml:"timeout"`
}

// ProxyConfig controls the two-tier Burp routing (FIX #5).
type ProxyConfig struct {
	// SelectiveRouting turns on the Tier-1 (direct) / Tier-2 (Burp) split.
	SelectiveRouting bool `yaml:"selective_routing"`
}

// FilterConfig controls the zero-false-positive filtering (FIX #1/#2).
type FilterConfig struct {
	StripCloudflareParams bool `yaml:"strip_cloudflare_params"`
	EnforceScopeOnJS      bool `yaml:"enforce_scope_on_js"`
}

// AIExtra holds the require-confirmation-for-critical toggle (FIX #7). It is
// separate from OllamaConfig so the existing ollama block is untouched.
type AIExtra struct {
	RequireConfirmationForCritical bool `yaml:"require_confirmation_for_critical"`
}

type YAMLConfig struct {
	APIKeys APIKeys      `yaml:"api_keys"`
	Ollama  OllamaConfig `yaml:"ollama"`
	Proxy   ProxyConfig  `yaml:"proxy"`
	Filter  FilterConfig `yaml:"filter"`
	AIExtra AIExtra      `yaml:"ai"`
}

func LoadYAMLConfig(path string) (*YAMLConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		cfg := &YAMLConfig{}
		// Still resolve environment variables so a run with NO config.yaml can
		// operate purely on exported keys (EXPANSION 1, Tier 1).
		cfg.APIKeys = ResolveAPIKeys(cfg.APIKeys)
		cfg.Ollama.Endpoint = "http://127.0.0.1:11434"
		cfg.Ollama.Model = "gemma:2b"
		cfg.Ollama.Timeout = 15
		return cfg, nil
	}
	var cfg YAMLConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("config parse error: %w", err)
	}
	// Sensible defaults so the AI layer never panics on empty config.
	if cfg.Ollama.Endpoint == "" {
		cfg.Ollama.Endpoint = "http://127.0.0.1:11434"
	}
	if cfg.Ollama.Model == "" {
		cfg.Ollama.Model = "gemma:2b"
	}
	if cfg.Ollama.Timeout <= 0 {
		cfg.Ollama.Timeout = 15
	}
	// EXPANSION 1 — apply the 3-tier API-key precedence: OS environment
	// variables (Tier 1) override the config.yaml values (Tier 2). Sources with
	// neither fall through to the native key-less scrapers (Tier 3) at runtime.
	cfg.APIKeys = ResolveAPIKeys(cfg.APIKeys)
	return &cfg, nil
}

// ═══════════════════════════════════════════════════════════════
// EXPANSION 1 — 3-TIER API KEY PRECEDENCE & AUTO-SYNC
//
//	TIER 1 (highest): OS environment variables (export SHODAN_API_KEY=…)
//	         ↓
//	TIER 2 (secondary): config.yaml api_keys block
//	         ↓
//	TIER 3 (fallback): native key-less public scrapers (handled at scan time)
//
// ResolveAPIKeys returns a copy of base with any environment variable that is
// set taking precedence over the config-file value. An empty environment
// variable never clobbers a non-empty config value.
// ═══════════════════════════════════════════════════════════════
func ResolveAPIKeys(base APIKeys) APIKeys {
	pick := func(env, cfgVal string) string {
		if v := strings.TrimSpace(os.Getenv(env)); v != "" {
			return v
		}
		return cfgVal
	}
	return APIKeys{
		Shodan:         pick("SHODAN_API_KEY", base.Shodan),
		VirusTotal:     pick("VIRUSTOTAL_API_KEY", base.VirusTotal),
		SecurityTrails: pick("SECURITYTRAILS_API_KEY", base.SecurityTrails),
		Chaos:          pick("CHAOS_API_KEY", base.Chaos),
		GitHub:         pick("GITHUB_TOKEN", base.GitHub),
		AlienVault:     pick("ALIENVAULT_API_KEY", base.AlienVault),
		Censys:         pick("CENSYS_API_KEY", base.Censys),
		HaveIBeenPwned: pick("HIBP_API_KEY", base.HaveIBeenPwned),
	}
}

// ActiveKeyNames lists (for logging) the API-key sources that resolved to a
// non-empty value after the 3-tier merge. It never prints the key material.
func ActiveKeyNames(k APIKeys) []string {
	var out []string
	add := func(name, val string) {
		if strings.TrimSpace(val) != "" {
			out = append(out, name)
		}
	}
	add("shodan", k.Shodan)
	add("virustotal", k.VirusTotal)
	add("securitytrails", k.SecurityTrails)
	add("chaos", k.Chaos)
	add("github", k.GitHub)
	add("alienvault", k.AlienVault)
	add("censys", k.Censys)
	return out
}

// SyncProviderConfigs writes the active API keys into the on-disk config files
// that the external CLI tools read on their own (subfinder + amass), so a key
// exported once via the environment automatically reaches every downstream
// tool without the user editing multiple files (EXPANSION 1 auto-sync).
//
// It returns the list of files it created/updated. Failures are collected in
// err but never abort the scan (best-effort convenience).
func SyncProviderConfigs(k APIKeys) (written []string, err error) {
	home := os.Getenv("HOME")
	if home == "" {
		return nil, fmt.Errorf("HOME not set; cannot sync provider configs")
	}
	var errs []string

	// ── subfinder provider-config.yaml ────────────────────────────────
	if p, e := syncSubfinderProviders(home, k); e != nil {
		errs = append(errs, e.Error())
	} else if p != "" {
		written = append(written, p)
	}

	// ── amass config.ini data-source keys ─────────────────────────────
	if p, e := syncAmassKeys(home, k); e != nil {
		errs = append(errs, e.Error())
	} else if p != "" {
		written = append(written, p)
	}

	if len(errs) > 0 {
		return written, fmt.Errorf("provider sync warnings: %s", strings.Join(errs, "; "))
	}
	return written, nil
}

// syncSubfinderProviders writes ~/.config/subfinder/provider-config.yaml with
// the active keys. subfinder reads this file automatically on every run.
func syncSubfinderProviders(home string, k APIKeys) (string, error) {
	if k.Shodan == "" && k.VirusTotal == "" && k.SecurityTrails == "" &&
		k.Chaos == "" && k.GitHub == "" && k.Censys == "" {
		return "", nil // nothing to sync — leave any user file untouched
	}
	dir := filepath.Join(home, ".config", "subfinder")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "provider-config.yaml")

	var b strings.Builder
	b.WriteString("# Auto-generated by MOHAMMED (EXPANSION 1 auto-sync).\n")
	b.WriteString("# Keys resolved via 3-tier precedence: env > config.yaml.\n")
	writeList := func(name, val string) {
		if strings.TrimSpace(val) == "" {
			return
		}
		b.WriteString(fmt.Sprintf("%s:\n  - %s\n", name, val))
	}
	writeList("shodan", k.Shodan)
	writeList("virustotal", k.VirusTotal)
	writeList("securitytrails", k.SecurityTrails)
	writeList("chaos", k.Chaos)
	writeList("github", k.GitHub)
	writeList("censys", k.Censys)

	if err := os.WriteFile(path, []byte(b.String()), 0600); err != nil {
		return "", err
	}
	return path, nil
}

// syncAmassKeys merges the active keys into ~/.config/amass/config.ini. It
// preserves the free-source scaffold and appends [data_sources.<X>] apikey
// stanzas for every key that is set.
func syncAmassKeys(home string, k APIKeys) (string, error) {
	if k.Shodan == "" && k.VirusTotal == "" && k.SecurityTrails == "" &&
		k.Chaos == "" && k.Censys == "" {
		return "", nil
	}
	dir := filepath.Join(home, ".config", "amass")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "config.ini")

	base := ""
	if existing, e := os.ReadFile(path); e == nil {
		base = string(existing)
	}
	if !strings.Contains(base, "[data_sources]") {
		base += "\n[data_sources]\nminimum_ttl = 1440\n"
	}

	var b strings.Builder
	b.WriteString(base)
	b.WriteString("\n# ── Auto-synced API keys (MOHAMMED EXPANSION 1) ──\n")
	stanza := func(source, val string) {
		if strings.TrimSpace(val) == "" {
			return
		}
		if strings.Contains(base, "[data_sources."+source+"]\n[api_key]") {
			return // already present
		}
		b.WriteString(fmt.Sprintf("[data_sources.%s]\n[data_sources.%s.Credentials]\napikey = %s\n\n", source, source, val))
	}
	stanza("Shodan", k.Shodan)
	stanza("VirusTotal", k.VirusTotal)
	stanza("SecurityTrails", k.SecurityTrails)
	stanza("Chaos", k.Chaos)
	stanza("Censys", k.Censys)

	if err := os.WriteFile(path, []byte(b.String()), 0600); err != nil {
		return "", err
	}
	return path, nil
}

type Scope struct {
	Domains        []string
	IPs            []string
	CIDRs          []string
	ExcludeDomains []string
}

// LoadScope parses a scope file, normalizes every entry, and DEDUPLICATES
// all domains / IPs / CIDRs. Wildcard entries (*.example.com) are collapsed
// to their apex (example.com). This fixes BUG #9 (whatnot.com appeared twice
// and phase 03 ran twice, wasting 30+ minutes).
func LoadScope(path string) (*Scope, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open scope file: %w", err)
	}
	defer file.Close()

	// Ordered, deduplicated accumulators. We keep insertion order (nicer output)
	// while using a set to reject duplicates.
	domainSet := make(map[string]bool)
	ipSet := make(map[string]bool)
	cidrSet := make(map[string]bool)
	excludeSet := make(map[string]bool)

	var domains, ips, cidrs, excludes []string

	scanner := bufio.NewScanner(file)
	// Some scope lines (large wordlist-style scopes) can exceed the default 64KB.
	buf := make([]byte, 0, 1024*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// ── Out-of-scope rules prefixed with '-' ──────────────
		if strings.HasPrefix(line, "-") {
			clean := normalizeHost(strings.TrimPrefix(line, "-"))
			if clean != "" && !excludeSet[clean] {
				excludeSet[clean] = true
				excludes = append(excludes, clean)
			}
			continue
		}

		clean := normalizeHost(line)
		if clean == "" {
			continue
		}

		switch {
		case strings.Contains(clean, "/"):
			if !cidrSet[clean] {
				cidrSet[clean] = true
				cidrs = append(cidrs, clean)
			}
		case isIP(clean):
			if !ipSet[clean] {
				ipSet[clean] = true
				ips = append(ips, clean)
			}
		default:
			if !domainSet[clean] {
				domainSet[clean] = true
				domains = append(domains, clean)
			}
		}
	}

	return &Scope{
		Domains:        domains,
		IPs:            ips,
		CIDRs:          cidrs,
		ExcludeDomains: excludes,
	}, scanner.Err()
}

// normalizeHost strips scheme, path, port, wildcard prefix and lowercases.
// "*.example.com" → "example.com", "https://api.foo.com:443/x" → "api.foo.com".
func normalizeHost(raw string) string {
	clean := strings.TrimSpace(raw)
	clean = strings.TrimPrefix(clean, "https://")
	clean = strings.TrimPrefix(clean, "http://")
	if idx := strings.Index(clean, "/"); idx != -1 {
		// Keep CIDR notation (contains '/') intact; only trim URL paths.
		// A CIDR looks like "10.0.0.0/24" — the char after '/' is a digit and
		// there are no letters. Detect a URL path (has letters or is long).
		suffix := clean[idx+1:]
		if !looksLikeCIDRSuffix(suffix) {
			clean = clean[:idx]
		}
	}
	if idx := strings.Index(clean, ":"); idx != -1 {
		clean = clean[:idx]
	}
	clean = strings.TrimPrefix(clean, "*.")
	clean = strings.TrimSuffix(clean, ".")
	return strings.ToLower(strings.TrimSpace(clean))
}

// looksLikeCIDRSuffix returns true if s is purely a numeric prefix length (0-128).
func looksLikeCIDRSuffix(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func isIP(val string) bool {
	return net.ParseIP(val) != nil
}

// IsApexDomain reports whether a domain is a root/apex domain (exactly one dot,
// e.g. "example.com") versus a subdomain (e.g. "api.example.com").
//
// This is deliberately conservative: multi-label public suffixes such as
// "example.co.uk" are treated as apex when the entry has <= 2 labels beyond a
// known 2-part TLD. For the common bug-bounty case (example.com / example.io)
// the simple dot-count rule is correct and avoids a heavyweight PSL dependency.
//
// Fixes BUG #2: amass/bbot must ONLY run on apex domains, never subdomains,
// otherwise they return exit-status 2 or 0 results.
func IsApexDomain(domain string) bool {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if domain == "" {
		return false
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return false
	}
	if len(labels) == 2 {
		return true
	}
	// Handle common two-part TLDs (co.uk, com.au, co.jp, ...).
	twoPartTLDs := map[string]bool{
		"co.uk": true, "org.uk": true, "gov.uk": true, "ac.uk": true,
		"com.au": true, "net.au": true, "org.au": true,
		"co.jp": true, "co.nz": true, "co.za": true,
		"com.br": true, "com.mx": true, "com.tr": true, "com.sa": true,
	}
	lastTwo := strings.Join(labels[len(labels)-2:], ".")
	if twoPartTLDs[lastTwo] {
		// apex is registrable + the two-part TLD → exactly 3 labels.
		return len(labels) == 3
	}
	return false
}

// ExtractApexDomains returns the deduplicated set of apex/root domains derived
// from the given list. Subdomains are collapsed to their apex so that passive
// enum tools (amass/bbot) receive only registrable roots.
//
// "www.whatnot.com", "api.whatnot.com", "whatnot.com" → ["whatnot.com"].
func ExtractApexDomains(domains []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, d := range domains {
		apex := ApexOf(d)
		if apex == "" || seen[apex] {
			continue
		}
		seen[apex] = true
		out = append(out, apex)
	}
	return out
}

// ApexOf returns the apex/registrable domain for any host.
// "auction-service.whatnot.com" → "whatnot.com".
func ApexOf(domain string) string {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return domain
	}
	twoPartTLDs := map[string]bool{
		"co.uk": true, "org.uk": true, "gov.uk": true, "ac.uk": true,
		"com.au": true, "net.au": true, "org.au": true,
		"co.jp": true, "co.nz": true, "co.za": true,
		"com.br": true, "com.mx": true, "com.tr": true, "com.sa": true,
	}
	if len(labels) >= 3 {
		lastTwo := strings.Join(labels[len(labels)-2:], ".")
		if twoPartTLDs[lastTwo] {
			return strings.Join(labels[len(labels)-3:], ".")
		}
	}
	return strings.Join(labels[len(labels)-2:], ".")
}

func EnsureDir(dir string) error {
	return os.MkdirAll(dir, 0755)
}

func GetOutputFolder(target string) string {
	clean := strings.ReplaceAll(target, ".", "_")
	clean = strings.ReplaceAll(clean, "/", "_")
	return filepath.Join("output", clean)
}
