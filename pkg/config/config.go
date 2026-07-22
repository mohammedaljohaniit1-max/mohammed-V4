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
	APIKeys    APIKeys
	Ollama     OllamaConfig
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

type YAMLConfig struct {
	APIKeys APIKeys      `yaml:"api_keys"`
	Ollama  OllamaConfig `yaml:"ollama"`
}

func LoadYAMLConfig(path string) (*YAMLConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return &YAMLConfig{}, nil
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
	return &cfg, nil
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
