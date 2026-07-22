package config

import (
	"bufio"
	"fmt"
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
	Enabled  bool   `yaml:"enabled"`
	Endpoint string `yaml:"endpoint"`
	Model    string `yaml:"model"`
	Timeout  int    `yaml:"timeout"`
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
	return &cfg, nil
}

type Scope struct {
	Domains       []string
	IPs           []string
	CIDRs         []string
	ExcludeDomains []string
}

func LoadScope(path string) (*Scope, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open scope file: %w", err)
	}
	defer file.Close()

	scope := &Scope{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Handle out-of-scope rules prefixed with '-'
		if strings.HasPrefix(line, "-") {
			clean := strings.TrimPrefix(line, "-")
			clean = strings.TrimPrefix(clean, "*.")
			clean = strings.TrimPrefix(clean, "https://")
			clean = strings.TrimPrefix(clean, "http://")
			if clean != "" {
				scope.ExcludeDomains = append(scope.ExcludeDomains, strings.ToLower(clean))
			}
			continue
		}

		clean := strings.TrimPrefix(line, "https://")
		clean = strings.TrimPrefix(clean, "http://")
		if idx := strings.Index(clean, "/"); idx != -1 {
			clean = clean[:idx]
		}
		if idx := strings.Index(clean, ":"); idx != -1 {
			clean = clean[:idx]
		}
		clean = strings.TrimPrefix(clean, "*.")
		clean = strings.TrimSpace(clean)
		if clean == "" {
			continue
		}

		if strings.Contains(clean, "/") {
			scope.CIDRs = append(scope.CIDRs, clean)
		} else if isIP(clean) {
			scope.IPs = append(scope.IPs, clean)
		} else {
			scope.Domains = append(scope.Domains, strings.ToLower(clean))
		}
	}
	return scope, scanner.Err()
}

func isIP(val string) bool {
	parts := strings.Split(val, ".")
	return len(parts) == 4
}

func EnsureDir(dir string) error {
	return os.MkdirAll(dir, 0755)
}

func GetOutputFolder(target string) string {
	clean := strings.ReplaceAll(target, ".", "_")
	clean = strings.ReplaceAll(clean, "/", "_")
	return filepath.Join("output", clean)
}
