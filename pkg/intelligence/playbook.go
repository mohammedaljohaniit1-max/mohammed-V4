package intelligence

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Playbook is the parsed representation of a playbooks/*.yaml file (mandate §1.3).
// It is intentionally a faithful mirror of the YAML so operators can edit the
// YAML without touching Go.
type Playbook struct {
	Technology       string   `yaml:"technology" json:"technology"`
	MatchLanguage    string   `yaml:"match_language" json:"match_language"`
	Description      string   `yaml:"description" json:"description"`
	HighValueSurface []string `yaml:"high_value_surfaces" json:"high_value_surfaces"`
	DetectHeaders    []string `yaml:"detect_headers" json:"detect_headers"`
	DetectCookies    []string `yaml:"detect_cookies" json:"detect_cookies"`
	CustomChecks     []string `yaml:"custom_checks" json:"custom_checks"`
	PriorityNote     string   `yaml:"priority_note" json:"priority_note"`

	CommonVulnerabilities []struct {
		Name string `yaml:"name" json:"name"`
		When string `yaml:"when,omitempty" json:"when,omitempty"`
		Note string `yaml:"note,omitempty" json:"note,omitempty"`
	} `yaml:"common_vulnerabilities" json:"common_vulnerabilities"`
}

// PlaybookLibrary is an in-memory index of loaded playbooks keyed by
// match_language.
type PlaybookLibrary struct {
	byLanguage map[string]Playbook
}

// LoadPlaybooks reads every *.yaml file in dir and indexes it by match_language.
// A malformed file is an error (fail loud during setup, never silently ship a
// half-loaded library).
func LoadPlaybooks(dir string) (*PlaybookLibrary, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read playbook dir %q: %w", dir, err)
	}
	lib := &PlaybookLibrary{byLanguage: map[string]Playbook{}}
	loaded := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("read playbook %q: %w", name, err)
		}
		var pb Playbook
		if err := yaml.Unmarshal(raw, &pb); err != nil {
			return nil, fmt.Errorf("parse playbook %q: %w", name, err)
		}
		key := strings.TrimSpace(pb.MatchLanguage)
		if key == "" {
			return nil, fmt.Errorf("playbook %q has empty match_language", name)
		}
		lib.byLanguage[key] = pb
		loaded++
	}
	if loaded == 0 {
		return nil, fmt.Errorf("no playbooks found in %q", dir)
	}
	return lib, nil
}

// For returns the playbook for a detected language and whether one exists.
func (l *PlaybookLibrary) For(language string) (Playbook, bool) {
	pb, ok := l.byLanguage[strings.TrimSpace(language)]
	return pb, ok
}

// Languages returns the sorted set of languages the library covers.
func (l *PlaybookLibrary) Languages() []string {
	out := make([]string, 0, len(l.byLanguage))
	for k := range l.byLanguage {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Len returns how many playbooks are loaded.
func (l *PlaybookLibrary) Len() int { return len(l.byLanguage) }

// SelectFor returns the playbook that matches the core's currently detected
// language, if any. This is the glue the mandate describes: "Phase 3 discovers
// the target uses Rails -> Intelligence Core loads Rails playbook."
func (l *PlaybookLibrary) SelectFor(ic *IntelligenceCore) (Playbook, bool) {
	return l.For(ic.Tech().Language)
}
