package intelligence

import (
	"encoding/json"
	"time"
)

// Profile is the serialisable snapshot written to
// output/{target}/intelligence_profile.json (mandate §1.1). It is a pure
// projection of the core's current state — building it takes a read lock and
// copies everything, so the returned value is safe to marshal concurrently.
type Profile struct {
	SchemaVersion  int         `json:"schema_version"`
	Target         string      `json:"target"`
	GeneratedAt    time.Time   `json:"generated_at"`
	Class          TargetClass `json:"class"`
	Strategy       Strategy    `json:"strategy"`
	Tech           TechStack   `json:"tech"`
	WAFPresent     bool        `json:"waf_present"`
	WAFVendor      string      `json:"waf_vendor,omitempty"`
	AuthMechanisms []AuthType  `json:"auth_mechanisms"`
	Protocols      []Protocol  `json:"protocols"`
	Sessions       []string    `json:"sessions"`
	Endpoints      []string    `json:"endpoints"`
	Params         []string    `json:"params"`
	DiscoveryCount int         `json:"discovery_count"`
}

// ProfileSchemaVersion is bumped when the JSON shape changes.
const ProfileSchemaVersion = 1

// Profile builds a serialisable snapshot of the current intelligence state.
func (ic *IntelligenceCore) Profile() Profile {
	present, vendor := ic.WAF()
	return Profile{
		SchemaVersion:  ProfileSchemaVersion,
		Target:         ic.Target(),
		GeneratedAt:    time.Now().UTC(),
		Class:          ic.Class(),
		Strategy:       ic.Strategy(),
		Tech:           ic.Tech(),
		WAFPresent:     present,
		WAFVendor:      vendor,
		AuthMechanisms: ic.AuthMechanisms(),
		Protocols:      ic.Protocols(),
		Sessions:       ic.Sessions(),
		Endpoints:      ic.Endpoints(),
		Params:         ic.Params(),
		DiscoveryCount: ic.DiscoveryCount(),
	}
}

// MarshalJSON produces the indented JSON document for the profile file.
func (p Profile) MarshalIndent() ([]byte, error) {
	return json.MarshalIndent(p, "", "  ")
}
