package session

import "testing"

func TestModeFor_SensitiveIsGentle(t *testing.T) {
	if ModeFor(true).AllowPortScan {
		t.Fatal("sensitive/hardened target must use gentle mode (no port scan)")
	}
	if !ModeFor(false).AllowPortScan {
		t.Fatal("non-sensitive target should allow port scan (normal mode)")
	}
}

func TestGentleForClass(t *testing.T) {
	cases := []struct {
		class     string
		flagged   bool
		wantGentle bool
	}{
		{"A", false, true},   // ultra-hardened -> gentle
		{"", false, true},    // unknown -> gentle (careful)
		{"B", false, false},  // well-hardened but can take load
		{"C", false, false},  // partially secured
		{"D", false, false},  // unprotected
		{"D", true, true},    // operator override: gov/sensitive -> gentle even if D
		{"C", true, true},    // operator override wins
	}
	for _, c := range cases {
		if got := GentleForClass(c.class, c.flagged); got != c.wantGentle {
			t.Errorf("GentleForClass(%q, flagged=%v) = %v, want %v", c.class, c.flagged, got, c.wantGentle)
		}
	}
}
