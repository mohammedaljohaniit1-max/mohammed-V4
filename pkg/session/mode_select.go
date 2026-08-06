package session

// ModeFor picks the right pacing profile from a target's strategy signals,
// bridging pkg/intelligence's A/B/C/D classification to concrete request pacing.
//
// The mapping is intentionally conservative and matches the operator's warning
// about sensitive Saudi-government-style targets: when in doubt, go gentle.
//
//	sensitiveOrHardened == true  -> GentleMode (slow, no port scan / brute / fuzz,
//	                                immediate 429/503 backoff). This covers Class A
//	                                AND any target explicitly flagged sensitive
//	                                (gov / low-capacity / "even nmap may be banned").
//	sensitiveOrHardened == false -> NormalMode (Class C/D that can take the load).
//
// Keeping this a tiny pure function (rather than importing pkg/intelligence here)
// avoids a package cycle: the caller reads Strategy from the profile and passes
// the two booleans in.
func ModeFor(sensitiveOrHardened bool) *GentleMode {
	if sensitiveOrHardened {
		return NewGentleMode()
	}
	return NewNormalMode()
}

// GentleForClassA reports whether a given class label (as produced by
// pkg/intelligence: "A"/"B"/"C"/"D") should default to gentle pacing.
// Class A (ultra-hardened) and any unknown/sensitive class default to gentle.
func GentleForClass(classLabel string, operatorFlaggedSensitive bool) bool {
	if operatorFlaggedSensitive {
		return true
	}
	switch classLabel {
	case "A", "": // ultra-hardened or unknown -> be careful
		return true
	default: // B/C/D -> normal load is acceptable
		return false
	}
}
