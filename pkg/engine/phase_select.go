package engine

// ═══════════════════════════════════════════════════════════════════════════
// V12.2 PROCESS CRISIS · FAILURE #5 FIX — --skip / --only Phase Selection
// ---------------------------------------------------------------------------
// EMPIRICAL EVIDENCE: after the user interrupted the scan during Phase 12 and
// resumed with --resume auto, Phase 12 started FROM SCRATCH again (another
// 1h40m) because it had never completed. There was no way to say "skip the
// broken phase and move on".
//
// The fix (mandate §2.5): a --skip flag that accepts single phases, comma lists
// and ranges (4,12,20 or 12-20), and an --only flag that runs EXCLUSIVELY the
// listed phases. Phase numbers are 1-based and match the "Phase NN/MM" labels
// printed by the orchestrator.
// ═══════════════════════════════════════════════════════════════════════════

import (
	"sort"
	"strconv"
	"strings"
)

// ParsePhaseList parses a --skip/--only argument into a set of 1-based phase
// numbers. It accepts comma-separated values and inclusive ranges, e.g.
// "4,12,20" or "12-20" or "4,12-15,20". Whitespace is tolerated; malformed
// tokens are ignored (best-effort — a typo must never crash a scan). An empty
// or whitespace-only string yields an empty (nil) map.
func ParsePhaseList(spec string) map[int]bool {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil
	}
	out := make(map[int]bool)
	for _, tok := range strings.Split(spec, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if strings.Contains(tok, "-") {
			parts := strings.SplitN(tok, "-", 2)
			lo, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
			hi, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err1 != nil || err2 != nil {
				continue
			}
			if lo > hi {
				lo, hi = hi, lo
			}
			for n := lo; n <= hi; n++ {
				if n > 0 {
					out[n] = true
				}
			}
			continue
		}
		if n, err := strconv.Atoi(tok); err == nil && n > 0 {
			out[n] = true
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// SetPhaseSelection records the parsed --skip and --only sets on the state so
// the orchestrator can consult them via ShouldRunPhase.
func (s *State) SetPhaseSelection(skip, only map[int]bool) {
	s.SkipPhases = skip
	s.OnlyPhases = only
}

// ShouldRunPhase reports whether the 1-based phaseNum should execute given the
// active --skip/--only selection. --only takes precedence: when it is set, ONLY
// those phases run. Otherwise a phase runs unless it is in the skip set.
func (s *State) ShouldRunPhase(phaseNum int) bool {
	if len(s.OnlyPhases) > 0 {
		return s.OnlyPhases[phaseNum]
	}
	return !s.SkipPhases[phaseNum]
}

// sortedPhaseNums is a tiny helper for deterministic log output of a phase set.
func sortedPhaseNums(m map[int]bool) []int {
	out := make([]int, 0, len(m))
	for n := range m {
		out = append(out, n)
	}
	sort.Ints(out)
	return out
}
