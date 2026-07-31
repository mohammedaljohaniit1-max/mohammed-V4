package engine

import (
	"reflect"
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════
// V12.2 PROCESS CRISIS · FAILURE #5 REGRESSION TESTS
// ---------------------------------------------------------------------------
// Proves --skip / --only phase selection actually parses single phases, comma
// lists and inclusive ranges, and that ShouldRunPhase applies the correct
// precedence (--only wins over --skip). Before the fix a resumed scan re-ran
// the interrupted Phase 12 from scratch (another 1h40m) because there was no
// way to skip it.
// ═══════════════════════════════════════════════════════════════════════════

func TestV122_ParsePhaseList_SingleCommaRange(t *testing.T) {
	cases := []struct {
		spec string
		want map[int]bool
	}{
		{"", nil},
		{"   ", nil},
		{"12", map[int]bool{12: true}},
		{"4,12,20", map[int]bool{4: true, 12: true, 20: true}},
		{"12-15", map[int]bool{12: true, 13: true, 14: true, 15: true}},
		{"4,12-14,20", map[int]bool{4: true, 12: true, 13: true, 14: true, 20: true}},
		{" 4 , 12 - 14 ", map[int]bool{4: true, 12: true, 13: true, 14: true}},
		{"15-12", map[int]bool{12: true, 13: true, 14: true, 15: true}}, // reversed range tolerated
		{"abc,,7", map[int]bool{7: true}},                              // malformed tokens ignored
		{"0,-3,5", map[int]bool{5: true}},                             // non-positive ignored
	}
	for _, tc := range cases {
		got := ParsePhaseList(tc.spec)
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("ParsePhaseList(%q) = %v, want %v", tc.spec, got, tc.want)
		}
	}
}

func TestV122_ShouldRunPhase_SkipAndOnlyPrecedence(t *testing.T) {
	// --skip 4,12: everything runs except 4 and 12.
	s := &State{}
	s.SetPhaseSelection(ParsePhaseList("4,12"), ParsePhaseList(""))
	if s.ShouldRunPhase(4) || s.ShouldRunPhase(12) {
		t.Fatal("phases 4 and 12 must be skipped by --skip 4,12")
	}
	if !s.ShouldRunPhase(1) || !s.ShouldRunPhase(13) {
		t.Fatal("phases 1 and 13 must run under --skip 4,12")
	}

	// --only 13,14,15: EXCLUSIVELY those phases run; --skip is irrelevant.
	s2 := &State{}
	s2.SetPhaseSelection(ParsePhaseList("4,12"), ParsePhaseList("13-15"))
	for _, n := range []int{13, 14, 15} {
		if !s2.ShouldRunPhase(n) {
			t.Fatalf("phase %d must run under --only 13-15", n)
		}
	}
	for _, n := range []int{1, 4, 12, 16} {
		if s2.ShouldRunPhase(n) {
			t.Fatalf("phase %d must NOT run under --only 13-15 (only wins over skip)", n)
		}
	}

	// No selection at all: every phase runs.
	s3 := &State{}
	s3.SetPhaseSelection(nil, nil)
	if !s3.ShouldRunPhase(1) || !s3.ShouldRunPhase(99) {
		t.Fatal("with no selection every phase must run")
	}
}

func TestV122_SortedPhaseNums(t *testing.T) {
	got := sortedPhaseNums(map[int]bool{20: true, 4: true, 12: true})
	want := []int{4, 12, 20}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("sortedPhaseNums = %v, want %v", got, want)
	}
}
