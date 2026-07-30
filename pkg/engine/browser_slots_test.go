package engine

import "testing"

// TestFix6_BrowserSlotsCappedAtThree proves the V12.1 FIX #6 concurrency cap:
// no matter how many threads are configured, at most 3 headless-Chrome tabs may
// be open at once, keeping Chrome's RSS under the recycle threshold.
func TestFix6_BrowserSlotsCappedAtThree(t *testing.T) {
	cases := []struct {
		threads int
		want    int
	}{
		{0, 2},   // degenerate → safe default 2
		{1, 1},   // fewer threads than the cap → threads
		{2, 2},   // exactly the mid range
		{3, 3},   // at the cap
		{8, 3},   // above the cap → hard-limited to 3
		{100, 3}, // far above → still 3
	}
	for _, tc := range cases {
		if got := browserSlots(tc.threads); got != tc.want {
			t.Errorf("browserSlots(%d) = %d, want %d (FIX #6 cap=3)", tc.threads, got, tc.want)
		}
	}
}
