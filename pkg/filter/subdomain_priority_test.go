package filter

import (
	"reflect"
	"testing"
)

func TestPrioritizeLiveTargets(t *testing.T) {
	input := []string{
		"www.zid.sa",
		"zid.sa",
		"dev.zid.sa",
		"api.zid.sa",
		"static.zid.sa",
		"checkout.zid.sa",
		"internal-auth.zid.sa",
		"staging.zid.sa",
		"admin.zid.sa",
	}

	got := PrioritizeLiveTargets(input)

	// High priority hosts (staging, dev, api, internal, admin) must appear before standard or low priority
	expectedHigh := []string{
		"admin.zid.sa",
		"api.zid.sa",
		"dev.zid.sa",
		"internal-auth.zid.sa",
		"staging.zid.sa",
	}

	expectedStandard := []string{
		"checkout.zid.sa",
	}

	expectedLow := []string{
		"static.zid.sa",
		"www.zid.sa",
		"zid.sa",
	}

	expectedTotal := append(expectedHigh, expectedStandard...)
	expectedTotal = append(expectedTotal, expectedLow...)

	if !reflect.DeepEqual(got, expectedTotal) {
		t.Fatalf("PrioritizeLiveTargets mismatch:\n got:  %v\n want: %v", got, expectedTotal)
	}
}
