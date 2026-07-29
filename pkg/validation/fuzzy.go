package validation

// fuzzy.go implements the V8.0 LEVEL MAX fuzzy-baseline layer for the
// false-positive engine. The V7.x baseline compared a target response against a
// single random-path probe using exact SHA-256 equality plus a crude ±2% length
// window. That misses two whole classes of catch-all:
//
//   - SPA shells that inject a per-request CSRF nonce or timestamp (so every
//     byte-length differs slightly but the page is semantically identical);
//   - CDN / WAF error pages that vary a request-id but are otherwise the same
//     block page for every non-existent path.
//
// To catch those deterministically we compute two locality-sensitive fuzzy
// hashes over the response body and compare them:
//
//   - SimHash (Charikar): a 64-bit fingerprint whose Hamming distance is
//     proportional to the cosine distance of the underlying token vectors. Two
//     bodies that differ only by a nonce have a SimHash Hamming distance of 0-3;
//     two genuinely different pages differ by 15-30+ bits.
//   - Normalised Levenshtein similarity over a size-bounded shingle of the body,
//     used as a second, independent opinion so a SimHash collision alone can
//     never mislabel a real finding as a catch-all.
//
// Everything here is pure and allocation-bounded (bodies are truncated before
// hashing) so it is fully unit-testable with no network I/O.

import (
	"strings"
)

// simhashBits is the fingerprint width. 64 bits is the standard Charikar width
// and fits a single uint64 so Hamming distance is one popcount.
const simhashBits = 64

// SimHash computes a 64-bit Charikar SimHash over the whitespace-normalised
// token stream of s. Identical inputs hash identically; near-identical inputs
// (a nonce swapped) hash within a few bits.
func SimHash(s string) uint64 {
	tokens := shingleTokens(s)
	if len(tokens) == 0 {
		return 0
	}
	// Weighted bit accumulator: +weight when the token-hash bit is 1, -weight
	// when 0. The sign of each column becomes the final fingerprint bit.
	var v [simhashBits]int
	for tok, weight := range tokens {
		h := fnv64(tok)
		for i := 0; i < simhashBits; i++ {
			if (h>>uint(i))&1 == 1 {
				v[i] += weight
			} else {
				v[i] -= weight
			}
		}
	}
	var fp uint64
	for i := 0; i < simhashBits; i++ {
		if v[i] > 0 {
			fp |= 1 << uint(i)
		}
	}
	return fp
}

// HammingDistance returns the number of differing bits between two 64-bit
// fingerprints (popcount of the XOR).
func HammingDistance(a, b uint64) int {
	return popcount(a ^ b)
}

// popcount counts set bits using the classic SWAR algorithm (no dependency on
// math/bits so behaviour is identical on every Go version we target).
func popcount(x uint64) int {
	x = x - ((x >> 1) & 0x5555555555555555)
	x = (x & 0x3333333333333333) + ((x >> 2) & 0x3333333333333333)
	x = (x + (x >> 4)) & 0x0f0f0f0f0f0f0f0f
	return int((x * 0x0101010101010101) >> 56)
}

// fnv64 is the 64-bit FNV-1a hash of a token. Inlined so we do not allocate a
// hash.Hash per token in the SimHash hot loop.
func fnv64(s string) uint64 {
	const (
		offset = 1469598103934665603
		prime  = 1099511628211
	)
	var h uint64 = offset
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= prime
	}
	return h
}

// shingleTokens returns a weighted token multiset for SimHash. It lower-cases,
// collapses runs of non-alphanumeric characters to single spaces, and counts
// word frequency. To keep a nonce/token from dominating a short body, the body
// is truncated to 32 KiB before tokenising.
func shingleTokens(s string) map[string]int {
	if len(s) > 32*1024 {
		s = s[:32*1024]
	}
	out := make(map[string]int, 128)
	var b strings.Builder
	flush := func() {
		if b.Len() == 0 {
			return
		}
		out[b.String()]++
		b.Reset()
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z':
			b.WriteByte(c + 32)
		case (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'):
			b.WriteByte(c)
		default:
			flush()
		}
	}
	flush()
	return out
}

// LevenshteinSimilarity returns a 0.0–1.0 similarity ratio between a and b,
// computed as 1 - editDistance/maxLen over a length-bounded prefix of each
// string. Inputs are truncated to 2 KiB first so the O(n·m) DP stays cheap; for
// baseline classification a 2 KiB prefix captures the page skeleton, which is
// exactly what distinguishes a shared error template from a real document.
func LevenshteinSimilarity(a, b string) float64 {
	const cap = 2048
	if len(a) > cap {
		a = a[:cap]
	}
	if len(b) > cap {
		b = b[:cap]
	}
	if a == b {
		return 1.0
	}
	if len(a) == 0 || len(b) == 0 {
		return 0.0
	}
	d := levenshtein(a, b)
	maxLen := len(a)
	if len(b) > maxLen {
		maxLen = len(b)
	}
	return 1.0 - float64(d)/float64(maxLen)
}

// levenshtein computes the classic edit distance with a rolling two-row DP so
// memory is O(min(len)) rather than O(len²).
func levenshtein(a, b string) int {
	if len(a) < len(b) {
		a, b = b, a
	}
	prev := make([]int, len(b)+1)
	curr := make([]int, len(b)+1)
	for j := 0; j <= len(b); j++ {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		curr[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			curr[j] = min3(
				prev[j]+1,      // deletion
				curr[j-1]+1,    // insertion
				prev[j-1]+cost, // substitution
			)
		}
		prev, curr = curr, prev
	}
	return prev[len(b)]
}

func min3(a, b, c int) int {
	m := a
	if b < m {
		m = b
	}
	if c < m {
		m = c
	}
	return m
}

// FuzzyVerdict is the structured opinion of the fuzzy comparator.
type FuzzyVerdict struct {
	// SimHashDistance is the Hamming distance between the two fingerprints.
	SimHashDistance int
	// LevSimilarity is the normalised Levenshtein similarity (0.0–1.0).
	LevSimilarity float64
	// SameTemplate is true when BOTH signals agree the two bodies are the same
	// underlying template (SimHash within threshold AND Levenshtein high). The
	// AND requirement is deliberate: it takes two independent LSH opinions to
	// declare a catch-all, so one hash colliding can never suppress a real bug.
	SameTemplate bool
	// Reason is a short human explanation for the evidence trail.
	Reason string
}

// simhashCatchAllMaxBits is the maximum Hamming distance at which two bodies are
// considered the same template by SimHash. 6/64 bits ≈ >90% token overlap:
// enough slack to absorb a nonce/csrf token, tight enough that a genuinely
// different page (which differs by 15+ bits) is never captured.
const simhashCatchAllMaxBits = 6

// levCatchAllMinSim is the minimum Levenshtein similarity for the second
// opinion. 0.92 means the 2 KiB skeletons are ≥92% identical.
const levCatchAllMinSim = 0.92

// FuzzyCompare computes both fuzzy signals over two bodies and returns a
// structured verdict. It is the core primitive the fuzzy baseline uses to
// decide "is the target just the site's universal catch-all response?".
func FuzzyCompare(a, b string) FuzzyVerdict {
	dist := HammingDistance(SimHash(a), SimHash(b))
	sim := LevenshteinSimilarity(a, b)
	same := dist <= simhashCatchAllMaxBits && sim >= levCatchAllMinSim
	v := FuzzyVerdict{SimHashDistance: dist, LevSimilarity: sim, SameTemplate: same}
	if same {
		v.Reason = "fuzzy: SimHash distance " + itoa(dist) + "/64 and Levenshtein similarity " +
			ftoa(sim) + " → same underlying template (catch-all/SPA/error page)"
	} else {
		v.Reason = "fuzzy: SimHash distance " + itoa(dist) + "/64, Levenshtein similarity " +
			ftoa(sim) + " → distinct content"
	}
	return v
}

// itoa is a tiny non-allocating-ish int formatter (avoids importing strconv in
// two files for one call each).
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// ftoa formats a 0.0–1.0 ratio to two decimals without importing strconv.
func ftoa(f float64) string {
	if f < 0 {
		f = 0
	}
	if f > 1 {
		f = 1
	}
	whole := int(f)
	frac := int((f-float64(whole))*100 + 0.5)
	if frac >= 100 {
		whole++
		frac -= 100
	}
	fs := itoa(frac)
	if len(fs) < 2 {
		fs = "0" + fs
	}
	return itoa(whole) + "." + fs
}
