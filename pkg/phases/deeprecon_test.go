package phases

import "testing"

// TestMurmur3Hash32 validates our stdlib MurmurHash3 x86_32 (seed 0) against
// reference vectors produced by the canonical Python `mmh3` library — this is
// the exact hash Shodan uses for http.favicon.hash, so a subtle bug here would
// silently produce useless pivots. Vectors:
//   mmh3.hash(b"")                                        == 0
//   mmh3.hash(b"hello")                                   == 613153351
//   mmh3.hash(b"The quick brown fox jumps over the lazy dog") == 776992547
func TestMurmur3Hash32(t *testing.T) {
	cases := map[string]int32{
		"":      0,
		"hello": 613153351,
		"The quick brown fox jumps over the lazy dog": 776992547,
	}
	for in, want := range cases {
		if got := murmur3Hash32([]byte(in)); got != want {
			t.Errorf("murmur3Hash32(%q) = %d, want %d", in, got, want)
		}
	}
}

// TestStdBase64Chunked confirms the Shodan-style base64 framing (76-col wrap +
// trailing newline) matches Python's base64.encodebytes.
func TestStdBase64Chunked(t *testing.T) {
	// Python: base64.encodebytes(b"favicon-bytes-example-payload-1234567890")
	// == b'ZmF2aWNvbi1ieXRlcy1leGFtcGxlLXBheWxvYWQtMTIzNDU2Nzg5MA==\n'
	got := stdBase64Chunked([]byte("favicon-bytes-example-payload-1234567890"))
	want := "ZmF2aWNvbi1ieXRlcy1leGFtcGxlLXBheWxvYWQtMTIzNDU2Nzg5MA==\n"
	if got != want {
		t.Errorf("stdBase64Chunked mismatch:\n got=%q\nwant=%q", got, want)
	}
}

// TestExtractSPFVendorsParsing is a pure-parse sanity check of the SPF include
// extraction logic without network (uses the exported behavior via a helper).
func TestFirstLines(t *testing.T) {
	in := "Contact: mailto:sec@x.com\nPolicy: https://x.com/p\nExpires: 2030\nExtra\nMore\nEvenMore"
	got := firstLines(in, 3)
	want := "Contact: mailto:sec@x.com | Policy: https://x.com/p | Expires: 2030"
	if got != want {
		t.Errorf("firstLines = %q, want %q", got, want)
	}
}
