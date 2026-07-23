package phases

// ═══════════════════════════════════════════════════════════════════════════
// Deep External Recon (zero-login attack-surface expansion)
// ---------------------------------------------------------------------------
// This phase adds passive intelligence that widens the *external* attack
// surface without any authentication and without new tool binaries — it is
// pure curl + stdlib and degrades gracefully when a source is unreachable:
//
//   1. security.txt / RFC 9116 disclosure — surfaces contact + policy paths.
//   2. SPF / DMARC vendor-chain extraction — every `include:` / `redirect=`
//      in a domain's SPF record is a THIRD-PARTY service trusted to send mail
//      as the target (SendGrid, Mailgun, Salesforce, ...). Each is a real
//      supply-chain attack-surface lead an external tester must enumerate.
//   3. Favicon mmh3 hash — the Shodan `http.favicon.hash:<h>` pivot that maps
//      an app's icon to every other host on the internet serving it (shadow
//      infra, staging clones, forgotten mirrors). Computed locally, no key.
//   4. ASN / netblock mapping — resolves apex A records to owning ASNs so the
//      tester sees the full IP perimeter, not just the hostnames.
//
// Everything discovered is recorded as Info/Low findings so it lands in the
// final report; nothing here is intrusive or authenticated.
// ═══════════════════════════════════════════════════════════════════════════

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"strings"

	"github.com/mohammed-v3/core/pkg/config"
	"github.com/mohammed-v3/core/pkg/engine"
	"github.com/mohammed-v3/core/pkg/runner"
)

type DeepReconPhase struct{}

func (p *DeepReconPhase) Name() string { return "Deep External Recon" }
func (p *DeepReconPhase) Description() string {
	return "security.txt · SPF/DMARC vendor chain · favicon mmh3 (Shodan pivot) · ASN/netblock mapping"
}

func (p *DeepReconPhase) Execute(ctx context.Context, s *engine.State) error {
	apexDomains := config.ExtractApexDomains(s.Scope.Domains)

	var report []string

	for _, apex := range apexDomains {
		// ── 1. security.txt (RFC 9116) ──────────────────────────────────────
		for _, path := range []string{"/.well-known/security.txt", "/security.txt"} {
			body := curlGet(ctx, fmt.Sprintf("https://%s%s", apex, path), "-L", "-m", "15")
			if body != "" && (strings.Contains(strings.ToLower(body), "contact:") ||
				strings.Contains(strings.ToLower(body), "policy:")) {
				s.Printf("│  security.txt found: %s%s\n", apex, path)
				s.AddFinding(map[string]interface{}{
					"title":    "security.txt disclosure",
					"severity": "Info",
					"url":      apex + path,
					"tool":     "deeprecon",
					"evidence": firstLines(body, 5),
				})
				report = append(report, fmt.Sprintf("security.txt %s%s", apex, path))
				break
			}
		}

		// ── 2. SPF / DMARC vendor chain ─────────────────────────────────────
		vendors := extractSPFVendors(apex)
		if len(vendors) > 0 {
			s.Printf("│  SPF trusted senders [%s]: %s\n", apex, strings.Join(vendors, ", "))
			s.AddFinding(map[string]interface{}{
				"title":    "Third-party mail senders (SPF include chain)",
				"severity": "Info",
				"url":      apex,
				"tool":     "deeprecon",
				"evidence": "SPF include/redirect: " + strings.Join(vendors, ", "),
			})
			report = append(report, fmt.Sprintf("SPF-vendors %s: %s", apex, strings.Join(vendors, " ")))
		}

		// ── 3. Favicon mmh3 hash (Shodan pivot) ─────────────────────────────
		if h, ok := faviconHash(ctx, apex); ok {
			s.Printf("│  favicon mmh3 [%s]: %d  → shodan http.favicon.hash:%d\n", apex, h, h)
			s.AddFinding(map[string]interface{}{
				"title":    "Favicon hash (Shodan infrastructure pivot)",
				"severity": "Info",
				"url":      apex,
				"tool":     "deeprecon",
				"evidence": fmt.Sprintf("http.favicon.hash:%d", h),
			})
			report = append(report, fmt.Sprintf("favicon %s: %d", apex, h))
		}

		// ── 4. ASN / netblock mapping ───────────────────────────────────────
		asns := resolveASNs(ctx, apex)
		if len(asns) > 0 {
			s.Printf("│  ASN/netblock [%s]: %s\n", apex, strings.Join(asns, ", "))
			s.AddFinding(map[string]interface{}{
				"title":    "Owning ASN / netblock",
				"severity": "Info",
				"url":      apex,
				"tool":     "deeprecon",
				"evidence": strings.Join(asns, "; "),
			})
			report = append(report, fmt.Sprintf("ASN %s: %s", apex, strings.Join(asns, " ")))
		}
	}

	if len(report) > 0 {
		writeLines(filepath.Join(s.OutputFolder, "deeprecon.txt"), report)
	}
	s.Printf("│  Deep recon: %d intelligence items\n", len(report))
	return nil
}

// ─────────────────────────────────────────────────────────────────────────
// helpers
// ─────────────────────────────────────────────────────────────────────────

func firstLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.TrimSpace(strings.Join(lines, " | "))
}

// extractSPFVendors reads the apex TXT records and pulls every include: /
// redirect= host from the SPF policy — each is a third-party sender.
func extractSPFVendors(apex string) []string {
	txts, err := net.LookupTXT(apex)
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, txt := range txts {
		if !strings.HasPrefix(strings.ToLower(txt), "v=spf1") {
			continue
		}
		for _, field := range strings.Fields(txt) {
			f := strings.ToLower(field)
			var host string
			switch {
			case strings.HasPrefix(f, "include:"):
				host = strings.TrimPrefix(field, "include:")
			case strings.HasPrefix(f, "redirect="):
				host = strings.TrimPrefix(field, "redirect=")
			}
			host = strings.TrimSpace(host)
			if host != "" && !seen[host] {
				seen[host] = true
				out = append(out, host)
			}
		}
	}
	return out
}

// faviconHash downloads /favicon.ico and returns its mmh3 hash the same way
// Shodan indexes it: standard-base64 (with newline every 76 chars + trailing
// newline) of the raw bytes, hashed with 32-bit MurmurHash3 (seed 0).
func faviconHash(ctx context.Context, apex string) (int32, bool) {
	raw := curlGetRaw(ctx, fmt.Sprintf("https://%s/favicon.ico", apex), "-L", "-m", "15")
	if len(raw) == 0 {
		return 0, false
	}
	b64 := stdBase64Chunked(raw)
	return murmur3Hash32([]byte(b64)), true
}

// resolveASNs maps the apex's resolved IPs to their owning ASN via the
// Team Cymru whois-over-DNS style HTTP endpoint (ip-api, no key). Degrades to
// empty on any failure.
func resolveASNs(ctx context.Context, apex string) []string {
	ips, err := net.LookupIP(apex)
	if err != nil || len(ips) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, ip := range ips {
		v4 := ip.To4()
		if v4 == nil {
			continue // IPv4 only for this lightweight lookup
		}
		body := curlGet(ctx, fmt.Sprintf("http://ip-api.com/json/%s?fields=as,org,query", v4.String()), "-m", "10")
		if body == "" {
			continue
		}
		var m map[string]interface{}
		if json.Unmarshal([]byte(body), &m) != nil {
			continue
		}
		as, _ := m["as"].(string)
		org, _ := m["org"].(string)
		entry := strings.TrimSpace(fmt.Sprintf("%s (%s) via %s", as, org, v4.String()))
		if entry != "" && !seen[entry] {
			seen[entry] = true
			out = append(out, entry)
		}
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────────
// Minimal MurmurHash3 x86 32-bit + Shodan-style base64 (stdlib-only, no deps)
// ─────────────────────────────────────────────────────────────────────────

// stdBase64Chunked replicates python's base64.encodebytes: standard base64
// with a newline inserted every 76 output chars and a trailing newline — this
// exact framing is what Shodan hashes.
func stdBase64Chunked(data []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var enc strings.Builder
	for i := 0; i < len(data); i += 3 {
		var n uint32
		rem := len(data) - i
		n = uint32(data[i]) << 16
		if rem > 1 {
			n |= uint32(data[i+1]) << 8
		}
		if rem > 2 {
			n |= uint32(data[i+2])
		}
		enc.WriteByte(alphabet[(n>>18)&0x3F])
		enc.WriteByte(alphabet[(n>>12)&0x3F])
		if rem > 1 {
			enc.WriteByte(alphabet[(n>>6)&0x3F])
		} else {
			enc.WriteByte('=')
		}
		if rem > 2 {
			enc.WriteByte(alphabet[n&0x3F])
		} else {
			enc.WriteByte('=')
		}
	}
	// Insert newline every 76 chars + trailing newline (encodebytes semantics).
	raw := enc.String()
	var out strings.Builder
	for i := 0; i < len(raw); i += 76 {
		end := i + 76
		if end > len(raw) {
			end = len(raw)
		}
		out.WriteString(raw[i:end])
		out.WriteByte('\n')
	}
	return out.String()
}

// murmur3Hash32 implements MurmurHash3 x86 32-bit (seed 0), matching the
// mmh3.hash() output Shodan uses for favicons.
func murmur3Hash32(data []byte) int32 {
	const (
		c1 = 0xcc9e2d51
		c2 = 0x1b873593
	)
	var h uint32 // seed = 0
	nblocks := len(data) / 4
	for i := 0; i < nblocks; i++ {
		k := binary.LittleEndian.Uint32(data[i*4:])
		k *= c1
		k = (k << 15) | (k >> 17)
		k *= c2
		h ^= k
		h = (h << 13) | (h >> 19)
		h = h*5 + 0xe6546b64
	}
	var k uint32
	tail := data[nblocks*4:]
	switch len(tail) {
	case 3:
		k ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k ^= uint32(tail[0])
		k *= c1
		k = (k << 15) | (k >> 17)
		k *= c2
		h ^= k
	}
	h ^= uint32(len(data))
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return int32(h)
}

// curlGetRaw fetches binary content (favicon) and returns raw bytes.
func curlGetRaw(ctx context.Context, url string, extraArgs ...string) []byte {
	args := append([]string{"-s"}, extraArgs...)
	args = append(args, url)
	res := runner.RunTool(ctx, "curl", args, nil)
	if res.OK() {
		return []byte(res.Stdout)
	}
	return nil
}
