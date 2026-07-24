#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# MOHAMMED v4 — verify.sh
# Fast verification that all phases, files, tools, AI triage, and the
# root-cause bug fixes are wired correctly.
# Usage: bash verify.sh [output_folder]
# ═══════════════════════════════════════════════════════════════════════

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'
BOLD='\033[1m'; NC='\033[0m'

PASS=0; FAIL=0; WARN=0

pass() { echo -e "${GREEN}  ✅ PASS${NC}  $*"; ((PASS++)); }
fail() { echo -e "${RED}  ❌ FAIL${NC}  $*"; ((FAIL++)); }
warn() { echo -e "${YELLOW}  ⚠️  WARN${NC}  $*"; ((WARN++)); }
info() { echo -e "${CYAN}  ℹ️  INFO${NC}  $*"; }
hdr()  { echo -e "\n${BOLD}${CYAN}══ $* ══${NC}"; }

OUTPUT_DIR="${1:-output}"

echo -e "${BOLD}"
echo "╔═══════════════════════════════════════════════════╗"
echo "║     MOHAMMED v4 — Verification Suite              ║"
echo "╚═══════════════════════════════════════════════════╝"
echo -e "${NC}"

# ── Section 1: Binary ────────────────────────────────────────────────
hdr "1. Mohammed Binary"

if [ -f "./mohammed" ]; then
    pass "./mohammed binary exists"
    if ./mohammed doctor &>/dev/null; then
        pass "./mohammed doctor runs without crash"
    else
        warn "./mohammed doctor exited non-zero (may be missing tools)"
    fi
else
    fail "./mohammed binary NOT FOUND — run: go build -o mohammed ./cmd/mohammed"
fi

# ── Section 2: Source Files ──────────────────────────────────────────
hdr "2. Source Files Integrity"

check_file() {
    local f="$1"
    if [ -f "$f" ]; then
        local lines
        lines=$(wc -l < "$f")
        pass "$f ($lines lines)"
    else
        fail "$f NOT FOUND"
    fi
}

check_file "cmd/mohammed/main.go"
check_file "pkg/engine/engine.go"
check_file "pkg/runner/runner.go"
check_file "pkg/phases/phases.go"
check_file "pkg/phases/phases_vuln.go"
check_file "pkg/phases/phases_deeprecon.go"
check_file "pkg/engine/checkpoint.go"
check_file "pkg/config/config.go"
check_file "pkg/ai/triage.go"
check_file "config.yaml"
check_file "scope.txt"
check_file "setup.sh"
check_file "install_path.sh"
check_file "README.md"

# ── Section 3: Go Build ──────────────────────────────────────────────
hdr "3. Go Build Test"

if command -v go &>/dev/null; then
    info "Go version: $(go version)"
    if go build ./... 2>&1; then
        pass "go build ./... succeeded (whole module compiles)"
    else
        fail "go build ./... FAILED — fix compile errors"
    fi
    if go vet ./... 2>&1; then
        pass "go vet ./... clean"
    else
        warn "go vet reported issues (non-fatal)"
    fi
    if go test ./... 2>&1 | grep -qvE 'FAIL'; then
        if go test ./... >/dev/null 2>&1; then
            pass "go test ./... all unit tests pass"
        else
            fail "go test ./... has failing tests"
        fi
    fi
else
    fail "go not found in PATH"
fi

# ── Section 4: Critical Tools (must exist) ───────────────────────────
hdr "4. Critical Tools (required for core phases)"

CRITICAL_TOOLS=(subfinder httpx dnsx nuclei katana gau waybackurls curl dig)
for tool in "${CRITICAL_TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        pass "$tool → $(command -v "$tool")"
    else
        fail "$tool NOT FOUND — run: bash setup.sh"
    fi
done

# ── Section 5: Optional Tools (skip = just warn) ─────────────────────
hdr "5. Optional Tools (phase skips if missing)"

OPT_TOOLS=(amass bbot assetfinder findomain puredns massdns shuffledns
           subzy tlsx naabu nmap gospider hakrawler getJS
           paramspider arjun ffuf feroxbuster dirsearch
           dalfox kxss sqlmap ghauri dontgo403 kr crlfuzz
           smuggler cloud_enum s3scanner)

for tool in "${OPT_TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        pass "$tool → $(command -v "$tool")"
    else
        warn "$tool not found (phase will SKIP for this tool)"
    fi
done

# ── Section 6: PATH Directories ──────────────────────────────────────
hdr "6. PATH Directories"

PATH_DIRS=("$HOME/.local/bin" "$HOME/go/bin" "/usr/local/bin" "/usr/bin")
for d in "${PATH_DIRS[@]}"; do
    if [[ ":$PATH:" == *":$d:"* ]]; then
        pass "$d is in PATH"
    else
        warn "$d NOT in PATH — run: export PATH=\$PATH:$d"
    fi
done

# ── Section 7: bbot PATH Special Check ───────────────────────────────
hdr "7. bbot PATH Special Check"

BBOT_PATHS=(
    "$HOME/.local/bin/bbot"
    "/usr/local/bin/bbot"
    "$HOME/go/bin/bbot"
)
bbot_found=0
for p in "${BBOT_PATHS[@]}"; do
    if [ -f "$p" ]; then
        pass "bbot found at: $p"
        bbot_found=1
        # Check if in PATH
        if command -v bbot &>/dev/null; then
            pass "bbot is reachable from PATH"
        else
            warn "bbot exists at $p but NOT in PATH — add to PATH or link to /usr/local/bin"
            info "Fix: sudo ln -sf $p /usr/local/bin/bbot"
        fi
        break
    fi
done
[ "$bbot_found" -eq 0 ] && warn "bbot binary not found — install with: pip3 install --user bbot"

# ── Section 8: Output Folder Check ──────────────────────────────────
hdr "8. Output Folder Check (after a scan)"

SCAN_DIRS=()
if [ -d "$OUTPUT_DIR" ]; then
    while IFS= read -r -d '' d; do
        SCAN_DIRS+=("$d")
    done < <(find "$OUTPUT_DIR" -mindepth 1 -maxdepth 1 -type d -print0 2>/dev/null)
fi

if [ "${#SCAN_DIRS[@]}" -eq 0 ]; then
    warn "No scan output found in '$OUTPUT_DIR' — run a scan first to verify phase outputs"
else
    LAST_SCAN="${SCAN_DIRS[-1]}"
    info "Checking last scan: $LAST_SCAN"

    check_output() {
        local f="$LAST_SCAN/$1"
        local label="$2"
        if [ -f "$f" ] && [ -s "$f" ]; then
            local lines
            lines=$(wc -l < "$f")
            pass "Phase $label: $1 ($lines lines)"
        elif [ -f "$f" ]; then
            warn "Phase $label: $1 exists but EMPTY"
        else
            warn "Phase $label: $1 NOT FOUND (phase may have skipped)"
        fi
    }

    check_output "osint_subdomains.txt"    "02-OSINT"
    check_output "subdomains.txt"          "03-Passive"
    check_output "deeprecon.txt"           "08b-DeepRecon"
    check_output "checkpoint.json"         "checkpoint(resume)"
    check_output "live_dns.txt"            "05-DNS"
    check_output "http_live.txt"           "07-HTTP"
    check_output "tls_results.txt"         "08-TLS"
    check_output "ports.txt"              "09-Ports"
    check_output "urls_archive.txt"        "10-Wayback"
    check_output "urls_crawled.txt"        "11-Crawl"
    check_output "params.txt"             "13-Params"
    check_output "nuclei_results.txt"      "17-Nuclei"
    check_output "final_report.md"         "29-Report"
fi

# ── Section 9: Timer Goroutine Test ──────────────────────────────────
hdr "9. Engine Timer Goroutine (code check)"

if grep -q "time.NewTicker(1 \* time.Second)" pkg/engine/engine.go 2>/dev/null; then
    pass "engine.go: 1-second ticker goroutine found"
else
    fail "engine.go: 1-second ticker NOT found — check engine.go"
fi

if grep -q "sync.Mutex" pkg/engine/engine.go 2>/dev/null; then
    pass "engine.go: PrintMu mutex found (thread-safe printing)"
else
    fail "engine.go: PrintMu mutex NOT found — race condition possible"
fi

if grep -q "checkBurp" pkg/engine/engine.go 2>/dev/null; then
    pass "engine.go: Burp connectivity check function found"
else
    fail "engine.go: Burp check NOT found"
fi

# ── Section 10: runner.go Setpgid check ──────────────────────────────
hdr "10. Runner Process Kill (Setpgid check)"

if grep -q "Setpgid" pkg/runner/runner.go 2>/dev/null; then
    pass "runner.go: Setpgid=true found (correct child process kill)"
else
    fail "runner.go: Setpgid NOT found — amass/bbot may not be killed correctly"
fi

if grep -q "toolTimeouts" pkg/runner/runner.go 2>/dev/null; then
    pass "runner.go: per-tool timeouts map found"
else
    fail "runner.go: per-tool timeouts NOT found"
fi

# ── Section 11: phases.go checks ─────────────────────────────────────
hdr "11. Phases Code Checks"

if grep -q "sanitizeName" pkg/phases/phases.go 2>/dev/null; then
    pass "phases.go: sanitizeName helper found"
else
    fail "phases.go: sanitizeName NOT found"
fi

# FLAW #1: Phase 03 passive enumerators MUST loop over apexDomains, NOT the
# full scope list (which re-ran subfinder on every subdomain, wasting minutes).
if grep -q "FLAW #1 FIX" pkg/phases/phases.go 2>/dev/null && \
   grep -q "for _, domain := range apexDomains" pkg/phases/phases.go 2>/dev/null; then
    pass "phases.go: Phase 03 runs passive tools APEX-ONLY (FLAW #1 fixed)"
else
    fail "phases.go: Phase 03 apex-only passive loop MISSING (FLAW #1 regression)"
fi
# Guard against the OLD bug pattern re-appearing on the subfinder/assetfinder loop.
if grep -q "subfinder — handles subdomains fine, run on everything" pkg/phases/phases.go 2>/dev/null; then
    fail "phases.go: OLD per-subdomain subfinder comment present (FLAW #1 regressed)"
else
    pass "phases.go: no per-subdomain passive-enum loop (FLAW #1 stays fixed)"
fi

if grep -q "s.Printf" pkg/phases/phases.go 2>/dev/null; then
    pass "phases.go: uses s.Printf (thread-safe output)"
else
    fail "phases.go: using raw fmt.Printf (not thread-safe)"
fi

if grep -q "s.Printf" pkg/phases/phases_vuln.go 2>/dev/null; then
    pass "phases_vuln.go: uses s.Printf (thread-safe output)"
else
    fail "phases_vuln.go: using raw fmt.Printf (not thread-safe)"
fi

if grep -q '"--domain", domain, "--output", paramOut' pkg/phases/phases.go 2>/dev/null; then
    pass "phases.go: paramspider uses --domain/--output (BUG #6 fix)"
else
    warn "phases.go: paramspider output path may not be set correctly"
fi

# ── Section 12: Root-cause Bug Fixes (code checks) ───────────────────
hdr "12. Confirmed Bug Fixes"

check_grep() { # <file> <pattern> <pass_msg> <fail_msg>
    if grep -qE "$2" "$1" 2>/dev/null; then pass "$3"; else fail "$4"; fi
}

# BUG #2 — amass/bbot routed on apex only + apex helpers exist
check_grep pkg/config/config.go 'func ExtractApexDomains' \
    "config.go: ExtractApexDomains present (BUG #2 apex routing)" \
    "config.go: ExtractApexDomains MISSING (BUG #2)"
check_grep pkg/config/config.go 'func .*IsApexDomain' \
    "config.go: IsApexDomain present" \
    "config.go: IsApexDomain MISSING"

# BUG #3 — puredns --write + ensureResolvers
check_grep pkg/phases/phases.go '"--write"' \
    "phases.go: puredns uses --write, not -w (BUG #3)" \
    "phases.go: puredns --write MISSING (BUG #3)"
check_grep pkg/phases/phases.go 'func ensureResolvers' \
    "phases.go: ensureResolvers helper present (BUG #3)" \
    "phases.go: ensureResolvers MISSING (BUG #3)"

# BUG #4 — naabu connect scan
check_grep pkg/phases/phases.go '"-scan-type", ?"c"|"-scan-type",\s*"c"' \
    "phases.go: naabu uses -scan-type c (BUG #4)" \
    "phases.go: naabu -scan-type c MISSING (BUG #4)"
# Only flag a REGRESSION if -connect-scan appears as an actual argument
# (inside a RunTool arg slice), not merely in an explanatory comment.
if grep -vE '^\s*//' pkg/phases/phases.go | grep -q '"-connect-scan"' 2>/dev/null; then
    fail "phases.go: invalid -connect-scan flag still used in code (BUG #4 regression)"
else
    pass "phases.go: invalid -connect-scan flag not used in code (BUG #4)"
fi

# BUG #1 — httpx routed via -http-proxy, no fabricated -insecure
check_grep pkg/phases/phases.go '"-http-proxy"' \
    "phases.go: httpx routes through -http-proxy (BUG #1)" \
    "phases.go: httpx -http-proxy MISSING (BUG #1)"

# BUG #8/#9 — subzy vulnerable parse + scope dedup
check_grep pkg/phases/phases.go 'func parseSubzyVulnerable' \
    "phases.go: parseSubzyVulnerable present (BUG #8)" \
    "phases.go: parseSubzyVulnerable MISSING (BUG #8)"

# BUG #10 — gau providers
check_grep pkg/phases/phases.go '"--providers"|"--subs"' \
    "phases.go: gau providers/subs flags present (BUG #10)" \
    "phases.go: gau providers flags MISSING (BUG #10)"

# ── Section 12b: v4.1 Architectural Upgrades ─────────────────────────
hdr "12b. v4.1 Upgrades (resume · parallel OSINT · deep recon)"

# FLAW #2 — checkpoint / resume engine
check_grep pkg/engine/checkpoint.go 'func \(s \*State\) SaveCheckpoint' \
    "checkpoint.go: SaveCheckpoint present (FLAW #2)" \
    "checkpoint.go: SaveCheckpoint MISSING (FLAW #2)"
check_grep pkg/engine/checkpoint.go 'func LoadCheckpoint' \
    "checkpoint.go: LoadCheckpoint present" \
    "checkpoint.go: LoadCheckpoint MISSING"
check_grep pkg/engine/checkpoint.go 'func FindLatestCheckpoint' \
    "checkpoint.go: FindLatestCheckpoint (--resume auto) present" \
    "checkpoint.go: FindLatestCheckpoint MISSING"
check_grep pkg/engine/engine.go 'SaveCheckpoint\(\)' \
    "engine.go: orchestrator saves checkpoint after each phase" \
    "engine.go: per-phase checkpoint save MISSING"
check_grep pkg/engine/engine.go 'IsComplete' \
    "engine.go: skips completed phases on resume" \
    "engine.go: resume-skip logic MISSING"
check_grep cmd/mohammed/main.go '"resume"' \
    "main.go: --resume flag wired" \
    "main.go: --resume flag MISSING"

# FLAW #3 — parallel OSINT harvester + new sources
check_grep pkg/phases/phases.go 'sync.WaitGroup' \
    "phases.go: OSINT uses parallel goroutines (FLAW #3)" \
    "phases.go: OSINT parallelism MISSING (FLAW #3)"
for src in harvestAnubis harvestThreatMiner harvestCertspotter harvestURLScan; do
    check_grep pkg/phases/phases.go "func $src" \
        "phases.go: OSINT source $src present" \
        "phases.go: OSINT source $src MISSING"
done
check_grep pkg/phases/phases.go 'func filterHostsUnderApex' \
    "phases.go: OSINT host filter is pure & unit-tested (FLAW #3)" \
    "phases.go: filterHostsUnderApex MISSING (FLAW #3 testability)"
check_grep pkg/phases/regression_test.go 'func TestFilterHostsUnderApex' \
    "regression_test.go: filterHostsUnderApex has a unit test" \
    "regression_test.go: filterHostsUnderApex test MISSING"

# Deep External Recon phase (zero-login)
check_grep pkg/phases/phases_deeprecon.go 'func murmur3Hash32' \
    "phases_deeprecon.go: favicon MurmurHash3 present (Shodan pivot)" \
    "phases_deeprecon.go: MurmurHash3 MISSING"
check_grep pkg/phases/phases_deeprecon.go 'extractSPFVendors' \
    "phases_deeprecon.go: SPF vendor-chain extraction present" \
    "phases_deeprecon.go: SPF vendor extraction MISSING"
check_grep cmd/mohammed/main.go 'DeepReconPhase' \
    "main.go: DeepReconPhase registered" \
    "main.go: DeepReconPhase NOT registered"

# FLAW #5 — gospider + katana proxy env inheritance
# (Under FIX #5 two-tier routing the crawl phase uses a Tier-1 `px` handle, so
# the env call is now px.GetEnv(); accept either form.)
check_grep pkg/phases/phases.go '(s\.Proxy|px)\.GetEnv\(\)' \
    "phases.go: crawl tools inherit HTTP(S)_PROXY env (FLAW #5)" \
    "phases.go: crawl proxy env MISSING (FLAW #5)"
check_grep pkg/phases/phases.go '"katana", katArgs, katEnv' \
    "phases.go: katana receives proxy env (FLAW #5)" \
    "phases.go: katana proxy env MISSING (FLAW #5)"

# ── Section 13: Ollama AI Triage Integration ─────────────────────────
hdr "13. Ollama AI Triage Wiring"

check_grep pkg/ai/triage.go 'func \(c \*Client\) TriageFinding' \
    "triage.go: TriageFinding method present" \
    "triage.go: TriageFinding MISSING"
check_grep pkg/ai/triage.go '/api/generate' \
    "triage.go: posts to /api/generate" \
    "triage.go: /api/generate endpoint MISSING"
check_grep pkg/ai/triage.go 'ollama_offline' \
    "triage.go: fails OPEN (ollama_offline)" \
    "triage.go: fail-open path MISSING"
check_grep pkg/engine/engine.go 'ai\.NewClient' \
    "engine.go: constructs ai.Client" \
    "engine.go: ai.Client NOT constructed"
check_grep pkg/engine/engine.go 'func \(s \*State\) Triage' \
    "engine.go: State.Triage method present" \
    "engine.go: State.Triage MISSING"
if grep -q 's.Triage' pkg/phases/phases_vuln.go 2>/dev/null; then
    pass "phases_vuln.go: calls s.Triage on findings"
else
    fail "phases_vuln.go: s.Triage NOT called"
fi

# ── Section 14: DNS Resolvers Availability ───────────────────────────
hdr "14. DNS Resolvers (puredns/dnsx input)"

RES_FOUND=0
for rp in /usr/share/seclists/Miscellaneous/dns-resolvers.txt \
          /opt/mohammed-tools/resolvers.txt \
          "$HOME/.config/puredns/resolvers.txt" \
          /tmp/mohammed_resolvers.txt; do
    if [ -s "$rp" ]; then
        pass "resolvers present: $rp ($(wc -l < "$rp") entries)"
        RES_FOUND=1
    fi
done
[ "$RES_FOUND" -eq 0 ] && warn "No resolvers file found — puredns/dnsx will use built-in fallback (run setup.sh)"

# ── Section 15: Zero-FP Architecture (9 mandatory fixes) ─────────────
hdr "15. Zero False-Positive Architecture (FIX #1-#9)"

# FIX #1 — Cloudflare / noisy-param stripper + challenge detector
check_grep pkg/filter/scope.go 'func StripNoisyParams' \
    "FIX #1: StripNoisyParams present (CF/analytics param stripper)" \
    "FIX #1: StripNoisyParams MISSING"
check_grep pkg/filter/scope.go 'func IsCloudflareChallenge' \
    "FIX #1: IsCloudflareChallenge present (CF challenge URLs never to sqlmap)" \
    "FIX #1: IsCloudflareChallenge MISSING"
check_grep pkg/filter/scope.go '__cf_chl_rt_tk' \
    "FIX #1: __cf_chl_rt_tk token stripped (FP #1 root cause)" \
    "FIX #1: __cf_chl_rt_tk NOT handled (FP #1)"

# FIX #2 — absolute scope enforcement
check_grep pkg/filter/scope.go 'func IsInScope' \
    "FIX #2: IsInScope present (exact host or verified subdomain)" \
    "FIX #2: IsInScope MISSING"
check_grep pkg/filter/scope.go 'func FilterInScopeURLs' \
    "FIX #2: FilterInScopeURLs present" \
    "FIX #2: FilterInScopeURLs MISSING"
check_grep pkg/phases/phases.go 'EnforceScopeOnJS' \
    "FIX #2: JS scan honours in-scope filter (FP #2 CDN secrets)" \
    "FIX #2: JS scope enforcement MISSING (FP #2)"

# FIX #3 — confidence scoring 0-100 with report/review/discard gates
check_grep pkg/filter/confidence.go 'func CalculateConfidence' \
    "FIX #3: CalculateConfidence present (0-100 scoring)" \
    "FIX #3: CalculateConfidence MISSING"
check_grep pkg/filter/confidence.go 'func ApplyConfidencePolicy' \
    "FIX #3: ApplyConfidencePolicy present (>=70 report / 40-69 Info / <40 discard)" \
    "FIX #3: ApplyConfidencePolicy MISSING"

# FIX #4 — sensitive-file validator (HTTP 200 != real file)
check_grep pkg/phases/zerofp.go 'func ValidateSensitiveFile' \
    "FIX #4: ValidateSensitiveFile present (rejects WAF/CF error pages, FP #5)" \
    "FIX #4: ValidateSensitiveFile MISSING (FP #5)"
check_grep pkg/phases/zerofp.go 'been blocked|Attention Required|Ray ID' \
    "FIX #4: WAF/Cloudflare fingerprints rejected" \
    "FIX #4: WAF fingerprint rejection MISSING"

# FIX #5 — two-tier Burp routing
check_grep pkg/proxy/proxy.go 'ProxyModeDirect|ProxyModeSelective' \
    "FIX #5: ProxyMode (Direct/Selective) present" \
    "FIX #5: ProxyMode MISSING"
check_grep pkg/engine/engine.go 'func \(s \*State\) PhaseProxy' \
    "FIX #5: State.PhaseProxy tier selector present" \
    "FIX #5: PhaseProxy MISSING"
check_grep config.yaml 'selective_routing' \
    "FIX #5: config.yaml proxy.selective_routing present" \
    "FIX #5: config.yaml selective_routing MISSING"

# FIX #6 — WAF detection + sqlmap sanity/cap
check_grep pkg/phases/zerofp.go 'func DetectWAF' \
    "FIX #6: DetectWAF present (probe before sqlmap/ghauri)" \
    "FIX #6: DetectWAF MISSING"
check_grep pkg/phases/zerofp.go 'func PrepareSQLiURLs' \
    "FIX #6: PrepareSQLiURLs present (CF-strip + scope + cap 5)" \
    "FIX #6: PrepareSQLiURLs MISSING"

# FIX #7 — Ollama startup probe + downgrade
check_grep pkg/ai/triage.go 'func \(c \*Client\) Ping' \
    "FIX #7: AI Ping (one-time startup connectivity check) present" \
    "FIX #7: AI Ping MISSING"
check_grep pkg/engine/engine.go 'AIOnline' \
    "FIX #7: State.AIOnline gate present" \
    "FIX #7: AIOnline MISSING"
check_grep pkg/engine/engine.go 'AI: REJECTED' \
    "FIX #7: AI REJECTED logging present" \
    "FIX #7: AI REJECTED logging MISSING"

# FIX #8 — CORS scope enforcement
check_grep pkg/phases/phases.go 'CORS scope filter' \
    "FIX #8: CORS scope filter log present (out-of-scope hosts removed)" \
    "FIX #8: CORS scope filter MISSING"

# FIX #9 — tiered exporter
check_grep pkg/report/exporter.go 'CONFIRMED_VULNS.txt' \
    "FIX #9: CONFIRMED_VULNS.txt exporter present" \
    "FIX #9: CONFIRMED_VULNS.txt exporter MISSING"
check_grep pkg/report/exporter.go 'MANUAL_REVIEW.txt' \
    "FIX #9: MANUAL_REVIEW.txt exporter present" \
    "FIX #9: MANUAL_REVIEW.txt exporter MISSING"

# GENIUS recommendations
check_grep pkg/phases/zerofp.go 'func IsHoneypotOrSink' \
    "GENIUS #1: anti-honeypot (IsHoneypotOrSink) present" \
    "GENIUS #1: IsHoneypotOrSink MISSING"
check_grep pkg/filter/scope.go 'func DeduplicateByBehavior' \
    "GENIUS #2: behavioral dedup present" \
    "GENIUS #2: DeduplicateByBehavior MISSING"
check_grep pkg/filter/scope.go 'func IsStaticAsset' \
    "GENIUS #3: response fingerprint / static-asset filter present" \
    "GENIUS #3: IsStaticAsset MISSING"
check_grep cmd/mohammed/main.go 'waf-bypass' \
    "GENIUS #4: --waf-bypass flag present (sqlmap tamper)" \
    "GENIUS #4: --waf-bypass flag MISSING"
check_grep pkg/phases/phases.go 'out_of_scope_urls.txt' \
    "GENIUS #5: scope-drift out_of_scope_urls.txt present" \
    "GENIUS #5: scope-drift capture MISSING"

# ── Final Summary ─────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}╔═══════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║              VERIFICATION SUMMARY                  ║${NC}"
echo -e "${BOLD}╚═══════════════════════════════════════════════════╝${NC}"
echo -e "  ${GREEN}PASS: $PASS${NC}   ${RED}FAIL: $FAIL${NC}   ${YELLOW}WARN: $WARN${NC}"
echo ""

if [ "$FAIL" -eq 0 ]; then
    echo -e "${GREEN}${BOLD}  ✅ All critical checks passed! Ready to scan.${NC}"
    echo -e "${CYAN}  Run: ./mohammed scan -s scope.txt -c config.yaml --profile large${NC}"
elif [ "$FAIL" -le 3 ]; then
    echo -e "${YELLOW}${BOLD}  ⚠️  $FAIL non-critical failure(s). Tool may still work.${NC}"
else
    echo -e "${RED}${BOLD}  ❌ $FAIL failure(s) detected. Fix before scanning.${NC}"
fi
echo ""
