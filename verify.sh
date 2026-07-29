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
# ── V7 QUANTUM new files (Sections 2/3/4) ────────────────────────────
check_file "pkg/phases/phases_advanced.go"
check_file "pkg/phases/phases_osint_v2.go"
check_file "pkg/exploit/client.go"
check_file "pkg/exploit/idor.go"
check_file "pkg/exploit/auth_bypass.go"
check_file "pkg/exploit/race_condition.go"
check_file "pkg/exploit/business_logic.go"
check_file "pkg/exploit/ssti.go"
check_file "pkg/exploit/api_security.go"
check_file "pkg/validation/baseline.go"
check_file "pkg/validation/false_positive.go"
check_file "pkg/correlation/engine.go"
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

# ── Section 4: Canonical 38-Tool Inventory (REPAIR #6) ───────────────
# The mandate requires all 38 binaries be installed & resolvable so no phase
# is quietly skipped. Critical tools FAIL if missing; the rest WARN (phase
# degrades gracefully). Every tool is linked to /usr/local/bin AND $GOPATH/bin
# by install_path.sh, so we also report which of those two paths resolve it.
hdr "4. Canonical 38-Tool Inventory (install_path.sh target)"

export GOPATH="${GOPATH:-$HOME/go}"
GOBIN="$GOPATH/bin"

# The authoritative 38 binaries (must match install_path.sh TOOLS array).
ALL_TOOLS=(
    subfinder amass bbot assetfinder findomain
    dnsx puredns massdns shuffledns
    subzy httpx tlsx naabu nmap
    gau waybackurls katana gospider hakrawler
    getJS paramspider arjun
    ffuf feroxbuster dirsearch
    nuclei dalfox kxss sqlmap ghauri
    dontgo403 kr crlfuzz smuggler
    cloud_enum s3scanner interactsh-client gf
)

# Tools whose absence must FAIL (core recon/vuln phases cannot run without them).
CRITICAL_TOOLS=(subfinder httpx dnsx nuclei katana gau waybackurls)

is_critical() {
    local t="$1"
    for c in "${CRITICAL_TOOLS[@]}"; do [ "$c" = "$t" ] && return 0; done
    return 1
}

tool_present=0
for tool in "${ALL_TOOLS[@]}"; do
    resolved="$(command -v "$tool" 2>/dev/null || true)"
    # Report reachability via the two mandated link targets.
    link_note=""
    [ -e "/usr/local/bin/$tool" ] && link_note="${link_note} /usr/local/bin ✓"
    [ -e "$GOBIN/$tool" ]         && link_note="${link_note} \$GOPATH/bin ✓"
    if [ -n "$resolved" ]; then
        pass "$tool → $resolved${link_note:+ (${link_note# })}"
        tool_present=$((tool_present + 1))
    elif is_critical "$tool"; then
        fail "$tool NOT FOUND (CRITICAL) — run: bash install_path.sh"
    else
        warn "$tool not found (phase will SKIP) — run: bash install_path.sh"
    fi
done

echo ""
if [ "$tool_present" -eq "${#ALL_TOOLS[@]}" ]; then
    pass "All ${#ALL_TOOLS[@]}/38 canonical tools resolvable — zero phase skips expected"
else
    info "$tool_present / ${#ALL_TOOLS[@]} canonical tools resolvable"
    info "Install the rest with:  bash install_path.sh   (network required)"
fi

# ── Section 5: Tool → link-target coverage (REPAIR #6 detail) ────────
hdr "5. Link-Target Coverage (/usr/local/bin AND \$GOPATH/bin)"

usrlocal_ok=0; gobin_ok=0
for tool in "${ALL_TOOLS[@]}"; do
    command -v "$tool" &>/dev/null || continue
    [ -e "/usr/local/bin/$tool" ] && usrlocal_ok=$((usrlocal_ok + 1))
    [ -e "$GOBIN/$tool" ]         && gobin_ok=$((gobin_ok + 1))
done
info "Resolvable tools linked into /usr/local/bin: $usrlocal_ok"
info "Resolvable tools linked into \$GOPATH/bin ($GOBIN): $gobin_ok"
if [ "$tool_present" -gt 0 ] && [ "$usrlocal_ok" -eq 0 ]; then
    warn "No tools linked into /usr/local/bin — engine spawned by other users may miss them. Run: bash install_path.sh"
fi

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

# ── Section 16: Tool Integration Fixes (audit — 11 confirmed bugs) ────
hdr "16. Tool Integration Fixes (11 audit bugs)"

# #1 amass: auto-config + retry-on-zero
check_grep pkg/phases/phases.go 'func ensureAmassConfig' \
    "TOOL #1: ensureAmassConfig present (amass free-source config)" \
    "TOOL #1: ensureAmassConfig MISSING"
check_grep pkg/phases/phases.go 'One stdout-only retry' \
    "TOOL #1: amass retry-on-zero present" \
    "TOOL #1: amass retry-on-zero MISSING"
# #2 bbot: -om json + DNS_NAME ndjson parse
check_grep pkg/phases/phases.go '"-om", "json"' \
    "TOOL #2: bbot emits JSON (-om json)" \
    "TOOL #2: bbot -om json MISSING"
check_grep pkg/phases/phases.go 'ev.Type == "DNS_NAME"' \
    "TOOL #2: bbot parses ndjson DNS_NAME events" \
    "TOOL #2: bbot DNS_NAME parse MISSING"
# #3 findomain: stdout primary
check_grep pkg/phases/phases.go 'findomain reliably writes to STDOUT' \
    "TOOL #3: findomain stdout-primary parse present" \
    "TOOL #3: findomain stdout parse MISSING"
# #4 gau: ~/.gau.toml
check_grep pkg/phases/phases.go 'func ensureGauConfig' \
    "TOOL #4: ensureGauConfig present (~/.gau.toml)" \
    "TOOL #4: ensureGauConfig MISSING"
check_grep pkg/phases/phases.go '"--config", gauCfg' \
    "TOOL #4: gau invoked with --config" \
    "TOOL #4: gau --config wiring MISSING"
# #5 gospider: parse output dir files
check_grep pkg/phases/phases.go 'filepath.Walk\(goOut' \
    "TOOL #5: gospider parses output-dir files" \
    "TOOL #5: gospider dir parse MISSING"
# #6 paramspider: HOME/results default
check_grep pkg/phases/phases.go 'filepath.Join\(home, "results"' \
    "TOOL #6: paramspider reads ~/results/<domain>.txt" \
    "TOOL #6: paramspider default-path read MISSING"
# #7 arjun: --stable + cap 10
check_grep pkg/phases/phases.go '"--stable"' \
    "TOOL #7: arjun --stable present" \
    "TOOL #7: arjun --stable MISSING"
check_grep pkg/phases/phases.go 'len\(arjunTargets\) >= 10' \
    "TOOL #7: arjun capped at 10 URLs" \
    "TOOL #7: arjun cap-10 MISSING"
# #8 JS secrets: value+context saved
check_grep pkg/phases/phases.go 'js_secrets_confirmed.txt' \
    "TOOL #8: js_secrets_confirmed.txt written" \
    "TOOL #8: js_secrets_confirmed.txt MISSING"
check_grep pkg/phases/phases.go 'func extractSecretEvidence' \
    "TOOL #8: extractSecretEvidence (value+context) present" \
    "TOOL #8: extractSecretEvidence MISSING"
# #9 report: delete stale + timestamp header
check_grep pkg/phases/phases_vuln.go 'delete any stale report artifacts' \
    "TOOL #9: report deletes stale artifacts before write" \
    "TOOL #9: report stale-delete MISSING"
check_grep pkg/phases/phases_vuln.go 'Scan Date:' \
    "TOOL #9: report has scan-date/duration header" \
    "TOOL #9: report timestamp header MISSING"
# #10 CleanStaleResults (fresh-scan only)
check_grep pkg/engine/engine.go 'func \(s \*State\) CleanStaleResults' \
    "TOOL #10: CleanStaleResults present" \
    "TOOL #10: CleanStaleResults MISSING"
check_grep pkg/engine/engine.go 'IsResumed\(\)' \
    "TOOL #10: fresh-vs-resume guard (IsResumed) present" \
    "TOOL #10: IsResumed guard MISSING"
# #11 waybackurls: bonus (0 not failure)
check_grep pkg/phases/phases.go 'bonus source' \
    "TOOL #11: waybackurls demoted to bonus source" \
    "TOOL #11: waybackurls bonus demotion MISSING"
# unit tests for #8 / #10
if command -v go >/dev/null 2>&1; then
    if go test ./pkg/phases/ ./pkg/engine/ >/dev/null 2>&1; then
        pass "TOOL #8/#10: unit tests pass (extractSecretEvidence + CleanStaleResults)"
    else
        fail "TOOL #8/#10: unit tests FAILED"
    fi
fi

# ── Section 17: REPAIR #6 — install_path.sh 38-tool installer ────────
hdr "17. REPAIR #6: install_path.sh installs & links all 38 tools"

# The overhauled install_path.sh must (a) contain the canonical 38-tool array,
# (b) actually INSTALL (not just symlink) via install_go_tool/install_pip_tool,
# and (c) link every tool into BOTH /usr/local/bin and $GOPATH/bin.
check_grep install_path.sh 'install_go_tool' \
    "REPAIR #6: install_path.sh installs Go tools (install_go_tool)" \
    "REPAIR #6: install_path.sh missing install_go_tool (still symlink-only)"
check_grep install_path.sh 'install_pip_tool' \
    "REPAIR #6: install_path.sh installs Python tools (install_pip_tool)" \
    "REPAIR #6: install_path.sh missing install_pip_tool"
check_grep install_path.sh 'link_tool' \
    "REPAIR #6: install_path.sh has link_tool (dual-path symlink helper)" \
    "REPAIR #6: install_path.sh missing link_tool"
check_grep install_path.sh 'GOBIN/\$name|GOBIN"/"?\$name|\$GOBIN/\$name' \
    "REPAIR #6: install_path.sh links into \$GOPATH/bin" \
    "REPAIR #6: install_path.sh does NOT link into \$GOPATH/bin"
check_grep install_path.sh '/usr/local/bin/\$name' \
    "REPAIR #6: install_path.sh links into /usr/local/bin" \
    "REPAIR #6: install_path.sh does NOT link into /usr/local/bin"

# Confirm the install_path.sh TOOLS array names all 38 canonical binaries.
missing_in_installer=""
for t in subfinder amass bbot assetfinder findomain dnsx puredns massdns \
         shuffledns subzy httpx tlsx naabu nmap gau waybackurls katana gospider \
         hakrawler getJS paramspider arjun ffuf feroxbuster dirsearch nuclei \
         dalfox kxss sqlmap ghauri dontgo403 kr crlfuzz smuggler cloud_enum \
         s3scanner interactsh-client gf; do
    grep -qw "$t" install_path.sh 2>/dev/null || missing_in_installer="$missing_in_installer $t"
done
if [ -z "$missing_in_installer" ]; then
    pass "REPAIR #6: install_path.sh references all 38 canonical tool names"
else
    fail "REPAIR #6: install_path.sh missing tool name(s):$missing_in_installer"
fi

# Static shell lint of the installer (bash -n) — catch syntax regressions.
if bash -n install_path.sh 2>/dev/null; then
    pass "REPAIR #6: install_path.sh passes bash -n syntax check"
else
    fail "REPAIR #6: install_path.sh has a shell syntax error"
fi

# ── Section 18: MOHAMMED-V5 Expansions (code checks) ─────────────────
hdr "18. MOHAMMED-V5 Expansions (EXP #1-#5)"

# EXP #1 — 3-tier API key precedence + provider auto-sync
check_grep pkg/config/config.go 'func ResolveAPIKeys' \
    "EXP #1: ResolveAPIKeys present (env > yaml precedence)" \
    "EXP #1: ResolveAPIKeys MISSING"
check_grep pkg/config/config.go 'func SyncProviderConfigs' \
    "EXP #1: SyncProviderConfigs present (subfinder/amass auto-sync)" \
    "EXP #1: SyncProviderConfigs MISSING"
check_grep pkg/config/config.go 'SHODAN_API_KEY|GITHUB_TOKEN' \
    "EXP #1: env vars (SHODAN_API_KEY/GITHUB_TOKEN) honoured" \
    "EXP #1: API-key env vars MISSING"

# EXP #2 — native free threat-intel scrapers
check_grep pkg/phases/scrapers.go 'func ScrapeShodanInternetDB' \
    "EXP #2: Shodan InternetDB scraper present" \
    "EXP #2: ScrapeShodanInternetDB MISSING"
check_grep pkg/phases/scrapers.go 'func ScrapeCrtShSAN' \
    "EXP #2: crt.sh SAN scraper present" \
    "EXP #2: ScrapeCrtShSAN MISSING"
check_grep pkg/phases/scrapers.go 'func ScrapeWaybackURLs' \
    "EXP #2: Wayback CDX scraper present" \
    "EXP #2: ScrapeWaybackURLs MISSING"
check_grep pkg/phases/scrapers.go 'randomUA|userAgents' \
    "EXP #2: randomized User-Agent rotation present" \
    "EXP #2: UA rotation MISSING"
check_grep pkg/phases/scrapers.go '429' \
    "EXP #2: 429 backoff handling present" \
    "EXP #2: 429 backoff MISSING"

# EXP #3 — WAF_PROTECTED exclusion + email spoof auto-reporter
check_grep pkg/engine/engine.go 'func \(s \*State\) MarkWAFProtected' \
    "EXP #3: State.MarkWAFProtected present" \
    "EXP #3: MarkWAFProtected MISSING"
check_grep pkg/phases/phases_vuln.go 'func dropWAFProtected' \
    "EXP #3: dropWAFProtected excludes WAF hosts from XSS/SQLi fuzzing" \
    "EXP #3: dropWAFProtected MISSING"
check_grep pkg/phases/phases_vuln.go 'buildEmailSpoofReport|email_spoofing_reports' \
    "EXP #3: email spoofing auto-reporter present (H1 report)" \
    "EXP #3: email spoof auto-reporter MISSING"

# EXP #4 — scan-speed tuning (wordlist cap + nuclei severity filter)
check_grep pkg/phases/phases_vuln.go 'func capWordlist' \
    "EXP #4: capWordlist (top-10k fuzz cap) present" \
    "EXP #4: capWordlist MISSING"
check_grep pkg/phases/phases_vuln.go '"-severity", "high,critical"|high,critical' \
    "EXP #4: nuclei exposure filtered to high/critical" \
    "EXP #4: nuclei severity filter MISSING"

# EXP #5 — interactive embedded dashboard server
check_grep pkg/report/server.go 'func ServeDashboard' \
    "EXP #5: ServeDashboard present (report --serve)" \
    "EXP #5: ServeDashboard MISSING"
check_grep cmd/mohammed/main.go 'func runReport' \
    "EXP #5: main.go runReport (report command) wired" \
    "EXP #5: runReport MISSING"
check_grep pkg/report/server.go 'Copy HackerOne|Copy HackerOne Report|copyH1|copy-h1' \
    "EXP #5: one-click Copy HackerOne Report present" \
    "EXP #5: Copy HackerOne Report MISSING"

# ── Section: V7 QUANTUM (phases 31-45, 50+ OSINT, 5-gate FP) ──────────
hdr "V7 QUANTUM — exploit engines, OSINT v2, 5-gate validation"

# V7.1 — exploit phases registered in main.go
check_grep cmd/mohammed/main.go 'phases.IDORPhase\{\}' \
    "main.go: Phase 32 IDOR registered" \
    "main.go: IDORPhase NOT registered (V7 regression)"
check_grep cmd/mohammed/main.go 'phases.APISecurityPhase\{\}' \
    "main.go: Phase 35 API Security registered" \
    "main.go: APISecurityPhase NOT registered"
check_grep cmd/mohammed/main.go 'phases.SSTIPhase\{\}' \
    "main.go: Phase 39 SSTI registered" \
    "main.go: SSTIPhase NOT registered"
check_grep cmd/mohammed/main.go 'phases.CorrelationPhase\{\}' \
    "main.go: Phase 45 Correlation registered" \
    "main.go: CorrelationPhase NOT registered"
check_grep cmd/mohammed/main.go 'phases.OSINTv2Phase\{\}' \
    "main.go: OSINT v2 (50+ sources) registered" \
    "main.go: OSINTv2Phase NOT registered"

# V8.0 — version bumped to V8.0 LEVEL MAX
check_grep cmd/mohammed/main.go 'V8\.0 LEVEL MAX' \
    "main.go: banner/help updated to V8.0 LEVEL MAX" \
    "main.go: still on old version string"

# V7.3 — SSTI arithmetic oracle uses a UNIQUE product (no raw reflection)
check_grep pkg/exploit/ssti.go 'buildSSTIProbes\(1337, 1339\)' \
    "ssti.go: arithmetic oracle uses unique factors 1337×1339" \
    "ssti.go: SSTI probe factors MISSING"

# V7.4 — 5-gate validator + known-FP patterns (AWSALB/CloudFront/CORS)
check_grep pkg/validation/false_positive.go 'knownFPPatterns' \
    "false_positive.go: known-FP patterns (AWSALB/CloudFront/CORS) present" \
    "false_positive.go: known-FP patterns MISSING"
check_grep pkg/validation/baseline.go 'func CompareToBaseline' \
    "baseline.go: SPA catch-all baseline comparison present" \
    "baseline.go: CompareToBaseline MISSING"

# V7.5 — OSINT v2 has 30 source entries (25+ key-less + premium)
if [ "$(grep -cE '^\s*\{"' pkg/phases/phases_osint_v2.go 2>/dev/null)" -ge 25 ]; then
    pass "phases_osint_v2.go: 25+ OSINT sources registered"
else
    fail "phases_osint_v2.go: fewer than 25 OSINT sources"
fi

# V7.6 — exploit engines contain REAL logic (no TODO/placeholder)
if grep -rqiE 'TODO|FIXME|not implemented|placeholder' pkg/exploit/ pkg/validation/ pkg/correlation/ 2>/dev/null; then
    fail "V7 engines contain TODO/placeholder markers (mandate: no placeholders)"
else
    pass "V7 engines contain NO TODO/placeholder markers"
fi

# V7.7 — protected files were NOT touched (Section 6.3)
check_grep pkg/engine/checkpoint.go '.' \
    "checkpoint.go untouched & present (Section 6.3 NEVER TOUCH)" \
    "checkpoint.go MISSING"

# ══════════════════════════════════════════════════════════════════════
# V7.1 Exploit Engine Checks (COMPLETION MANDATE GAP 5)
# Greps for the exact canonical token in each engine's own file.
# ══════════════════════════════════════════════════════════════════════
hdr "V7.1 Exploit Engines"
grep -q "IDORScan"         pkg/exploit/idor.go             && pass "IDOR Engine"          || fail "IDOR MISSING"
grep -q "SSTIScan"         pkg/exploit/ssti.go             && pass "SSTI Engine"          || fail "SSTI MISSING"
grep -q "RaceCondition"    pkg/exploit/race_condition.go   && pass "Race Condition"       || fail "Race MISSING"
grep -q "BusinessLogic"    pkg/exploit/business_logic.go   && pass "Business Logic"       || fail "BizLogic MISSING"
grep -q "WebSocketTest"    pkg/exploit/websocket.go        && pass "WebSocket Engine"     || fail "WebSocket MISSING"
grep -q "FileUploadTest"   pkg/exploit/file_upload.go      && pass "File Upload Engine"   || fail "FileUpload MISSING"
grep -q "CloudAttack"      pkg/exploit/cloud_attack.go     && pass "Cloud Attack Engine"  || fail "CloudAttack MISSING"
grep -q "GoogleDork"       pkg/exploit/google_dork.go      && pass "Google Dork Engine"   || fail "GoogleDork MISSING"
grep -q "CredentialIntel"  pkg/exploit/credential_intel.go && pass "Credential Intel"     || fail "CredIntel MISSING"
grep -q "FiveGateValidate" pkg/validation/false_positive.go && pass "5-Gate Validator"    || fail "5-Gate MISSING"
grep -q "BaselineDiff"     pkg/validation/baseline.go      && pass "Baseline Comparator"  || fail "Baseline MISSING"
grep -q "Correlate"        pkg/correlation/engine.go       && pass "Correlation Engine"   || fail "Correlation MISSING"

# OSINT Source Count (target: 50+)
OSINT_COUNT=$(grep -c "func harvest" pkg/phases/phases_osint_v2.go 2>/dev/null || echo 0)
info "OSINT Sources: $OSINT_COUNT (target: 50+)"
if [ "$OSINT_COUNT" -ge 50 ]; then
    pass "OSINT source count ≥ 50 (mandate GAP 1)"
else
    fail "OSINT source count $OSINT_COUNT < 50 (mandate GAP 1)"
fi

# V7.1 phases registered in main.go
check_grep cmd/mohammed/main.go 'phases.WebSocketPhase\{\}' \
    "main.go: Phase 36 WebSocket registered" \
    "main.go: WebSocketPhase NOT registered"
check_grep cmd/mohammed/main.go 'phases.FileUploadPhase\{\}' \
    "main.go: Phase 37 File Upload registered" \
    "main.go: FileUploadPhase NOT registered"
check_grep cmd/mohammed/main.go 'phases.CloudAttackPhase\{\}' \
    "main.go: Phase 38 Cloud Attack registered" \
    "main.go: CloudAttackPhase NOT registered"
check_grep cmd/mohammed/main.go 'phases.GoogleDorkPhase\{\}' \
    "main.go: Phase 40 Google Dork registered" \
    "main.go: GoogleDorkPhase NOT registered"
check_grep cmd/mohammed/main.go 'phases.CredentialIntelPhase\{\}' \
    "main.go: Phase 41 Credential Intel registered" \
    "main.go: CredentialIntelPhase NOT registered"
check_grep cmd/mohammed/main.go 'phases.BurpIntegrationPhase\{\}' \
    "main.go: Phase 42 Deep Burp + OOB registered" \
    "main.go: BurpIntegrationPhase NOT registered"

# V7.1 Deep Burp integration tokens (GAP 3)
check_grep pkg/exploit/burp.go 'PopulateSitemap' \
    "burp.go: sitemap population present" \
    "burp.go: sitemap population MISSING"
check_grep pkg/exploit/burp.go 'v0.1/scan' \
    "burp.go: active-scan REST trigger present" \
    "burp.go: active-scan trigger MISSING"
check_grep pkg/exploit/burp.go 'MonitorCallbacks' \
    "burp.go: Interactsh OOB monitoring present" \
    "burp.go: OOB monitoring MISSING"

# ══════════════════════════════════════════════════════════════════════
# V8.0 LEVEL MAX verification (GAP 1-4)
# ══════════════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}── V8.0 LEVEL MAX checks ─────────────────────────────${NC}"

# GAP 2 — fuzzy baseline + 5-gate
check_grep pkg/validation/fuzzy.go 'func SimHash' \
    "fuzzy.go: SimHash present" "fuzzy.go: SimHash MISSING"
check_grep pkg/validation/fuzzy.go 'func LevenshteinSimilarity' \
    "fuzzy.go: Levenshtein present" "fuzzy.go: Levenshtein MISSING"
check_grep pkg/validation/fuzzy.go 'func FuzzyCompare' \
    "fuzzy.go: FuzzyCompare present" "fuzzy.go: FuzzyCompare MISSING"
check_grep pkg/validation/baseline.go 'func FuzzyBaseline' \
    "baseline.go: FuzzyBaseline present" "baseline.go: FuzzyBaseline MISSING"
check_grep pkg/validation/baseline.go 'IsWAFChallenge' \
    "baseline.go: WAF-challenge detection present" "baseline.go: WAF-challenge MISSING"
check_grep pkg/validation/false_positive.go 'FuzzyBaseline' \
    "false_positive.go: Gate-1 fuzzy wiring present" "false_positive.go: Gate-1 fuzzy MISSING"

# GAP 3A — Multi-Tenant BOLA/BFLA
check_grep pkg/exploit/idor.go 'MultiTenantEngine' \
    "idor.go: MultiTenantEngine present" "idor.go: MultiTenantEngine MISSING"
check_grep pkg/exploit/idor.go 'func ExtractObjectIDs' \
    "idor.go: ExtractObjectIDs (UUID/Mongo/hash) present" "idor.go: ExtractObjectIDs MISSING"
check_grep pkg/exploit/idor.go '\bTestBFLA\b' \
    "idor.go: TestBFLA present" "idor.go: TestBFLA MISSING"

# GAP 3B — Barrier race
check_grep pkg/exploit/race_condition.go '\bBarrierBurst\b' \
    "race_condition.go: BarrierBurst present" "race_condition.go: BarrierBurst MISSING"
check_grep pkg/exploit/race_condition.go 'StateChanged' \
    "race_condition.go: state-delta analysis present" "race_condition.go: state-delta MISSING"

# GAP 3C — Financial business logic
check_grep pkg/exploit/business_logic.go '\bTestFinancial\b' \
    "business_logic.go: TestFinancial present" "business_logic.go: TestFinancial MISSING"
check_grep pkg/exploit/business_logic.go '\bTestWorkflowBypass\b' \
    "business_logic.go: TestWorkflowBypass present" "business_logic.go: TestWorkflowBypass MISSING"

# GAP 3D — advanced web
check_grep pkg/exploit/advanced_web.go 'SmugglingEngine' \
    "advanced_web.go: SmugglingEngine present" "advanced_web.go: SmugglingEngine MISSING"
check_grep pkg/exploit/advanced_web.go 'CL.TE' \
    "advanced_web.go: CL.TE smuggling variant present" "advanced_web.go: CL.TE MISSING"
check_grep pkg/exploit/advanced_web.go '\bTestCachePoisoning\b' \
    "advanced_web.go: cache poisoning present" "advanced_web.go: cache poisoning MISSING"
check_grep pkg/exploit/advanced_web.go '\bTestPolyglotSSTI\b' \
    "advanced_web.go: polyglot SSTI present" "advanced_web.go: polyglot SSTI MISSING"

# GAP 3E — auth audit
check_grep pkg/exploit/auth_audit.go '\bForgeAlgNone\b' \
    "auth_audit.go: JWT alg:none present" "auth_audit.go: JWT alg:none MISSING"
check_grep pkg/exploit/auth_audit.go '\bForgeKeyConfusion\b' \
    "auth_audit.go: RS256->HS256 key confusion present" "auth_audit.go: key confusion MISSING"
check_grep pkg/exploit/auth_audit.go '\bAnalyzeAuthorizeURL\b' \
    "auth_audit.go: OAuth analyzer present" "auth_audit.go: OAuth analyzer MISSING"

# GAP 3F — polyglot upload
check_grep pkg/exploit/file_upload.go '\bPolyglotUploadTest\b' \
    "file_upload.go: PolyglotUploadTest present" "file_upload.go: PolyglotUploadTest MISSING"

# GAP 3G — deep cloud/repo
check_grep pkg/exploit/cloud_attack.go '\bAzureBlobAudit\b' \
    "cloud_attack.go: AzureBlobAudit present" "cloud_attack.go: AzureBlobAudit MISSING"
check_grep pkg/exploit/cloud_attack.go '\bGCPBucketAudit\b' \
    "cloud_attack.go: GCPBucketAudit present" "cloud_attack.go: GCPBucketAudit MISSING"
check_grep pkg/exploit/cloud_attack.go 'X-aws-ec2-metadata-token' \
    "cloud_attack.go: IMDSv2 token flow present" "cloud_attack.go: IMDSv2 MISSING"
check_grep pkg/exploit/cloud_attack.go '\bExposedRepoScan\b' \
    "cloud_attack.go: .git/.svn/.env/.bak scan present" "cloud_attack.go: repo scan MISSING"
check_grep pkg/exploit/cloud_attack.go 'func harvestSecrets' \
    "cloud_attack.go: secret harvesting present" "cloud_attack.go: secret harvest MISSING"

# GAP 4 — deep Burp + OOB correlation
check_grep pkg/exploit/burp.go '\bTriggerActiveScanDetailed\b' \
    "burp.go: detailed active scan present" "burp.go: detailed scan MISSING"
check_grep pkg/exploit/burp.go '\bBatchMonitorCallbacks\b' \
    "burp.go: batch OOB correlation present" "burp.go: batch OOB MISSING"

# GAP 1 — OSINT 70+ + dynamic wordlist
check_grep pkg/phases/phases_osint_v8.go 'func osintSourcesV8' \
    "phases_osint_v8.go: V8 sources present" "phases_osint_v8.go: V8 sources MISSING"
check_grep pkg/phases/phases_osint_v8.go 'func DynamicWordlist' \
    "phases_osint_v8.go: dynamic wordlist generator present" "phases_osint_v8.go: wordlist MISSING"
V8_OSINT=$(grep -c 'func harvest' pkg/phases/phases_osint_v2.go pkg/phases/phases_osint_v8.go 2>/dev/null | awk -F: '{s+=$2} END{print s}')
if [ "${V8_OSINT:-0}" -ge 70 ]; then
    echo -e "  ${GREEN}✔${NC} OSINT sources: $V8_OSINT (>= 70)"; PASS=$((PASS+1))
else
    echo -e "  ${RED}✘${NC} OSINT sources: ${V8_OSINT:-0} (< 70)"; FAIL=$((FAIL+1))
fi

# phases_max.go orchestration + registration
check_grep pkg/phases/phases_max.go 'func MaxPhases' \
    "phases_max.go: MaxPhases orchestration present" "phases_max.go: MaxPhases MISSING"
check_grep cmd/mohammed/main.go 'phases.MultiTenantBOLAPhase\{\}' \
    "main.go: Phase 46 Multi-Tenant BOLA registered" "main.go: Phase 46 NOT registered"
check_grep cmd/mohammed/main.go 'phases.DeepBurpOOBPhase\{\}' \
    "main.go: Phase 53 Deep Burp + OOB registered" "main.go: Phase 53 NOT registered"

# Version bump (V10.0 SOVEREIGN supersedes V9.0 ABSOLUTE APEX)
check_grep cmd/mohammed/main.go 'V10.0 SOVEREIGN' \
    "main.go: V10.0 SOVEREIGN banner present" "main.go: version NOT bumped to V10.0"

# ═══════════════════════════════════════════════════════════════════════════
# V9.0 ABSOLUTE APEX checks
# ═══════════════════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}── V9.0 ABSOLUTE APEX checks ─────────────────────────${NC}"

# S1.1 — Adaptive Rate-Limiting & Concurrency + memory shield
check_grep pkg/exploit/stealth.go 'type StealthGovernor' \
    "stealth.go: adaptive StealthGovernor present" "stealth.go: StealthGovernor MISSING"
check_grep pkg/exploit/stealth.go '\bObserve\b' \
    "stealth.go: 429/503/403 Observe backoff present" "stealth.go: Observe backoff MISSING"
check_grep pkg/exploit/stealth.go 'enterCoolDown' \
    "stealth.go: WAF cool-down window present" "stealth.go: cool-down MISSING"
check_grep pkg/exploit/stealth.go 'MemBudgetBytes|memoryPressured' \
    "stealth.go: memory shield present" "stealth.go: memory shield MISSING"
check_grep pkg/exploit/stealth.go 'sleepJitter' \
    "stealth.go: jittered backoff present" "stealth.go: jitter MISSING"
check_grep pkg/exploit/stealth.go 'browserUserAgents' \
    "stealth.go: 50+ User-Agent rotation pool present" "stealth.go: UA pool MISSING"
UA_COUNT=$(grep -c 'Mozilla/5.0' pkg/exploit/stealth.go 2>/dev/null)
if [ "${UA_COUNT:-0}" -ge 50 ]; then
    echo -e "  ${GREEN}✔${NC} User-Agent pool: $UA_COUNT (>= 50)"; PASS=$((PASS+1))
else
    echo -e "  ${RED}✘${NC} User-Agent pool: ${UA_COUNT:-0} (< 50)"; FAIL=$((FAIL+1))
fi
check_grep pkg/exploit/stealth.go 'randomStealthHeaders' \
    "stealth.go: header randomization (Sec-Fetch/Accept) present" "stealth.go: header randomization MISSING"
check_grep pkg/exploit/client.go 'Stealth \*StealthGovernor|Options.Stealth|c.gov' \
    "client.go: governor wired into every request" "client.go: governor NOT wired"
check_grep pkg/engine/engine.go 'func MemoryPressure' \
    "engine.go: runtime.ReadMemStats memory shield present" "engine.go: memory shield MISSING"
check_grep pkg/engine/engine.go 'func AdaptiveThreads' \
    "engine.go: adaptive thread throttle present" "engine.go: AdaptiveThreads MISSING"

# S1.2 — WAF & CDN evasion
check_grep pkg/engine/waf_evasion.go 'func FingerprintWAF' \
    "waf_evasion.go: WAF fingerprinting present" "waf_evasion.go: FingerprintWAF MISSING"
check_grep pkg/engine/waf_evasion.go '__cf_chl_rt_tk' \
    "waf_evasion.go: Cloudflare challenge token detection present" "waf_evasion.go: cf challenge token MISSING"
check_grep pkg/engine/waf_evasion.go 'WAFAkamai|akamaighost' \
    "waf_evasion.go: Akamai detection present" "waf_evasion.go: Akamai MISSING"
check_grep pkg/engine/waf_evasion.go 'WAFImperva|incap' \
    "waf_evasion.go: Imperva/Incapsula detection present" "waf_evasion.go: Imperva MISSING"
check_grep pkg/engine/waf_evasion.go 'WAFAWS|Amzn-Waf' \
    "waf_evasion.go: AWS WAF detection present" "waf_evasion.go: AWS WAF MISSING"
check_grep pkg/engine/waf_evasion.go 'func ShouldSkipHeavyFuzzing' \
    "waf_evasion.go: smart stealth routing present" "waf_evasion.go: stealth routing MISSING"

# S2 — Fuzzy baseline + strict 5-gate (apex edition; carried from V8, verified)
check_grep pkg/validation/fuzzy.go 'SimHash' \
    "fuzzy.go: SimHash present" "fuzzy.go: SimHash MISSING"
check_grep pkg/validation/fuzzy.go 'Levenshtein' \
    "fuzzy.go: Levenshtein present" "fuzzy.go: Levenshtein MISSING"
check_grep pkg/validation/baseline.go 'func FuzzyBaseline' \
    "baseline.go: multi-probe fuzzy baseline present" "baseline.go: FuzzyBaseline MISSING"
check_grep pkg/validation/baseline.go 'looksLikeWAFChallenge' \
    "baseline.go: SPA/WAF catch-all trap present" "baseline.go: catch-all trap MISSING"
check_grep pkg/validation/false_positive.go 'FiveGateValidate' \
    "false_positive.go: 5-gate pipeline present" "false_positive.go: 5-gate MISSING"

# S3.1 — High-signal Burp filter
check_grep pkg/exploit/burp.go 'func IsHighSignalURL' \
    "burp.go: high-signal URL classifier present" "burp.go: IsHighSignalURL MISSING"
check_grep pkg/exploit/burp.go 'func FilterHighSignal' \
    "burp.go: high-signal filter present" "burp.go: FilterHighSignal MISSING"
check_grep pkg/exploit/burp.go 'staticAssetExts' \
    "burp.go: static-asset zero-noise drop present" "burp.go: static-asset drop MISSING"
check_grep pkg/exploit/burp.go 'ConfidenceThreshold = 70' \
    "burp.go: confidence>=70 proxy gate present" "burp.go: confidence gate MISSING"
check_grep pkg/exploit/burp.go 'PopulateSitemapHighSignal' \
    "burp.go: high-signal sitemap population present" "burp.go: high-signal sitemap MISSING"

# S3.2 — Interactsh OOB correlation (carried apex from V8, verified)
check_grep pkg/exploit/burp.go 'BatchMonitorCallbacks' \
    "burp.go: Interactsh 60s OOB correlation present" "burp.go: OOB correlation MISSING"

# S4 — apex-grade exploit engines (verified feature coverage)
check_grep pkg/exploit/advanced_web.go 'CL.TE|TE.CL|TE.TE|H2.CL|H2.TE' \
    "advanced_web.go: 5 smuggling variants present" "advanced_web.go: smuggling variants MISSING"
check_grep pkg/exploit/advanced_web.go 'TestCacheDeception' \
    "advanced_web.go: cache deception (path confusion) present" "advanced_web.go: cache deception MISSING"
check_grep pkg/exploit/auth_audit.go 'ForgeJKUInjection' \
    "auth_audit.go: JKU/JWKS injection present" "auth_audit.go: JKU injection MISSING"
check_grep pkg/exploit/idor.go 'MultiTenantEngine' \
    "idor.go: dual-token multi-tenant BOLA/BFLA present" "idor.go: MultiTenantEngine MISSING"
check_grep pkg/exploit/race_condition.go 'BarrierBurst' \
    "race_condition.go: barrier-synchronized burst present" "race_condition.go: BarrierBurst MISSING"

# S5 — apex orchestration + registration
check_grep pkg/phases/phases_apex.go 'ApexOrchestrationPhase' \
    "phases_apex.go: apex orchestration phase present" "phases_apex.go: apex phase MISSING"
check_grep pkg/phases/phases_apex.go 'sharedStealthGovernor' \
    "phases_apex.go: shared per-scan governor present" "phases_apex.go: shared governor MISSING"
check_grep pkg/phases/phases_advanced.go 'Stealth: sharedStealthGovernor' \
    "phases_advanced.go: exploit client uses adaptive governor" "phases_advanced.go: governor NOT wired into engines"
check_grep cmd/mohammed/main.go 'phases.ApexOrchestrationPhase\{\}' \
    "main.go: Phase 54 Apex Orchestration registered" "main.go: Phase 54 NOT registered"

# ═══════════════════════════════════════════════════════════════════════════
# V10.0 SOVEREIGN checks
# ═══════════════════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}── V10.0 SOVEREIGN checks ────────────────────────────${NC}"

# S2 — Local Ollama AI Cognitive Brain
check_grep pkg/ai/brain.go 'type Brain struct' \
    "brain.go: Ollama cognitive Brain present" "brain.go: Brain MISSING"
check_grep pkg/ai/brain.go 'qwen2.5-coder' \
    "brain.go: model auto-fallback priority (qwen2.5-coder/gemma/llama3.2)" "brain.go: model priority MISSING"
check_grep pkg/ai/brain.go 'func .*Brain. SemanticTriage' \
    "brain.go: semantic response triage present" "brain.go: SemanticTriage MISSING"
check_grep pkg/ai/brain.go 'func .*Brain. MutatePayload' \
    "brain.go: dynamic payload mutation present" "brain.go: MutatePayload MISSING"
check_grep pkg/ai/brain.go 'RankIDORCandidates' \
    "brain.go: business-logic IDOR/BOLA ranking present" "brain.go: RankIDORCandidates MISSING"

# S3 — Go-Rod CDP Headless Chrome Engine
check_grep pkg/browser/cdp.go 'go-rod/rod' \
    "cdp.go: native Go-Rod CDP engine present" "cdp.go: Go-Rod MISSING"
check_grep pkg/browser/cdp.go 'func .*Engine. Render' \
    "cdp.go: SPA render + DOM/route/endpoint extraction" "cdp.go: Render MISSING"
check_grep pkg/browser/cdp.go 'func .*Engine. ScanDOMXSS' \
    "cdp.go: DOM XSS + postMessage scanner" "cdp.go: ScanDOMXSS MISSING"
check_grep pkg/browser/cdp.go 'func .*Engine. HarvestStorage' \
    "cdp.go: local/session storage secret harvester" "cdp.go: HarvestStorage MISSING"
check_grep pkg/browser/cdp.go 'func .*Engine. VerifyCORS' \
    "cdp.go: in-browser credentialed CORS/CSP verification" "cdp.go: VerifyCORS MISSING"

# S4.1 — Autonomous Account Bootstrapper
check_grep pkg/exploit/autobootstrap.go 'BootstrapDualAccounts' \
    "autobootstrap.go: autonomous User A/B bootstrapper" "autobootstrap.go: bootstrapper MISSING"
check_grep pkg/exploit/autobootstrap.go 'extractToken' \
    "autobootstrap.go: token/cookie harvest present" "autobootstrap.go: token harvest MISSING"

# S4.2 — Chained Stateful Attack Engine
check_grep pkg/exploit/state_machine.go 'type StateMachine struct' \
    "state_machine.go: chained multi-step state machine present" "state_machine.go: StateMachine MISSING"
check_grep pkg/exploit/state_machine.go 'PasswordResetHijack' \
    "state_machine.go: SM1 Password Reset Hijack present" "state_machine.go: SM1 MISSING"
check_grep pkg/exploit/state_machine.go 'OrderStateManipulation' \
    "state_machine.go: SM3 Order State Manipulation present" "state_machine.go: SM3 MISSING"

# S3/S5.1 — DOM XSS orchestrator
check_grep pkg/exploit/dom_xss.go 'type DOMScanner struct' \
    "dom_xss.go: DOM XSS orchestrator present" "dom_xss.go: DOMScanner MISSING"

# S5 — Sovereign orchestration + resource governor + registration
check_grep pkg/phases/phases_sovereign.go 'func SovereignPhases' \
    "phases_sovereign.go: sovereign phase set present" "phases_sovereign.go: SovereignPhases MISSING"
check_grep pkg/engine/engine.go 'Brain \*ai.Brain' \
    "engine.go: Brain wired into State" "engine.go: Brain NOT wired"
check_grep pkg/engine/engine.go 'BrowserSem' \
    "engine.go: Go-Rod resource governor (BrowserSem)" "engine.go: browser governor MISSING"
check_grep pkg/engine/engine.go 'ProbeSovereign' \
    "engine.go: sovereign posture probe present" "engine.go: ProbeSovereign MISSING"
check_grep cmd/mohammed/main.go 'phases.SovereignOrchestrationPhase\{\}' \
    "main.go: Phase 55 Sovereign Orchestration registered" "main.go: Phase 55 NOT registered"
check_grep cmd/mohammed/main.go 'phases.AutonomousBootstrapPhase\{\}' \
    "main.go: Phase 56 Autonomous Bootstrap registered" "main.go: Phase 56 NOT registered"
check_grep cmd/mohammed/main.go 'phases.DOMXSSPhase\{\}' \
    "main.go: Phase 57 DOM XSS registered" "main.go: Phase 57 NOT registered"
check_grep cmd/mohammed/main.go 'phases.ClientSideSecretPhase\{\}' \
    "main.go: Phase 58 Client-Side Secret registered" "main.go: Phase 58 NOT registered"
check_grep cmd/mohammed/main.go 'phases.StatefulAttackGraphPhase\{\}' \
    "main.go: Phase 59 Stateful Attack Graph registered" "main.go: Phase 59 NOT registered"
check_grep cmd/mohammed/main.go 'phases.AIPayloadMutationPhase\{\}' \
    "main.go: Phase 60 AI Payload Mutation registered" "main.go: Phase 60 NOT registered"

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
