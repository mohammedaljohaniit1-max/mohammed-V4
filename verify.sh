#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# MOHAMMED v3 — verify.sh
# Fast verification that all phases, files, and tools are working.
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
echo "║     MOHAMMED v3 — Verification Suite              ║"
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
check_file "pkg/config/config.go"
check_file "config.yaml"
check_file "scope.txt"
check_file "setup.sh"

# ── Section 3: Go Build ──────────────────────────────────────────────
hdr "3. Go Build Test"

if command -v go &>/dev/null; then
    info "Go version: $(go version)"
    if go build -o /tmp/mohammed_test ./cmd/mohammed 2>&1; then
        pass "go build succeeded"
        rm -f /tmp/mohammed_test
    else
        fail "go build FAILED — fix compile errors"
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

if grep -q "for _, domain := range s.Scope.Domains" pkg/phases/phases.go 2>/dev/null; then
    pass "phases.go: Phase 03 iterates ALL domains (not just Domains[0])"
else
    fail "phases.go: Phase 03 may only scan first domain"
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

if grep -q "\-\-output.*paramOut\|--output.*OutputFolder" pkg/phases/phases.go 2>/dev/null; then
    pass "phases.go: paramspider uses explicit output path"
else
    warn "phases.go: paramspider output path may not be set correctly"
fi

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
