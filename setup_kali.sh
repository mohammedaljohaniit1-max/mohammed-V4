#!/usr/bin/env bash
# setup_kali.sh — one-shot installer/preparer for MOHAMMED on Kali Linux.
#
# What it does:
#   1. checks/installs base deps (git, curl, jq, go >= 1.22)
#   2. installs the recon/scan toolset the engine drives (subfinder, httpx,
#      naabu, nuclei, katana, dnsx, gau, ffuf, dalfox, ...). These are only
#      ACTUALLY used on programs whose policy permits them — the guard-rail
#      (pkg/scope) refuses to run aggressive tools on forbidden/gov targets, so
#      installing them is safe; the policy, not the install, controls usage.
#   3. builds all MOHAMMED binaries (mohammed, tip, osint, scope, preset)
#   4. runs the guard-rail self-check for every target scope + verifies the
#      engine plan (passive-forced vs full) is correct per policy
#
# It is SAFE to re-run. It does NOT run any scan. Run scans with recon/<t>.sh.
#
# Usage:  bash setup_kali.sh

set -uo pipefail
GREEN='\033[32m'; YEL='\033[33m'; RED='\033[31m'; CYA='\033[36m'; NC='\033[0m'
ok(){ printf "${GREEN}[+]${NC} %s\n" "$*"; }
info(){ printf "${CYA}[*]${NC} %s\n" "$*"; }
warn(){ printf "${YEL}[!]${NC} %s\n" "$*"; }
err(){ printf "${RED}[x]${NC} %s\n" "$*"; }
have(){ command -v "$1" >/dev/null 2>&1; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

# ---- 1. base dependencies ---------------------------------------------------
info "Checking base dependencies (git, curl, jq, go) ..."
NEED_APT=()
for b in git curl jq; do have "$b" || NEED_APT+=("$b"); done
if [[ ${#NEED_APT[@]} -gt 0 ]]; then
  warn "Installing via apt: ${NEED_APT[*]} (needs sudo)"
  sudo apt-get update -y && sudo apt-get install -y "${NEED_APT[@]}"
fi

if ! have go; then
  warn "Go not found. Installing Go via apt (golang-go). For newest Go use https://go.dev/dl/"
  sudo apt-get update -y && sudo apt-get install -y golang-go
fi
GOV="$(go version 2>/dev/null | grep -oE 'go[0-9]+\.[0-9]+' | head -1)"
ok "Go: ${GOV:-not found}"
if [[ -z "$GOV" ]]; then err "Go is required (>=1.22). Install from https://go.dev/dl/ then re-run."; exit 1; fi

export GOBIN="${GOBIN:-$HOME/go/bin}"
export PATH="$PATH:$GOBIN"
mkdir -p "$GOBIN"

# ---- 2. recon/scan toolset --------------------------------------------------
# The engine drives these. The guard-rail decides per-program whether each may
# actually run — so installing the aggressive ones is safe (they stay DENIED on
# forbidden/gov targets and only fire on wildcard_bounty programs like ICI).
# Format: "binary|go-install-path"
TOOLS=(
  "subfinder|github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  "assetfinder|github.com/tomnomnom/assetfinder@latest"
  "httpx|github.com/projectdiscovery/httpx/cmd/httpx@latest"
  "dnsx|github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  "naabu|github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
  "katana|github.com/projectdiscovery/katana/cmd/katana@latest"
  "nuclei|github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  "gau|github.com/lc/gau/v2/cmd/gau@latest"
  "waybackurls|github.com/tomnomnom/waybackurls@latest"
  "ffuf|github.com/ffuf/ffuf/v2@latest"
  "dalfox|github.com/hahwul/dalfox/v2@latest"
  "gospider|github.com/jaeles-project/gospider@latest"
  # V12.4: the 7 tools the ICI PARIS XL run reported as Missing. The engine
  # degrades gracefully without them, but they materially improve enumeration
  # (alterx permutations, anew dedup, cero cert-SAN scraping, httprobe liveness,
  # notify alerting, subjs JS-URL mining, uncover engine pivots).
  "alterx|github.com/projectdiscovery/alterx/cmd/alterx@latest"
  "anew|github.com/tomnomnom/anew@latest"
  "cero|github.com/glebarez/cero@latest"
  "httprobe|github.com/tomnomnom/httprobe@latest"
  "notify|github.com/projectdiscovery/notify/cmd/notify@latest"
  "subjs|github.com/lc/subjs@latest"
  "uncover|github.com/projectdiscovery/uncover/cmd/uncover@latest"
)
info "Installing recon/scan toolset via Go (${#TOOLS[@]} tools) ..."
for entry in "${TOOLS[@]}"; do
  bin="${entry%%|*}"; path="${entry##*|}"
  if have "$bin"; then ok "$bin already present"; continue; fi
  if go install -v "$path" 2>/dev/null; then ok "$bin installed"
  else warn "$bin install failed (skipped; engine degrades gracefully / crt.sh+wayback built-ins still work)"; fi
done
info "Tip: 'nuclei -update-templates' once, to pull the latest templates."

# ---- 3. build MOHAMMED binaries --------------------------------------------
info "Building MOHAMMED binaries into ./bin ..."
mkdir -p bin
go build -o bin/mohammed ./cmd/mohammed 2>/dev/null && ok "bin/mohammed" || warn "mohammed build skipped"
go build -o bin/tip      ./cmd/tip      && ok "bin/tip"
go build -o bin/osint    ./cmd/osint    && ok "bin/osint"
go build -o bin/scope    ./cmd/scope    && ok "bin/scope"
go build -o bin/preset   ./cmd/preset   && ok "bin/preset"

# ---- 4. guard-rail + engine-plan self-check for every target ----------------
info "Guard-rail + engine-plan self-check (per target) ..."
FAIL=0
for f in scope/*.json; do
  t="$(basename "$f" .json)"
  nu="$(./bin/scope -file "$f" -tool nuclei 2>/dev/null | grep -o 'ALLOWED\|DENIED' | head -1)"
  su="$(./bin/scope -file "$f" -tool subfinder 2>/dev/null | grep -o 'ALLOWED\|DENIED' | head -1)"
  plan="$(./bin/preset -file "$f" -mode full 2>/dev/null | grep -oE 'profile=[a-z]+' | head -1)"
  printf "    %-12s nuclei=%-7s subfinder=%-7s full-plan=%s\n" "$t" "$nu" "$su" "$plan"
  # Invariant: subfinder (passive) must always be allowed.
  [[ "$su" == "ALLOWED" ]] || { err "  $t: subfinder unexpectedly $su"; FAIL=1; }
done

echo
if [[ "$FAIL" == "0" ]]; then ok "SETUP COMPLETE. Guard-rail + engine plans verified."
else err "SETUP finished with warnings above — review before scanning."; fi

cat <<'EOF'

── HOW TO SCAN ──────────────────────────────────────────────────────────────
Each target has TWO commands. Default is FULL (the guard-rail keeps it legal:
forbidden/gov targets are auto-pinned to passive). Add 'passive' for OSINT-only.

  FULL (max legal intensity — real engine: governor + WAF-bypass + AI):
    bash recon/iciparisxl.sh          # Intigriti: automation ALLOWED @5 req/s → FULL engine
    bash recon/flagyard.sh            # reports_rejected → active recon (no aggressive)
    bash recon/nearpay.sh             # reports_rejected → active recon
    bash recon/ejada.sh               # FORBIDDEN → auto PASSIVE
    bash recon/nournet.sh             # gov → auto PASSIVE
    bash recon/zain.sh                # gov → auto PASSIVE
    bash recon/mobily.sh              # FORBIDDEN → auto PASSIVE

  PASSIVE (OSINT only, safe anywhere):
    bash recon/iciparisxl.sh passive

Then hand results to an EXTERNAL AI:
    bash recon/collect.sh iciparisxl-full
    bash recon/ai_summarize.sh iciparisxl-full     # paste prompt into ChatGPT/Claude/Gemini
──────────────────────────────────────────────────────────────────────────────
EOF
