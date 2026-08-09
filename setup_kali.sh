#!/usr/bin/env bash
# setup_kali.sh — one-shot installer/preparer for MOHAMMED on Kali Linux.
#
# What it does:
#   1. checks/installs Go (>=1.22), git, curl, jq
#   2. installs the passive recon helper tools that ARE allowed (subfinder, httpx)
#      via the Go toolchain (no root needed for these)
#   3. builds all MOHAMMED binaries (mohammed, tip, osint, scope)
#   4. runs the guard-rail self-check for every target scope
#
# It is SAFE to re-run. It does NOT run any scan. Run the scans separately with
# recon/<target>.sh (all passive).
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

# Ensure GOPATH/bin on PATH for the tools we 'go install'.
export GOBIN="${GOBIN:-$HOME/go/bin}"
export PATH="$PATH:$GOBIN"
mkdir -p "$GOBIN"

# ---- 2. allowed passive recon tools (optional but recommended) --------------
# Only PASSIVE/PROBE tools. NEVER installs aggressive scanners here
# (no nuclei/ffuf/dalfox/naabu/nmap/puredns — those stay DENIED by the guard-rail).
# Format: "binary|go-install-path"
PASSIVE_TOOLS=(
  "subfinder|github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"   # passive subdomains
  "assetfinder|github.com/tomnomnom/assetfinder@latest"                        # passive subdomains
  "amass|github.com/owasp-amass/amass/v4/...@master"                           # used ONLY with -passive
  "gau|github.com/lc/gau/v2/cmd/gau@latest"                                    # passive archived URLs
  "waybackurls|github.com/tomnomnom/waybackurls@latest"                        # passive archived URLs
  "httpx|github.com/projectdiscovery/httpx/cmd/httpx@latest"                   # gentle liveness (probe)
)
info "Installing allowed PASSIVE recon tools via Go (subfinder, assetfinder, amass, gau, waybackurls, httpx) ..."
for entry in "${PASSIVE_TOOLS[@]}"; do
  bin="${entry%%|*}"; path="${entry##*|}"
  if have "$bin"; then ok "$bin already present"; continue; fi
  if go install -v "$path" 2>/dev/null; then
    ok "$bin installed"
  else
    warn "$bin install failed (skipped; crt.sh/wayback built-ins still work)"
  fi
done

# ---- 3. build MOHAMMED binaries --------------------------------------------
info "Building MOHAMMED binaries into ./bin ..."
mkdir -p bin
go build -o bin/mohammed ./cmd/mohammed 2>/dev/null && ok "bin/mohammed" || warn "mohammed build skipped"
go build -o bin/tip      ./cmd/tip      && ok "bin/tip"
go build -o bin/osint    ./cmd/osint    && ok "bin/osint"
go build -o bin/scope    ./cmd/scope    && ok "bin/scope"

# ---- 4. guard-rail self-check for every target ------------------------------
info "Guard-rail self-check (per target: is nuclei denied? is subfinder allowed?)"
FAIL=0
for f in scope/*.json; do
  t="$(basename "$f" .json)"
  nu="$(./bin/scope -file "$f" -tool nuclei 2>/dev/null | grep -o 'ALLOWED\|DENIED' | head -1)"
  su="$(./bin/scope -file "$f" -tool subfinder 2>/dev/null | grep -o 'ALLOWED\|DENIED' | head -1)"
  if [[ "$nu" != "DENIED" || "$su" != "ALLOWED" ]]; then
    err "  $t: nuclei=$nu subfinder=$su  (UNEXPECTED)"; FAIL=1
  else
    ok "  $t: nuclei=DENIED subfinder=ALLOWED"
  fi
done

echo
if [[ "$FAIL" == "0" ]]; then
  ok "SETUP COMPLETE. Everything verified."
else
  err "SETUP finished with guard-rail warnings above — review before scanning."
fi
cat <<EOF

Next — run a PASSIVE scan for any target (each has its own command/scope):
  bash recon/flagyard.sh      # *.flagyard.com   (passive + gentle liveness)
  bash recon/nearpay.sh       # *-sa-dev-*.nearpay.io
  bash recon/ejada.sh         # ehub.ejada.com   (PASSIVE ONLY)
  bash recon/nournet.sh       # eservices.nour.net.sa (PASSIVE ONLY, gov)
  bash recon/zain.sh          # zain.app         (PASSIVE ONLY, gov)
  bash recon/mobily.sh        # mobily.com.sa    (PASSIVE ONLY)

Each preset now runs (only if installed + allowed by the guard-rail):
  crt.sh + subfinder + assetfinder + amass(-passive)  -> subdomains
  wayback + gau + waybackurls                         -> archived URLs
All PASSIVE. Aggressive scanners (nuclei/ffuf/dalfox/naabu/nmap) stay DENIED.

Then bundle + hand to an EXTERNAL AI:
  bash recon/collect.sh <target>
  bash recon/ai_summarize.sh <target>        # paste prompt into ChatGPT/Claude/Gemini
EOF
