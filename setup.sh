#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
# MOHAMMED v4 — Automated Tool Installer, PATH Configurator & Builder
# ---------------------------------------------------------------------------
# Installs every tool referenced by the engine (38 external binaries), wires
# them onto PATH permanently, downloads DNS resolvers + wordlists that the
# active phases require (fixes puredns/dnsx SKIP), builds the mohammed binary,
# and finishes with a full `mohammed doctor` verification.
#
# Idempotent: re-running skips anything already present.
# Usage: bash setup.sh
# ═══════════════════════════════════════════════════════════════════════════
set -uo pipefail   # NOTE: no -e — a single tool failure must not abort the whole install.

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*"; }
info() { echo -e "${CYAN}[*]${NC} $*"; }

# ── Resolve project directory = directory this script lives in ──────────────
# (fixes the old hardcoded /mnt/c/Users/... path bug — works on any machine)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJ_DIR="$SCRIPT_DIR"

# ── sudo shim (works whether or not sudo exists / is needed) ────────────────
if command -v sudo &>/dev/null && [ "$(id -u)" -ne 0 ]; then
    SUDO="sudo"
else
    SUDO=""   # already root or no sudo — run directly
fi

# ── Detect shell rc file ────────────────────────────────────────────────────
SHELL_RC="$HOME/.bashrc"
if [ -n "${ZSH_VERSION:-}" ] || [ "$(basename "${SHELL:-bash}")" = "zsh" ]; then
    SHELL_RC="$HOME/.zshrc"
fi
touch "$SHELL_RC" 2>/dev/null || true

# ── Directories ─────────────────────────────────────────────────────────────
export GOPATH="${GOPATH:-$HOME/go}"
GOBIN="$GOPATH/bin"
LOCAL_BIN="$HOME/.local/bin"
OPT_DIR="/opt/mohammed-tools"
TMP_BUILD="/tmp/mohammed_build_$$"

mkdir -p "$GOBIN" "$LOCAL_BIN" "$TMP_BUILD"
$SUDO mkdir -p "$OPT_DIR" 2>/dev/null || mkdir -p "$OPT_DIR" 2>/dev/null || OPT_DIR="$HOME/mohammed-tools"
mkdir -p "$OPT_DIR" 2>/dev/null || true

# ── PATH setup (permanent) ──────────────────────────────────────────────────
add_to_path() {
    local dir="$1"
    export PATH="$PATH:$dir"
    if ! grep -qF "export PATH=\"\$PATH:$dir\"" "$SHELL_RC" 2>/dev/null; then
        echo "export PATH=\"\$PATH:$dir\"" >> "$SHELL_RC"
        info "Added $dir to PATH in $SHELL_RC"
    fi
}

log "Setting up PATH entries..."
add_to_path "/usr/local/go/bin"
add_to_path "$GOBIN"
add_to_path "$LOCAL_BIN"
add_to_path "/usr/local/bin"
add_to_path "/snap/bin"
if ! grep -qF "export GOPATH=$GOPATH" "$SHELL_RC" 2>/dev/null; then
    echo "export GOPATH=$GOPATH" >> "$SHELL_RC"
fi

# ── System dependencies ─────────────────────────────────────────────────────
log "Installing system dependencies..."
$SUDO apt-get update -y -qq 2>/dev/null || warn "apt-get update failed (non-fatal)"
$SUDO apt-get install -y -qq \
    curl wget git jq nmap dnsutils bind9-utils unzip \
    python3 python3-pip python3-venv pipx \
    build-essential libpcap-dev \
    ruby ruby-dev rubygems \
    2>/dev/null || warn "Some system packages may have failed (non-fatal)"

# ── Ensure Go is available (needed to build the binary + go-based tools) ─────
if ! command -v go &>/dev/null; then
    warn "Go not found — installing Go 1.22.4 manually..."
    GO_VERSION="1.22.4"
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o /tmp/go.tar.gz \
        && $SUDO rm -rf /usr/local/go \
        && $SUDO tar -C /usr/local -xzf /tmp/go.tar.gz \
        && export PATH="$PATH:/usr/local/go/bin" \
        || err "Go install failed — the binary build will not work without Go"
fi
command -v go &>/dev/null && log "Go version: $(go version)" || err "Go still not on PATH"

# ── link helper: put a built binary somewhere on PATH ───────────────────────
link_bin() {
    local src="$1" name="$2"
    [ -f "$src" ] || return 1
    if $SUDO ln -sf "$src" "/usr/local/bin/$name" 2>/dev/null; then :
    elif ln -sf "$src" "$LOCAL_BIN/$name" 2>/dev/null; then :
    fi
}

# ── install_go_tool <import_path> <binary_name> ─────────────────────────────
install_go_tool() {
    local import="$1" name="$2"
    if command -v "$name" &>/dev/null; then log "$name already installed"; return 0; fi
    info "go install $name ..."
    if GOPATH="$GOPATH" GOBIN="$GOBIN" go install -v "$import" 2>/dev/null; then
        link_bin "$GOBIN/$name" "$name"
        command -v "$name" &>/dev/null && log "$name installed" || warn "$name installed to $GOBIN but not on PATH yet"
    else
        warn "$name: go install failed"
    fi
}

# ── install_pip_tool <package> <binary_name> ────────────────────────────────
install_pip_tool() {
    local pkg="$1" name="${2:-$1}"
    if command -v "$name" &>/dev/null; then log "$name already installed"; return 0; fi
    info "pip install $name ..."
    pipx install "$pkg" 2>/dev/null \
        || pip3 install --quiet --user "$pkg" 2>/dev/null \
        || pip3 install --quiet --break-system-packages "$pkg" 2>/dev/null \
        || pip3 install --quiet "$pkg" 2>/dev/null \
        || warn "$name: pip install failed"
    link_bin "$LOCAL_BIN/$name" "$name"
    link_bin "$HOME/.local/bin/$name" "$name"
}

# ── install_py_wrapper <script_abs_path> <binary_name> ──────────────────────
install_py_wrapper() {
    local script="$1" name="$2"
    command -v "$name" &>/dev/null && { log "$name already installed"; return 0; }
    local dest="/usr/local/bin/$name"
    if ! $SUDO bash -c "printf '#!/usr/bin/env bash\nexec python3 %s \"\$@\"\n' '$script' > $dest" 2>/dev/null; then
        dest="$LOCAL_BIN/$name"
        printf '#!/usr/bin/env bash\nexec python3 %s "$@"\n' "$script" > "$dest"
    fi
    chmod +x "$dest" 2>/dev/null; $SUDO chmod +x "$dest" 2>/dev/null || true
    log "$name wrapper installed → $dest"
}

# ════════════════════════════════════════════════════════════════════════════
echo ""; log "═══ STEP 1: ProjectDiscovery + Go recon tools ═══"
# ════════════════════════════════════════════════════════════════════════════
install_go_tool "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"       "subfinder"
install_go_tool "github.com/projectdiscovery/httpx/cmd/httpx@latest"                  "httpx"
install_go_tool "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"                    "dnsx"
install_go_tool "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"               "naabu"
install_go_tool "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"             "nuclei"
install_go_tool "github.com/projectdiscovery/katana/cmd/katana@latest"                "katana"
install_go_tool "github.com/projectdiscovery/tlsx/cmd/tlsx@latest"                    "tlsx"
install_go_tool "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"        "shuffledns"
install_go_tool "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest" "interactsh-client"
install_go_tool "github.com/lc/gau/v2/cmd/gau@latest"                                 "gau"
install_go_tool "github.com/tomnomnom/waybackurls@latest"                             "waybackurls"
install_go_tool "github.com/tomnomnom/assetfinder@latest"                             "assetfinder"
install_go_tool "github.com/tomnomnom/gf@latest"                                      "gf"
install_go_tool "github.com/tomnomnom/qsreplace@latest"                               "qsreplace"
install_go_tool "github.com/tomnomnom/unfurl@latest"                                  "unfurl"
install_go_tool "github.com/hahwul/dalfox/v2@latest"                                  "dalfox"
install_go_tool "github.com/Emoe/kxss@latest"                                         "kxss"
install_go_tool "github.com/PentestPad/subzy@latest"                                  "subzy"
install_go_tool "github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"                   "crlfuzz"
install_go_tool "github.com/jaeles-project/gospider@latest"                           "gospider"
install_go_tool "github.com/hakluke/hakrawler@latest"                                 "hakrawler"
install_go_tool "github.com/003random/getJS/v2@latest"                                "getJS"
install_go_tool "github.com/d3mondev/puredns/v2@latest"                               "puredns"
install_go_tool "github.com/ffuf/ffuf/v2@latest"                                      "ffuf"

# massdns — required by puredns/shuffledns; build from source
if ! command -v massdns &>/dev/null; then
    info "Building massdns from source..."
    if git clone --depth 1 https://github.com/blechschmidt/massdns.git "$TMP_BUILD/massdns" 2>/dev/null; then
        ( cd "$TMP_BUILD/massdns" && make >/dev/null 2>&1 && link_bin "$TMP_BUILD/massdns/bin/massdns" "massdns" )
        command -v massdns &>/dev/null && log "massdns installed" || warn "massdns build failed"
    else
        warn "massdns clone failed"
    fi
fi

# feroxbuster
if ! command -v feroxbuster &>/dev/null; then
    info "Installing feroxbuster..."
    ( cd "$TMP_BUILD" && curl -fsSL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash >/dev/null 2>&1 \
        && link_bin "$TMP_BUILD/feroxbuster" "feroxbuster" ) \
        || $SUDO apt-get install -y -qq feroxbuster 2>/dev/null || warn "feroxbuster install failed"
fi

# findomain
if ! command -v findomain &>/dev/null; then
    info "Installing findomain..."
    curl -fsSL "https://github.com/findomain/findomain/releases/latest/download/findomain-linux" -o "$TMP_BUILD/findomain" 2>/dev/null \
        && chmod +x "$TMP_BUILD/findomain" && link_bin "$TMP_BUILD/findomain" "findomain" \
        && log "findomain installed" || warn "findomain install failed"
fi

# ════════════════════════════════════════════════════════════════════════════
echo ""; log "═══ STEP 2: Python-based tools ═══"
# ════════════════════════════════════════════════════════════════════════════
# sqlmap
if ! command -v sqlmap &>/dev/null; then
    $SUDO apt-get install -y -qq sqlmap 2>/dev/null || install_pip_tool "sqlmap" "sqlmap"
fi
install_pip_tool "arjun" "arjun"
install_pip_tool "bbot"  "bbot"
install_pip_tool "s3scanner" "s3scanner"
install_pip_tool "ghauri" "ghauri"

# amass — snap or go
if ! command -v amass &>/dev/null; then
    info "Installing amass..."
    $SUDO snap install amass 2>/dev/null \
        || install_go_tool "github.com/owasp-amass/amass/v4/...@master" "amass" \
        || warn "amass install failed"
fi

# paramspider (clone install is the reliable path — pip pkg is stale)
if ! command -v paramspider &>/dev/null; then
    info "Installing paramspider..."
    if git clone --depth 1 https://github.com/devanshbatham/paramspider.git "$OPT_DIR/paramspider" 2>/dev/null; then
        pip3 install --quiet --break-system-packages "$OPT_DIR/paramspider" 2>/dev/null \
            || pip3 install --quiet --user "$OPT_DIR/paramspider" 2>/dev/null \
            || pip3 install --quiet "$OPT_DIR/paramspider" 2>/dev/null || true
    fi
    link_bin "$LOCAL_BIN/paramspider" "paramspider"
    link_bin "$HOME/.local/bin/paramspider" "paramspider"
    command -v paramspider &>/dev/null && log "paramspider installed" || warn "paramspider install failed"
fi

# dirsearch
if ! command -v dirsearch &>/dev/null; then
    $SUDO apt-get install -y -qq dirsearch 2>/dev/null || {
        git clone --depth 1 https://github.com/maurosoria/dirsearch.git "$OPT_DIR/dirsearch" 2>/dev/null
        install_py_wrapper "$OPT_DIR/dirsearch/dirsearch.py" "dirsearch"
    }
fi

# ════════════════════════════════════════════════════════════════════════════
echo ""; log "═══ STEP 3: Git-built / wrapper tools ═══"
# ════════════════════════════════════════════════════════════════════════════
# dontgo403
if ! command -v dontgo403 &>/dev/null; then
    info "Building dontgo403..."
    if git clone --depth 1 https://github.com/devploit/dontgo403.git "$TMP_BUILD/dontgo403" 2>/dev/null; then
        ( cd "$TMP_BUILD/dontgo403" && go build -o dontgo403 . 2>/dev/null && link_bin "$TMP_BUILD/dontgo403/dontgo403" "dontgo403" )
        command -v dontgo403 &>/dev/null && log "dontgo403 installed" || warn "dontgo403 build failed"
    fi
fi

# kiterunner (kr)
if ! command -v kr &>/dev/null; then
    info "Building kiterunner (kr)..."
    if git clone --depth 1 https://github.com/assetnote/kiterunner.git "$TMP_BUILD/kiterunner" 2>/dev/null; then
        ( cd "$TMP_BUILD/kiterunner" && (make build 2>/dev/null || go build -o dist/kr ./cmd/kiterunner 2>/dev/null) \
            && link_bin "$TMP_BUILD/kiterunner/dist/kr" "kr" )
        command -v kr &>/dev/null && log "kiterunner (kr) installed" || warn "kiterunner build failed"
    fi
fi

# smuggler (python wrapper)
if ! command -v smuggler &>/dev/null; then
    info "Installing smuggler..."
    git clone --depth 1 https://github.com/defparam/smuggler.git "$OPT_DIR/smuggler" 2>/dev/null \
        || git -C "$OPT_DIR/smuggler" pull 2>/dev/null || true
    install_py_wrapper "$OPT_DIR/smuggler/smuggler.py" "smuggler"
fi

# cloud_enum (python wrapper)
if ! command -v cloud_enum &>/dev/null; then
    info "Installing cloud_enum..."
    git clone --depth 1 https://github.com/initstring/cloud_enum.git "$OPT_DIR/cloud_enum" 2>/dev/null \
        || git -C "$OPT_DIR/cloud_enum" pull 2>/dev/null || true
    pip3 install --quiet --break-system-packages -r "$OPT_DIR/cloud_enum/requirements.txt" 2>/dev/null \
        || pip3 install --quiet -r "$OPT_DIR/cloud_enum/requirements.txt" 2>/dev/null || true
    install_py_wrapper "$OPT_DIR/cloud_enum/cloud_enum.py" "cloud_enum"
fi

# ════════════════════════════════════════════════════════════════════════════
echo ""; log "═══ STEP 4: Wordlists, resolvers & templates ═══"
# ════════════════════════════════════════════════════════════════════════════
# DNS resolvers — REQUIRED by puredns/dnsx active bruteforce (fixes SKIP/exit 1)
RESOLVERS="$OPT_DIR/resolvers.txt"
if [ ! -s "$RESOLVERS" ]; then
    info "Downloading DNS resolvers..."
    curl -fsSL "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt" -o "$RESOLVERS" 2>/dev/null \
        || printf '1.1.1.1\n8.8.8.8\n8.8.4.4\n9.9.9.9\n1.0.0.1\n208.67.222.222\n' > "$RESOLVERS"
    log "resolvers → $RESOLVERS ($(wc -l < "$RESOLVERS" 2>/dev/null || echo 0) entries)"
fi
# mirror to the fallback path the engine writes if this is missing
cp -f "$RESOLVERS" /tmp/mohammed_resolvers.txt 2>/dev/null || true

# SecLists
if [ ! -d "/usr/share/seclists" ] && [ ! -d "$HOME/SecLists" ]; then
    info "Installing SecLists (this is large)..."
    $SUDO apt-get install -y -qq seclists 2>/dev/null || {
        git clone --depth 1 https://github.com/danielmiessler/SecLists.git "$TMP_BUILD/SecLists" 2>/dev/null \
            && ($SUDO mv "$TMP_BUILD/SecLists" /usr/share/seclists 2>/dev/null || mv "$TMP_BUILD/SecLists" "$HOME/SecLists") \
            && log "SecLists installed"
    }
fi

# nuclei templates
if command -v nuclei &>/dev/null; then
    info "Updating nuclei templates..."
    nuclei -update-templates -silent 2>/dev/null || true
fi

# ════════════════════════════════════════════════════════════════════════════
echo ""; log "═══ STEP 5: PATH hardening (link every tool system-wide) ═══"
# ════════════════════════════════════════════════════════════════════════════
for tool in subfinder amass bbot assetfinder findomain \
            dnsx puredns massdns shuffledns \
            subzy httpx tlsx naabu \
            gau waybackurls katana gospider hakrawler \
            getJS paramspider arjun \
            ffuf feroxbuster dirsearch \
            nuclei dalfox kxss sqlmap ghauri \
            dontgo403 kr crlfuzz smuggler cloud_enum s3scanner; do
    command -v "$tool" &>/dev/null && continue
    for cand in "$LOCAL_BIN/$tool" "$HOME/.local/bin/$tool" "$GOBIN/$tool"; do
        [ -f "$cand" ] && { link_bin "$cand" "$tool"; break; }
    done
done

# ════════════════════════════════════════════════════════════════════════════
echo ""; log "═══ STEP 6: Building MOHAMMED v4 binary ═══"
# ════════════════════════════════════════════════════════════════════════════
if command -v go &>/dev/null; then
    ( cd "$PROJ_DIR" && go build -o mohammed ./cmd/mohammed ) \
        && { chmod +x "$PROJ_DIR/mohammed"; log "mohammed binary built → $PROJ_DIR/mohammed"; } \
        || err "Build failed — inspect Go source (run: go build ./...)"
else
    err "Go unavailable — cannot build binary"
fi

# ════════════════════════════════════════════════════════════════════════════
echo ""; log "═══ STEP 7: Doctor check ═══"
# ════════════════════════════════════════════════════════════════════════════
export PATH="$PATH:$GOBIN:$LOCAL_BIN:/usr/local/bin:/usr/local/go/bin"
if [ -x "$PROJ_DIR/mohammed" ]; then
    ( cd "$PROJ_DIR" && ./mohammed doctor ) || true
fi

# Cleanup transient build dir (keep $OPT_DIR — smuggler/cloud_enum/resolvers live there)
rm -rf "$TMP_BUILD"

echo ""
log "════════════════════════════════════════════════════════"
log "  Setup complete."
log "  1) Reload PATH:   source $SHELL_RC"
log "  2) Verify tools:  ./mohammed doctor   (or bash verify.sh)"
log "  3) (optional) AI: ollama serve & ollama pull gemma:2b"
log "  Resolvers: $RESOLVERS"
log "════════════════════════════════════════════════════════"
