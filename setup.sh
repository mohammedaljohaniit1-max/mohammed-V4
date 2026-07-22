#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# MOHAMMED v3 — Automated Tool Installer & PATH Configurator
# Installs all 39+ tools, adds them to PATH permanently, and verifies.
# Usage: bash setup.sh
# ═══════════════════════════════════════════════════════════════════════
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*"; }
info() { echo -e "${CYAN}[*]${NC} $*"; }

# ── Detect shell rc file ─────────────────────────────────────────────
SHELL_RC="$HOME/.bashrc"
if [ -n "${ZSH_VERSION:-}" ] || [ "$(basename "$SHELL")" = "zsh" ]; then
    SHELL_RC="$HOME/.zshrc"
fi

# ── Directories ──────────────────────────────────────────────────────
GOPATH="${GOPATH:-$HOME/go}"
GOBIN="$GOPATH/bin"
LOCAL_BIN="$HOME/.local/bin"
OPT_DIR="/opt/mohammed-tools"
TMP_BUILD="/tmp/mohammed_build_$$"

mkdir -p "$GOBIN" "$LOCAL_BIN" "$OPT_DIR" "$TMP_BUILD"

# ── PATH setup (permanent) ───────────────────────────────────────────
add_to_path() {
    local dir="$1"
    # Add to current session
    export PATH="$PATH:$dir"
    # Add to shell rc if not already there
    if ! grep -qF "$dir" "$SHELL_RC" 2>/dev/null; then
        echo "export PATH=\"\$PATH:$dir\"" >> "$SHELL_RC"
        info "Added $dir to PATH in $SHELL_RC"
    fi
}

log "Setting up PATH entries..."
add_to_path "$GOBIN"
add_to_path "$LOCAL_BIN"
add_to_path "/usr/local/bin"
add_to_path "/snap/bin"
export GOPATH="$GOPATH"
if ! grep -qF "GOPATH" "$SHELL_RC" 2>/dev/null; then
    echo "export GOPATH=$GOPATH" >> "$SHELL_RC"
fi

log "PATH is: $PATH"

# ── System dependencies ──────────────────────────────────────────────
log "Installing system dependencies..."
sudo apt-get update -y -qq 2>/dev/null || warn "apt-get update failed (non-fatal)"
sudo apt-get install -y -qq \
    curl wget git jq nmap dnsutils bind9-utils \
    python3 python3-pip python3-venv \
    golang-go build-essential libpcap-dev \
    ruby ruby-dev rubygems \
    2>/dev/null || warn "Some system packages may have failed (non-fatal)"

# Ensure Go is available
if ! command -v go &>/dev/null; then
    warn "Go not found via apt — installing manually..."
    GO_VERSION="1.22.4"
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o /tmp/go.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf /tmp/go.tar.gz
    add_to_path "/usr/local/go/bin"
fi
log "Go version: $(go version)"

# ── Helper: install_go_tool <import_path> <binary_name> ──────────────
install_go_tool() {
    local import="$1"
    local name="$2"
    if command -v "$name" &>/dev/null; then
        log "$name already installed at $(command -v "$name")"
        return 0
    fi
    info "Installing $name via go install..."
    if GOPATH="$GOPATH" GOBIN="$GOBIN" go install -v "$import" 2>/dev/null; then
        # Try to link to /usr/local/bin for system-wide access
        if [ -f "$GOBIN/$name" ]; then
            sudo ln -sf "$GOBIN/$name" "/usr/local/bin/$name" 2>/dev/null || \
                ln -sf "$GOBIN/$name" "$LOCAL_BIN/$name" 2>/dev/null || true
            log "$name installed → $(command -v "$name" 2>/dev/null || echo "$GOBIN/$name")"
        fi
    else
        warn "$name: go install failed"
    fi
}

# ── Helper: install_git_go <repo> <binary_name> [build_args] ─────────
install_git_go() {
    local repo="$1"
    local name="$2"
    shift 2
    if command -v "$name" &>/dev/null; then
        log "$name already installed at $(command -v "$name")"
        return 0
    fi
    info "Building $name from source: $repo"
    local dir="$TMP_BUILD/$name"
    git clone --depth 1 "$repo" "$dir" 2>/dev/null || { warn "$name: git clone failed"; return 1; }
    cd "$dir"
    if go build -o "$name" "${@:-.}" 2>/dev/null; then
        sudo mv "$name" "/usr/local/bin/$name" 2>/dev/null || \
            mv "$name" "$LOCAL_BIN/$name" 2>/dev/null || true
        log "$name built and installed"
    else
        warn "$name: build failed"
    fi
    cd "$TMP_BUILD"
}

# ── Helper: install_pip_tool <package> <binary_name> ─────────────────
install_pip_tool() {
    local pkg="$1"
    local name="${2:-$1}"
    if command -v "$name" &>/dev/null; then
        log "$name already installed at $(command -v "$name")"
        return 0
    fi
    info "Installing $name via pip3..."
    pip3 install --quiet --user "$pkg" 2>/dev/null || \
    pip3 install --quiet "$pkg" 2>/dev/null || \
    pip install --quiet --user "$pkg" 2>/dev/null || \
        warn "$name: pip install failed"
    # pip --user installs to ~/.local/bin
    if [ -f "$LOCAL_BIN/$name" ]; then
        sudo ln -sf "$LOCAL_BIN/$name" "/usr/local/bin/$name" 2>/dev/null || true
        log "$name installed at $LOCAL_BIN/$name"
    fi
}

# ── Helper: install_wrapper <script_path> <binary_name> ──────────────
install_wrapper() {
    local script="$1"
    local name="$2"
    local dest="/usr/local/bin/$name"
    if command -v "$name" &>/dev/null; then
        log "$name already installed"
        return 0
    fi
    sudo bash -c "cat > $dest << 'WRAPPER'
#!/usr/bin/env bash
exec python3 $script \"\$@\"
WRAPPER"
    sudo chmod +x "$dest"
    log "$name wrapper installed at $dest"
}

# ════════════════════════════════════════════════════════════════════════
echo ""
log "═══ STEP 1: Go-based Tools ═══"
# ════════════════════════════════════════════════════════════════════════

install_go_tool "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"       "subfinder"
install_go_tool "github.com/projectdiscovery/httpx/cmd/httpx@latest"                  "httpx"
install_go_tool "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"                   "dnsx"
install_go_tool "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"              "naabu"
install_go_tool "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"             "nuclei"
install_go_tool "github.com/projectdiscovery/katana/cmd/katana@latest"               "katana"
install_go_tool "github.com/projectdiscovery/tlsx/cmd/tlsx@latest"                   "tlsx"
install_go_tool "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"        "shuffledns"
install_go_tool "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest" "interactsh-client"
install_go_tool "github.com/lc/gau/v2/cmd/gau@latest"                                "gau"
install_go_tool "github.com/tomnomnom/waybackurls@latest"                             "waybackurls"
install_go_tool "github.com/tomnomnom/assetfinder@latest"                             "assetfinder"
install_go_tool "github.com/tomnomnom/gf@latest"                                      "gf"
install_go_tool "github.com/tomnomnom/qsreplace@latest"                               "qsreplace"
install_go_tool "github.com/tomnomnom/unfurl@latest"                                  "unfurl"
install_go_tool "github.com/hahwul/dalfox/v2@latest"                                  "dalfox"
install_go_tool "github.com/Emoe/kxss@latest"                                         "kxss"
install_go_tool "github.com/PentestToolsCom/subzy@latest"                             "subzy"
install_go_tool "github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"                  "crlfuzz"
install_go_tool "github.com/OJ/gobuster/v3@latest"                                    "gobuster"
install_go_tool "github.com/jaeles-project/gospider@latest"                           "gospider"
install_go_tool "github.com/hakluke/hakrawler@latest"                                  "hakrawler"
install_go_tool "github.com/003random/getJS@latest"                                   "getJS"
install_go_tool "github.com/d3mondev/puredns/v2@latest"                               "puredns"
install_go_tool "github.com/infosec-au/altdns@latest"                                 "altdns" 2>/dev/null || true

# massdns — build from source
if ! command -v massdns &>/dev/null; then
    info "Building massdns from source..."
    git clone --depth 1 https://github.com/blechschmidt/massdns.git "$TMP_BUILD/massdns" 2>/dev/null || true
    cd "$TMP_BUILD/massdns"
    make 2>/dev/null && (sudo mv bin/massdns /usr/local/bin/ || mv bin/massdns "$LOCAL_BIN/") && log "massdns installed" || warn "massdns build failed"
    cd "$TMP_BUILD"
fi

# ffuf — prefer apt, fallback go install
if ! command -v ffuf &>/dev/null; then
    sudo apt-get install -y -qq ffuf 2>/dev/null || \
    install_go_tool "github.com/ffuf/ffuf/v2@latest" "ffuf"
fi

# feroxbuster
if ! command -v feroxbuster &>/dev/null; then
    info "Installing feroxbuster..."
    if curl -fsSL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash 2>/dev/null; then
        sudo mv feroxbuster /usr/local/bin/ 2>/dev/null || mv feroxbuster "$LOCAL_BIN/" 2>/dev/null || true
        log "feroxbuster installed"
    else
        sudo apt-get install -y -qq feroxbuster 2>/dev/null || warn "feroxbuster install failed"
    fi
fi

# findomain
if ! command -v findomain &>/dev/null; then
    info "Installing findomain..."
    FINDOMAIN_URL="https://github.com/findomain/findomain/releases/latest/download/findomain-linux"
    curl -fsSL "$FINDOMAIN_URL" -o "$TMP_BUILD/findomain" 2>/dev/null && \
        chmod +x "$TMP_BUILD/findomain" && \
        (sudo mv "$TMP_BUILD/findomain" /usr/local/bin/findomain || mv "$TMP_BUILD/findomain" "$LOCAL_BIN/findomain") && \
        log "findomain installed" || warn "findomain install failed"
fi

# ════════════════════════════════════════════════════════════════════════
echo ""
log "═══ STEP 2: Python-based Tools ═══"
# ════════════════════════════════════════════════════════════════════════

# sqlmap — prefer apt
if ! command -v sqlmap &>/dev/null; then
    sudo apt-get install -y -qq sqlmap 2>/dev/null || \
    install_pip_tool "sqlmap" "sqlmap"
fi

# arjun
install_pip_tool "arjun" "arjun"

# paramspider
if ! command -v paramspider &>/dev/null; then
    info "Installing paramspider..."
    pip3 install --quiet --user paramspider 2>/dev/null || \
    pip3 install --quiet paramspider 2>/dev/null || {
        # Fallback: clone and install
        git clone --depth 1 https://github.com/devanshbatham/paramspider.git "$TMP_BUILD/paramspider" 2>/dev/null
        cd "$TMP_BUILD/paramspider"
        pip3 install --quiet -e . 2>/dev/null || pip3 install --quiet . 2>/dev/null || true
        cd "$TMP_BUILD"
    }
    # Create system-wide symlink if installed to user dir
    if [ -f "$LOCAL_BIN/paramspider" ]; then
        sudo ln -sf "$LOCAL_BIN/paramspider" "/usr/local/bin/paramspider" 2>/dev/null || true
        log "paramspider linked to /usr/local/bin"
    fi
fi

# bbot
if ! command -v bbot &>/dev/null; then
    info "Installing bbot..."
    pip3 install --quiet --user bbot 2>/dev/null || pip3 install --quiet bbot 2>/dev/null || warn "bbot pip failed"
    if [ -f "$LOCAL_BIN/bbot" ]; then
        sudo ln -sf "$LOCAL_BIN/bbot" "/usr/local/bin/bbot" 2>/dev/null || true
        log "bbot linked to /usr/local/bin"
    fi
fi

# ghauri
if ! command -v ghauri &>/dev/null; then
    info "Installing ghauri..."
    pip3 install --quiet --user ghauri 2>/dev/null || {
        git clone --depth 1 https://github.com/r0oth3x49/ghauri.git "$TMP_BUILD/ghauri" 2>/dev/null
        cd "$TMP_BUILD/ghauri"
        pip3 install --quiet -e . 2>/dev/null || true
        cd "$TMP_BUILD"
    }
    if [ -f "$LOCAL_BIN/ghauri" ]; then
        sudo ln -sf "$LOCAL_BIN/ghauri" "/usr/local/bin/ghauri" 2>/dev/null || true
        log "ghauri linked to /usr/local/bin"
    fi
fi

# dirsearch
if ! command -v dirsearch &>/dev/null; then
    sudo apt-get install -y -qq dirsearch 2>/dev/null || {
        git clone --depth 1 https://github.com/maurosoria/dirsearch.git "$TMP_BUILD/dirsearch" 2>/dev/null
        pip3 install --quiet -e "$TMP_BUILD/dirsearch" 2>/dev/null || true
        install_wrapper "$TMP_BUILD/dirsearch/dirsearch.py" "dirsearch"
    }
fi

# s3scanner
install_pip_tool "s3scanner" "s3scanner"

# ════════════════════════════════════════════════════════════════════════
echo ""
log "═══ STEP 3: Git-built Tools ═══"
# ════════════════════════════════════════════════════════════════════════

# dontgo403
if ! command -v dontgo403 &>/dev/null; then
    info "Building dontgo403..."
    git clone --depth 1 https://github.com/mbrg/dontgo403.git "$TMP_BUILD/dontgo403" 2>/dev/null
    cd "$TMP_BUILD/dontgo403"
    go build -o dontgo403 . 2>/dev/null && \
        (sudo mv dontgo403 /usr/local/bin/dontgo403 || mv dontgo403 "$LOCAL_BIN/dontgo403") && \
        log "dontgo403 installed" || warn "dontgo403 build failed"
    cd "$TMP_BUILD"
fi

# kiterunner (kr)
if ! command -v kr &>/dev/null; then
    info "Building kiterunner (kr)..."
    git clone --depth 1 https://github.com/assetnote/kiterunner.git "$TMP_BUILD/kiterunner" 2>/dev/null
    cd "$TMP_BUILD/kiterunner"
    if make build 2>/dev/null; then
        sudo mv dist/kr /usr/local/bin/kr 2>/dev/null || mv dist/kr "$LOCAL_BIN/kr" 2>/dev/null || \
        sudo mv kr /usr/local/bin/kr 2>/dev/null || mv kr "$LOCAL_BIN/kr" 2>/dev/null || true
    elif go build -o kr ./cmd/kiterunner 2>/dev/null; then
        sudo mv kr /usr/local/bin/kr 2>/dev/null || mv kr "$LOCAL_BIN/kr" 2>/dev/null || true
    fi
    command -v kr &>/dev/null && log "kiterunner (kr) installed" || warn "kiterunner build failed"
    cd "$TMP_BUILD"
fi

# smuggler
if ! command -v smuggler &>/dev/null; then
    info "Installing smuggler..."
    git clone --depth 1 https://github.com/defparam/smuggler.git "$OPT_DIR/smuggler" 2>/dev/null || \
    git -C "$OPT_DIR/smuggler" pull 2>/dev/null || true
    sudo bash -c "cat > /usr/local/bin/smuggler << 'EOF'
#!/usr/bin/env bash
exec python3 $OPT_DIR/smuggler/smuggler.py \"\$@\"
EOF"
    sudo chmod +x /usr/local/bin/smuggler
    log "smuggler wrapper installed"
fi

# cloud_enum
if ! command -v cloud_enum &>/dev/null; then
    info "Installing cloud_enum..."
    git clone --depth 1 https://github.com/initstring/cloud_enum.git "$OPT_DIR/cloud_enum" 2>/dev/null || \
    git -C "$OPT_DIR/cloud_enum" pull 2>/dev/null || true
    pip3 install --quiet -r "$OPT_DIR/cloud_enum/requirements.txt" 2>/dev/null || true
    sudo bash -c "cat > /usr/local/bin/cloud_enum << 'EOF'
#!/usr/bin/env bash
exec python3 $OPT_DIR/cloud_enum/cloud_enum.py \"\$@\"
EOF"
    sudo chmod +x /usr/local/bin/cloud_enum
    log "cloud_enum wrapper installed"
fi

# ════════════════════════════════════════════════════════════════════════
echo ""
log "═══ STEP 4: Wordlists & Templates ═══"
# ════════════════════════════════════════════════════════════════════════

# SecLists
if [ ! -d "/usr/share/seclists" ] && [ ! -d "$HOME/SecLists" ]; then
    info "Installing SecLists..."
    sudo apt-get install -y -qq seclists 2>/dev/null || {
        git clone --depth 1 https://github.com/danielmiessler/SecLists.git /tmp/SecLists 2>/dev/null
        sudo mv /tmp/SecLists /usr/share/seclists && log "SecLists installed at /usr/share/seclists"
    }
fi

# nuclei templates update
if command -v nuclei &>/dev/null; then
    info "Updating nuclei templates..."
    nuclei -update-templates -silent 2>/dev/null || true
fi

# massdns resolvers
if [ ! -f "/opt/mohammed-tools/resolvers.txt" ]; then
    info "Downloading DNS resolvers..."
    curl -fsSL "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt" \
        -o "$OPT_DIR/resolvers.txt" 2>/dev/null || true
fi

# ════════════════════════════════════════════════════════════════════════
echo ""
log "═══ STEP 5: Final PATH Hardening ═══"
# ════════════════════════════════════════════════════════════════════════
# For tools installed to ~/.local/bin, create /usr/local/bin symlinks
for tool in subfinder httpx dnsx naabu nuclei katana tlsx shuffledns \
            gau waybackurls assetfinder dalfox kxss subzy crlfuzz \
            gospider hakrawler getJS puredns paramspider arjun bbot \
            ghauri dontgo403 kr ffuf feroxbuster dirsearch s3scanner; do
    local_path="$LOCAL_BIN/$tool"
    go_path="$GOBIN/$tool"
    sys_path="/usr/local/bin/$tool"

    if [ ! -f "$sys_path" ]; then
        if [ -f "$local_path" ]; then
            sudo ln -sf "$local_path" "$sys_path" 2>/dev/null || true
            info "Linked $tool: $local_path → $sys_path"
        elif [ -f "$go_path" ]; then
            sudo ln -sf "$go_path" "$sys_path" 2>/dev/null || true
            info "Linked $tool: $go_path → $sys_path"
        fi
    fi
done

# ════════════════════════════════════════════════════════════════════════
echo ""
log "═══ STEP 6: Building MOHAMMED v3 Binary ═══"
# ════════════════════════════════════════════════════════════════════════

PROJ_DIR=""
if [ -d "/mnt/c/Users/vxxvv/Desktop/hack/mohammed" ]; then
    PROJ_DIR="/mnt/c/Users/vxxvv/Desktop/hack/mohammed"
elif [ -d "$HOME/mohammed" ]; then
    PROJ_DIR="$HOME/mohammed"
fi

if [ -n "$PROJ_DIR" ]; then
    cd "$PROJ_DIR"
    info "Building from: $PROJ_DIR"
    go build -o mohammed ./cmd/mohammed 2>&1 && \
        log "mohammed binary built successfully" || \
        err "Build failed — check Go source for errors"
    chmod +x mohammed
else
    warn "MOHAMMED project directory not found — skipping binary build"
fi

# ════════════════════════════════════════════════════════════════════════
echo ""
log "═══ STEP 7: Doctor Check — Verifying All Tools ═══"
# ════════════════════════════════════════════════════════════════════════

source "$SHELL_RC" 2>/dev/null || true
export PATH="$PATH:$GOBIN:$LOCAL_BIN:/usr/local/bin"

if [ -n "$PROJ_DIR" ] && [ -f "$PROJ_DIR/mohammed" ]; then
    cd "$PROJ_DIR"
    ./mohammed doctor
fi

# Cleanup
rm -rf "$TMP_BUILD"

echo ""
log "════════════════════════════════════════════════"
log "  Setup Complete! Run: source $SHELL_RC"
log "  Then: ./mohammed doctor  (to verify all tools)"
log "════════════════════════════════════════════════"
