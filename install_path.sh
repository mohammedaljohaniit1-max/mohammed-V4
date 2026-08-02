#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
# MOHAMMED V12.0 OMEGA — Auto-Installer & PATH Enforcer
# ---------------------------------------------------------------------------
# Root cause fixed: "Missing tools or PATH mismatch cause quiet phase skips."
#
# This script now does THREE things, idempotently:
#   1. INSTALLS all 38 external binaries the engine spawns (was: symlink-only).
#   2. LINKS every installed binary into BOTH /usr/local/bin AND $GOPATH/bin
#      so the tool resolves no matter which process (or user) launches it.
#   3. ENFORCES the tool directories onto PATH for the current shell AND
#      permanently (written to the shell rc file).
#
# The 38 canonical binaries (must all be resolvable for zero phase skips):
#   subfinder chaos bbot assetfinder findomain dnsx puredns massdns shuffledns
#   subzy httpx tlsx naabu nmap gau waybackurls katana gospider hakrawler getJS
#   paramspider arjun ffuf feroxbuster dirsearch nuclei dalfox kxss sqlmap
#   ghauri dontgo403 kr crlfuzz smuggler cloud_enum s3scanner interactsh-client gf
#
# Run this whenever `mohammed doctor` reports a tool "Missing", after cloning
# fresh, or any time PATH gets clobbered.
#
# Usage: bash   install_path.sh          (install + link + persist PATH to rc)
#        source install_path.sh          (same, but also updates CURRENT shell)
#        SKIP_INSTALL=1 bash install_path.sh   (PATH/symlink-only, no downloads)
# ═══════════════════════════════════════════════════════════════════════════
set -uo pipefail   # NOTE: no -e — one tool failure must not abort the run.

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; RED='\033[0;31m'; NC='\033[0m'
_log()  { echo -e "${GREEN}[+]${NC} $*"; }
_warn() { echo -e "${YELLOW}[!]${NC} $*"; }
_info() { echo -e "${CYAN}[*]${NC} $*"; }
_err()  { echo -e "${RED}[✗]${NC} $*"; }

# ── sudo shim ───────────────────────────────────────────────────────────────
if command -v sudo &>/dev/null && [ "$(id -u)" -ne 0 ]; then SUDO="sudo"; else SUDO=""; fi

# ── Resolve shell rc file ───────────────────────────────────────────────────
SHELL_RC="$HOME/.bashrc"
if [ -n "${ZSH_VERSION:-}" ] || [ "$(basename "${SHELL:-bash}")" = "zsh" ]; then
    SHELL_RC="$HOME/.zshrc"
fi
touch "$SHELL_RC" 2>/dev/null || true

# ── Directories that hold recon tools ───────────────────────────────────────
export GOPATH="${GOPATH:-$HOME/go}"
GOBIN="$GOPATH/bin"
LOCAL_BIN="$HOME/.local/bin"
OPT_DIR="/opt/mohammed-tools"
TMP_BUILD="/tmp/mohammed_install_$$"

mkdir -p "$GOBIN" "$LOCAL_BIN" "$TMP_BUILD" 2>/dev/null || true
$SUDO mkdir -p "$OPT_DIR" 2>/dev/null || mkdir -p "$OPT_DIR" 2>/dev/null || OPT_DIR="$HOME/mohammed-tools"
mkdir -p "$OPT_DIR" 2>/dev/null || true

PATH_DIRS=(
    "/usr/local/go/bin"     # go itself
    "$GOBIN"                # go install targets
    "$LOCAL_BIN"            # pip --user / pipx
    "/usr/local/bin"        # system-wide symlinks + wrappers
    "/snap/bin"             # snap-installed tools
)
# Make sure the tool dirs are on PATH for THIS run so `command -v` sees fresh installs.
for d in "${PATH_DIRS[@]}"; do
    case ":$PATH:" in *":$d:"*) : ;; *) export PATH="$PATH:$d" ;; esac
done

# ═══════════════════════════════════════════════════════════════════════════
# The 38 canonical binaries. `link_tool` uses this to fan out symlinks.
# ═══════════════════════════════════════════════════════════════════════════
TOOLS=(
    subfinder chaos bbot assetfinder findomain
    dnsx puredns massdns shuffledns
    subzy httpx tlsx naabu nmap
    gau waybackurls katana gospider hakrawler
    getJS paramspider arjun
    ffuf feroxbuster dirsearch
    nuclei dalfox kxss sqlmap ghauri
    nomore403 dontgo403 kiterunner kr crlfuzz smuggler
    cloud_enum s3scanner interactsh-client gf
)

# ── Append a directory to PATH (session + persistent, dedup-safe) ───────────
add_dir() {
    local dir="$1"
    case ":$PATH:" in
        *":$dir:"*) : ;;                       # already in current PATH
        *) export PATH="$PATH:$dir" ;;
    esac
    if ! grep -qF "export PATH=\"\$PATH:$dir\"" "$SHELL_RC" 2>/dev/null; then
        echo "export PATH=\"\$PATH:$dir\"" >> "$SHELL_RC"
        _info "persisted $dir → $SHELL_RC"
    fi
}

# ── link_tool <src> <name> : symlink into BOTH /usr/local/bin AND $GOPATH/bin ─
# The mandate requires binaries be reachable via /usr/local/bin AND $GOPATH/bin.
link_tool() {
    local src="$1" name="$2"
    [ -e "$src" ] || return 1
    # 1) /usr/local/bin (system-wide) — fall back to ~/.local/bin if no perms.
    if ! $SUDO ln -sf "$src" "/usr/local/bin/$name" 2>/dev/null; then
        ln -sf "$src" "$LOCAL_BIN/$name" 2>/dev/null || true
    fi
    # 2) $GOPATH/bin (Go convention path the engine also probes).
    [ "$src" = "$GOBIN/$name" ] || ln -sf "$src" "$GOBIN/$name" 2>/dev/null || true
    return 0
}

# ── Locate an already-present binary anywhere sensible, then link it out ─────
relink_existing() {
    local name="$1"
    local resolved
    resolved="$(command -v "$name" 2>/dev/null || true)"
    if [ -n "$resolved" ]; then link_tool "$resolved" "$name"; return 0; fi
    for cand in "$GOBIN/$name" "$LOCAL_BIN/$name" "$HOME/.local/bin/$name" \
                "/usr/local/bin/$name" "/snap/bin/$name" "$OPT_DIR/$name"; do
        if [ -e "$cand" ]; then link_tool "$cand" "$name"; return 0; fi
    done
    return 1
}

# ── Installers (skip if already resolvable) ─────────────────────────────────
install_go_tool() {
    local import="$1" name="$2"
    command -v "$name" &>/dev/null && { relink_existing "$name"; return 0; }
    command -v go &>/dev/null || { _warn "$name: go not installed — skipping"; return 1; }
    _info "go install $name ..."
    if GOPATH="$GOPATH" GOBIN="$GOBIN" go install -v "$import" 2>/dev/null; then
        link_tool "$GOBIN/$name" "$name"
        command -v "$name" &>/dev/null && _log "$name installed" || _warn "$name built to $GOBIN but not on PATH"
    else
        _warn "$name: go install failed"
    fi
}

install_pip_tool() {
    local pkg="$1" name="${2:-$1}"
    command -v "$name" &>/dev/null && { relink_existing "$name"; return 0; }
    _info "pip install $name ..."
    pipx install "$pkg" 2>/dev/null \
        || pip3 install --quiet --user "$pkg" 2>/dev/null \
        || pip3 install --quiet --break-system-packages "$pkg" 2>/dev/null \
        || pip3 install --quiet "$pkg" 2>/dev/null \
        || _warn "$name: pip install failed"
    relink_existing "$name"
}

install_py_wrapper() {
    local script="$1" name="$2"
    command -v "$name" &>/dev/null && { relink_existing "$name"; return 0; }
    local dest="/usr/local/bin/$name"
    if ! $SUDO bash -c "printf '#!/usr/bin/env bash\nexec python3 %s \"\$@\"\n' '$script' > $dest" 2>/dev/null; then
        dest="$LOCAL_BIN/$name"
        printf '#!/usr/bin/env bash\nexec python3 %s "$@"\n' "$script" > "$dest"
    fi
    chmod +x "$dest" 2>/dev/null; $SUDO chmod +x "$dest" 2>/dev/null || true
    link_tool "$dest" "$name"
    _log "$name wrapper installed → $dest"
}

# ═══════════════════════════════════════════════════════════════════════════
# INSTALL PHASE (skippable with SKIP_INSTALL=1)
# ═══════════════════════════════════════════════════════════════════════════
if [ "${SKIP_INSTALL:-0}" != "1" ]; then
    _log "Installing the 45 MOHAMMED tools (V12.1: +7 modern tools; idempotent — present tools skipped)..."

    # System deps needed by several tools (nmap, dig, ruby gems, libpcap for naabu).
    if command -v apt-get &>/dev/null; then
        $SUDO apt-get update -y -qq 2>/dev/null || _warn "apt-get update failed (non-fatal)"
        $SUDO apt-get install -y -qq \
            curl wget git jq nmap dnsutils bind9-utils unzip \
            python3 python3-pip python3-venv pipx build-essential libpcap-dev \
            2>/dev/null || _warn "some apt packages may have failed (non-fatal)"
    fi

    # Ensure Go exists (required for the go-based tools + the mohammed binary).
    if ! command -v go &>/dev/null; then
        _warn "Go not found — installing Go 1.22.5..."
        GO_VERSION="1.22.5"
        curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o "$TMP_BUILD/go.tar.gz" \
            && $SUDO rm -rf /usr/local/go \
            && $SUDO tar -C /usr/local -xzf "$TMP_BUILD/go.tar.gz" \
            && export PATH="$PATH:/usr/local/go/bin" \
            || _err "Go install failed — go-based tools will be skipped"
    fi

    # ── ProjectDiscovery + tomnomnom + community Go tools ───────────────────
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
    install_go_tool "github.com/hahwul/dalfox/v2@latest"                                  "dalfox"
    install_go_tool "github.com/Emoe/kxss@latest"                                         "kxss"
    install_go_tool "github.com/PentestPad/subzy@latest"                                  "subzy"
    install_go_tool "github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"                   "crlfuzz"
    install_go_tool "github.com/jaeles-project/gospider@latest"                           "gospider"
    install_go_tool "github.com/hakluke/hakrawler@latest"                                 "hakrawler"
    install_go_tool "github.com/003random/getJS/v2@latest"                                "getJS"
    install_go_tool "github.com/d3mondev/puredns/v2@latest"                               "puredns"
    install_go_tool "github.com/ffuf/ffuf/v2@latest"                                      "ffuf"

    # ── V12.1 SECTION 3: modern recon/vuln tooling (2024-2026) ──────────────
    install_go_tool "github.com/projectdiscovery/chaos-client/cmd/chaos@latest"           "chaos"
    install_go_tool "github.com/projectdiscovery/alterx/cmd/alterx@latest"                "alterx"
    install_go_tool "github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest"            "cdncheck"
    install_go_tool "github.com/projectdiscovery/uncover/cmd/uncover@latest"              "uncover"
    install_go_tool "github.com/projectdiscovery/notify/cmd/notify@latest"                "notify"
    install_go_tool "github.com/edoardottt/cariddi/cmd/cariddi@latest"                    "cariddi"
    install_go_tool "github.com/trufflesecurity/trufflehog/v3@latest"                     "trufflehog"

    # ── ppmap (source build — no go install path; git clone + go build) ─────
    if ! command -v ppmap &>/dev/null && command -v go &>/dev/null; then
        _info "Building ppmap from source..."
        if git clone --depth 1 https://github.com/kleiton0x00/ppmap.git "$TMP_BUILD/ppmap" 2>/dev/null; then
            ( cd "$TMP_BUILD/ppmap" && go build -o "$OPT_DIR/ppmap" . >/dev/null 2>&1 && link_tool "$OPT_DIR/ppmap" "ppmap" )
            command -v ppmap &>/dev/null && _log "ppmap installed" || _warn "ppmap build failed"
        else
            _warn "ppmap clone failed"
        fi
    fi

    # ── massdns (source build — required by puredns/shuffledns) ─────────────
    if ! command -v massdns &>/dev/null; then
        _info "Building massdns from source..."
        if git clone --depth 1 https://github.com/blechschmidt/massdns.git "$TMP_BUILD/massdns" 2>/dev/null; then
            ( cd "$TMP_BUILD/massdns" && make >/dev/null 2>&1 && cp bin/massdns "$OPT_DIR/massdns" 2>/dev/null && link_tool "$OPT_DIR/massdns" "massdns" )
            command -v massdns &>/dev/null && _log "massdns installed" || _warn "massdns build failed"
        else
            _warn "massdns clone failed"
        fi
    fi

    # ── feroxbuster ─────────────────────────────────────────────────────────
    if ! command -v feroxbuster &>/dev/null; then
        _info "Installing feroxbuster..."
        ( cd "$OPT_DIR" && curl -fsSL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash >/dev/null 2>&1 \
            && link_tool "$OPT_DIR/feroxbuster" "feroxbuster" ) \
            || $SUDO apt-get install -y -qq feroxbuster 2>/dev/null || _warn "feroxbuster install failed"
    fi

    # ── findomain (release binary) ──────────────────────────────────────────
    if ! command -v findomain &>/dev/null; then
        _info "Installing findomain..."
        curl -fsSL "https://github.com/findomain/findomain/releases/latest/download/findomain-linux" -o "$OPT_DIR/findomain" 2>/dev/null \
            && chmod +x "$OPT_DIR/findomain" && link_tool "$OPT_DIR/findomain" "findomain" \
            && _log "findomain installed" || _warn "findomain install failed"
    fi

    # ── Python-based tools ────────────────────────────────────────────────────
    if ! command -v sqlmap &>/dev/null; then
        $SUDO apt-get install -y -qq sqlmap 2>/dev/null || install_pip_tool "sqlmap" "sqlmap"
    fi
    install_pip_tool "arjun" "arjun"
    install_pip_tool "bbot"  "bbot"
    install_pip_tool "s3scanner" "s3scanner"
    install_pip_tool "ghauri" "ghauri"

    # ── V12.3 FAILURE 1: legacy OWASP enumerator PURGED ──────────────────────
    # Passive subdomain enumeration is now a concurrent fan-out of
    # subfinder + bbot + findomain + assetfinder + chaos (see phases.go
    # passiveEnumApexConcurrently). Install chaos-client as the DB-backed
    # passive source that replaces the legacy enumerator.
    if ! command -v chaos &>/dev/null; then
        _info "Installing chaos-client..."
        install_go_tool "github.com/projectdiscovery/chaos-client/cmd/chaos@latest" "chaos" \
            || _warn "chaos install failed"
        relink_existing "chaos"
    fi

    # ── paramspider (V6: Kali apt package — installs to /usr/bin) ─────────────
    # BUG #1: on Kali the canonical paramspider ships as an apt package that
    # lands at /usr/bin/paramspider. Prefer it; only fall back to the git/pip
    # install on non-apt systems. The apt route is what the production box used.
    if ! command -v paramspider &>/dev/null; then
        _info "Installing paramspider (apt preferred)..."
        $SUDO apt-get install -y -qq paramspider 2>/dev/null || {
            if git clone --depth 1 https://github.com/devanshbatham/paramspider.git "$OPT_DIR/paramspider_src" 2>/dev/null; then
                pip3 install --quiet --break-system-packages "$OPT_DIR/paramspider_src" 2>/dev/null \
                    || pip3 install --quiet --user "$OPT_DIR/paramspider_src" 2>/dev/null \
                    || pip3 install --quiet "$OPT_DIR/paramspider_src" 2>/dev/null || true
            fi
        }
        relink_existing "paramspider"
        command -v paramspider &>/dev/null && _log "paramspider installed" || _warn "paramspider install failed"
    fi

    # ── dirsearch ─────────────────────────────────────────────────────────────
    if ! command -v dirsearch &>/dev/null; then
        $SUDO apt-get install -y -qq dirsearch 2>/dev/null || {
            git clone --depth 1 https://github.com/maurosoria/dirsearch.git "$OPT_DIR/dirsearch" 2>/dev/null
            install_py_wrapper "$OPT_DIR/dirsearch/dirsearch.py" "dirsearch"
        }
        relink_existing "dirsearch"
    fi

    # ── dontgo403 → nomore403 (V6: repo renamed) ──────────────────────────────
    # BUG (Section 2): devploit/dontgo403 was renamed to devploit/nomore403. The
    # old go build target no longer resolves. Install via `go install` and expose
    # BOTH names so callers using the legacy "dontgo403" binary keep working.
    if ! command -v dontgo403 &>/dev/null && ! command -v nomore403 &>/dev/null; then
        _info "Installing nomore403 (formerly dontgo403)..."
        install_go_tool "github.com/devploit/nomore403@latest" "nomore403"
        if command -v nomore403 &>/dev/null; then
            # Symlink the legacy name to the new binary.
            link_tool "$(command -v nomore403)" "dontgo403"
            _log "nomore403 installed (dontgo403 symlink created)"
        else
            _warn "nomore403 install failed"
        fi
    fi

    # ── kiterunner (kr) (V7 Section 1.2: PRE-BUILT BINARY, not go install) ────
    # `go install` FAILS on modern Go for kiterunner. The proven method on Kali
    # 2026.2 is to download the v1.0.2 release tarball, drop the `kr` binary on
    # PATH, and symlink `kiterunner` → `kr`. We fall back to `go install` only if
    # the download is unavailable (offline mirror).
    if ! command -v kr &>/dev/null && ! command -v kiterunner &>/dev/null; then
        _info "Installing kiterunner v1.0.2 (pre-built binary)..."
        KR_URL="https://github.com/assetnote/kiterunner/releases/download/v1.0.2/kiterunner_1.0.2_linux_amd64.tar.gz"
        if wget -q "$KR_URL" -O /tmp/kr.tar.gz 2>/dev/null && tar -xzf /tmp/kr.tar.gz -C /tmp 2>/dev/null && [ -f /tmp/kr ]; then
            cp /tmp/kr "$OPT_DIR/kr" 2>/dev/null && chmod +x "$OPT_DIR/kr"
            link_tool "$OPT_DIR/kr" "kr"
            command -v kr &>/dev/null && link_tool "$(command -v kr)" "kiterunner"
            rm -f /tmp/kr.tar.gz /tmp/kr 2>/dev/null || true
            command -v kr &>/dev/null && _log "kiterunner v1.0.2 installed (kiterunner symlink created)" || _warn "kiterunner install failed"
        else
            _warn "kiterunner binary download failed — trying go install fallback"
            install_go_tool "github.com/assetnote/kiterunner/cmd/kiterunner@latest" "kiterunner" \
                && command -v kiterunner &>/dev/null && link_tool "$(command -v kiterunner)" "kr"
        fi
    fi

    # ── smuggler (python wrapper) ─────────────────────────────────────────────
    if ! command -v smuggler &>/dev/null; then
        _info "Installing smuggler..."
        git clone --depth 1 https://github.com/defparam/smuggler.git "$OPT_DIR/smuggler" 2>/dev/null \
            || git -C "$OPT_DIR/smuggler" pull 2>/dev/null || true
        install_py_wrapper "$OPT_DIR/smuggler/smuggler.py" "smuggler"
    fi

    # ── cloud_enum (V6: git clone /opt + requests-futures + bash wrapper) ─────
    # BUG #2: the Go runner expects a `cloud_enum` binary on PATH. cloud_enum is
    # a python script, so we clone it to /opt/cloud_enum, install its deps
    # (requirements.txt PLUS requests-futures, which the requirements file omits
    # on some tags and whose absence makes cloud_enum crash on import), and drop
    # a bash wrapper on PATH that execs the script. This is the exact recipe
    # proven on the Kali production box.
    if ! command -v cloud_enum &>/dev/null; then
        _info "Installing cloud_enum..."
        git clone --depth 1 https://github.com/initstring/cloud_enum.git "$OPT_DIR/cloud_enum" 2>/dev/null \
            || git -C "$OPT_DIR/cloud_enum" pull 2>/dev/null || true
        pip3 install --quiet --break-system-packages -r "$OPT_DIR/cloud_enum/requirements.txt" 2>/dev/null \
            || pip3 install --quiet -r "$OPT_DIR/cloud_enum/requirements.txt" 2>/dev/null || true
        # requests-futures is required at import time but missing from some tags.
        # V7 Section 1.4: --ignore-installed avoids a conflict with a distro-pinned
        # older requests-futures that pip otherwise refuses to overwrite on Kali.
        pip3 install requests-futures --break-system-packages --ignore-installed 2>/dev/null \
            || pip3 install --quiet --break-system-packages requests-futures 2>/dev/null \
            || pip3 install --quiet requests-futures 2>/dev/null || true
        # Bash wrapper (not a python-import wrapper) so `cloud_enum <args>` works
        # from any CWD and lands on PATH as a real executable.
        cat > "$OPT_DIR/cloud_enum_wrapper.sh" <<EOF
#!/usr/bin/env bash
exec python3 "$OPT_DIR/cloud_enum/cloud_enum.py" "\$@"
EOF
        chmod +x "$OPT_DIR/cloud_enum_wrapper.sh"
        link_tool "$OPT_DIR/cloud_enum_wrapper.sh" "cloud_enum"
        command -v cloud_enum &>/dev/null && _log "cloud_enum installed" || _warn "cloud_enum install failed"
    fi
else
    _warn "SKIP_INSTALL=1 — skipping downloads, only linking + PATH enforcement."
fi

# ═══════════════════════════════════════════════════════════════════════════
# LINK PHASE — fan every resolvable tool out to /usr/local/bin AND $GOPATH/bin
# ═══════════════════════════════════════════════════════════════════════════
_log "Linking all resolvable tools into /usr/local/bin and \$GOPATH/bin ..."
link_count=0
for tool in "${TOOLS[@]}"; do
    if relink_existing "$tool"; then
        link_count=$((link_count + 1))
    fi
done

# ═══════════════════════════════════════════════════════════════════════════
# PATH PHASE — persist tool directories to the shell rc
# ═══════════════════════════════════════════════════════════════════════════
_log "Enforcing PATH entries..."
for d in "${PATH_DIRS[@]}"; do add_dir "$d"; done
if ! grep -qF "export GOPATH=$GOPATH" "$SHELL_RC" 2>/dev/null; then
    echo "export GOPATH=$GOPATH" >> "$SHELL_RC"
    _info "persisted GOPATH=$GOPATH → $SHELL_RC"
fi

# ═══════════════════════════════════════════════════════════════════════════
# V10.0 SOVEREIGN PHASE — Chromium / Go-Rod headless engine + Ollama brain
# ═══════════════════════════════════════════════════════════════════════════
_log "V10.0 SOVEREIGN: provisioning headless Chromium + probing Ollama brain ..."

# ── Chromium for the Go-Rod CDP engine (pkg/browser/cdp.go) ─────────────────
# Go-Rod auto-downloads a private Chromium on first run, but on air-gapped /
# minimal boxes we prefer a system browser. Detect an existing binary and, if
# absent, try the distro package. Either way we export CHROME_BIN so cdp.go's
# NewEngine() picks it up (it honours CHROME_BIN / ROD_BROWSER_BIN).
CHROME_FOUND=""
for cand in chromium chromium-browser google-chrome google-chrome-stable chrome; do
    if command -v "$cand" &>/dev/null; then
        CHROME_FOUND="$(command -v "$cand")"
        break
    fi
done
for cand in /usr/bin/chromium /usr/bin/chromium-browser /usr/bin/google-chrome \
            /snap/bin/chromium /root/.cache/rod/browser/*/chrome; do
    [ -n "$CHROME_FOUND" ] && break
    if [ -x "$cand" ]; then CHROME_FOUND="$cand"; break; fi
done

if [ -z "$CHROME_FOUND" ]; then
    _info "No system Chromium detected — attempting package install (best-effort)..."
    if command -v apt-get &>/dev/null; then
        (apt-get update -y && apt-get install -y chromium || \
         apt-get install -y chromium-browser) &>/dev/null || true
    elif command -v dnf &>/dev/null; then
        dnf install -y chromium &>/dev/null || true
    elif command -v pacman &>/dev/null; then
        pacman -Sy --noconfirm chromium &>/dev/null || true
    fi
    for cand in chromium chromium-browser google-chrome google-chrome-stable; do
        if command -v "$cand" &>/dev/null; then CHROME_FOUND="$(command -v "$cand")"; break; fi
    done
fi

if [ -n "$CHROME_FOUND" ]; then
    _log "Chromium ready for Go-Rod CDP engine → $CHROME_FOUND"
    if ! grep -qF "export CHROME_BIN=" "$SHELL_RC" 2>/dev/null; then
        echo "export CHROME_BIN=$CHROME_FOUND"      >> "$SHELL_RC"
        echo "export ROD_BROWSER_BIN=$CHROME_FOUND" >> "$SHELL_RC"
        _info "persisted CHROME_BIN=$CHROME_FOUND → $SHELL_RC"
    fi
    export CHROME_BIN="$CHROME_FOUND"
    export ROD_BROWSER_BIN="$CHROME_FOUND"
else
    _warn "No system Chromium found — Go-Rod will auto-download a private build"
    _warn "on first scan (network required). The CDP engine FAILS OPEN otherwise:"
    _warn "DOM/CORS phases skip cleanly, the scan never crashes."
fi

# ── Ollama local AI cognitive brain (pkg/ai/brain.go) ───────────────────────
OLLAMA_ENDPOINT="${OLLAMA_HOST:-http://127.0.0.1:11434}"
if command -v ollama &>/dev/null; then
    _log "Ollama binary present → $(command -v ollama)"
else
    _warn "Ollama not installed. Install (free, local) with:"
    _warn "    curl -fsSL https://ollama.com/install.sh | sh"
    _warn "  then pull the V11 cascade:  ollama pull llama3.2:3b && ollama pull qwen2.5:7b && ollama pull deepseek-r1:7b"
fi

# V11.0 FINAL SOVEREIGN — 3-tier AI cascade models (FLAW #2). The engine also
# auto-pulls these at startup when ollama.auto_pull is true, but pulling here
# means the first scan is instant instead of blocking on a multi-GB download.
V11_CASCADE_MODELS=("llama3.2:3b" "qwen2.5:7b" "deepseek-r1:7b")

# Non-fatal connectivity probe — mirrors brain.Probe() /api/tags.
if command -v curl &>/dev/null; then
    if curl -fsS --max-time 3 "$OLLAMA_ENDPOINT/api/tags" &>/dev/null; then
        _log "Ollama reachable at $OLLAMA_ENDPOINT — cognitive brain ONLINE"
        MODELS="$(curl -fsS --max-time 3 "$OLLAMA_ENDPOINT/api/tags" 2>/dev/null \
                  | grep -oE '"name":"[^"]+"' | cut -d'"' -f4 | tr '\n' ' ')"
        [ -n "$MODELS" ] && _info "installed models:$MODELS"
        _info "V11 cascade: fast=llama3.2:3b  deep=qwen2.5:7b  reasoning=deepseek-r1:7b"
        # Auto-pull any missing cascade tier model (best-effort, non-fatal).
        if command -v ollama &>/dev/null; then
            for m in "${V11_CASCADE_MODELS[@]}"; do
                if ! printf '%s' "$MODELS" | grep -qF "$m"; then
                    _info "pulling missing cascade model: $m (this may take a while)..."
                    ollama pull "$m" >/dev/null 2>&1 \
                        && _log "pulled $m" \
                        || _warn "failed to pull $m — engine will retry at startup (auto_pull)"
                fi
            done
        fi
    else
        _warn "Ollama not reachable at $OLLAMA_ENDPOINT — brain runs OFFLINE."
        _warn "Semantic triage & payload mutation fall back to deterministic"
        _warn "heuristics (fail-open). No paid APIs are ever used."
    fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# SUMMARY — report resolvable count against the canonical 38
# ═══════════════════════════════════════════════════════════════════════════
present=0; missing=""
for tool in "${TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        present=$((present + 1))
    else
        missing="$missing $tool"
    fi
done

# Cleanup transient build dir (keep $OPT_DIR — wrappers/binaries live there).
rm -rf "$TMP_BUILD" 2>/dev/null || true

echo ""
_log "Linked $link_count tool(s) into /usr/local/bin + \$GOPATH/bin."
_log "Resolvable: $present / ${#TOOLS[@]} of the canonical 38 tools."
if [ -n "$missing" ]; then
    _warn "Still missing:$missing"
    _warn "Re-run  bash install_path.sh  (network required), or  bash setup.sh  for the full build."
else
    _log "All 38 tools resolvable — zero phase skips expected."
fi

# If this script was executed (not sourced), remind the user to reload.
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    echo ""
    _info "This shell's PATH was NOT modified (you ran instead of sourced)."
    _info "Apply now with:  source $SHELL_RC   (or:  source install_path.sh)"
fi
