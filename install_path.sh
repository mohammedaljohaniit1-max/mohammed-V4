#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
# MOHAMMED v4 — PATH Enforcement
# ---------------------------------------------------------------------------
# Guarantees that every directory the recon tools install into is on PATH,
# both for the CURRENT shell and PERMANENTLY (written to the shell rc file),
# and links any tool found under ~/.local/bin or $GOPATH/bin into
# /usr/local/bin so it is visible to every process (including the mohammed
# engine, which spawns tools via exec.Command and inherits this PATH).
#
# Run this whenever `mohammed doctor` reports a tool "Missing" even though it
# is installed, or after installing a new tool by hand.
#
# Usage: source install_path.sh    (recommended — updates the current shell)
#        bash   install_path.sh    (persists to rc; current shell unaffected)
# ═══════════════════════════════════════════════════════════════════════════

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
_log()  { echo -e "${GREEN}[+]${NC} $*"; }
_warn() { echo -e "${YELLOW}[!]${NC} $*"; }
_info() { echo -e "${CYAN}[*]${NC} $*"; }

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

PATH_DIRS=(
    "/usr/local/go/bin"     # go itself
    "$GOBIN"                # go install targets
    "$LOCAL_BIN"            # pip --user / pipx
    "/usr/local/bin"        # system-wide symlinks + wrappers
    "/snap/bin"             # snap-installed tools (amass)
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

_log "Enforcing PATH entries..."
for d in "${PATH_DIRS[@]}"; do add_dir "$d"; done

# Persist GOPATH too
if ! grep -qF "export GOPATH=$GOPATH" "$SHELL_RC" 2>/dev/null; then
    echo "export GOPATH=$GOPATH" >> "$SHELL_RC"
    _info "persisted GOPATH=$GOPATH → $SHELL_RC"
fi

# ── Link scattered binaries into /usr/local/bin ─────────────────────────────
# The engine spawns tools by bare name; a symlink in /usr/local/bin makes each
# tool resolvable regardless of which installer dropped it where.
TOOLS=(
    subfinder amass bbot assetfinder findomain
    dnsx puredns massdns shuffledns
    subzy httpx tlsx naabu nmap
    gau waybackurls katana gospider hakrawler
    getJS paramspider arjun
    ffuf feroxbuster dirsearch
    nuclei dalfox kxss sqlmap ghauri
    dontgo403 kr crlfuzz smuggler
    cloud_enum s3scanner
    curl dig git interactsh-client
)

link_count=0
for tool in "${TOOLS[@]}"; do
    command -v "$tool" &>/dev/null && continue         # already resolvable
    for cand in "$LOCAL_BIN/$tool" "$HOME/.local/bin/$tool" "$GOBIN/$tool"; do
        if [ -f "$cand" ]; then
            if $SUDO ln -sf "$cand" "/usr/local/bin/$tool" 2>/dev/null \
               || ln -sf "$cand" "$LOCAL_BIN/$tool" 2>/dev/null; then
                _info "linked $tool → $cand"
                link_count=$((link_count + 1))
            fi
            break
        fi
    done
done

# ── Summary ─────────────────────────────────────────────────────────────────
present=0; missing=""
for tool in "${TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        present=$((present + 1))
    else
        missing="$missing $tool"
    fi
done

echo ""
_log "PATH enforcement complete. Linked $link_count new tool(s)."
_log "Resolvable: $present / ${#TOOLS[@]} tools."
if [ -n "$missing" ]; then
    _warn "Still missing:$missing"
    _warn "Run  bash setup.sh  to install them."
fi

# If this script was executed (not sourced), remind the user to reload.
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    echo ""
    _info "This shell's PATH was NOT modified (you ran instead of sourced)."
    _info "Apply now with:  source $SHELL_RC   (or:  source install_path.sh)"
fi
