#!/usr/bin/env bash
# recon/lib.sh — shared helpers for the per-target PASSIVE recon presets.
#
# DESIGN (read this before editing):
#   * These scripts are 100% PASSIVE by default. They query PUBLIC OSINT
#     sources (crt.sh, web.archive.org) that do NOT touch the target's own
#     servers, plus — only where the program's scope allows a "probe" — a single
#     gentle httpx liveness check.
#   * They NEVER run nuclei / ffuf / dalfox / naabu / nmap / puredns. Ever.
#   * Before doing anything, each preset asks the Go guard-rail (cmd/scope) what
#     is allowed for that program, and refuses to exceed it.
#   * Nothing here modifies the Go tool. Pure bash, isolated in recon/.
#
# Honesty: every output is raw evidence. No result is "confirmed" and no bug is
# claimed. A human reviews the evidence and tests manually.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCOPE_DIR="$REPO_ROOT/scope"
OUT_ROOT="${OUT_ROOT:-$REPO_ROOT/recon/out}"

# Gentle defaults for sensitive/limited targets (operator idea #2).
DELAY="${DELAY:-2}"           # seconds between any active request
HTTPX_RL="${HTTPX_RL:-5}"     # httpx max requests/second (only if allowed)
UA="${UA:-mohammed-recon/1.0 (passive; bugbounty research)}"

log()  { printf '\033[36m[*]\033[0m %s\n' "$*" >&2; }
ok()   { printf '\033[32m[+]\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[33m[!]\033[0m %s\n' "$*" >&2; }
err()  { printf '\033[31m[x]\033[0m %s\n' "$*" >&2; }

have() { command -v "$1" >/dev/null 2>&1; }

# scope_allows <scope-file> <tool> -> exit 0 if allowed, 1 if denied.
# Uses the Go guard-rail so bash + Go agree on policy.
scope_allows() {
  local sf="$1" tool="$2" out
  out="$(cd "$REPO_ROOT" && go run ./cmd/scope -file "$sf" -tool "$tool" 2>/dev/null)"
  echo "$out" | grep -q "ALLOWED"
}

# require_scope_file <name> -> echoes absolute path or exits.
require_scope_file() {
  local sf="$SCOPE_DIR/$1"
  if [[ ! -f "$sf" ]]; then
    err "scope file not found: $sf"
    exit 1
  fi
  echo "$sf"
}

# passive_subdomains <apex> -> one host per line, via crt.sh (public CT logs).
# PASSIVE: queries a public certificate-transparency service, never the target.
# Two sources for resilience (crt.sh is flaky/rate-limited): crt.sh JSON, then
# the HackerTarget hostsearch API as a fallback. Both are public OSINT.
passive_subdomains() {
  local apex="$1" tmp
  have curl || { warn "curl missing; skipping crt.sh"; return 0; }
  tmp="$(mktemp)"

  # Source 1: crt.sh (retry twice; it rate-limits aggressively).
  local try
  for try in 1 2; do
    curl -s --max-time 30 -A "$UA" \
      "https://crt.sh/?q=%25.${apex}&output=json" 2>/dev/null \
    | { have jq && jq -r '.[].name_value' 2>/dev/null || tr ',' '\n'; } \
    >> "$tmp"
    [[ -s "$tmp" ]] && break
    sleep "$DELAY"
  done

  # Source 2 (fallback): HackerTarget hostsearch (public, no key, small quota).
  if [[ ! -s "$tmp" ]]; then
    curl -s --max-time 30 -A "$UA" \
      "https://api.hackertarget.com/hostsearch/?q=${apex}" 2>/dev/null \
    | grep -v 'API count exceeded' | cut -d',' -f1 >> "$tmp"
  fi

  # Clean: strip wildcards, keep only valid hostnames under the apex.
  sed 's/^\*\.//' "$tmp" \
  | tr 'A-Z' 'a-z' | tr -d ' \t\r' \
  | grep -E '^[a-z0-9._-]+$' \
  | grep -Ei "(^|\.)${apex//./\\.}$" \
  | sort -u
  rm -f "$tmp"
}

# passive_urls <apex> -> archived URLs via the Wayback Machine CDX API.
# PASSIVE: queries web.archive.org, not the target. Filters out non-URL lines
# (e.g. a 429 HTML error page) so only real http(s) URLs are kept.
passive_urls() {
  local apex="$1"
  have curl || { warn "curl missing; skipping wayback"; return 0; }
  curl -s --max-time 40 -A "$UA" \
    "https://web.archive.org/cdx/search/cdx?url=*.${apex}/*&output=text&fl=original&collapse=urlkey&limit=5000" \
    2>/dev/null \
  | grep -Ei '^https?://' \
  | grep -Ei "${apex//./\\.}" \
  | sort -u
}

# gentle_httpx <hosts-file> <out-file> : ONLY call when scope allows "httpx".
# Runs a single, low-rate liveness pass. Skips silently if httpx isn't installed.
gentle_httpx() {
  local hosts="$1" out="$2"
  if ! have httpx; then
    warn "httpx not installed — skipping gentle liveness (passive results still saved)"
    return 0
  fi
  log "gentle httpx liveness (rate=${HTTPX_RL}/s, delay respected) ..."
  httpx -silent -rate-limit "$HTTPX_RL" -H "User-Agent: $UA" \
        -status-code -title -tech-detect -no-color \
        -l "$hosts" -o "$out" 2>/dev/null || true
}

# init_out <program-slug> -> creates + echoes the run output dir.
init_out() {
  local slug="$1"
  local dir="$OUT_ROOT/$slug/$(date +%Y-%m-%d_%H%M%S)"
  mkdir -p "$dir"
  ln -sfn "$dir" "$OUT_ROOT/$slug/latest"
  echo "$dir"
}
