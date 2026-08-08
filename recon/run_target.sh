#!/usr/bin/env bash
# recon/run_target.sh — the PASSIVE recon preset engine.
#
# Usage:
#   recon/run_target.sh <scope-file.json> <apex-or-host> [extra-host ...]
#
# It:
#   1. loads the program scope + shows the guard-rail verdict (what's allowed),
#   2. runs ONLY passive OSINT (crt.sh subdomains + wayback URLs),
#   3. runs a SINGLE gentle httpx liveness pass ONLY if the scope allows "httpx"
#      AND the target is not sensitive_gov,
#   4. writes everything under recon/out/<program>/<timestamp>/,
#   5. prints where the results are so you can feed them to recon/collect.sh.
#
# It NEVER runs aggressive tools. The per-target wrapper scripts just call this
# with the right scope file + hosts.

set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=recon/lib.sh
source "$DIR/lib.sh"

SCOPE_FILE="${1:-}"
shift || true
HOSTS=("$@")

if [[ -z "$SCOPE_FILE" || ${#HOSTS[@]} -eq 0 ]]; then
  err "usage: run_target.sh <scope-file.json> <host> [host ...]"
  exit 1
fi
[[ -f "$SCOPE_FILE" ]] || { err "scope file not found: $SCOPE_FILE"; exit 1; }

PROGRAM="$(cd "$REPO_ROOT" && go run ./cmd/scope -file "$SCOPE_FILE" 2>/dev/null | head -1 | sed 's/^== //; s/ ==$//')"
SLUG="$(basename "$SCOPE_FILE" .json)"
OUT="$(init_out "$SLUG")"

log "Program : $PROGRAM"
log "Scope   : $SCOPE_FILE"
log "Output  : $OUT"
echo

# ---- 1. show guard-rail verdict --------------------------------------------
log "Guard-rail tool matrix (what MOHAMMED may run here):"
(cd "$REPO_ROOT" && go run ./cmd/scope -file "$SCOPE_FILE") | tee "$OUT/00_scope_policy.txt" | \
  grep -E '^\s+\[(ALLOW|DENY )\]' >&2 || true
echo

# Detect sensitive_gov + httpx permission.
SENSITIVE="$(grep -c '"sensitive_gov": true' "$SCOPE_FILE" || true)"
HTTPX_OK=0
if scope_allows "$SCOPE_FILE" "httpx" && [[ "$SENSITIVE" == "0" ]]; then
  HTTPX_OK=1
fi

# ---- 2. passive subdomains (crt.sh) ----------------------------------------
: > "$OUT/subdomains.txt"
for h in "${HOSTS[@]}"; do
  apex="$(echo "$h" | sed -E 's#^https?://##; s#/.*$##')"
  log "crt.sh subdomains for $apex ..."
  passive_subdomains "$apex" >> "$OUT/subdomains.txt"
done
# Always include the seed hosts themselves.
for h in "${HOSTS[@]}"; do echo "$h" | sed -E 's#^https?://##; s#/.*$##'; done >> "$OUT/subdomains.txt"
sort -u -o "$OUT/subdomains.txt" "$OUT/subdomains.txt"
ok "subdomains: $(wc -l < "$OUT/subdomains.txt") host(s) -> subdomains.txt"

# ---- 3. passive archived URLs (wayback) ------------------------------------
: > "$OUT/urls.txt"
for h in "${HOSTS[@]}"; do
  apex="$(echo "$h" | sed -E 's#^https?://##; s#/.*$##')"
  log "wayback URLs for $apex ..."
  passive_urls "$apex" >> "$OUT/urls.txt"
  sleep "$DELAY"
done
sort -u -o "$OUT/urls.txt" "$OUT/urls.txt"
ok "archived URLs: $(wc -l < "$OUT/urls.txt") -> urls.txt"

# Quick interesting-URL triage (params, api, admin, upload, auth) — passive grep.
grep -Ei '(\?|=|/api/|/admin|/upload|/login|/token|/graphql|\.json|\.env|/v[0-9]/)' \
  "$OUT/urls.txt" 2>/dev/null | sort -u > "$OUT/urls_interesting.txt" || true
ok "interesting URLs: $(wc -l < "$OUT/urls_interesting.txt" 2>/dev/null || echo 0) -> urls_interesting.txt"

# ---- 4. optional gentle liveness -------------------------------------------
if [[ "$HTTPX_OK" == "1" ]]; then
  gentle_httpx "$OUT/subdomains.txt" "$OUT/live_hosts.txt"
  [[ -s "$OUT/live_hosts.txt" ]] && ok "live hosts -> live_hosts.txt ($(wc -l < "$OUT/live_hosts.txt"))"
else
  warn "httpx liveness SKIPPED (scope=passive-only or sensitive_gov). This is intentional & safe."
  echo "SKIPPED: httpx not permitted by program policy (passive-only / sensitive_gov)." > "$OUT/live_hosts.txt"
fi

# ---- 5. run manifest --------------------------------------------------------
cat > "$OUT/manifest.json" <<EOF
{
  "program": "$(echo "$PROGRAM" | sed 's/"/\\"/g')",
  "slug": "$SLUG",
  "scope_file": "$SCOPE_FILE",
  "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "mode": "passive$([ "$HTTPX_OK" == "1" ] && echo "+gentle-liveness")",
  "sensitive_gov": $([ "$SENSITIVE" == "0" ] && echo false || echo true),
  "hosts": [$(printf '"%s",' "${HOSTS[@]}" | sed 's/,$//')],
  "files": {
    "scope_policy": "00_scope_policy.txt",
    "subdomains": "subdomains.txt",
    "urls": "urls.txt",
    "urls_interesting": "urls_interesting.txt",
    "live_hosts": "live_hosts.txt"
  }
}
EOF

echo
ok "DONE. Results in: $OUT"
log "Next: recon/collect.sh $SLUG   (bundle results)"
log "Then: recon/ai_summarize.sh $SLUG   (build AI prompt / call external AI)"
