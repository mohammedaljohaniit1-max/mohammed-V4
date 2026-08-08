#!/usr/bin/env bash
# recon/collect.sh — aggregate a program's latest recon run into ONE bundle
# (JSON + a compact text digest) ready to hand to an AI.
#
# Usage:  recon/collect.sh <program-slug>        # e.g. flagyard
#         recon/collect.sh <program-slug> <dir>  # explicit run dir
#
# Output: <run-dir>/bundle.json  and  <run-dir>/digest.txt
#
# The digest is intentionally COMPACT (capped line counts) so it fits an AI
# context window without truncation surprises. Nothing is fabricated: it only
# aggregates the raw evidence the passive run already produced.

set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$DIR/lib.sh"

SLUG="${1:-}"
[[ -z "$SLUG" ]] && { err "usage: collect.sh <program-slug> [run-dir]"; exit 1; }
RUN="${2:-$OUT_ROOT/$SLUG/latest}"
[[ -d "$RUN" ]] || { err "run dir not found: $RUN (run recon/$SLUG.sh first)"; exit 1; }

# Caps to keep the digest AI-friendly.
MAX_SUBS="${MAX_SUBS:-300}"
MAX_URLS="${MAX_URLS:-400}"

subs=$(wc -l < "$RUN/subdomains.txt" 2>/dev/null || echo 0)
urls=$(wc -l < "$RUN/urls.txt" 2>/dev/null || echo 0)
iurls=$(wc -l < "$RUN/urls_interesting.txt" 2>/dev/null || echo 0)

# ---- bundle.json (machine) --------------------------------------------------
{
  echo "{"
  echo "  \"manifest\": $(cat "$RUN/manifest.json" 2>/dev/null || echo '{}'),"
  echo "  \"counts\": { \"subdomains\": $subs, \"urls\": $urls, \"interesting\": $iurls },"
  printf '  "subdomains": ['
  head -n "$MAX_SUBS" "$RUN/subdomains.txt" 2>/dev/null | sed 's/"/\\"/g' | awk 'NR>1{printf ","} {printf "\"%s\"",$0}'
  printf '],\n'
  printf '  "interesting_urls": ['
  head -n "$MAX_URLS" "$RUN/urls_interesting.txt" 2>/dev/null | sed 's/"/\\"/g' | awk 'NR>1{printf ","} {printf "\"%s\"",$0}'
  printf ']\n'
  echo "}"
} > "$RUN/bundle.json"

# ---- digest.txt (human + AI) -----------------------------------------------
{
  echo "=== RECON DIGEST: $SLUG ==="
  echo "generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "mode: passive OSINT (crt.sh + wayback)$([ -s "$RUN/live_hosts.txt" ] && grep -q SKIPPED "$RUN/live_hosts.txt" && echo ' (liveness skipped by policy)' || echo ' (+ gentle liveness)')"
  echo
  echo "COUNTS: subdomains=$subs  urls=$urls  interesting=$iurls"
  echo
  echo "--- SUBDOMAINS (first $MAX_SUBS) ---"
  head -n "$MAX_SUBS" "$RUN/subdomains.txt" 2>/dev/null
  echo
  echo "--- INTERESTING URLS (first $MAX_URLS) ---"
  head -n "$MAX_URLS" "$RUN/urls_interesting.txt" 2>/dev/null
  if [[ -s "$RUN/live_hosts.txt" ]] && ! grep -q SKIPPED "$RUN/live_hosts.txt"; then
    echo
    echo "--- LIVE HOSTS ---"
    cat "$RUN/live_hosts.txt"
  fi
} > "$RUN/digest.txt"

ok "bundle -> $RUN/bundle.json"
ok "digest -> $RUN/digest.txt  ($(wc -l < "$RUN/digest.txt") lines)"
log "Next: recon/ai_summarize.sh $SLUG"
