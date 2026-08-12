#!/usr/bin/env bash
# recon/collect.sh — aggregate a program's latest ENGINE run into ONE compact
# digest ready to hand to an EXTERNAL AI for triage/summarisation.
#
# The scans are now run by the REAL MOHAMMED engine (via recon/<target>.sh),
# which writes its output under recon/out-engine/<slug>-<mode>/. This script
# collects the engine's real artefacts (report.json / final_report.json /
# CONFIRMED_VULNS.txt / MANUAL_REVIEW.txt / report.md) into digest.txt +
# bundle.json.
#
# Usage:  recon/collect.sh <slug>[-<mode>]     # e.g. iciparisxl-full, ejada-full
#         recon/collect.sh <slug> <run-dir>    # explicit engine output dir
#
# Nothing is fabricated: it only aggregates what the engine produced.

set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$DIR/.." && pwd)"
ENGINE_OUT="${ENGINE_OUT:-$REPO_ROOT/recon/out-engine}"

SLUG="${1:-}"
[[ -z "$SLUG" ]] && { echo "usage: collect.sh <slug>[-mode] [run-dir]" >&2; exit 1; }

# Resolve the run directory. Accept an explicit dir, an exact slug dir, or the
# newest matching <slug>* dir (so 'collect.sh iciparisxl' finds iciparisxl-full).
if [[ -n "${2:-}" ]]; then
  RUN="$2"
elif [[ -d "$ENGINE_OUT/$SLUG" ]]; then
  RUN="$ENGINE_OUT/$SLUG"
else
  RUN="$(ls -dt "$ENGINE_OUT/$SLUG"* 2>/dev/null | head -1 || true)"
fi
[[ -n "$RUN" && -d "$RUN" ]] || { echo "engine output not found for '$SLUG' under $ENGINE_OUT (run recon/$SLUG.sh first)" >&2; exit 1; }

# The engine may nest output under a per-target subfolder; find the dir that
# actually holds the report files.
find_report_dir() {
  local base="$1"
  if compgen -G "$base/*.json" >/dev/null 2>&1 || [[ -f "$base/report.md" ]]; then
    echo "$base"; return
  fi
  # search one or two levels down for report.json / final_report.json
  local hit
  hit="$(find "$base" -maxdepth 3 -type f \( -name 'report.json' -o -name 'final_report.json' -o -name 'report.md' \) 2>/dev/null | head -1)"
  [[ -n "$hit" ]] && dirname "$hit" || echo "$base"
}
RDIR="$(find_report_dir "$RUN")"

MAX_LINES="${MAX_LINES:-600}"
pick() { for f in "$@"; do [[ -f "$f" ]] && { echo "$f"; return; }; done; }

REPORT_JSON="$(pick "$RDIR/final_report.json" "$RDIR/report.json")"
REPORT_MD="$(pick "$RDIR/report.md")"
CONFIRMED="$(pick "$RDIR/CONFIRMED_VULNS.txt")"
REVIEW="$(pick "$RDIR/MANUAL_REVIEW.txt")"

# ---- bundle.json (machine) --------------------------------------------------
{
  echo "{"
  echo "  \"slug\": \"$SLUG\","
  echo "  \"run_dir\": \"$RDIR\","
  echo "  \"generated_at\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
  if [[ -n "$REPORT_JSON" ]]; then
    echo "  \"report\": $(cat "$REPORT_JSON")"
  else
    echo "  \"report\": null"
  fi
  echo "}"
} > "$RUN/bundle.json" 2>/dev/null || echo '{}' > "$RUN/bundle.json"

# ---- digest.txt (human + AI) -----------------------------------------------
{
  echo "=== MOHAMMED ENGINE DIGEST: $SLUG ==="
  echo "generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "run dir  : $RDIR"
  echo
  if [[ -n "$CONFIRMED" ]]; then
    echo "--- CONFIRMED VULNS ---"
    head -n "$MAX_LINES" "$CONFIRMED"
    echo
  fi
  if [[ -n "$REVIEW" ]]; then
    echo "--- MANUAL REVIEW (engine flagged, human must verify) ---"
    head -n "$MAX_LINES" "$REVIEW"
    echo
  fi
  if [[ -n "$REPORT_MD" ]]; then
    echo "--- REPORT (markdown, truncated) ---"
    head -n "$MAX_LINES" "$REPORT_MD"
    echo
  fi
  if [[ -z "$CONFIRMED$REVIEW$REPORT_MD" ]]; then
    echo "(no report artefacts found in $RDIR — the engine may still be running,"
    echo " or this was a passive run with findings only in report.json / bundle.json)"
    echo
    echo "Files present:"
    ls -1 "$RDIR" 2>/dev/null | head -40
  fi
} > "$RUN/digest.txt"

echo "[+] bundle -> $RUN/bundle.json"
echo "[+] digest -> $RUN/digest.txt  ($(wc -l < "$RUN/digest.txt") lines)"
echo "[*] Next: recon/ai_summarize.sh $SLUG"
