#!/usr/bin/env bash
# recon/run_target.sh — drive the REAL MOHAMMED engine for one program.
#
# This is a THIN wrapper around cmd/preset (the scope->engine bridge). It does
# NOT do any scanning itself — it computes the legally-correct engine plan from
# the program's scope JSON and runs the real ./bin/mohammed with the right
# profile / rate / threads. The engine's governor, WAF-bypass and AI cascade do
# the actual work at the intensity the program permits.
#
# Usage:
#   run_target.sh <scope-file.json> [passive|full]
#
#   passive : OSINT-only scan (no active payloads) — safe on ANY program.
#   full    : maximum LEGAL intensity for that program. Forbidden/sensitive
#             programs are auto-downgraded to passive by the bridge, so this is
#             still safe to run on ejada/Mobily/gov targets.
#
# Default mode is 'full' (the bridge keeps it legal per policy).

set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$DIR/.." && pwd)"

SCOPE_FILE="${1:-}"
MODE="${2:-full}"

if [[ -z "$SCOPE_FILE" ]]; then
  echo "usage: run_target.sh <scope-file.json> [passive|full]" >&2
  exit 1
fi
[[ -f "$SCOPE_FILE" ]] || { echo "scope file not found: $SCOPE_FILE" >&2; exit 1; }

cd "$REPO_ROOT"

# Prefer a prebuilt binary; fall back to `go run` if it's missing.
PRESET_BIN="./bin/preset"
MOH_BIN="./bin/mohammed"
if [[ ! -x "$PRESET_BIN" ]]; then
  echo "[*] ./bin/preset not found — building it ..." >&2
  go build -o "$PRESET_BIN" ./cmd/preset || { echo "build preset failed" >&2; exit 1; }
fi
if [[ ! -x "$MOH_BIN" ]]; then
  echo "[*] ./bin/mohammed not found — building it ..." >&2
  go build -o "$MOH_BIN" ./cmd/mohammed || { echo "build mohammed failed" >&2; exit 1; }
fi

echo "[*] Program scope : $SCOPE_FILE"
echo "[*] Mode          : $MODE"
echo

# The bridge prints the plan + writes the scope.txt, then -run executes the
# real engine with the computed flags.
"$PRESET_BIN" -file "$SCOPE_FILE" -mode "$MODE" -bin "$MOH_BIN" -run
