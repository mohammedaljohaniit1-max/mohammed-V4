#!/usr/bin/env bash
# Flagyard (Tuwaiq) — *.flagyard.com — reports_rejected (passive + gentle liveness OK)
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$DIR/run_target.sh" "$DIR/../scope/flagyard.json" flagyard.com
