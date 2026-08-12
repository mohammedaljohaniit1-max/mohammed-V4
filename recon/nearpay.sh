#!/usr/bin/env bash
# Nearpay — reports_rejected. FULL = active recon (no aggressive scan).
# Usage: recon/nearpay.sh [passive|full]   (default: full)
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$DIR/run_target.sh" "$DIR/../scope/nearpay.json" "${1:-full}"
