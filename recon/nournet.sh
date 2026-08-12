#!/usr/bin/env bash
# Nournet — sensitive_gov. Auto-pinned PASSIVE even in full mode.
# Usage: recon/nournet.sh [passive|full]   (both stay passive by policy)
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$DIR/run_target.sh" "$DIR/../scope/nournet.json" "${1:-full}"
