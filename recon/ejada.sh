#!/usr/bin/env bash
# ejada — FORBIDDEN (legal-action clause). Auto-pinned PASSIVE even in full mode.
# Usage: recon/ejada.sh [passive|full]   (both stay passive by policy)
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$DIR/run_target.sh" "$DIR/../scope/ejada.json" "${1:-full}"
