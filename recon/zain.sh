#!/usr/bin/env bash
# Zain — sensitive_gov (rate_limited on paper, but gov => PASSIVE-pinned).
# Usage: recon/zain.sh [passive|full]   (both stay passive by policy)
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$DIR/run_target.sh" "$DIR/../scope/zain.json" "${1:-full}"
