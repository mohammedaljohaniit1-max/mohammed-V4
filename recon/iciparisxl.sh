#!/usr/bin/env bash
# ICI PARIS XL (AS Watson / Intigriti) — wildcard_bounty: automation ALLOWED at
# max 5 req/s. FULL mode unleashes the real engine (governor + WAF-bypass + AI),
# rate-capped, with the required @intigriti.me User-Agent.
# Usage: recon/iciparisxl.sh [passive|full]   (default: full)
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$DIR/run_target.sh" "$DIR/../scope/iciparisxl.json" "${1:-full}"
