#!/usr/bin/env bash
# Nearpay — *-sa-dev-*.nearpay.io (dev) — reports_rejected (passive + gentle liveness OK)
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$DIR/run_target.sh" "$DIR/../scope/nearpay.json" nearpay.io
