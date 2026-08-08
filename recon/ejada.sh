#!/usr/bin/env bash
# ejada eHub — ehub.ejada.com — FORBIDDEN automation => PASSIVE ONLY (no liveness)
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$DIR/run_target.sh" "$DIR/../scope/ejada.json" ejada.com
