#!/usr/bin/env bash
# Mobily — mobily.com.sa — FORBIDDEN automation => PASSIVE ONLY (no liveness)
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$DIR/run_target.sh" "$DIR/../scope/mobily.json" mobily.com.sa
