#!/usr/bin/env bash
# Zain.App — zain.app — SENSITIVE GOV (telecom) => PASSIVE ONLY + Gentle (<=100 rps if ever active)
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$DIR/run_target.sh" "$DIR/../scope/zain.json" zain.app
