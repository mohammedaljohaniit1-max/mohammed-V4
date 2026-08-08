#!/usr/bin/env bash
# Nournet eServices — eservices.nour.net.sa — SENSITIVE GOV => PASSIVE ONLY + Gentle
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$DIR/run_target.sh" "$DIR/../scope/nournet.json" nour.net.sa
