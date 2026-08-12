#!/usr/bin/env bash
# recon/ai_summarize.sh — hand the recon digest to an EXTERNAL AI for triage.
#
# The operator asked for an EXTERNAL model (not the local Ollama). Two modes:
#
#   1) PROMPT MODE (default, ALWAYS works):
#        recon/ai_summarize.sh <slug>
#      Builds a ready-to-paste prompt at <run>/ai_prompt.txt. Open it and paste
#      into ChatGPT / Claude / Gemini — any external AI. This is the reliable
#      path and needs no API key.
#
#   2) API MODE (needs the LLM key Injected in the project's API Keys tab):
#        recon/ai_summarize.sh <slug> --api [--model gpt-5-mini]
#      Calls the OpenAI-compatible endpoint from ~/.genspark_llm.yaml. If the
#      proxy returns 403 (key not authorised yet) it fails HONESTLY and tells
#      you to use prompt mode or Inject the key.
#
# Honesty: the AI is asked to TRIAGE and PRIORITISE passive evidence and propose
# MANUAL test ideas. It must NOT invent findings. The prompt says so explicitly.

set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$DIR/.." && pwd)"
ENGINE_OUT="${ENGINE_OUT:-$REPO_ROOT/recon/out-engine}"
ok()   { printf '\033[32m[+]\033[0m %s\n' "$*" >&2; }
log()  { printf '\033[36m[*]\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[33m[!]\033[0m %s\n' "$*" >&2; }
err()  { printf '\033[31m[x]\033[0m %s\n' "$*" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }

SLUG="${1:-}"; shift || true
[[ -z "$SLUG" ]] && { err "usage: ai_summarize.sh <slug>[-mode] [--api] [--model M]"; exit 1; }

# Resolve run dir the same way collect.sh does (exact, then newest <slug>*).
if [[ -d "$ENGINE_OUT/$SLUG" ]]; then
  RUN="$ENGINE_OUT/$SLUG"
else
  RUN="$(ls -dt "$ENGINE_OUT/$SLUG"* 2>/dev/null | head -1 || true)"
fi
[[ -n "$RUN" && -d "$RUN" ]] || { err "no run for $SLUG (run recon/$SLUG.sh then recon/collect.sh $SLUG)"; exit 1; }
[[ -f "$RUN/digest.txt" ]] || { err "no digest — run recon/collect.sh $SLUG first"; exit 1; }

USE_API=0; MODEL="gpt-5-mini"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --api) USE_API=1 ;;
    --model) shift; MODEL="${1:-gpt-5-mini}" ;;
    *) warn "unknown arg: $1" ;;
  esac
  shift || true
done

read -r -d '' SYS <<'EOSYS'
You are a senior bug-bounty triage analyst. You receive the output of an
automated scan engine (MOHAMMED) run against an AUTHORISED bug-bounty program:
confirmed findings, manual-review candidates, and recon evidence. Your job:
  1. Summarise and DE-DUPLICATE the findings; drop noise and likely false
     positives; cluster related issues (same root cause / shared codebase).
  2. Prioritise what a HUMAN should verify first, with a short WHY and the exact
     asset/endpoint. Map each to a plausible impact (auth bypass, IDOR/BOLA,
     payment/order abuse, mass data exposure, RCE) where the evidence supports it.
  3. Respect the program's out-of-scope list (e.g. rate-limit bypass, self-XSS,
     missing headers, low-impact CSRF, email spoofing) — flag and drop those.
  4. Be brutally honest. Do NOT claim a vulnerability is confirmed unless the
     engine marked it CONFIRMED with proof. Never fabricate endpoints.
  5. Output: (a) top 5-10 things to verify manually with WHY + asset, (b) items
     to drop (out-of-scope / FP), (c) a one-paragraph honest summary.
EOSYS

PROMPT_FILE="$RUN/ai_prompt.txt"
{
  echo "### PROGRAM: $SLUG ###"
  echo
  echo "### MOHAMMED ENGINE DIGEST ###"
  cat "$RUN/digest.txt"
} > "$PROMPT_FILE"

if [[ "$USE_API" == "0" ]]; then
  ok "PROMPT MODE."
  echo
  echo "System instruction (paste as system / first message):"
  echo "------------------------------------------------------"
  echo "$SYS"
  echo "------------------------------------------------------"
  ok "User content is ready at: $PROMPT_FILE"
  log "Paste BOTH into any EXTERNAL AI (ChatGPT / Claude / Gemini)."
  exit 0
fi

# ---- API MODE ---------------------------------------------------------------
have python3 || { err "python3 required for --api mode"; exit 1; }
CFG="$HOME/.genspark_llm.yaml"
[[ -f "$CFG" ]] || { err "no $CFG — Inject the LLM key in the project's API Keys tab, or use prompt mode."; exit 1; }

log "Calling external AI ($MODEL) via the configured proxy ..."
SYS="$SYS" MODEL="$MODEL" PROMPT_FILE="$PROMPT_FILE" OUT="$RUN/ai_summary.md" python3 - <<'PY'
import os, json, yaml, urllib.request, urllib.error, sys
cfg = yaml.safe_load(open(os.path.expanduser("~/.genspark_llm.yaml")))["openai"]
sys_msg = os.environ["SYS"]; model = os.environ["MODEL"]
user = open(os.environ["PROMPT_FILE"], encoding="utf-8").read()
body = json.dumps({"model": model, "messages":[
    {"role":"system","content":sys_msg},
    {"role":"user","content":user}]}).encode()
req = urllib.request.Request(cfg["base_url"].rstrip("/")+"/chat/completions",
    data=body, headers={"Authorization":"Bearer "+cfg["api_key"],
                        "Content-Type":"application/json"})
try:
    r = urllib.request.urlopen(req, timeout=120)
    txt = json.loads(r.read())["choices"][0]["message"]["content"]
    open(os.environ["OUT"],"w",encoding="utf-8").write(txt)
    print("\n"+txt+"\n")
    print("[+] saved ->", os.environ["OUT"], file=sys.stderr)
except urllib.error.HTTPError as e:
    print(f"[x] API returned HTTP {e.code}: {e.read()[:200]!r}", file=sys.stderr)
    if e.code in (401,403):
        print("[!] The LLM proxy is not authorised for this sandbox yet.", file=sys.stderr)
        print("    Fix: project -> API Keys tab -> generate + INJECT the key.", file=sys.stderr)
        print("    Meanwhile use PROMPT MODE (drop --api) and paste into any AI.", file=sys.stderr)
    sys.exit(2)
except Exception as e:
    print(f"[x] {type(e).__name__}: {e}", file=sys.stderr); sys.exit(2)
PY
