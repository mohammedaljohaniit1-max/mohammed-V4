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
source "$DIR/lib.sh"

SLUG="${1:-}"; shift || true
[[ -z "$SLUG" ]] && { err "usage: ai_summarize.sh <program-slug> [--api] [--model M]"; exit 1; }
RUN="$OUT_ROOT/$SLUG/latest"
[[ -d "$RUN" ]] || { err "no run for $SLUG (run recon/$SLUG.sh then recon/collect.sh $SLUG)"; exit 1; }
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

POLICY="$(cat "$RUN/00_scope_policy.txt" 2>/dev/null | sed -n '/POLICY NOTES/,$p')"

read -r -d '' SYS <<'EOSYS'
You are a senior bug-bounty triage analyst. You receive PASSIVE recon evidence
(subdomains from certificate transparency + archived URLs) for an authorised
bug-bounty program. Your job:
  1. Group the assets and point out the highest-value places a HUMAN should test
     manually (auth flows, IDOR/BOLA candidates, upload/API/admin/GraphQL, params).
  2. Respect the program policy notes: several forbid automated scanning; do NOT
     suggest running scanners. Suggest MANUAL test ideas only.
  3. Be brutally honest. Do NOT claim any vulnerability exists — this is only
     recon. Never fabricate endpoints that are not in the evidence.
  4. Output: (a) 5-10 prioritised manual test targets with WHY, (b) any obvious
     out-of-scope items to avoid, (c) concise notes. Keep it tight.
EOSYS

PROMPT_FILE="$RUN/ai_prompt.txt"
{
  echo "### PROGRAM POLICY NOTES ###"
  echo "$POLICY"
  echo
  echo "### PASSIVE RECON DIGEST ###"
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
