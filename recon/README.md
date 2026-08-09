# recon/ — per-target PASSIVE recon presets (bugbounty.sa)

These are **safe, policy-aware bash presets** for the six targets. They do **not**
modify the Go tool. Every preset is **passive by default** and obeys each
program's scope via the Go guard-rail (`cmd/scope`). They **never** run
nuclei / ffuf / dalfox / naabu / nmap / puredns.

## Why passive-only?

All six programs forbid or reject automated scanning (ejada & Mobily warn of
*legal action*). So the tool's job here is **passive OSINT + evidence gathering**;
**you** do the manual testing. See `../خطة_الاهداف_والتطوير.md`.

## The 4-step workflow

```bash
# 1) Run the preset for a target (passive: crt.sh subdomains + wayback URLs,
#    plus a GENTLE httpx liveness pass ONLY where policy allows it).
bash recon/flagyard.sh          # or nearpay / ejada / nournet / zain / mobily

# 2) Bundle the latest run into one JSON + a compact text digest.
bash recon/collect.sh flagyard

# 3a) Build a ready-to-paste prompt for ANY external AI (ChatGPT/Claude/Gemini).
bash recon/ai_summarize.sh flagyard
#     -> prints the system prompt + writes recon/out/flagyard/latest/ai_prompt.txt
#        Paste both into your external AI to get a prioritised MANUAL test plan.

# 3b) OR call the external OpenAI-compatible API directly (needs the LLM key
#     Injected in the project's API Keys tab; otherwise it fails with a clear 403).
bash recon/ai_summarize.sh flagyard --api --model gpt-5-mini
```

## Per-target behaviour (enforced automatically)

| preset        | scope file              | automation        | httpx liveness |
|---------------|-------------------------|-------------------|----------------|
| `flagyard.sh` | `scope/flagyard.json`   | reports_rejected  | YES (gentle)   |
| `nearpay.sh`  | `scope/nearpay.json`    | reports_rejected  | YES (gentle)   |
| `ejada.sh`    | `scope/ejada.json`      | **forbidden**     | **NO** (passive-only) |
| `nournet.sh`  | `scope/nournet.json`    | reports_rejected + **gov** | **NO** |
| `zain.sh`     | `scope/zain.json`       | rate_limited + **gov** | **NO** |
| `mobily.sh`   | `scope/mobily.json`     | **forbidden**     | **NO** (passive-only) |

"Passive OSINT" here means crt.sh (certificate transparency) and
web.archive.org (Wayback) — **public third-party sources that never touch the
target's own servers**. The optional httpx pass is the only step that contacts
the target, and it is skipped entirely for forbidden / sensitive-gov programs.

## Tuning (env vars)

- `DELAY=2`      seconds between active requests (politeness).
- `HTTPX_RL=5`   httpx max requests/second (only where allowed).
- `UA="..."`     User-Agent string.
- `OUT_ROOT=...` where results are written (default `recon/out/`).

## Honesty

Output is **raw evidence only**. Nothing is marked "confirmed" and no bug is
claimed. The AI step is asked to *triage and prioritise*, and is explicitly told
not to fabricate endpoints or claim vulnerabilities. You verify manually and
submit a PoC (all programs require exploit code).
