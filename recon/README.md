# recon/ — per-program drivers for the REAL MOHAMMED engine

These scripts are **thin wrappers** that drive the real scanner
(`cmd/mohammed`) at the **legally-correct intensity** for each bug-bounty
program. They do **not** re-implement scanning — the engine's governor
(WAF-adaptive rate control), 8-WAF bypass matrix, AI cascade, and 65+ phases do
the work. The wrappers only compute *how hard* the engine may push, from each
program's policy.

## How it works

```
scope/<program>.json   →   cmd/preset (bridge)   →   scope.txt + mohammed flags   →   ./bin/mohammed scan ...
   (legal policy)            (EnginePlan)              (profile/rate/threads/UA)         (real engine)
```

`cmd/preset` reads the program's `automation` policy and picks a plan:

| policy in scope JSON | full-mode plan | meaning |
|---|---|---|
| `wildcard_bounty` | `--profile large --waf-bypass`, rate = 90% of `max_rps` | automation explicitly allowed → **unleash the engine, throttled** |
| `rate_limited` | `large`, capped at `max_rps` | allowed under a ceiling |
| `reports_rejected` | `--profile small` | active recon + probe, **no aggressive vuln-scan** |
| `forbidden` | `--profile passive` | **auto-pinned passive** (legal-action clause) |
| `sensitive_gov: true` | `--profile passive` | **auto-pinned passive** regardless of automation |

The `full` mode is **safe on every target**: forbidden/gov programs are
automatically downgraded to passive, so you can run `recon/ejada.sh` without
ever sending active traffic.

## Commands (each target has its own)

```bash
# FULL (default) — max legal intensity for that program
bash recon/iciparisxl.sh            # Intigriti ICI PARIS XL — FULL engine @ 5 req/s
bash recon/flagyard.sh              # reports_rejected — active recon only
bash recon/ejada.sh                 # forbidden — auto passive
bash recon/mobily.sh                # forbidden — auto passive
bash recon/nournet.sh               # gov — auto passive
bash recon/zain.sh                  # gov — auto passive
bash recon/nearpay.sh               # reports_rejected — active recon only

# PASSIVE — OSINT only, safe anywhere
bash recon/iciparisxl.sh passive
```

You can also drive the bridge directly (prints the exact command without
running it):

```bash
./bin/preset -file scope/iciparisxl.json -mode full          # print plan + command
./bin/preset -file scope/iciparisxl.json -mode full -run     # actually run the engine
```

## Then: hand results to an EXTERNAL AI

```bash
bash recon/collect.sh iciparisxl-full        # aggregate engine output → digest.txt + bundle.json
bash recon/ai_summarize.sh iciparisxl-full   # prints a ready-to-paste prompt (ChatGPT/Claude/Gemini)
```

`ai_summarize.sh` defaults to **prompt mode** (always works, no key). The
`--api` mode calls the configured LLM proxy but currently returns 403 until the
key is Injected in the project's API Keys tab — prompt mode is the reliable
external-AI path.

## Per-target summary

| target | scope | policy | full-mode behaviour |
|---|---|---|---|
| ICI PARIS XL | `scope/iciparisxl.json` | wildcard_bounty (5 req/s, UA `@intigriti.me`) | **FULL engine + WAF-bypass, rate-capped** |
| Flagyard | `scope/flagyard.json` | reports_rejected | active recon, no aggressive |
| Nearpay | `scope/nearpay.json` | reports_rejected | active recon, no aggressive |
| ejada | `scope/ejada.json` | forbidden | auto passive |
| Nournet | `scope/nournet.json` | reports_rejected + gov | auto passive |
| Zain | `scope/zain.json` | rate_limited + gov | auto passive |
| Mobily | `scope/mobily.json` | forbidden | auto passive |

Nothing here is fabricated: the engine produces the evidence; a human verifies
before reporting.
