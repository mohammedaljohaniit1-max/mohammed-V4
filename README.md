# MOHAMMED v4

**Ultimate Security Reconnaissance & Vulnerability Discovery Framework**

A single Go binary that orchestrates 38+ best-in-class recon and vulnerability
tools across **29 sequential phases** — from passive OSINT and subdomain
enumeration to active fuzzing, injection testing, request smuggling, and an
AI-assisted false-positive triage layer powered by a local Ollama model.

Module: `github.com/mohammed-v3/core` · Branch: `main` · Go 1.22+

---

## Table of Contents
1. [Overview](#1-overview)
2. [Architecture](#2-architecture)
3. [Installation Guide](#3-installation-guide)
4. [The 29 Phases](#4-the-29-phases)
5. [Configuration Schema (`config.yaml`)](#5-configuration-schema-configyaml)
6. [Ollama AI Triage Guide](#6-ollama-ai-triage-guide)
7. [Burp Suite Proxy Guide](#7-burp-suite-proxy-guide)
8. [Scope File Format (`scope.txt`)](#8-scope-file-format-scopetxt)
9. [Troubleshooting](#9-troubleshooting)

---

## 1. Overview

MOHAMMED v4 is a **phase-based orchestrator**. Each phase implements a small
interface (`Name() / Description() / Execute()`), is registered once in
`cmd/mohammed/main.go`, and is run in order by the engine. Every tool is spawned
in its **own process group** so a hung `amass`/`bbot` can be killed cleanly
(`Setpgid` + `kill(-pgid)`), and every phase has a **per-tool timeout** so one
slow tool never stalls the whole scan.

Key design principles:

| Principle | How it is enforced |
|-----------|--------------------|
| **Never degrade** | No phase, tool, or feature is ever stubbed out or removed. Missing tools cause a graceful `SKIP`, not a crash. |
| **Thread-safe output** | All phase output goes through `s.Printf()` (guarded by `PrintMu`). A 1-second live ticker redraws the status line with `\r\033[K` without corruption. |
| **Root-cause fixes** | Every `SKIP` / `0 results` is traced to the real cause (wrong flag, missing resolvers, scope misrouting) — never patched over. |
| **Fail-open AI** | If Ollama is offline, triage returns `(true, "ollama_offline")` so a real finding is *never* silently dropped. |
| **Strict compilation** | `go build ./...` and `go vet ./...` are both clean. Zero unused imports / dead variables. |

Commands:

```
./mohammed scan     Run recon + vuln scan with target-size profiles
./mohammed doctor   Check tool availability and PATH environment
./mohammed setup    One-click install of all 38+ tools (delegates to setup.sh)
./mohammed help     Show the guidance menu
```

Scan profiles (`--profile`): `small` · `medium` (default) · `large`/`bugbounty` · `passive`.

---

## 2. Architecture

```
                          ┌─────────────────────────────┐
                          │      cmd/mohammed/main.go    │
                          │  CLI parse · profile filter  │
                          │  registers 29 phases in order│
                          └───────────────┬─────────────┘
                                          │
                    ┌─────────────────────▼──────────────────────┐
                    │              pkg/engine (State)             │
                    │  • PrintMu (thread-safe s.Printf)           │
                    │  • 1s live ticker  \r\033[K                 │
                    │  • checkBurp() proxy health                 │
                    │  • AI *ai.Client   • AddFinding / Triage    │
                    │  • Governor throttle · Proxy manager        │
                    └───┬──────────────┬─────────────┬───────────┘
                        │              │             │
          ┌─────────────▼───┐  ┌───────▼───────┐  ┌──▼───────────────┐
          │ pkg/phases      │  │ pkg/runner    │  │ pkg/ai (triage)  │
          │ phases.go 01-14 │  │ RunTool()     │  │ Ollama /api/     │
          │ phases_vuln 15-29│ │ Setpgid kill  │  │  generate        │
          │ s.Printf output │  │ per-tool T/O  │  │ fail-open verdict│
          └────────┬────────┘  └───────┬───────┘  └──────────────────┘
                   │                   │
                   │        exec.Command(tool, args…)
                   ▼                   ▼
   ┌───────────────────────────────────────────────────────────────┐
   │  38+ external tools: subfinder amass bbot httpx dnsx puredns    │
   │  naabu nuclei katana gau dalfox sqlmap subzy smuggler …         │
   │  (optionally routed through Burp proxy)                         │
   └───────────────────────────────────────────────────────────────┘
                   │
                   ▼
        output/<target>/  →  per-phase artifacts + final_report.{md,json}
```

Supporting packages: `pkg/config` (scope + YAML, apex routing, dedup),
`pkg/proxy` (Burp routing + env), `pkg/governor` (adaptive throttle / WAF
backoff), `pkg/filter` (evidence hashing), `pkg/report` (report helpers).

---

## 3. Installation Guide

### Prerequisites
- Linux (Debian/Ubuntu/Kali tested), `sudo` recommended but not required
- Go **1.22+** (setup.sh installs it automatically if missing)
- Python 3, pip/pipx, git, curl
- (Optional) [Ollama](https://ollama.com) for AI triage

### One-command install
```bash
git clone <this-repo> mohammed && cd mohammed
bash setup.sh                 # installs 38+ tools, resolvers, wordlists, builds binary
source ~/.bashrc              # (or ~/.zshrc) reload PATH
./mohammed doctor             # verify every tool resolves
```

`setup.sh` is **idempotent** — re-running skips anything already installed. It:
1. Adds `/usr/local/go/bin`, `$GOPATH/bin`, `~/.local/bin`, `/usr/local/bin`, `/snap/bin` to PATH permanently.
2. Installs Go tools (`go install`), Python tools (`pipx`/`pip`), and git-built tools.
3. Downloads DNS **resolvers** to `/opt/mohammed-tools/resolvers.txt` (+ `/tmp/mohammed_resolvers.txt`) — **required** by puredns/dnsx.
4. Installs SecLists + updates nuclei templates.
5. Builds the binary: `go build -o mohammed ./cmd/mohammed`.
6. Runs `./mohammed doctor`.

### Fixing PATH after a manual install
If `doctor` still reports a tool "Missing" even though it is installed:
```bash
source install_path.sh        # enforce PATH + symlink scattered binaries into /usr/local/bin
```

### Manual build only
```bash
export PATH=$PATH:/usr/local/go/bin
go build -o mohammed ./cmd/mohammed     # → zero compile errors
```

### Verify everything
```bash
bash verify.sh                # build + vet + tool + AI + bug-fix code checks
```

### Run a scan
```bash
# Large / bug-bounty (deep): bbot + amass + full crawl + all vuln phases
./mohammed scan -s scope.txt -c config.yaml --profile large --burp http://172.30.48.1:8080

# Medium (balanced, default)
./mohammed scan -s scope.txt -c config.yaml --profile medium

# Small (fast, no heavy bruteforce)
./mohammed scan -s scope.txt -c config.yaml --profile small

# Passive only (safe OSINT, no active payloads)
./mohammed scan -s scope.txt -c config.yaml --profile passive
```

**Scan flags:** `-s/--scope` (required) · `-c/--config` (default `config.yaml`) ·
`--profile` · `--burp <url>` · `--skip <phase#>` · `--threads` · `--rate` · `--output`.

---

## 4. The 29 Phases

| # | Phase | Primary tools | What it does |
|---|-------|---------------|--------------|
| 01 | Scope Validation | (internal) | Parses/dedupes scope, reports apex domains, warns on missing apex |
| 02 | OSINT | curl → crt.sh, RapidDNS, BufferOver, HackerTarget, Shodan, VT, SecurityTrails, OTX | Passive subdomain harvest (apex-only queries) |
| 03 | Subdomain Passive | subfinder, assetfinder (all), amass, bbot, findomain (apex-only) | Passive enumeration; amass/bbot routed to apex only (BUG #2) |
| 04 | Subdomain Active | puredns (`--write` + resolvers), massdns, dnsx, dnsgen | DNS bruteforce + permutations (BUG #3 resolvers) |
| 05 | DNS Resolve | dnsx | Resolve/dedupe to live A records |
| 06 | Takeover | subzy + HTTP fingerprint confirm + AI triage | Subdomain takeover, confirmed not just flagged (BUG #8) |
| 07 | HTTP Probe | httpx (`-json`, `-http-proxy` when Burp active) | Live host detection, titles, status, tech (BUG #1) |
| 08 | TLS Analysis | tlsx | Certificate / TLS metadata |
| 09 | Port Scan | naabu (`-scan-type c`), nmap | Top-1000 TCP connect scan, no root (BUG #4) |
| 10 | Wayback | gau (`--providers`, `--subs`), waybackurls | Archived URL harvest (BUG #10) |
| 11 | Crawl | katana (`-proxy`), gospider | Active crawl seeded from live hosts (BUG #5 empty-input guard) |
| 12 | JS Analysis | getJS + regex secret scan | Extract JS, hunt secrets/endpoints |
| 13 | Param Discovery | paramspider (`--domain/--output`), arjun | Parameter mining (BUG #6 output path) |
| 14 | CORS | curl (proxy-aware) | CORS misconfiguration probes |
| 15 | Cloud Recon | cloud_enum, s3scanner | Cloud bucket / asset discovery |
| 16 | Fuzzing | ffuf | Content/dir fuzz of live endpoints |
| 17 | Vuln Scan | nuclei (`-jsonl`) + AI triage | Template-based vulns; Critical/High/Medium triaged |
| 18 | XSS | kxss prefilter → dalfox (`--proxy`) | Reflected XSS on parameterized URLs (BUG #7 filtering) |
| 19 | SQLi | sqlmap, ghauri + AI triage | Injection testing on parameterized URLs |
| 20 | SSRF | nuclei (`-tags ssrf`, `-iserver`) | SSRF via OOB interaction |
| 21 | Open Redirect | nuclei / qsreplace payloads | Open redirect detection |
| 22 | Forbidden Bypass | dontgo403 | 401/403 bypass (extracted from httpx JSONL) |
| 23 | API Discovery | kr (kiterunner) | API route brute/discovery |
| 24 | CRLF | crlfuzz (proxy-aware) | CRLF injection / header splitting |
| 25 | Smuggling | smuggler + AI triage | HTTP request smuggling per-URL |
| 26 | Git Exposure | curl / nuclei | Exposed `.git` and VCS artifacts |
| 27 | Email Security | dig | SPF / DMARC / DKIM posture |
| 28 | Prototype Pollution | nuclei | Client/server prototype pollution |
| 29 | Report | (internal) | Writes `final_report.md` + `final_report.json` with AI verdicts |

> Profiles select a subset of phases: `passive` ≈ 01–13 passive-only,
> `small`/`medium`/`large` progressively enable active + vuln phases.

---

## 5. Configuration Schema (`config.yaml`)

```yaml
# ── API Keys (optional — phases that use them SKIP gracefully if blank) ──
api_keys:
  github: ""           # GitHub PAT
  shodan: ""           # Shodan API
  virustotal: ""       # VirusTotal API
  alienvault: ""       # AlienVault OTX
  securitytrails: ""   # SecurityTrails
  chaos: ""            # Chaos (ProjectDiscovery)
  censys: ""           # Censys

# ── Ollama — Local AI triage (no cloud, no data leaves the host) ──
ollama:
  enabled: true                       # false → triage always fails open (REAL)
  endpoint: "http://127.0.0.1:11434"  # local Ollama server
  model: "gemma:2b"                   # lightweight, fast
  temperature: 0.2                    # low = deterministic verdicts
  timeout: 15                         # seconds; on timeout → fail open (REAL)

# ── Proxy & WAF evasion ──
proxy:
  header_spoofing: true
  user_agent_rotation: true
  adaptive_throttling: true

# ── Context chain (auto token propagation) ──
context_chain:
  enabled: true
  auto_extract_js: true
  auto_inject_headers: true

# ── Parameter profiler ──
param_profiler:
  enabled: true
  min_priority: 1
```

**Defaults applied by the loader** if a field is blank/zero: `endpoint →
http://127.0.0.1:11434`, `model → gemma:2b`, `timeout → 15`.

---

## 6. Ollama AI Triage Guide

MOHAMMED uses a **local** LLM to demote false positives. It is called for the
noisiest phases — **subzy** (takeover), **nuclei** (vuln scan), and **smuggler**
(request smuggling). The AI can only *demote* a finding to `Info`; it can never
delete a real one.

### Install & run Ollama
```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama serve &                 # start the server on :11434
ollama pull gemma:2b           # ~1.6 GB, fast on CPU
```

### How triage works (`pkg/ai/triage.go`)
- **Endpoint:** `POST http://localhost:11434/api/generate` (`stream=false`).
- **Model:** `gemma:2b` (configurable), `temperature 0.2`, `num_predict 80`.
- **Timeout:** 15 s (configurable). Evidence is capped at 4000 chars.
- **Contract:** `TriageFinding(ctx, findingType, target, evidence) (bool, string)`
  returns `(isConfirmed, reason)`.
- **Fail-open:** if Ollama is disabled, unreachable, errors, times out, or
  returns an empty answer → `(true, "ollama_offline")`. **Real findings are
  never lost to an AI outage.**
- **Verdict parse:** the model must answer `REAL` or `FALSE_POSITIVE`. Only a
  clear `FALSE_POSITIVE` demotes the finding; anything else stays `REAL`.

### In the report
Each finding carries `ai_confirmed: true` when kept, or `ai_verdict` +
`original_severity` when demoted to `Info` — so you always see *why* the AI
made a call.

### Disable AI
Set `ollama.enabled: false` (or just don't run Ollama). Every finding is then
treated as REAL — identical to the fail-open path.

---

## 7. Burp Suite Proxy Guide

Route active HTTP traffic through Burp for inspection/replay with `--burp`:

```bash
./mohammed scan -s scope.txt -c config.yaml --profile large \
  --burp http://172.30.48.1:8080
```

At startup the engine runs **`checkBurp()`**: it builds an `http.Transport`
whose `Proxy` is your Burp URL and fetches
`http://detectportal.firefox.com/success.txt`. If that succeeds, proxy routing
is enabled for the whole scan.

**Per-tool proxy wiring** (verified against each tool's real flags — no
fabricated flags):

| Tool | Flag |
|------|------|
| httpx | `-http-proxy <url>` |
| katana | `-proxy <url>` |
| nuclei | `-proxy <url>` |
| dalfox | `--proxy <url>` |
| crlfuzz | `-x <url>` |
| curl / ffuf | `-x <url>` |

> The engine does **not** also set `HTTP_PROXY`/`HTTPS_PROXY` env for tools that
> already take an explicit proxy flag — that would double-proxy and cause
> connection failures. Tools are passed `nil`/clean env in those cases.

**Note on BUG #1:** httpx returning 0 endpoints through Burp was *not* a missing
`-insecure` flag (httpx has no such flag). The real fix is routing via
`-http-proxy` and avoiding double-proxying — see [Troubleshooting](#9-troubleshooting).

---

## 8. Scope File Format (`scope.txt`)

Plain text, one entry per line. `#` starts a comment. Blank lines ignored.

```text
# In-scope domains
whatnot.com
www.whatnot.com
api.whatnot.com

# Wildcard — expands to "enumerate all subdomains of whatnot.com"
*.whatnot.com

# Out of scope — prefix with '-' (also works with wildcards)
-*.stage.whatnot.com
-test.whatnot.com
```

Rules:
- **Domains, IPs, and CIDRs** are all accepted and auto-classified.
- **`*.example.com`** is treated as "all subdomains of `example.com`"; the apex
  `example.com` is derived for tools that only accept an apex (amass, bbot).
- **`-` prefix** = exclusion. Excluded hosts are filtered from every phase.
- **Deduplication (BUG #9):** duplicate domains/IPs/CIDRs/exclusions are
  collapsed automatically — listing `whatnot.com` twice yields one target.
- **Apex handling:** two-part TLDs (`co.uk`, `com.sa`, …) are handled correctly
  by `ApexOf()` so `foo.bar.co.uk` resolves to apex `bar.co.uk`.

---

## 9. Troubleshooting

Run `bash verify.sh` first — it checks the build, `go vet`, every tool, the AI
wiring, resolvers, and each bug fix.

| Symptom | Root cause | Fix |
|---------|-----------|-----|
| `doctor` says a tool is *Missing* but it's installed | binary not on PATH | `source install_path.sh` then re-open shell |
| **httpx 0 endpoints through Burp** (BUG #1) | double-proxy / wrong flag | fixed: httpx uses `-http-proxy` only, no env double-proxy, no fake `-insecure` |
| **amass/bbot slow or empty** (BUG #2) | fed full subdomain list / wrong timeout | fixed: amass/bbot run on **apex only**, bbot `-p subdomain-enum -f passive`, amass `-timeout 4` |
| **puredns exit 1** (BUG #3) | missing resolvers / missing massdns / wrong output flag | fixed: `ensureResolvers()` writes a resolvers file, guards for massdns, uses `--write` (not `-w`) |
| **naabu exit 2** (BUG #4) | invalid `-connect-scan` flag | fixed: `-scan-type c` (TCP connect, no root) |
| **gospider exit 1** (BUG #5) | empty input file | fixed: empty-input guard + seeds from live httpx URLs |
| **paramspider exit 2** (BUG #6) | wrong output path | fixed: `--domain <d> --output <file>` + reads `results/<domain>.txt` fallback |
| **dalfox SKIP** (BUG #7) | unfiltered params | fixed: `parameterizedURLs()` + `kxss` prefilter before dalfox |
| **subzy 251 false takeovers** (BUG #8) | flagged not confirmed | fixed: `--hide_fails`, HTTP fingerprint confirm, AI triage |
| **scope duplicate domain** (BUG #9) | no dedup | fixed: set-based dedup in `LoadScope` |
| **gau 0 URLs** (BUG #10) | missing providers/subs | fixed: `--providers wayback,commoncrawl,otx,urlscan --subs` |
| Ollama triage never demotes | Ollama not running | `ollama serve & ollama pull gemma:2b` (else it fails open = REAL) |
| Scan hangs on one tool | tool exceeded timeout | it is killed via process-group `kill(-pgid)`; check `pkg/runner` timeout map |
| Build error | stale Go | `export PATH=$PATH:/usr/local/go/bin` (Go 1.22+), then `go build ./...` |

### Build & verify (canonical commands)
```bash
export PATH=$PATH:/usr/local/go/bin
go build -o mohammed ./cmd/mohammed     # zero compile errors
go vet ./...                            # clean
bash verify.sh                          # full verification suite
```

---

*MOHAMMED v4 — every phase intact, every finding traced, every flag verified.*
