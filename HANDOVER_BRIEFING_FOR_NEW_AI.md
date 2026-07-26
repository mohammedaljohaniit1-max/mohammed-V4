# HANDOVER BRIEFING — MOHAMMED-V4

> **Read this file completely before touching any code.**
> It is the single source of truth for the next AI engineer taking over the
> MOHAMMED-V4 security-reconnaissance framework.

---

## 0. What this project is (and the legal frame)

**MOHAMMED-V4** is a phase-based automated **security reconnaissance and
vulnerability-discovery framework** written in Go. It orchestrates 30 sequential
phases that chain 38+ external CLI tools (subfinder, httpx, nuclei, katana,
dalfox, sqlmap, …) plus custom Go HTTP harvesters, then triages every finding with
a local Ollama model and emits a Markdown + JSON report.

**This is legitimate, authorized bug-bounty tooling.** It is only ever pointed at
domains that are explicitly **in scope on public HackerOne programs** (Whatnot and
Roblox). Nothing in this project is offensive-by-default: it is passive-first,
rate-limited, WAF-aware, and it deduplicates/verifies evidence to keep the
false-positive rate at zero. All work described here is defensive research on
authorized targets.

- **Repository:** https://github.com/mohammedaljohaniit1-max/mohammed-V4
- **Working branch:** `genspark_ai_developer` (always the latest code)
- **Go module path:** `github.com/mohammed-v3/core` — **never rename this.**
- **This briefing was written against commit `d996776`** ("fix(tools): resolve 11
  confirmed tool integration failures"). Line numbers are accurate to that commit;
  grep the function name if the file has since grown.

---

## 1. Environment

| Item | Value |
|---|---|
| Language | Go **1.22** (`go.mod`), toolchain tested on go1.22.4 linux/amd64 |
| Go PATH in sandbox | `export PATH=$PATH:/usr/local/go/bin` |
| Dependencies | **only** `gopkg.in/yaml.v3 v3.0.1` (stdlib everywhere else) |
| Build | `go build ./...` and `go build -o mohammed ./cmd/mohammed` |
| Test | `go test ./...` (packages `engine`, `config`, `phases`, `proxy` have tests) |
| Vet | `go vet ./...` (must stay clean) |
| Verify | `bash verify.sh` (code + tool-availability audit) |
| AI triage backend | local **Ollama** at `http://127.0.0.1:11434`, model `gemma:2b` |
| Recon tool install | `bash setup.sh` (installs the 38 tools); PATH fix via `install_path.sh` |

**Tool install locations** the runner searches (`pkg/runner/runner.go:ResolveToolPath`,
lines 112-137): system `PATH`, then `~/.local/bin`, `~/go/bin`, `/usr/local/bin`,
`/usr/bin`, `/snap/bin`, `/opt/homebrew/bin`.

The 38 registered tools are in `cmd/mohammed/main.go:allTools` (lines 73-85):
subfinder, amass, bbot, assetfinder, findomain, dnsx, puredns, massdns, shuffledns,
subzy, httpx, tlsx, naabu, nmap, gau, waybackurls, katana, gospider, hakrawler,
getJS, paramspider, arjun, ffuf, feroxbuster, dirsearch, nuclei, dalfox, kxss,
sqlmap, ghauri, dontgo403, kr, crlfuzz, smuggler, cloud_enum, s3scanner, curl, dig, git.

---

## 2. Full architecture — every file, what it does

```
cmd/mohammed/main.go        CLI entry: parses flags, loads scope+config, builds
                            the 30-phase list, applies the profile filter, wires
                            SIGINT→checkpoint save, runs the orchestrator.
pkg/engine/engine.go        State (shared data bus) + Orchestrator (phase runner
                            with live 1s timer, Burp health-check, resume-skip,
                            per-phase checkpoint save).
pkg/engine/checkpoint.go    Checkpoint struct + atomic Save/Load/Restore/FindLatest
                            (resume engine).
pkg/config/config.go        Config/Scope/APIKeys/OllamaConfig structs, scope parser
                            (dedup, wildcard→apex), apex-domain helpers.
pkg/runner/runner.go        RunTool(): resolve binary, per-tool timeout, Setpgid
                            process-group kill, env injection, --debug logging.
pkg/proxy/proxy.go          ProxyManager: Burp URL + GetEnv() (HTTP(S)_PROXY map).
pkg/ai/triage.go            Ollama /api/generate client, fail-open triage verdict.
pkg/governor/governor.go    Adaptive concurrency/delay throttle on WAF hits.
pkg/filter/filter.go        Evidence dedup via SHA-256 body hashing.
pkg/report/report.go        (legacy) Markdown/JSON report helpers — NOTE: the LIVE
                            report is written by ReportPhase in phases_vuln.go.
pkg/phases/phases.go        Phases 01-14 + all OSINT harvesters.
pkg/phases/phases_vuln.go   Phases 15-29 vuln/report.
pkg/phases/phases_deeprecon.go  DeepReconPhase "Deep External Recon".
config.yaml                 API keys + Ollama + proxy/context/param toggles.
verify.sh                   Verification script (code + tool availability).
setup.sh / install_path.sh  Tool installer + PATH helper.
scope.txt / scope2.txt      Whatnot / Roblox HackerOne scopes.
```

### 2.1 The Phase interface (`pkg/engine/engine.go:22-26`)
```go
type Phase interface {
    Name() string
    Description() string
    Execute(ctx context.Context, state *State) error
}
```

### 2.2 Shared State (`pkg/engine/engine.go:31-60`)
`State` carries `Config`, `Scope`, `Governor`, `Proxy`, `AI`, and the growing
result sets `Subdomains []string`, `LiveHosts []string`, `URLs []string`,
`Parameters map[string][]string`, `Findings []map[string]interface{}`,
`OutputFolder`, `StartTime`, plus `CompletedPhases`/`completedSet` for resume.
Concurrency-safe helpers: `Printf` (PrintMu), `AddFinding`/`Triage` (findingsMu),
`MarkComplete`/`IsComplete`.

### 2.3 Orchestrator.Run (`pkg/engine/engine.go:209-360`)
- Prints header + starts a 1-second live timer goroutine (`\r\033[K` single line).
- **Burp health check** (`checkBurp`, lines 166-204): if Burp is set but
  unreachable, it **hard-disables** the proxy in State so the whole pipeline falls
  back to direct networking (this was a catastrophic silent-0-results bug fix).
- For each phase: **skips** if `IsComplete` (resume), executes, then **marks
  complete on success and calls `SaveCheckpoint()` after EVERY phase**.
- On `ctx.Done()` (SIGINT) it saves a checkpoint and prints the resume hint.

### 2.4 The 30 phases (registration order, `cmd/mohammed/main.go:241-272`)

| # | Struct | `Name()` | File |
|---|---|---|---|
| 01 | `ScopeValidationPhase` | Scope Validation | phases.go:70 |
| 02 | `OSINTPhase` | OSINT Intelligence Gathering | phases.go:103 |
| 03 | `SubdomainPassivePhase` | Passive Subdomain Enumeration | phases.go:504 |
| 04 | `SubdomainActivePhase` | Active Subdomain Bruteforce | phases.go |
| 05 | `DNSResolvePhase` | DNS Resolution & Enrichment | phases.go |
| 06 | `TakeoverPhase` | Subdomain Takeover Check | phases.go |
| 07 | `HTTPProbePhase` | HTTP Probing & Tech Fingerprinting | phases.go |
| 08 | `TLSAnalysisPhase` | TLS/SSL Analysis | phases.go |
| 08b | `DeepReconPhase` | Deep External Recon | phases_deeprecon.go:39 |
| 09 | `PortScanPhase` | Port Scanning | phases.go |
| 10 | `WaybackPhase` | Wayback & Historical URL Mining | phases.go |
| 11 | `CrawlPhase` | Web Crawling & Spidering | phases.go |
| 12 | `JSAnalysisPhase` | JS Analysis & Secret Extraction | phases.go:1899 |
| 13 | `ParamDiscoveryPhase` | Parameter Discovery | phases.go |
| 14 | `CORSPhase` | CORS Misconfiguration Check | phases.go |
| 15 | `CloudReconPhase` | Cloud & Bucket Reconnaissance | phases_vuln.go:67 |
| 16 | `FuzzingPhase` | Directory & Content Fuzzing | phases_vuln.go:143 |
| 17 | `VulnScanPhase` | Vulnerability Scanning (Nuclei) | phases_vuln.go:216 |
| 18 | `XSSPhase` | XSS Detection | phases_vuln.go:317 |
| 19 | `SQLiPhase` | SQL Injection Analysis | phases_vuln.go:384 |
| 20 | `SSRFPhase` | SSRF Scanning | phases_vuln.go:444 |
| 21 | `OpenRedirectPhase` | Open Redirect Testing | phases_vuln.go:497 |
| 22 | `ForbiddenBypassPhase` | 403/401 Bypass Testing | phases_vuln.go:546 |
| 23 | `APIDiscoveryPhase` | API Route Discovery | phases_vuln.go:608 |
| 24 | `CRLFPhase` | CRLF Injection Check | phases_vuln.go:679 |
| 25 | `SmugglingPhase` | HTTP Request Smuggling | phases_vuln.go:720 |
| 26 | `GitExposurePhase` | Git & Sensitive File Exposure | phases_vuln.go:769 |
| 27 | `EmailSecurityPhase` | Email Security Verification | phases_vuln.go:849 |
| 28 | `PrototypePollutionPhase` | Prototype Pollution Scan | phases_vuln.go:894 |
| 29 | `ReportPhase` | Final Report Generation | phases_vuln.go:~950 |

> The array in `main.go` holds **30 entries** (the deep-recon phase is the "08b"
> extra). Profiles (`small`/`medium`/`large`/`passive`) are keyed by `Name()`
> strings, **not** slice index (`smallPhases`/`passivePhases` maps in
> `main.go:282-296`), so inserting/reordering phases is safe.

---

## 3. Working features (with function names + line numbers)

### 3.1 Scope handling (`pkg/config/config.go`)
- `LoadScope` (89-156): parses scope, strips scheme/port/path, collapses `*.x`→`x`,
  **deduplicates** domains/IPs/CIDRs, honors `-`-prefixed out-of-scope lines.
- `IsApexDomain` (208-233), `ApexOf` (256-275), `ExtractApexDomains` (240-252):
  apex/root derivation with a two-part-TLD table (co.uk, com.sa, …). **This is the
  backbone of the apex-only passive-enum design.**

### 3.2 Parallel OSINT harvester — Phase 02 (`pkg/phases/phases.go`)
`OSINTPhase.Execute` runs a **fan-out/fan-in async harvester**: a `sync.WaitGroup`
+ `sync.Mutex`, a closure `run(source, apex, fn)` launching one goroutine per
source, and `addAll(apex, hosts)` merging results through the pure, unit-tested
`filterHostsUnderApex` (221-243). Harvesters (each returns `[]string`):

| Source | Function | Line | Key/free |
|---|---|---|---|
| Shodan | `harvestShodan` | 256 | keyed |
| VirusTotal | `harvestVirusTotal` | ~270 | keyed |
| SecurityTrails | `harvestSecurityTrails` | ~288 | keyed |
| Chaos | `harvestChaos` | ~303 | keyed |
| crt.sh | `harvestCrtSh` | 317 | **free** |
| HackerTarget | `harvestHackerTarget` | ~344 | **free** |
| RapidDNS | `harvestRapidDNS` | ~356 | **free** |
| BufferOver | `harvestBufferOver` | ~371 | **free** |
| AnubisDB (jldc.me) | `harvestAnubis` | 391 | **free** |
| ThreatMiner | `harvestThreatMiner` | ~399 | **free** |
| Certspotter | `harvestCertspotter` | 416 | **free** |
| AlienVault OTX | `harvestOTX` | ~439 | free (key optional) |
| URLScan | `harvestURLScan` | 475 | **free** |

All use the shared `curlGet(ctx, url, extraArgs...)` wrapper.

### 3.3 Passive enumeration — Phase 03 (`pkg/phases/phases.go:504+`)
subfinder + assetfinder + amass + bbot + findomain, **apex-only** (`for _, domain
:= range apexDomains`). `ensureAmassConfig` (934) writes a minimal free-source
`~/.config/amass/config.ini` before amass runs. Merges Phase-02 OSINT output.

### 3.4 Active enumeration — Phase 04
puredns (`--write` + `--resolvers`) → massdns → dnsx fallback. `ensureResolvers`
and `ensureDNSWordlist` guarantee inputs exist.

### 3.5 Takeover — Phase 06
`confirmTakeover` does an HTTP fingerprint confirm; `parseSubzyVulnerable` only
keeps subzy entries actually marked vulnerable → AI triage.

### 3.6 HTTP probe — Phase 07
httpx with `-json`; routes through Burp via **`-http-proxy`** when active.
`directProbe` is a stdlib fallback; `extractURLsFromHTTPX` parses the JSON.

### 3.7 Deep External Recon — Phase 08b (`pkg/phases/phases_deeprecon.go`)
Zero-login pivots per apex: RFC 9116 `security.txt`, SPF/DMARC vendor chain,
**favicon mmh3 hash** (`http.favicon.hash:` Shodan pivot), ASN/netblock via
`ip-api.com/json`. Endpoints: `https://%s/favicon.ico`,
`http://ip-api.com/json/%s?fields=as`.

### 3.8 Wayback/URL mining — Phase 10
gau (`--providers`, `--threads`, `--retries`, `--subs`, `--config`) + waybackurls,
plus custom `harvestURLScanURLs` and `harvestCommonCrawlURLs`. `dedupeURLs`.

### 3.9 State checkpoint / resume (`pkg/engine/checkpoint.go`)
- `Checkpoint` struct (28-40): version, target, output folder, timestamps,
  completed phases, subdomains, live hosts, URLs, parameters, findings.
- `SaveCheckpoint` (51-90): **atomic** (write `.tmp` then `os.Rename`).
- `LoadCheckpoint` (93-106): rejects `version==0`.
- `RestoreInto` (110-136): rehydrates State + rebuilds `completedSet`.
- `FindLatestCheckpoint` (141-171): newest `output/*/checkpoint.json` by mtime.
- CLI wiring in `main.go:217-237`: `--resume auto` or `--resume <path>`.

### 3.10 AI triage (`pkg/ai/triage.go`)
`TriageFinding` (85) POSTs to `/api/generate` (stream=false, temp 0.2, num_predict
80), caps evidence at 4000 bytes, `parseVerdict` (142) interprets REAL vs
FALSE_POSITIVE. **Fails OPEN**: any error/disabled → `(true, "ollama_offline")`.
`State.Triage` (engine.go:122) demotes confirmed FPs to `Info` (never dropped).

### 3.11 Runner (`pkg/runner/runner.go`)
`RunTool` (142) with `toolTimeouts` map (56-107); `runToolInternal` (160) sets
`Setpgid` and kills the whole process group on timeout (`syscall.Kill(-pgid,...)`);
`cmd.Env = os.Environ()` then appends injected env (198-201) — so proxy env never
clobbers PATH. `SetDebug`/`DebugEnabled` (22-25) drive `--debug` command logging.

---

## 4. CONFIRMED BUGS (7) — root cause + fix approach + success criteria

> These are the 7 bugs the project owner originally confirmed with **live scan
> evidence**. They are documented in full so the rationale is preserved.
>
> ### ⚠️ CURRENT STATUS (branch `genspark_ai_developer`, commit `d996776`)
> Audit commit **`fix(tools): resolve 11 confirmed tool integration failures`
> (d996776)** has **already implemented fixes for 6 of the 7 bugs**. Your job is to
> **VERIFY each fix with a real scan** (don't assume) and finish the one still open.
>
> | Bug | Status in current code | Where |
> |---|---|---|
> | #1 amass 0 results | **Fixed (verify)** — `ensureAmassConfig` writes config + retry-once | phases.go:934 |
> | #2 bbot 0 results | **Fixed (verify)** — now `-om json`, parses `output.ndjson` DNS_NAME | phases.go:641-661 |
> | #3 JS secrets no value | **Fixed (verify)** — `extractSecretEvidence` captures match+value+context | phases.go:~1970 |
> | #4 stale report data | **Fixed (verify)** — deletes stale `final_report.*` before write | phases_vuln.go:1117-1124 |
> | #5 Burp idle-channel errors | **STILL OPEN — do this** | engine.go:checkBurp / proxy.go |
> | #6 gau missing .gau.toml | **Fixed (verify)** — `ensureGauConfig` writes `~/.gau.toml` | phases.go:993 |
> | #7 stale result files | **Fixed (verify)** — `State.CleanStaleResults()` fresh-scan only | engine + phases |
>
> **The only genuinely-open confirmed bug is #5 (Burp idle HTTP channel).** Treat
> #1-#4, #6, #7 as "implemented, needs live regression proof". Fix/verify bugs
> **first**, before any new feature.

### BUG #1 — amass returns 0 results every scan
- **Evidence:** `0 / 1 [____] 0.00% p/s` for ~30s, then nothing.
- **Root cause:** missing `~/.config/amass/config.ini` (no data sources enabled).
- **Status (d996776):** FIXED — `ensureAmassConfig` (phases.go:934) writes the
  config and retries once on a zero result. **Verify with a live apex scan.**
- **Done when:** a real apex scan shows `amass: N subdomains` with `N>0`.

### BUG #2 — bbot returns 0 results every scan
- **Evidence:** `bbot: 0 subdomains [OK]` on every domain.
- **Root cause:** output-format parsing mismatch — the old code walked the bbot
  output dir for `*.txt` only, which modern bbot may not emit for passive enum.
- **Status (d996776):** FIXED — bbot now runs with `-om json` and parses
  `output.ndjson` DNS_NAME events first (phases.go:641-661), `.txt` as fallback.
  **Verify with a live apex scan.**
- **Done when:** real scan shows `bbot: N subdomains` with `N>0`.

### BUG #3 — JS secrets: pattern NAME only, no matched value
- **Evidence:** report showed `evidence: pattern: api_key_generic` with **no key**.
- **Root cause:** `JSAnalysisPhase` (phases.go:1899) used a
  `secretPatterns map[string]string` of **substrings** matched with
  `strings.Contains`; the finding stored `"pattern: " + label` (the label), never
  the matched string.
- **Status (d996776):** FIXED — `extractSecretEvidence` now captures the match
  line, actual value and ±40-char context and writes `js_secrets_confirmed.txt`.
  **Verify the finding evidence now contains a real value.**
- **Done when:** a JS finding shows the real matched token, not just the pattern name.

### BUG #4 — final_report.md shows OLD scan data
- **Evidence:** a new scan (Critical:0) produced a report showing old Critical:6.
- **Root cause:** `ReportPhase.Execute` (phases_vuln.go:~950) wrote the report
  without deleting stale artifacts first, so a reused output folder bled old data.
- **Status (d996776):** FIXED — the report phase now `os.Remove`s stale
  `final_report.*`/tiered `.txt` before writing (phases_vuln.go:1117-1124) and adds
  a Scan Date/Duration/Tool-Version header. **Verify with two back-to-back scans.**
- **Done when:** back-to-back scans produce reports whose counts match the current run.

### BUG #5 — Burp "Unsolicited response received on idle HTTP channel"  ⟵ STILL OPEN
- **Evidence (roblox scan):** `Unsolicited response received on idle HTTP channel`,
  `Invalid client request received: Request is empty`.
- **Root cause:** sqlmap/ghauri keep-alive connections to the Burp proxy idle-out and
  send empty requests; the Go proxy/HTTP clients (`engine.go:checkBurp`,
  `proxy.go:TestConnection`) don't disable keep-alive / don't close idle conns.
- **Fix approach:** set `Transport{ DisableKeepAlives: true, IdleConnTimeout }` and
  `Close: true` on proxy-check clients; for CLI tools, ensure per-invocation
  connection close (e.g. pass `Connection: close` where supported) so no idle
  channel is left dangling between tool runs.
- **Done when:** a Burp-routed scan produces no "Unsolicited response"/"empty
  request" errors in Burp's event log.

### BUG #6 — gau: missing ~/.gau.toml
- **Evidence:** `Config file /home/kali/.gau.toml not found`.
- **Root cause:** gau config not auto-created → gau falls back to limited defaults.
- **Status (d996776):** FIXED — `ensureGauConfig` (phases.go:993) writes
  `~/.gau.toml` and passes `--config`. **Verify gau no longer logs config-not-found.**
- **Done when:** gau runs with no config-not-found warning and URL counts rise.

### BUG #7 — stale result files not cleared (cross-scan pollution)
- **Evidence:** `sqli_results.txt` retained data from a previous scan.
- **Root cause:** vuln phases wrote fixed-name result files without truncating them.
- **Status (d996776):** FIXED — `State.CleanStaleResults()` wipes prior
  `.txt/.json/.md` on a FRESH scan only (guarded so `--resume` keeps checkpoint.json).
  **Verify a fresh scan's result files contain only current-run data.**
- **Done when:** a fresh scan's per-phase result files contain only that run's data.

---

## 5. THE 8-ITEM IMPROVEMENT WISHLIST

Only start these **after** BUG #5 is closed and #1-#4/#6/#7 are verified.
Priority is top-to-bottom. Each item lists intent + concrete implementation notes.

### IMPROVEMENT #1 — Replace paid API keys with free, no-key data sources
- **Why:** `config.yaml` api_keys are empty, so Shodan/VirusTotal/SecurityTrails/Chaos
  harvesters currently no-op. We want coverage WITHOUT paid keys.
- **How:**
  - Shodan → `https://internetdb.shodan.io/{ip}` (free, no key: open ports, CPEs, hostnames).
  - VirusTotal/SecurityTrails subdomains → keep crt.sh + Anubis + Certspotter + urlscan
    (already implemented as `harvestCrtSh`/`harvestAnubis`/`harvestCertspotter`/`harvestURLScan`).
  - Chaos → replace with free passive sources below.
- **Where:** `pkg/phases/phases.go` OSINTPhase harvesters (256-475); add
  `harvestInternetDB` alongside the existing `harvest*` closures wired into the
  parallel `run()`/`addAll()` fan-in.
- **Done when:** with an empty api_keys block, subdomain + port coverage is unchanged
  or better vs. a keyed run.

### IMPROVEMENT #2 — Add new free OSINT sources
- **How:** add `hackertarget.com/hostsearch`, `rapiddns.io`, `dnsdumpster` (token flow),
  `web.archive.org/cdx` for historic hosts, `alienvault OTX passive DNS` (free tier).
- **Where:** new `harvest*` closures in OSINTPhase, each behind a per-source goroutine,
  results funneled through `filterHostsUnderApex` (phases.go:221-243) so out-of-scope
  hosts are dropped.
- **Done when:** each new source contributes unique in-scope hosts and respects apex scope.

### IMPROVEMENT #3 — Smarter XSS detection
- **Why:** SCAN 2 found 5 reflecting params but 0 confirmed XSS.
- **How:** context-aware payloads (HTML body vs attribute vs JS string vs URL), unique
  canary marker per param, confirm reflection is unencoded + lands in an executable
  context before flagging; optionally headless-verify with a DOM check.
- **Where:** the XSS phase in `phases_vuln.go`; keep evidence going through
  `filter.EvidenceVerifier` (SHA-256 dedup) so duplicates collapse.
- **Done when:** reflected-but-encoded params are NOT reported; only executable-context
  reflections are, each with a reproducing URL.

### IMPROVEMENT #4 — SSRF deep analysis
- **Why:** SCAN 2 flagged 5 SSRF candidates with no confirmation pipeline.
- **How:** out-of-band interaction (self-hosted collector / Burp Collaborator-style
  callback token), blind-SSRF timing checks, cloud-metadata probes (169.254.169.254,
  metadata.google.internal) gated to in-scope hosts only.
- **Where:** SSRF phase in `phases_vuln.go`; findings triaged by `ai.TriageFinding`
  (fail-open) then `engine.Triage` (demotes false-positives to Info).
- **Done when:** SSRF findings carry OOB proof or are demoted; no unproven High/Med SSRF.

### IMPROVEMENT #5 — Email-spoofing HackerOne report generator
- **Why:** `EmailSecurityPhase` (phases_vuln.go:849) already detects missing/weak
  SPF/DKIM/DMARC (e.g. rbx.com all-false) but does NOT emit a submittable report.
- **How:** when a domain has spoofable email posture, generate a HackerOne-ready
  Markdown report (title, severity, steps-to-repro incl a spoofed-mail proof, impact,
  remediation) into the run's report dir.
- **Where:** extend `EmailSecurityPhase`; reuse the ReportPhase (phases_vuln.go:~950)
  writer + the stale-clear logic (1117-1124) so old templates are removed first.
- **Done when:** a domain missing DMARC produces `report_email_spoofing_<domain>.md`.

### IMPROVEMENT #6 — Cut scan time to under 90 minutes
- **Why:** whatnot took 206 min, roblox 150 min.
- **How:** raise safe parallelism in the OSINT fan-in and per-phase workers, honor the
  adaptive `governor` (governor.go) to back off only under pressure, cap URL explosion
  (roblox produced 689k URLs) with smarter dedup/sampling before heavy phases.
- **Where:** OSINTPhase concurrency, `pkg/governor/governor.go`, URL-collection phases.
- **Done when:** an equivalent whatnot-scale scan finishes < 90 min with equal findings.

### IMPROVEMENT #7 — Interactive report viewer
- **How:** add a `--serve --port 8090` flag to `runScan`/main that boots a small stdlib
  `net/http` server rendering the run's final report (filter by severity, view evidence).
- **Where:** `cmd/mohammed/main.go` (flag + subcommand) reading the ReportPhase output.
- **Done when:** `mohammed --serve --port 8090` serves the latest report at localhost:8090.

### IMPROVEMENT #8 — Multi-target parallel scanning
- **How:** add `--parallel N` so several scope targets run as isolated Orchestrator runs
  concurrently, each with its own State + checkpoint dir, bounded by N.
- **Where:** `cmd/mohammed/main.go` runScan; reuse `engine.State`/`checkpoint.go`
  (SaveCheckpoint atomic tmp+rename, FindLatestCheckpoint) per target.
- **Done when:** two scope files scan simultaneously without state/report cross-talk.

---

## 6. THE TWO REAL SCAN RESULTS (baseline to compare against)

These are prior real runs. Use them as the regression baseline: after fixes, a
re-scan of the same target should match or exceed these numbers with 0 false positives.

### SCAN 1 — whatnot.com (scope.txt)
| Metric | Value |
|---|---|
| Wall time | ~206 minutes |
| Subdomains discovered | 119 |
| Live hosts | 31 |
| URLs collected | 3,431 |
| Findings | 32 (1 Medium / 31 Info) |
| False positives | 0 |
| Approx Burp requests | ~6,955 |

### SCAN 2 — roblox.com (scope2.txt: roblox/rbx/blox.link/ra.roblox.com)
| Metric | Value |
|---|---|
| Wall time | ~150 minutes |
| Subdomains discovered | 1,880 |
| Live hosts | 338 |
| URLs collected | 689,076 |
| Findings | 53 (8 Medium / 45 Info) |
| False positives | 0 |
| SSRF candidates | 5 (unconfirmed → IMPROVEMENT #4) |
| XSS | 5 params reflecting / 0 confirmed → IMPROVEMENT #3 |
| SQLi funnel | 17,766 candidates → 5 probed → 0 confirmed |
| Email posture | rbx.com SPF/DKIM/DMARC all FALSE (spoofable → IMPROVEMENT #5) |
| Approx Burp requests | ~1,860 |

---

## 7. API-KEYS SITUATION (what's missing, where)

- **In `config.yaml` (lines 7-14):** the `api_keys:` block is present but every value
  is EMPTY — github, shodan, virustotal, alienvault, securitytrails, chaos, censys.
- **Missing entirely from the YAML:** `haveibeenpwned` — the Go struct
  `config.APIKeys` (pkg/config/config.go:32-41) DOES define a `haveibeenpwned` field,
  but there is no matching line in config.yaml, so it can never be set from file.
- **Effect today:** keyed harvesters (Shodan/VT/SecurityTrails/Chaos) silently no-op;
  coverage currently comes from the keyless sources (crt.sh, Anubis, Certspotter,
  urlscan). This is exactly why IMPROVEMENT #1/#2 (free sources) matter.
- **Do NOT** hardcode secrets. If keys are ever added, they belong in config.yaml
  api_keys (and add the missing `haveibeenpwned:` line to keep struct/YAML in sync).

---

## 8. SCOPE FILES

- **`scope.txt`** — Whatnot HackerOne scope (apex: whatnot.com). Used by SCAN 1.
- **`scope2.txt`** — Roblox HackerOne scope. Contains: `roblox.com`, `rbx.com`,
  `blox.link`, `ra.roblox.com`, plus wildcards `*.roblox.com`, `*.rbx.com`. Used by SCAN 2.
- **How scope is consumed:** `config.LoadScope` (config.go:89-156) dedups entries,
  and apex logic (`IsApexDomain` 208-233, `ExtractApexDomains` 240-252, `ApexOf`
  256-275 with its two-part-TLD table incl `co.uk`/`com.sa`) keeps passive enumeration
  anchored to in-scope apexes. `filterHostsUnderApex` (phases.go:221-243) drops any
  harvested host that isn't under an in-scope apex — respect this in every new source.

---

## 9. SUCCESS CRITERIA & GOLDEN RULES

### How to prove a fix (the new AI MUST do this for every change)
1. `export PATH=$PATH:/usr/local/go/bin`
2. `go build ./...` → exit 0
3. `go vet ./...` → clean
4. `go test ./...` → `ok` for engine/config/phases/proxy
5. `bash verify.sh` → all sections green (esp. "12b. v4.1 Upgrades" and "16" tool fixes)
6. **Live proof per bug/feature:** paste the actual tool/scan output showing the old
   symptom is gone (e.g. amass now returns >0 hosts; bbot output.ndjson parsed; gau no
   config-not-found; Burp event log clean of empty-request errors).

### Golden rules (non-negotiable)
- **READ BEFORE CODING.** Read this briefing, then the GitHub codebase at
  `genspark_ai_developer`, before touching anything.
- **NEVER invent CLI flags.** (Example: httpx has NO `-insecure`.) Verify a flag exists
  in the tool's `--help` before using it.
- **PROVE every fix** with real output — do not claim "fixed" without a test artifact.
- **COMMIT after each change** to `genspark_ai_developer`, open/update the PR, share the link.
- **Prioritize remote code on conflict** — the remote branch is the source of truth.
- **Module path is `github.com/mohammed-v3/core` — NEVER rename it.**
- **This is legitimate, authorized HackerOne bug-bounty work.** Only scan in-scope
  assets (scope.txt / scope2.txt). Ethical, legal, authorized testing only.

### Priority order for the new AI
1. Verify BUGS #1-#4, #6, #7 (already fixed at d996776) with live output.
2. Close the only open bug: **BUG #5 (Burp idle HTTP channel).**
3. Then work IMPROVEMENTS #1 → #8 in order, proving each.

---

*End of handover briefing. Written against commit `d996776`. Grep function names if
line numbers have drifted.*
