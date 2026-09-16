# MOHAMMED V4 — Autonomous Attack Surface & Defensive Audit Engine

**High-Assurance, Governed Attack Surface Management & Security Verification Platform**

[![Go Version](https://img.shields.io/badge/Go-1.22.5%2B-blue.svg)](https://golang.org)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Kali-red.svg)](https://www.kali.org)
[![Zero-False-Positive](https://img.shields.io/badge/Architecture-Zero--FP%20Enforced-brightgreen.svg)](#zero-false-positive-architecture)
[![Safety Governor](https://img.shields.io/badge/Target%20Protection-Autonomous%20Governor-orange.svg)](#core-safety-governor--autonomous-pacing)
[![Production Benchmark](https://img.shields.io/badge/Standard-100%25%20Enterprise%20Ready-success.svg)](#hybrid-re-engineering-production-benchmark-modules)

---

## 🎯 Executive Overview & Pipeline Architecture

**MOHAMMED V4** is a high-assurance, multi-stage automated attack surface management (ASM) and diagnostic security audit engine designed for **Enterprise Networks, Organizations, and Authorized Bug Bounty Asset Discovery**.

Built to replace brittle multi-tool bash scripts with a single unified, resilient Go framework, MOHAMMED V4 operates on a strict **Zero-API, Zero-False-Positive, and Target-Safety** foundation:
- **Zero Commercial API Dependency**: Operates entirely using native public OSINT intelligence (Certificate Transparency logs, Wayback CDX, AlienVault OTX, DNS) and high-speed native Go scanners.
- **Strict Content Invariant Validation**: Eliminates phantom alerts on wildcard DNS or custom 404/200-OK landing pages via exact magic-byte verification, strict regex patterns, and baseline diffing.
- **Safety Governor Protection**: Guarantees zero denial-of-service risk on audited systems with autonomous capacity sensing, rate throttling, and automatic circuit breakers.

```
                           MOHAMMED V4 PIPELINE ARCHITECTURE
   
   +---------------------------------------------------------------------------------+
   |                           PHASE 00-02: ZERO-API PASSIVE OSINT                   |
   |   Public CT Logs (crt.sh, certspotter) * Wayback CDX * AlienVault OTX * DNS     |
   |   -> Native Keyless Scrapers & Shodan InternetDB IP Intelligence                |
   +---------------------------------------------------------------------------------+
                                         |
                                         v
   +---------------------------------------------------------------------------------+
   |               PHASE 03-07: ATTACK SURFACE RECON & LIVE PROBING                  |
   |   subfinder * dnsx (deduplication & wildcard filtering) * httpx live probing    |
   +---------------------------------------------------------------------------------+
                                         |
                                         v
   +---------------------------------------------------------------------------------+
   |               PHASE 08-16: HIGH-SPEED DEDUPLICATED PORT AUDIT                   |
   |   Hostname-to-IP Deduplication * 25 Concurrent Dialers * 400ms Connect Timeout  |
   |   Top-100 Web/Admin Ports * 3-Minute Hard Phase Safety Ceiling                  |
   +---------------------------------------------------------------------------------+
                                         |
                                         v
   +---------------------------------------------------------------------------------+
   |               PHASE 17: SURGICAL AUDIT & RECURSIVE INTELLIGENCE                 |
   |   • Module 1: Recursive Schema-Driven API Auditor (OpenAPI/Swagger BOLA & Auth) |
   |   • Module 2: JavaScript & Source-Map Deep Harvester (Entropy Credentials)      |
   |   • Module 3: Dangling CNAME & Subdomain Takeover Resolver (SaaS Abandonment)   |
   |   • Module 4: Zero-Tolerance Surgical Probes (Zip Magic Bytes, Strict Regex)   |
   |   • Curated CVE-2020-14882 WebLogic & Spring Actuator Inspection                |
   +---------------------------------------------------------------------------------+
                                         |
                                         v
   +---------------------------------------------------------------------------------+
   |                   PHASE 54: AUTONOMOUS TARGET SAFETY GOVERNOR                   |
   |   Auto-Capacity Probing (RTT/CDN) * Concurrency Semaphore * Circuit Breaker     |
   +---------------------------------------------------------------------------------+
                                         |
                                         v
   +---------------------------------------------------------------------------------+
   |               REPORT GENERATION & ZERO-FP SANITIZATION ENGINE                   |
   |   Filter Internal Telemetry  *  Clean Field Formatting  *  Tiered Outputs       |
   |   --> CONFIRMED_VULNS.txt (Conf >= 70)  |  MANUAL_REVIEW.txt (Human Triage)     |
   +---------------------------------------------------------------------------------+
```

---

## 🛠️ Complete Tool Ecosystem (Zero-API Hybrid Toolset)

MOHAMMED V4 integrates 10 essential CLI utilities, compiled and configured via `./mohammed setup`:

| # | Tool | Category | Architectural Role in MOHAMMED V4 |
|---|---|---|---|
| 1 | `subfinder` | Recon & Discovery | Fast passive subdomain enumeration across public intelligence sources without commercial API keys. |
| 2 | `dnsx` | Recon & DNS | High-speed DNS resolution, CNAME chain tracing, and multi-resolver wildcard filtering. |
| 3 | `httpx` | Probing & Discovery | Multi-purpose HTTP probe detecting alive services, status codes, response headers, and technologies. |
| 4 | `katana` | Crawling & Scraping | Modern web crawler for endpoint extraction, link discovery, and client-side form detection. |
| 5 | `gau` | Archive Harvesting | Fetches historical URLs from Wayback Machine, Common Crawl, and AlienVault OTX. |
| 6 | `alterx` | Permutation & Mutation | Generates intelligent subdomain variations using contextual wordlists and syntax patterns. |
| 7 | `arjun` | Parameter Discovery | Discovers hidden HTTP GET/POST/JSON parameters for deep interface inspection. |
| 8 | `ffuf` | Content Fuzzing | High-performance Go fuzzer for directory brute-forcing, virtual host fuzzing, and route discovery. |
| 9 | `cariddi` | Asset Extraction | Scans HTTP responses and JS files for endpoints, parameters, and sensitive strings. |
| 10 | `trufflehog` | Secret Verification | High-entropy detector that flags leaked API keys and credentials with live verification checks. |

---

## 🔬 Core Phase Catalog & Benchmark Modules

### 1. Zero-API Passive Reconnaissance & Discovery
- **Native Threat-Intel Scrapers (`pkg/phases/scrapers.go`)**: Direct HTTP scrapers for crt.sh, Wayback CDX, AlienVault OTX, and Shodan InternetDB.
- **DNS Clean & Wildcard Filtering**: Native integration of `dnsx` filters non-resolving or sinkholed records before any active probe is triggered.

### 2. High-Speed IP-Deduplicated Port Scanner (`pkg/phases/light_portscan.go`)
- **IP Deduplication Engine**: Maps all subdomains to IPv4 addresses, grouping duplicate hostnames that point to shared edge or CDN anycast IPs.
- **25-Worker Async Connect Pool**: Scans Top-100 web/admin/management ports (80, 443, 8080, 8443, 3000, 5000, 9000, 10000, etc.) with 400ms connect timeouts.
- **3-Minute Hard Ceiling**: Bounded execution timeout ensures port scanning never delays an audit workflow.

### 3. Recursive Schema-Driven API Auditor (`pkg/phases/api_schema_auditor.go`)
- Discovers and parses OpenAPI/Swagger specifications (`/v3/api-docs`, `/swagger.json`, `/openapi.json`) in memory.
- Audits unauthenticated privilege paths (`admin`, `mgmt`, `internal`, `token`, `export`) and flags broken authentication with authentic JSON payload validation.
- Extracts BOLA/IDOR object identifiers (`{uimUserId}`, `{id}`) to prioritize identity-based authorization checks.

### 4. JavaScript & Source-Map Deep Harvester (`pkg/phases/js_harvester.go`)
- Crawls client-side script bundles and audits inline scripts.
- Detects leaked cloud keys (AWS, Google, GitHub, Slack) and filters placeholders via **Shannon entropy verification**.
- Uncovers hidden API endpoints and alerts on publicly exposed `.js.map` source maps.

### 5. Dangling CNAME & Subdomain Takeover Resolver (`pkg/phases/takeover_resolver.go`)
- Performs live CNAME resolution across all discovered subdomains.
- Validates cloud abandonment fingerprints against AWS S3, GitHub Pages, Heroku, Azure Traffic Manager, Zendesk, and CloudFront.

### 6. Zero-Tolerance Surgical Probes (`pkg/phases/surgical_probes.go` & `curated_templates.go`)
- **Strict Content Invariant Validation**: Enforces standard ZIP magic bytes (`PK\x03\x04`), `.env` key-value regex patterns, and exact Git repository headers.
- **Compile-Time / Init-Time Panic Assertion**: Prevents empty or whitespace-only signatures in curated templates, stopping false alarms on generic 200 OK responses.

---

## 🛡️ Core Safety Governor & Autonomous Pacing

Target stability is guaranteed by the integrated **Adaptive Target Governor** (`pkg/governor`):

1. **Autonomous Target Capacity Detection (`--smart-rate`)**:
   - Sends baseline round-trip time (RTT) probes before active phases.
   - Detects CDN fronting (Cloudflare, Akamai, CloudFront) and automatically calibrates request pacing:
     - **High Latency (>1000ms) or Single IP**: Throttles down to `1 req/s`, concurrency `1`.
     - **Standard Application Tier (300ms–800ms)**: Sets `2–3 req/s`, concurrency `2`.
     - **Edge CDN Fronted (<500ms)**: Scales safely up to `5 req/s`, concurrency `4`.
2. **Circuit Breaker Protection**:
   - Automatically trips on HTTP `429 Too Many Requests`, `503 Service Unavailable`, or `504 Gateway Timeout`.
   - Freezes requests, applies exponential backoff cooldown (`5s` to `60s`), and tests with half-open recovery probes.
3. **Pacing Jitter**:
   - Injects random 150ms–300ms delays to eliminate synchronized request spikes.

---

## 🚀 CLI Flags & Operational Modes

### Command Structure
```bash
./mohammed <command> [flags]
```

### Commands
- `scan`: Execute reconnaissance, port auditing, and diagnostic verification.
- `report`: Serve the interactive HTML dashboard for a completed scan (`--serve --port 8090`).
- `doctor`: Comprehensive health check validating all 10 tools, network connectivity, DNS latency, socket binding, and filesystem I/O.
- `setup`: Automated one-click installation and compilation of all 10 ecosystem tools.
- `help`: Display complete CLI help and usage options.

### Scan Options & Flags

| Flag | Type | Description |
|---|---|---|
| `-s, --scope` | `string` | Target scope file path, or built-in scope profile (`gitlab` / `github`) [Required]. |
| `-c, --config` | `string` | Path to configuration file (default: `config.yaml`). |
| `--profile` | `string` | Scan profile: `small` \| `medium` \| `large` \| `passive` (default: `medium`). |
| `--smart-rate` | `bool` | Autonomous target sensing (probes latency/CDN to auto-tune rate & concurrency). |
| `--rate` | `int` | Custom requests-per-minute ceiling (e.g. `120`). |
| `--threads` | `int` | Global thread and worker concurrency limit (default: `30`). |
| `--skip` | `string` | Comma-separated list or range of phase numbers to skip (e.g. `4,12,20` or `12-20`). |
| `--only` | `string` | Run ONLY specified phase numbers (e.g. `13,14,15` or `13-15`). |
| `--resume` | `string` | Resume interrupted audit: `auto` (picks latest in `output/`) or path to `checkpoint.json`. |
| `--burp` | `string` | Proxy all outgoing HTTP traffic through Burp Suite or an upstream proxy (e.g. `http://127.0.0.1:8080`). |
| `--output` | `string` | Custom output directory for artifacts and reports (default: `output/`). |

### Profile Recommendations

1. **`--profile small` (Single App / Sensitive Target)**:
   - Minimal active probing, low concurrency, strict rate limiting.
   - Ideal for production web applications and sensitive APIs.
2. **`--profile medium` (Standard Audit)**:
   - Balanced recon, IP-deduplicated port scan, API schema analysis, and surgical checks.
   - Recommended default for standard corporate scopes (10–50 hosts).
3. **`--profile large` (Large Scope / Bounty)**:
   - Deep recursive crawling, full parameter discovery, extensive wordlists, and JS harvesting.
   - Best for expansive organizational scopes.
4. **`--profile passive` (Zero-Touch Compliance)**:
   - 100% external OSINT (CT logs, Wayback, AlienVault OTX, DNS).
   - Zero packets sent to target IPs.

---

## 🔧 Troubleshooting & Maintenance

### 1. Diagnostic Health Check (`./mohammed doctor`)
Run doctor to verify system prerequisites:
```bash
./mohammed doctor
```
The doctor command performs 4 rigorous checks:
1. **Tool Presence & Versioning**: Tests whether all 10 tools (`subfinder`, `dnsx`, `httpx`, `katana`, `gau`, `alterx`, `arjun`, `ffuf`, `cariddi`, `trufflehog`) are present in `$PATH` or `$GOPATH/bin`.
2. **DNS & Network Latency**: Verifies connectivity and round-trip time across Cloudflare (`1.1.1.1:53`), Google (`8.8.8.8:53`), and Quad9 (`9.9.9.9:53`).
3. **Socket Binding Capabilities**: Tests ephemeral TCP and UDP socket listeners on the local host.
4. **Workspace Permissions**: Validates write and read integrity inside the designated output workspace.

### 2. Ecosystem Installer (`./mohammed setup`)
If any tools are missing, install and compile the complete ecosystem with a single command:
```bash
./mohammed setup
```

### 3. Interpreting Report Artifacts
Scan outputs are written to `output/<target>/` with clear separation of verified vs. triage findings:
- `CONFIRMED_VULNS.txt`: Findings with confidence $\ge 70$ backed by cryptographic or structural HTTP evidence.
- `MANUAL_REVIEW.txt`: Findings requiring human triage or validation.
- `final_report.json`: Machine-readable structured dossier for SIEM or dashboard ingestion.

---

## 🏛️ Hybrid ASM & Orchestration Architecture (Pillars 1–4)

MOHAMMED V4 integrates four foundational architectural pillars ensuring enterprise safety, zero false positives, and high-performance hybrid asset discovery:

### Pillar 1: Adaptive Target-Health Sensing & Load Governor (`pkg/governor/engine.go`)
- **Real-Time Target Telemetry Monitor**: Tracks EWMA round-trip latency ($\alpha=0.2$) and sliding window error ratios (HTTP 429, 502, 503, 504, connection resets).
- **Dynamic Backoff Algorithm**: Automatically trips a temporary backoff when error rates exceed 5% or when response latency spikes $\ge 3\times$ baseline RTT.
- **Circuit Breaker Pattern**: Freezes active probes on degraded endpoints while maintaining passive reconnaissance threads, allowing target infrastructure to stabilize.

### Pillar 2: Multi-Engine Hybrid Orchestration Pipeline (`pkg/phases/orchestrator.go`)
- **Unified In-Memory Asset Graph**: Coordinates external CLI tools (`subfinder`, `dnsx`, `httpx`, `katana`, `gau`, `ffuf`, `cariddi`, `bbot`) using bounded Go channels and Unix stdout streaming, avoiding disk I/O bottlenecks.
- **Smart Asset Canonicalization**: Normalizes URLs and hostnames, strips redundant query parameter permutations, and enforces out-of-scope regex boundaries.

### Pillar 3: Zero-Noise Differential Verification Gate (`pkg/verification/gate.go`)
- **Baseline Calibration**: Fingerprints baseline responses (status, length, SHA256 hash, title) to identify Soft-404 and catch-all behaviors.
- **Multi-Pass Differential Probing**: Re-probes candidate findings across multiple isolated passes to confirm state repeatability before reporting.
- **Structured Output Separation**:
  * `CONFIRMED_FINDINGS.json`: High-confidence ($\ge 70$), verified vulnerabilities with complete telemetry.
  * `MANUAL_ASSESSMENT.json`: Anomalies requiring human triage.

### Pillar 4: Ecosystem Setup & Doctor Resilience (`cmd/mohammed/`)
- **Multi-Tier Installer (`setup.go`)**: 3-tier installation pipeline (Go compilation $\to$ Apt system package fallbacks $\to$ pre-compiled release scripts).
- **System Resource Health Doctor (`doctor.go`)**: Verifies RAM allocations, file descriptor limits (`ulimit -n`), CPU core count, network latency, and socket binding.

---

## 📊 Verification & Test Matrix

All packages are continuously verified with Go unit tests and static analysis:

| Component | Path | Verification Command | Status |
|---|---|---|---|
| Target Health Governor (Pillar 1) | `pkg/governor/engine.go` | `go test -v ./pkg/governor -run TestTargetTelemetryMonitor` | PASS (0 regressions) |
| Hybrid Orchestrator (Pillar 2) | `pkg/phases/orchestrator.go` | `go test -v ./pkg/phases/...` | PASS (0 regressions) |
| Zero-Noise Gate (Pillar 3) | `pkg/verification/gate.go` | `go test -v ./pkg/verification -run TestZeroNoiseGate` | PASS (0 regressions) |
| Ecosystem Setup & Doctor (Pillar 4) | `cmd/mohammed/` | `go build ./cmd/mohammed` | PASS (Clean build) |
| API Schema Auditor | `pkg/phases/api_schema_auditor.go` | `go test -v ./pkg/phases -run TestAPISchemaAuditor` | PASS (0 regressions) |
| JS & Source Map Harvester | `pkg/phases/js_harvester.go` | `go test -v ./pkg/phases -run TestJSHarvester` | PASS (0 regressions) |
| Takeover Resolver | `pkg/phases/takeover_resolver.go` | `go test -v ./pkg/phases/...` | PASS (0 regressions) |
| Zero Catch-All Purge | `pkg/phases/surgical_probes.go` | `go test -v ./pkg/phases -run TestSurgicalProbesCatchAll` | PASS (0 regressions) |
| Deduplicated Port Scanner | `pkg/phases/light_portscan.go` | `go test -v ./pkg/phases -run TestLightPortScanPhase` | PASS (0 regressions) |
| Full Repository Suite | `cmd/...`, `pkg/...` | `go test ./...` | PASS (All 24 packages) |
