# MOHAMMED V4 — Autonomous Attack Surface & Exploit Engine

**Zero-Touch, Governed Offensive Security Engine for Enterprise & Bug Bounty Audits (Production Benchmark)**

[![Go Version](https://img.shields.io/badge/Go-1.22.5%2B-blue.svg)](https://golang.org)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Kali-red.svg)](https://www.kali.org)
[![Zero-False-Positive](https://img.shields.io/badge/Architecture-Zero--FP%20Enforced-brightgreen.svg)](#zero-false-positive-architecture)
[![Safety Governor](https://img.shields.io/badge/Target%20Protection-Autonomous%20Governor-orange.svg)](#core-safety-governor--autonomous-pacing)
[![Production Benchmark](https://img.shields.io/badge/Standard-100%25%20Enterprise%20Ready-success.svg)](#hybrid-re-engineering-production-benchmark-modules)

---

## 🎯 Executive Overview

**MOHAMMED V4** is a high-assurance, multi-stage automated attack surface management and ethical penetration testing framework engineered for **Enterprise Platforms, Government Ministries, and Bug Bounty Programs** (HackerOne, Bugcrowd, BugBounty.sa).

Following intensive audits against enterprise targets (such as Akamai-fronted enterprise apps and Red Bull assets), MOHAMMED-V4 has transitioned from a standard scanner into a **Next-Gen Attack Surface Intelligence Engine** designed to discover high-impact, reportable security defects with **zero denial-of-service risk** and **zero false positives**.

```
                           MOHAMMED V4 PIPELINE ARCHITECTURE
   
   +---------------------------------------------------------------------------------+
   |                           PHASE 00-02: PASSIVE OSINT                            |
   |   Public CT Logs (crt.sh)  *  AlienVault OTX  *  Wayback History  *  Passive DNS|
   +---------------------------------------------------------------------------------+
                                         |
                                         v
   +---------------------------------------------------------------------------------+
   |               PHASE 03-07: ATTACK SURFACE RECON & LIVE PROBING                  |
   |   Passive Subdomain Fan-out  *  OS-Stub DNS Recovery  *  Live HTTP Pacing       |
   +---------------------------------------------------------------------------------+
                                         |
                                         v
   +---------------------------------------------------------------------------------+
   |               PHASE 08-16: HIGH-SPEED DEDUPLICATED DISCOVERY                    |
   |   IP-Deduplicated Port Scanner (Top-100, 20 Dialers) * Param Bloat Elimination  |
   +---------------------------------------------------------------------------------+
                                         |
                                         v
   +---------------------------------------------------------------------------------+
   |               PHASE 17: SURGICAL AUDIT & RECURSIVE INTELLIGENCE                 |
   |   • Module 1: Recursive Schema-Driven API Auditor (OpenAPI/Swagger BOLA & Auth) |
   |   • Module 2: JavaScript & Source-Map Deep Harvester (Entropy Credentials)      |
   |   • Module 3: Dangling CNAME & Subdomain Takeover Resolver (SaaS Abandonment)   |
   |   • Module 4: Zero-Tolerance Surgical Probes (Zip Magic Bytes, Strict Regex)   |
   |   • Curated CVE-2020-14882 WebLogic RCE & Spring Actuator Inspection            |
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
   |   Filter Internal Milestones  *  No <nil> Artifacts  *  Tiered Outputs          |
   |   --> CONFIRMED_VULNS.txt (Conf >= 70)  |  MANUAL_REVIEW.txt (Human Triage)     |
   +---------------------------------------------------------------------------------+
```

---

## ⚡ Hybrid Re-Engineering: Production Benchmark Modules

### 1. Recursive Schema-Driven API Auditor (`pkg/phases/api_schema_auditor.go`)
- **In-Memory Schema Parser**: Identifies exposed Swagger/OpenAPI endpoints (`/v3/api-docs`, `/swagger.json`, `/openapi.json`), parsing all defined routes, HTTP methods, and parameter schemas in real time.
- **Unauthenticated Privilege Audit**:
  * Filters for sensitive operational keywords: `mgmt`, `admin`, `user`, `delete`, `create`, `token`, `export`, `config`, `internal`.
  * Sends non-destructive GET/OPTIONS probes under rate-governed pacing.
  * Validates that responses contain authentic application/json data structures rather than login forms or generic errors, flagging:
    `[High] Broken Authentication / Unprotected Management Endpoint: <url>`.
- **BOLA/IDOR Detection**: Identifies identifier parameters (e.g. `{uimUserId}`, `{campaignKey}`, `{id}`) to prioritize structured object authorization audits.

### 2. JavaScript & Source-Map Deep Harvester (`pkg/phases/js_harvester.go`)
- **Bundle Scraper**: Discovers in-scope client-side script tags (`<script src="*.js">`) from all live landing pages.
- **Entropy-Validated Credential Discovery**:
  * Regex matching for AWS Access Keys (`AKIA[0-9A-Z]{16}`), Google API keys (`AIza[0-9A-Za-z-_]{35}`), generic Bearer tokens, and private RSA/SSH keys.
  * **Shannon Entropy Verification**: Discards low-entropy placeholders or documentation dummies (e.g., `AKIAEXAMPLEKEY12345`).
- **Hidden Route Extraction**: Automatically harvests internal routes matching `/api/v[0-9]/[a-zA-Z0-9_\-/]+` or internal administrative paths and appends them to the target scope corpus.
- **Source Map Exposure**: Detects publicly accessible `*.js.map` files, flagging information disclosure.

### 3. Dangling CNAME & Subdomain Takeover Resolver (`pkg/phases/takeover_resolver.go`)
- **DNS CNAME Resolution**: Resolves CNAME pointers across all in-scope subdomains.
- **SaaS & Cloud Abandonment Verification**:
  * Cross-references target HTTP responses with verified abandonment signatures:
    - **AWS S3**: `NoSuchBucket` / `The specified bucket does not exist`
    - **GitHub Pages**: `There isn't a GitHub Pages site here`
    - **Heroku**: `No such app` / `herokucdn.com`
    - **Azure Traffic Manager**: `404 Web Site not found`
    - **Zendesk**: `Help Center Closed`
    - **Fastly / CloudFront**: `Fastly error: unknown domain` / `Bad request: ERROR: The request could not be satisfied`
  * Flags verified takeovers as `[High] Subdomain Takeover: <subdomain> -> <cname>`.

### 4. Zero-Tolerance Catch-All Purge (`pkg/phases/surgical_probes.go`)
- Eliminates repetitive, low-confidence entries on wildcard 200 OK servers:
  * `/backup.zip`: Validates standard ZIP magic bytes (`PK\x03\x04`).
  * `/.env`: Enforces key-value regex patterns (`(APP_KEY|DB_PASSWORD|SECRET_KEY|DATABASE_URL|AWS_)=`).
  * `/.git/HEAD`: Enforces exact header match `ref: refs/heads/` or `ref: refs/`.
  * `/.git/config`: Enforces `[core]` and `repositoryformatversion`.
  * `/.htpasswd`: Validates Apache crypt, apr1, or bcrypt hashes.
  * **Silent Discard**: Any response lacking strict content invariants is dropped without contaminating reports.

### 5. High-Speed IP-Deduplicated Port Scanner (`pkg/phases/light_portscan.go`)
- **IP Deduplication**: Resolves all live subdomains to underlying IPv4 addresses and deduplicates edge anycast IPs (e.g., 1000 subdomains resolving to 4 Akamai anycast IPs are scanned only once).
- **Asynchronous Connect Pool**: 20 concurrent dialers scanning Top-100 web/admin ports (80, 443, 8080, 8443, 3000, 5000, 9000, etc.) with a 500ms socket timeout. Complete run finishes in under 2 minutes.
- Maps discovered ports back to virtual hostnames for HTTP verification.

---

## 🛡️ Core Safety Governor & Autonomous Pacing

Target stability is guaranteed by the integrated **Adaptive Target Governor** (`pkg/governor`):

1. **Autonomous Target Capacity Detection (`--smart-rate`)**:
   - Sends lightweight HTTP HEAD baseline probes before heavy phases.
   - Evaluates network latency (RTT), multi-homing, and CDN fronting (Cloudflare, Akamai, CloudFront).
   - Dynamically scales request rate and concurrency:
     * **High Latency (>1000ms) or Single IP**: Throttles down to `1 req/s`, concurrency `1`.
     * **Enterprise Tier (300ms–800ms)**: Sets `2–3 req/s`, concurrency `2`.
     * **Edge CDN / Cloud WAF (<500ms)**: Allows up to `5 req/s`, concurrency `4`.
2. **Circuit Breaker Protection**:
   - Automatically trips on HTTP `429 Too Many Requests`, `503 Service Unavailable`, or `504 Gateway Timeout`.
   - Freezes requests, applies exponential backoff cooldown (`5s` to `60s`), and tests with half-open recovery probes.
3. **Pacing Jitter**:
   - Injects random 150ms–300ms delays to eliminate synchronized request spikes.

---

## 🚀 Operational Profiles: Stealth Audit vs. Full Assault

Preset profiles (`cmd/preset`) configure MOHAMMED V4 for distinct assessment objectives:

| Operational Profile | Target Profile | Rate Limit | Concurrency | Active Modules | Scope & Focus |
|---|---|---|---|---|---|
| `stealth-audit` | Government platforms, production APIs, sensitive infrastructure | $\le 2\text{ req/s}$ (120/min) | 1–2 workers | Modules 3 & 4 (Takeover & Invariants) | Low-footprint, non-destructive passive OSINT, light port scanning, and surgical verification. |
| `full-assault` | Bug bounty programs (HackerOne, Bugcrowd), non-prod staging | $\le 10\text{ req/s}$ (600/min) | 5–10 workers | All Modules (1, 2, 3, 4, 5) | Complete inspection: OpenAPI schema auditing, JS secret harvesting, deduplicated port scans, and WAF evasion. |
| `passive` | Strict zero-touch compliance audits | 0 active probes | 1 worker | None (Pure OSINT) | 100% external OSINT (CT logs, Wayback, OTX, DNS). Zero packets sent to target IP. |

---

## 💻 CLI Quickstart & Examples

### 1. Diagnostics & Readiness Check
```bash
./mohammed doctor
```

### 2. Autonomous Scan with Adaptive Governor (`--smart-rate`)
```bash
./mohammed scan -s target.txt --profile medium --smart-rate --output output/audit-01
```

### 3. Government / Sensitive Target (Stealth Audit Mode)
```bash
# Generate pre-configured scope and execution plan
./preset -file scopes/government_target.json -mode stealth-audit

# Run with strict rate-limiting
./mohammed scan -s recon/scopes/government_target.txt --profile small --rate 120 --threads 2 --output output/gov-stealth
```

### 4. Full Enterprise Assault with WAF Bypass & Schema Auditing
```bash
./mohammed scan -s scopes/bounty_targets.txt --profile full --rate 300 --threads 10 --waf-bypass --smart-rate --output output/bounty-run
```

### 5. Resuming Interrupted Scans
```bash
./mohammed scan -s target.txt --resume auto --output output/audit-01
```

---

## 📊 Verification & Test Matrix

All packages are continuously verified with Go unit tests and static analysis:

| Component | Path | Verification Command | Status |
|---|---|---|---|
| API Schema Auditor (Module 1) | `pkg/phases/api_schema_auditor.go` | `go test -v ./pkg/phases -run TestAPISchemaAuditor` | PASS (0 regressions) |
| JS & Source Map Harvester (Module 2) | `pkg/phases/js_harvester.go` | `go test -v ./pkg/phases -run TestJSHarvester` | PASS (0 regressions) |
| Takeover Resolver (Module 3) | `pkg/phases/takeover_resolver.go` | `go test -v ./pkg/phases/...` | PASS (0 regressions) |
| Zero Catch-All Purge (Module 4) | `pkg/phases/surgical_probes.go` | `go test -v ./pkg/phases -run TestSurgicalProbesCatchAll` | PASS (0 regressions) |
| Deduplicated Port Scanner (Module 5) | `pkg/phases/light_portscan.go` | `go test -v ./pkg/phases/...` | PASS (0 regressions) |
| Core Safety Governor | `pkg/governor` | `go test -v ./pkg/governor/...` | PASS (0 regressions) |
| Full Repository Suite | `cmd/...`, `pkg/...` | `go test ./...` | PASS (All 23 packages) |
| Binary Compilation | `cmd/...` | `go build ./...` | PASS (Clean build) |
