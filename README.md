# MOHAMMED V4 — Autonomous Attack Surface & Exploit Engine

**Zero-Touch, Governed Offensive Security Engine for Enterprise & Bug Bounty Audits**

[![Go Version](https://img.shields.io/badge/Go-1.22.5%2B-blue.svg)](https://golang.org)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Kali-red.svg)](https://www.kali.org)
[![Zero-False-Positive](https://img.shields.io/badge/Architecture-Zero--FP%20Enforced-brightgreen.svg)](#zero-false-positive-architecture)
[![Safety Governor](https://img.shields.io/badge/Target%20Protection-Autonomous%20Governor-orange.svg)](#core-safety-governor--autonomous-pacing)

---

## 🎯 Executive Overview

**MOHAMMED V4** is a high-assurance, multi-stage automated penetration testing and attack surface mapping framework engineered specifically for **Enterprise Platforms, Government Ministries, and Bug Bounty Programs** (HackerOne, Bugcrowd, BugBounty.sa).

Unlike legacy scanning tools that generate overwhelming false-positive noise, hammer sensitive production servers, or crash due to orphaned subprocesses, MOHAMMED V4 couples **deep OSINT and surgical active checks** with an **autonomous safety governor**, **strict baseline token verification**, and **AI-assisted report sanitization**.

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
   |                   PHASE 08-16: ASSET PRIORITIZATION & DISCOVERY                 |
   |   Staging/Internal Asset Float  *  Top-100 Diagnostic Ports  *  Param Filter    |
   +---------------------------------------------------------------------------------+
                                         |
                                         v
   +---------------------------------------------------------------------------------+
   |               PHASE 17-45: SURGICAL EXPLOIT & CURATED INSPECTION                |
   |   Exact Token Signature Check  *  CVE-2020-14882 WebLogic  *  Deep Cloud/Auth   |
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

## 🛡️ Core Safety Governor & Autonomous Pacing

Target stability is guaranteed by the integrated **Adaptive Target Governor** (`pkg/governor`):

1. **Autonomous Target Capacity Detection (`--smart-rate`)**:
   - Sends lightweight HTTP HEAD baseline probes before heavy phases.
   - Evaluates network latency (RTT), multi-homing, and CDN fronting (Cloudflare, Akamai, CloudFront).
   - Dynamically scales request rate and concurrency:
     * **High Latency (>1000ms) or Single IP**: Throttles down to `1 req/s`, concurrency `1`.
     * **Enterprise Tier (300ms–800ms)**: Sets `2–3 req/s`, concurrency `2`.
     * **Edge CDN / Cloud WAF (<400ms)**: Allows up to `5 req/s`, concurrency `4`.
2. **Circuit Breaker Protection**:
   - Automatically trips on HTTP `429 Too Many Requests`, `503 Service Unavailable`, or `504 Gateway Timeout`.
   - Freezes requests, applies exponential backoff cooldown (`5s` to `60s`), and tests with half-open recovery probes.
3. **Pacing Jitter**:
   - Injects random 200ms–400ms delays to eliminate synchronized request spikes.

---

## 🔬 Zero-False-Positive Architecture

Every finding must clear rigorous validation before it can be reported:

- **Strict Non-Empty Signatures**:
  * Vulnerability templates in `pkg/phases/curated_templates.go` enforce mandatory, non-empty response tokens (`RequiredSig`).
  * Empty signatures never match universally on HTTP 200 OK responses (preventing false alarms on custom health endpoints).
- **Dynamic Soft-404 Calibration**:
  * Probes non-existent randomized paths (`/.calib-<uuid>`) to establish content length baseline, status codes, and body hashes.
- **Exact Token & Regex Validation**:
  * `.env` files require `APP_KEY=` or `DB_PASSWORD=`.
  * `.git` exposure requires `[core]` or `ref: refs/heads/`.
  * Spring Actuator endpoints require valid structured JSON `{"status":"UP"}`.
- **Report Hygiene & Sanitization**:
  * Eliminates `<nil>` tool and title artifacts in `final_report.md` and `MANUAL_REVIEW.txt`.
  * Filters out internal pipeline progress milestones (Target Classification, Autonomous Bootstrap) from vulnerability tables.

---

## 🚀 Operational Profiles: Stealth Audit vs. Full Assault

Preset profiles (`cmd/preset`) configure MOHAMMED V4 for distinct assessment objectives:

| Operational Profile | Target Profile | Rate Limit | Concurrency | WAF Bypass | Scope & Focus |
|---|---|---|---|---|---|
| `stealth-audit` | Government platforms, production APIs, sensitive infrastructure | $\le 2\text{ req/s}$ (120/min) | 1–2 workers | Off (Safe passive) | Low-footprint, non-destructive passive OSINT, light port scanning, and surgical verification. |
| `full-assault` | Bug bounty programs (HackerOne, Bugcrowd), non-prod staging | $\le 10\text{ req/s}$ (600/min) | 5–10 workers | Active matrix enabled | Complete 65+ phase inspection, active fuzzing, differential response testing, and curated CVE templates. |
| `passive` | Strict zero-touch compliance audits | 0 active probes | 1 worker | Off | 100% external OSINT (CT logs, Wayback, OTX, DNS). Zero packets sent to target IP. |

---

## 💻 CLI Quickstart & Examples

### 1. Verification & Diagnostics

Run doctor to verify tools, path bindings, and environment readiness:
```bash
./mohammed doctor
```

### 2. Autonomous Scan with Adaptive Governor (`--smart-rate`)

Scan an enterprise target with automatic capacity sensing and safety gating:
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

### 4. Full Bounty Assault with WAF Bypass

```bash
./mohammed scan -s scopes/bounty_targets.txt --profile full --rate 300 --threads 10 --waf-bypass --output output/bounty-run
```

### 5. Resuming Interrupted Scans

```bash
# Auto-detect latest checkpoint and resume
./mohammed scan -s target.txt --resume auto --output output/audit-01

# Run only specific phases (e.g. phases 17 to 25)
./mohammed scan -s target.txt --only 17,18,19,20,21,22,23,24,25 --output output/audit-01
```

---

## 📊 Verification & Test Matrix

All packages are continuously verified with Go unit tests, race detector, and static analysis:

| Component | Path | Verification Command | Status |
|---|---|---|---|
| Safety Governor | `pkg/governor` | `go test -v ./pkg/governor/...` | PASS (0 regressions) |
| Curated Templates & Checks | `pkg/phases` | `go test -v ./pkg/phases/...` | PASS (0 regressions) |
| Report Generator & Exporter | `pkg/report` | `go test -v ./pkg/report/...` | PASS (0 regressions) |
| Zero-Touch Passive OSINT | `pkg/osint` | `go test -v ./pkg/osint/...` | PASS (0 regressions) |
| Baseline & Token Validator | `pkg/validation` | `go test -v ./pkg/validation/...` | PASS (0 regressions) |
| Full Repository Compilation | `cmd/...`, `pkg/...` | `go build ./...` | PASS (Clean build) |

---

## 📁 Report Artifacts

When a scan finishes, output files are generated in the specified `--output` directory:

- `CONFIRMED_VULNS.txt`: Validated vulnerabilities with confidence $\ge 70$ and HTTP/AI confirmation. Ready for immediate vulnerability submission.
- `MANUAL_REVIEW.txt`: Findings requiring human triage (confidence 40–69 or offline confirmation). Internal milestones and `<nil>` artifacts are strictly excluded.
- `final_report.md`: Complete executive summary table and categorized technical details.
- `final_report.json`: Machine-readable structured JSON format for SIEM or automated ticketing integration.
- `checkpoint.json`: Real-time state preservation allowing seamless recovery with `--resume`.
