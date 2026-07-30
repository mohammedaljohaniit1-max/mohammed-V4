# Responsible Disclosure Policy — MOHAMMED V12.1 ZERO-TOLERANCE

> **"Knock, don't break in."**
> MOHAMMED is an authorized-testing / bug-bounty automation engine. It is
> engineered to **PROVE** a vulnerability exists, never to weaponize it. Every
> engine in this project is bound by the four rules below, and — critically —
> those rules are **enforced in code**, not merely documented here.

Only run MOHAMMED against targets you are **explicitly authorized** to test
(a signed engagement, a written pentest authorization, or a bug-bounty program
whose scope explicitly includes the asset). Unauthorized scanning is illegal.

---

## RULE 1 — PROVE, DON'T EXPLOIT

Every exploit engine must *confirm* a vulnerability and then **STOP**. It must
never run a destructive, data-exfiltrating, or state-corrupting payload.

| Vulnerability class | Allowed proof (and nothing more) |
|---------------------|----------------------------------|
| **RCE**             | Time-based delay (`sleep`) **or** an out-of-band DNS callback → STOP |
| **SQL Injection**   | Database error signature **or** time-based delay → STOP |
| **Path Traversal**  | Read `/etc/hostname` only → STOP |
| **SSRF**            | DNS/HTTP callback to a controlled OOB canary → STOP |
| **XSS**             | `alert(document.domain)` only → STOP |

**Code enforcement:** `pkg/exploit/boundary.go` implements the Proof-of-Exploit
(PoE) engine. It ships a `denyDestructivePayload()` safety net that hard-refuses
known destructive markers (`whoami`, `/etc/passwd`, `union select …`,
`document.cookie`, `id_rsa`, `.env`, …). Every detector returns a strict
`Verdict` enum — `CONFIRMED_SAFE_PoC`, `CONFIRMED_NEEDS_MANUAL_REVIEW`, or
`NOT_VULNERABLE` — and never anything that requires having caused damage.

---

## RULE 2 — IN-SCOPE ONLY

Every request must pass an `IsInScope()` check **before** it is sent.
Out-of-scope discoveries are recorded to `out_of_scope_urls.txt` **only** and are
never actively probed.

**Code enforcement:** `pkg/filter.IsInScope()` gates the URL corpus, and the
5-gate validator (`pkg/validation`) uses it as its Gate-4 scope oracle, so no
finding can be stored for an out-of-scope asset.

---

## RULE 3 — NO PERSISTENCE

Never create files, accounts, or database entries on the target that cannot be
cleaned up. When the autonomous bootstrapper registers throwaway test accounts
(for BOLA/multi-tenant testing), every created account is logged to
`output/test_accounts_created.txt` so the operator can notify the program and
request cleanup.

**Code enforcement:** `pkg/exploit/autobootstrap.go` appends a timestamped line
(role, URL, username, email, password) to `test_accounts_created.txt` for every
account it creates.

---

## RULE 4 — RATE LIMITS ARE LAW

Even with the `--waf-bypass` flag enabled, MOHAMMED **never exceeds 10 requests
per second to any single host.** WAF evasion is about *shape*, not *volume*.

**Code enforcement:** `pkg/engine.NewBypassEngine()` clamps `max_rps_per_host`
to a hard ceiling of `10` and derives every bypass plan's minimum inter-request
delay from that floor. Behavioral-WAF plans (DataDome/PerimeterX/Arkose) use an
even slower, human-like 1.2 s–4.7 s jitter. The shared adaptive stealth governor
(`pkg/exploit.StealthGovernor`) additionally backs off on 429/503/403.

---

## Secret Weapon PoE boundaries (V12.0 OMEGA)

The five V12.0 OMEGA **Secret Weapons** (Phases 61-65) are pure-Go discovery and
exploit-reasoning engines. They surface *more* attack surface and *more*
candidates than any prior version — but they are bound by exactly the same four
rules above. None of them ever weaponizes a finding; each one PROVES and STOPS.

| Secret Weapon | What it does | PoE boundary (proof, and nothing more) |
|---------------|--------------|----------------------------------------|
| **#1 API Hunter** (`pkg/exploit/api_hunter.go`) | Classifies endpoints (AUTH/DATA/MONEY/ADMIN/OAUTH) and runs the right attack sequence per class. | MONEY/ADMIN probes are **read-only / observation-only** — it reads status + shape differentials, never submits a purchase, transfer, or destructive admin action. |
| **#2 Response Differential** (`pkg/exploit/differential.go`) | Cross-context **structural** JSON diff for BOLA/IDOR, ignoring timestamps / session IDs / CSRF tokens. | Compares responses across identities the operator already authorized; it reads other-tenant *shape*, never exfiltrates or mutates another user's records. |
| **#3 Smart Fuzz** (`pkg/exploit/smart_fuzz.go`) | WAF-adaptive mutation (baseline→probe→adapt) with optional Ollama-brain escalation. | **Stops at the first confirmed Proof-of-Exploit** — it fires no further payloads once a candidate is confirmed, and never escalates a confirmed XSS/SQLi/SSRF beyond the RULE 1 safe proof. |
| **#4 JS Deep** (`pkg/exploit/js_deep.go`) | Mines JavaScript for endpoints / admin / secrets / WS / GraphQL / S3 / source-maps; Shannon-entropy gated (rejects entropy < 3.5). | It **reports** discovered secrets/endpoints for manual review; it does **not** authenticate with a discovered credential or hit a discovered admin route. In-scope enforcement (`enforce_scope_on_js`) means only in-scope JS is mined. |
| **#5 Subdomain Intel** (`pkg/exploit/subdomain_intel.go`) | Functional grouping (production / staging-dev / internal / infra), staging-vs-prod diff, Wayback history. | Wayback dead-host takeover findings are surfaced as **candidates for manual verification** — it never claims or registers a dangling resource. It only reads publicly-archived (CDX) data and in-scope response headers. |

**Code enforcement:** every candidate a Secret Weapon surfaces is routed through
`storeCandidate()` into the same 5-gate false-positive validator
(`pkg/validation`), so Gate-4 scope and Gate-3 exploitability still apply, and
the Cloudflare-error / TLS-mismatch demotions from V12.0 (BUGS #2 & #3) keep
report noise out. Each weapon also honours a per-scan **budget**
(`secret_weapons.*_budget` in `config.yaml`) so no weapon can turn into a
high-volume, rate-abusing phase. Every weapon can be disabled independently via
its `secret_weapons.*` toggle.

## New-tool PoE boundaries (V12.1 ZERO-TOLERANCE)

The six modern tools added in V12.1 obey the same four rules and stop at proof:

| Tool | PoE boundary (proof, and nothing more) |
|------|----------------------------------------|
| **chaos / uncover** | Passive, read-only host discovery from public datasets; every host is scope-filtered (`parseHostLines`) before entering the corpus. No active probing occurs here. |
| **alterx** | Generates candidate hostnames only; candidates are **DNS-resolved** (dnsx) before use — no live host is ever assumed to exist. |
| **cariddi** | Extracts endpoints/secrets from responses the crawler already fetched in-scope; secrets are **reported for manual review**, never used to authenticate. |
| **trufflehog** | Scans only the scan's own output folder (in-scope artifacts). A **verified** secret is reported at Critical with the value redacted — MOHAMMED never re-uses the credential against the provider; trufflehog's own verification is the proof. |
| **ppmap** | Confirms a prototype-pollution sink and **stops** — it does not chain the pollution into RCE/XSS. |
| **cdncheck** | Pure passive classification of edge/CDN ownership; used only to *demote* smuggling findings (reduce risk), never to attack. |

---

## CAPTCHA & anti-bot handling (V11.0, FLAW #1)

MOHAMMED does **not** attempt to defeat CAPTCHAs on registration/login surfaces.
When the autonomous bootstrapper detects a CAPTCHA gate (`g-recaptcha`,
`h-captcha`, Cloudflare Turnstile, Arkose FunCaptcha), it logs
`CAPTCHA_BLOCKED — skipping autobootstrap on {host}`, sets the auth context to
`nil`, and falls back to unauthenticated testing — surfacing the limitation
clearly instead of silently failing.

---

## Reporting

Confirmed findings are auto-rendered into HackerOne-ready markdown reports at
`output/{target}/reports/{vuln_id}_h1_report.md` (Summary · Steps to Reproduce ·
Impact · Proof of Concept · Severity with CVSS 3.1 vector · Remediation). Review
every report and its non-destructive PoC before submitting it to a program.

_Use MOHAMMED ethically. The boundary is not optional — it is the product._
