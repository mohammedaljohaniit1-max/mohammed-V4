# Responsible Disclosure Policy — MOHAMMED V11.0 FINAL SOVEREIGN

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
