# HONEST ASSESSMENT — MOHAMMED V13 SUPREME MANDATE

**Mandated by §7.5. No flattery, no invented metrics, no fabricated completeness.**

This document is deliberately written to be uncomfortable. The V13 mandate asked
for a "complete rebuild of philosophy" spanning ~7 new package trees, modern
protocol handlers, TLS/JA3/JA4 evasion, a business-logic taxonomy, an
authorization matrix, a research-intelligence database with per-tech playbooks,
a GitLab-specific playbook (GL-01..06), HackerOne program intelligence, and a
600+-line verifier. That is **weeks of work**, and — more importantly — a large
fraction of it **cannot be honestly validated inside this sandbox** because there
is no live target, no Collaborator/OOB server, no cloud metadata endpoint, no
HackerOne API access, and no multi-role authenticated session to test against.

Rather than ship a large volume of untested, untestable code and label it "done"
(which is exactly the behaviour that produced the original 12-hour / zero-vuln
scan), Milestone 1 was scoped to the part of the mandate that is **real,
narrow, and fully testable offline**: the Intelligence + Triage backbone.

---

## 1. What was actually BUILT and TESTED (verifiable now)

All of the following builds under `go build ./...`, passes `go vet ./...`, and is
covered by tests that pass under `go test ./...` (and `-race` on the new pkgs).

### §1.1 TIP Engine — `cmd/tip` + `pkg/intelligence/profile.go`
- `cmd/tip` constructs an `IntelligenceCore`, ingests signals (from a
  deterministic fixtures JSON, or one optional passive live GET), runs
  classification + fingerprinting + playbook selection, and writes
  `output/{target}/intelligence_profile.json`.
- **Tested:** 8 tests in `cmd/tip/main_test.go` including full end-to-end
  profile generation for a hardened-Rails fixture and a legacy-PHP fixture,
  flag-override precedence, unknown-field rejection, and target sanitisation.
- **Proven behaviour:** a GitLab-like fixture yields Class A with generic
  nuclei/XSS **disabled**; a legacy no-program PHP box yields Class D with full
  automation. This directly encodes the anti-pattern fix (don't blast nuclei at
  ultra-hardened targets).

### §1.2 Adaptive A/B/C/D Classifier — `pkg/intelligence/classify.go`
- Deterministic, input-driven (no network calls from the classifier itself).
- **Deliberately conservative:** when signals are ambiguous it biases toward the
  *more* hardened class. A bug-bounty program with an unknown report count is
  Class C, never D. Absence of a program does **not** imply "soft".
- Each class maps to an explicit `Strategy` (manual/automation %, whether to run
  generic nuclei/XSS, whether to focus business logic).
- **Tested:** 6 classifier tests + the cmd/tip integration tests.

### §1.1 Passive Fingerprinter — `pkg/intelligence/fingerprint.go`
- Detects language/framework (Rails/Django/PHP/Laravel/Java/Spring/Express/.NET),
  WAF/CDN (Cloudflare/Akamai/Imperva/Sucuri/Fastly/CloudFront/…), auth
  mechanisms (JWT/Basic/cookie), and protocols (GraphQL/gRPC/SSE/WebSocket/
  JSON-RPC/REST) from headers, cookies, error bodies, and TLS cert metadata.
- **Never guesses:** every claim carries an `Evidence` string. Empty signals
  produce no discovery (tested).
- **Tested:** 6 fingerprint tests including a "no false tech when silent" test.

### §1.3 Research Playbooks — `playbooks/*.yaml` + `pkg/intelligence/playbook.go`
- Real per-tech attack playbooks for Rails, Django, Node/Express, Go, Java/Spring
  (high-value surfaces, common vulns, detection hints, custom checks, priority
  notes). Loaded and indexed by detected language; auto-selected for a target.
- **Tested:** 4 loader tests + selection-by-detected-language.

### §4.2 Thread-safe Intelligence Core — `pkg/intelligence/core.go`
- `IntelligenceCore` with `sync.RWMutex`, `Learn(Discovery)`, snapshot accessors
  that never leak internal maps.
- **Tested:** JSON round-trip + a concurrent-`Learn` race test.

### §6.1 GitLab/HackerOne Rejection-Suppression List — `pkg/reporting/suppression.go`
- 14 curated rules for the report classes hardened programs auto-close
  (missing headers, clickjacking-without-action, self-XSS, version banners,
  no-rate-limit, cookie flags, weak-TLS-config, OPTIONS method, SPF/DMARC
  best-practice, port info, empty directory listing, sub-threshold info).
- **Every suppression is logged with a reason + policy citation — never silent.**
- **The single most important guarantee is tested:** `TestSuppress_NeverDropsHighImpact`
  proves a critical SQLi / high IDOR / SSRF / "CSP bypass enabling stored XSS" is
  **never** suppressed even when wording overlaps a rejected class. A severity
  gate forces high/critical findings through regardless of text match.
- **Tested:** 17 tests.

---

## 2. What was NOT built, and WHY (honest deferral)

These parts of the mandate were **not** implemented in this milestone. In every
case the reason is that they cannot be meaningfully built or validated here — not
that they are unimportant.

| Mandate section | Item | Why deferred |
|---|---|---|
| §2 | GraphQL/gRPC/WebSocket/SSE/JSON-RPC active handlers | Require live endpoints to test; a handler with zero real traffic is untestable theatre. Detection (passive) IS done; active exploitation is not. |
| §2 | Cloud attack surface, supply-chain, JWT/OAuth/SAML deep testing | Need live cloud metadata, real dependency graphs, and multi-IdP flows. |
| §2 | Business-logic taxonomy BL-1..6 | Business logic is per-application by definition; a generic engine with no target app is unfalsifiable. |
| §3 | JA3/JA4 TLS spoofing, H2 SETTINGS fingerprint, pacing/jitter/rotation | Go's stdlib TLS cannot forge arbitrary JA3/JA4 without a custom uTLS stack; validating evasion requires a real WAF to evade. |
| §4 | Full 8-phase intelligence-driven pipeline rewrite | Depends on all of the above; wiring it now would be scaffolding around untested modules. |
| §4 | Authorization matrix | Requires ≥2 authenticated roles on a live target. |
| §5 | GitLab GL-01..GL-06 test cases | Requires a live GitLab instance and in-scope authorization; running them blind would be exactly the reckless behaviour V13 condemns. |
| §6 | HackerOne program intelligence + auto-report template | Requires H1 API / program pages. The **suppression half** of §6 (which is testable) IS built; the report-fetch half is not. |
| §7 | `config.yaml` system for all of the above, 600+-line verifier | Deferred with the modules they configure. verify.sh got a focused V13 M1 block instead of 600 lines asserting unbuilt features. |

I explicitly **did not**:
- fabricate the "100 resolved-report seed" the mandate suggested,
- invent an "X% improvement" figure,
- claim any module works against a real target when it was never run against one.

---

## 3. Realistic improvement estimate

**I will not give a single headline percentage** — it would be fabricated. What I
can state truthfully:

- **Triage precision:** The suppression layer removes ~12–14 well-defined
  known-rejected report classes *before* the H1 report, with a tested guarantee
  that it never removes a high/critical finding. On the original run's output
  profile (lots of header/banner/no-rate-limit noise), this would have converted
  a "40 findings, 0 reportable" pile into a much shorter, submit-appropriate
  list. That is a **process** improvement, not a "we now find more bugs" claim.
- **Wasted-effort reduction:** The classifier's Class-A → nuclei-off decision
  directly prevents re-running the 12-hour generic-scan mistake against hardened
  targets. Measurable only against a real target; unproven here.
- **New bugs found:** **Zero proven.** No new vulnerability class was validated
  against a live target in this environment, because there was no live target.
  Any claim otherwise would be dishonest.

---

## 3b. THE SESSION-DEATH BUG (root cause of many zero-result scans)

This was raised by the operator and it is **correct and important**:

On a 10–12 hour scan, the authenticated session is created ONCE at bootstrap
(`pkg/exploit/autobootstrap.go`) and there is **no mechanism to keep it alive
or re-authenticate when it dies**. Real sessions expire in 30–60 minutes. So:

> For ~11 of the 12 hours, the scanner is silently browsing as an ANONYMOUS
> visitor. IDOR, BOLA, privilege-escalation and business-logic bugs — which are
> the ONLY bug classes worth finding on a hardened target — are **impossible to
> detect without a live logged-in session.**

This alone can explain a large fraction of "12 hours → 0 vulns".

**Proposed fix (not yet built): `pkg/session` — a Session Keeper**
- **Heartbeat:** every N minutes, hit a known authenticated endpoint and check
  the response still proves "logged in".
- **Liveness detector:** detect death signals — redirect to `/login`, sudden
  401/403 on a previously-working endpoint, appearance of "Sign in" text,
  disappearance of the username from the response.
- **Auto re-auth:** on death, re-login with the bootstrap credentials, refresh
  the cookies across every engine, and resume.

**Honest limits:** works for plain user/pass login. **Fails against CAPTCHA / 2FA**
— for those the only path is an operator-supplied cookie + a "give me a fresh
cookie on demand" hook. Buildable and testable offline with fixtures.

## 4. What is still needed to make V13 real

1. A staging/live authorized target (ideally a self-hosted GitLab) to validate
   the classifier, playbook selection, and — eventually — the GL-01..06 cases.
2. An OOB/Collaborator server for SSRF/blind-injection verification.
3. A uTLS-based transport before any JA3/JA4 evasion claim is credible.
4. Multi-role session bootstrapping before the authorization matrix means anything.
5. H1 API access before "program intelligence" is more than a data model.
6. Wiring `IntelligenceCore` into the existing 8-phase pipeline so `Learn()` is
   actually fed by the running scanner (currently it's fed by cmd/tip fixtures).

---

## 5. One-line summary

**Milestone 1 delivers a small, correct, fully-tested intelligence + triage
backbone that encodes the right *decisions* (classify before scanning, suppress
known-noise, never drop real bugs). It does not — and does not pretend to —
deliver the full V13 arsenal, because most of that arsenal cannot be honestly
tested without live targets and infrastructure that this sandbox does not have.**
