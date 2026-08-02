# AIReconForge — v17 Zero-FP Rebuild (Burp Suite Extension)

A complete, ground-up rewrite of AIReconForge. The old version keyword-grepped
responses and reported everything, producing a **100% false-positive rate**.
This rebuild replaces that with a strict, sequential **5-gate pipeline**: a
candidate finding must pass **every gate** or it is **DROPPED**. Nothing is ever
reported on a single observation or a keyword match.

- **Language / build:** Java (compiled & tested on **JDK 21**; targets Java 17+)
- **API:** PortSwigger **Montoya API** (`montoya-api-2026.7`), Burp Suite 2024+
- **Products:** Works in **Burp Pro and Community** (SSRF OOB checks auto-disable
  when Collaborator is unavailable — SSRF is then *dropped*, never guessed).

## Load it into Burp

1. Burp → **Extensions** → **Installed** → **Add**
2. Extension type: **Java**
3. Select **`AIReconForge.jar`**
4. Two tabs appear: **Detection (5-Gate)** and **Traffic SmartCapture**.

## The 5-Gate Detection Engine

Every proxied response runs, on a **background thread**, through:

| Gate | Purpose | Drop condition (examples) |
|------|---------|---------------------------|
| **0 — Request Qualification** | Kill noise before probing | static assets, `/docs`, `/health`, status 404/405/410/429/5xx, image/font/video/pdf content-types. **KEEP** only if it has params / is POST-PUT-DELETE-PATCH / matches `/api`,`/v1-3`,`/graphql`,`/oauth`,`/auth`,`/login`,`/admin` / has auth headers / JSON-XML body. |
| **1 — Baseline Response Diff** | Prove the payload *did* something | re-send clean request, diff vs suspicious; **< 5% ⇒ DROP**. Timestamps / CSRF / nonce / session / UUID values are normalized out first. |
| **2 — Vuln-Specific Verification** | Active proof, not a guess | **XSS**: unique canary reflected *unencoded* in a dangerous context. **SQLi**: `SLEEP(5)` delta ≥ 4s confirmed twice **+** boolean `1=1`/`1=2` diff. **IDOR**: single session ⇒ Info "manual" only, **never** Critical/High. **SSRF**: OOB callback within 10s or **DROP**. **Open Redirect**: 3xx `Location` to attacker host. **CORS**: ACAO reflects evil origin **and** ACAC:true (wildcard-without-creds is *not* a vuln). **Race**: manual/Info only. |
| **3 — Context & Impact** | Right-size severity | public/unauth ⇒ max Info-Low; search/filter param ⇒ max Low; static HTML XSS ⇒ drop/self-XSS ⇒ Info. |
| **4 — Dedup & Confidence (0-100)** | One clean report each | dedup on **URL + Method + Param + VulnType**; report only **≥ 50**; **50-69 = "Needs Manual Verification"**; **< 50 DROP**. |

Confirmed findings show in the **Detection** tab *and* as Burp audit issues
(Dashboard/Site map), tagged with their confidence band.

## Traffic SmartCapture (separate tab)

Captures meaningful proxy traffic and filters out static assets, 404/410, docs,
health, duplicates, browser-internal schemes and static-CDN hosts.

- **Real-time counter:** `Captured | Filtered | Unique`
- **Buttons:** Start / Stop / Export / Clear
- **Table:** `# · Method · URL · Status · Content-Type · Size · Time`
- **Right-click:** Send to Repeater, Send to Intruder, Copy URL, Copy Full Request
- **Export** writes 10 categorized files to `~/traffic_export_YYYY-MM-DD_HH-MM/`:
  1. `01_api_endpoints.txt`
  2. `02_auth_and_sessions.txt`
  3. `03_forms_and_inputs.txt`
  4. `04_parameters_map.txt`
  5. `05_interesting_responses.txt`
  6. `06_redirects.txt`
  7. `07_unique_hosts.txt`
  8. `08_technology_fingerprint.txt`
  9. `09_full_traffic.json`
  10. `10_summary_report.md`

## Architecture / safety

- All analysis runs on a bounded background pool (**never** the proxy/UI thread).
- **Bounded capture queue** (max **50,000**; oldest records flush to a spill file beyond the cap — memory can't blow up).
- **10s hard timeout** on every verification request.
- **Global rate limiter: ≤ 10 req/s** across all active checks (token bucket).
- All regexes are **pre-compiled `static final Pattern`**; comparisons are **case-insensitive**.
- **Catch-all error handling** everywhere — the extension can never crash Burp.

## Build from source

```bash
javac -d build -cp montoya-api-2026.7.jar src/aireconforge/AIReconForge.java
mkdir -p build/META-INF/services
echo aireconforge.AIReconForge > build/META-INF/services/burp.api.montoya.BurpExtension
( cd build && jar --create --file ../AIReconForge.jar . )
```

## Tests

- **`test/LogicTest.java`** — pure-logic unit tests (rate limiter throttling,
  volatile-token-aware diff ratio, dedup key identity, confidence bands): **10/10 PASS**.
- **ServiceLoader load test** — confirms Burp's discovery mechanism finds exactly
  one `BurpExtension` and that `initialize(MontoyaApi)` is present.
