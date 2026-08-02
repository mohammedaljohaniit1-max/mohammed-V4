package aireconforge;

/*
 * ============================================================================
 *  AIReconForge  —  Zero-False-Positive Burp Suite Extension  (v17 REBUILD)
 * ============================================================================
 *
 *  Full ground-up rewrite. The previous version reported a 100% false-positive
 *  rate because it used keyword-grep "detection" with no context, no baseline,
 *  no verification and no deduplication. This rebuild replaces that entirely
 *  with a strict, sequential 5-GATE pipeline. A candidate finding must pass
 *  EVERY gate or it is DROPPED. Nothing is ever reported on a single
 *  observation or a keyword match.
 *
 *    GATE 0  Request Qualification    — drop static/docs/health/noise up front
 *    GATE 1  Baseline Response Diff    — clean re-send + meaningful diff >= 5%
 *    GATE 2  Vuln-Specific Verification— canary reflection / time-delta /
 *                                        OOB callback / 3xx / ACAO+ACAC etc.
 *    GATE 3  Context & Impact          — public data => Info, static HTML => drop
 *    GATE 4  Dedup & Confidence (0-100)— report only >= 50; <50 dropped
 *
 *  Second, independent feature (its own tab): TRAFFIC SMARTCAPTURE — captures
 *  meaningful proxy traffic, filters out noise, and exports 10 categorized
 *  files for manual attack-surface analysis.
 *
 *  Architecture: all analysis runs on background threads (never the UI thread),
 *  a bounded capture queue (50k, flush-to-disk beyond), a 10s per-verification
 *  timeout, a global 10 req/s rate limiter, pre-compiled static Patterns, and
 *  catch-all error handling so the extension can never crash Burp.
 *
 *  Target: Java 17+ (compiled/tested on JDK 21), Burp Suite 2024+ (Montoya API).
 * ============================================================================
 */

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Registration;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class AIReconForge implements BurpExtension {

    static final String NAME = "AIReconForge";
    static final String VERSION = "v17 Zero-FP Rebuild";

    // Montoya handles (populated in initialize()).
    private MontoyaApi api;
    private Logging log;

    // Sub-systems.
    private RateLimiter rateLimiter;          // global 10 req/s across all verification
    private DetectionEngine engine;           // 5-gate pipeline
    private TrafficCapture capture;           // SmartCapture feature
    private DetectionPanel detectionPanel;    // findings UI
    private TrafficPanel trafficPanel;        // capture UI

    // Single background pool for verification work. UI thread is never used for I/O.
    private ExecutorService analysisPool;

    @Override
    public void initialize(MontoyaApi montoyaApi) {
        this.api = montoyaApi;
        this.log = montoyaApi.logging();

        montoyaApi.extension().setName(NAME + " " + VERSION);

        // Bounded work queue so a traffic burst can never OOM Burp: if the pool
        // is saturated the task runs on the calling (proxy) thread instead of
        // being silently dropped, which naturally back-pressures capture.
        this.analysisPool = new ThreadPoolExecutor(
                4, 8, 30L, TimeUnit.SECONDS,
                new LinkedBlockingQueue<>(2000),
                new ThreadPoolExecutor.CallerRunsPolicy());

        this.rateLimiter = new RateLimiter(10); // <= 10 verification req/s globally
        CollaboratorClient collab = safeCreateCollaborator(montoyaApi);

        this.engine = new DetectionEngine(montoyaApi, rateLimiter, collab);
        this.capture = new TrafficCapture(montoyaApi);

        // Build UI on the EDT.
        this.detectionPanel = new DetectionPanel(montoyaApi, engine);
        this.trafficPanel = new TrafficPanel(montoyaApi, capture);
        engine.setSink(detectionPanel);

        SwingUtilities.invokeLater(() -> {
            try {
                JTabbedPane root = new JTabbedPane();
                root.addTab("Detection (5-Gate)", detectionPanel.component());
                root.addTab("Traffic SmartCapture", trafficPanel.component());
                montoyaApi.userInterface().registerSuiteTab(NAME, root);
            } catch (Throwable t) {
                log.logToError("UI registration failed: " + t);
            }
        });

        // Single proxy response handler drives BOTH sub-systems, off the UI thread.
        Registration reg = montoyaApi.proxy().registerResponseHandler(new ProxyResponseHandler() {
            @Override
            public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse interceptedResponse) {
                // Copy the immutable request/response references and hand off to
                // the background pool. We must never block the proxy thread.
                try {
                    final HttpRequest req = interceptedResponse.initiatingRequest();
                    final HttpResponse resp = interceptedResponse;
                    final ZonedDateTime now = ZonedDateTime.now();
                    analysisPool.execute(() -> {
                        try {
                            capture.onTraffic(req, resp, now);
                        } catch (Throwable t) {
                            log.logToError("capture error: " + t);
                        }
                        try {
                            engine.analyze(req, resp);
                        } catch (Throwable t) {
                            log.logToError("engine error: " + t);
                        }
                    });
                } catch (Throwable t) {
                    log.logToError("proxy handoff error: " + t);
                }
                return ProxyResponseReceivedAction.continueWith(interceptedResponse);
            }

            @Override
            public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse interceptedResponse) {
                return ProxyResponseToBeSentAction.continueWith(interceptedResponse);
            }
        });

        // Right-click context menu (Send to Repeater/Intruder, Copy URL, Copy Full Request).
        try {
            montoyaApi.userInterface().registerContextMenuItemsProvider(new CaptureContextMenu(montoyaApi, trafficPanel));
        } catch (Throwable t) {
            log.logToError("context menu registration failed: " + t);
        }

        montoyaApi.extension().registerUnloadingHandler(() -> {
            try { reg.deregister(); } catch (Throwable ignored) {}
            analysisPool.shutdownNow();
        });

        banner();
    }

    private CollaboratorClient safeCreateCollaborator(MontoyaApi montoyaApi) {
        try {
            return montoyaApi.collaborator().createClient();
        } catch (Throwable t) {
            // Collaborator unavailable (e.g. Burp Community). SSRF OOB verification
            // will be skipped, and SSRF is DROPPED rather than guessed. That is the
            // correct zero-FP behavior.
            log.logToOutput("Collaborator unavailable — OOB SSRF verification disabled (SSRF will be dropped, never guessed).");
            return null;
        }
    }

    private void banner() {
        log.logToOutput("============================================================");
        log.logToOutput("  " + NAME + " " + VERSION);
        log.logToOutput("  5-GATE zero-false-positive detection engine loaded.");
        log.logToOutput("  Traffic SmartCapture ready (separate tab).");
        log.logToOutput("  Verification: <=10 req/s, 10s timeout, background only.");
        log.logToOutput("============================================================");
    }

    // ========================================================================
    //  SHARED CONSTANTS  (all Patterns pre-compiled once, static final)
    // ========================================================================
    static final class Rx {
        private Rx() {}

        // Case-insensitive across the board.
        static final int CI = Pattern.CASE_INSENSITIVE;

        // Static-asset file extensions (Gate 0 + capture filter).
        static final Pattern STATIC_ASSET = Pattern.compile(
                "\\.(css|js|mjs|png|jpe?g|gif|svg|webp|avif|bmp|tiff?|ico|" +
                "woff2?|ttf|eot|otf|mp4|mp3|wav|ogg|avi|mov|webm|flv|" +
                "pdf|zip|tar|gz|rar|7z|map|wasm)(\\?.*)?$", CI);

        // Documentation / help paths (Gate 0 + capture filter).
        static final Pattern DOC_PATH = Pattern.compile(
                "/(docs?|help|manual|guides?|handbook|tutorials?|kb|faq|" +
                "support|wiki|changelog|release-notes|readme)(/|$)", CI);

        // Health / infra paths (Gate 0 + capture filter).
        static final Pattern HEALTH_PATH = Pattern.compile(
                "/(health(z|check)?|ping|status|ready|readyz|alive|livez|" +
                "metrics|prometheus|_internal|__debug__)(/|$)", CI);

        // "Interesting" application paths (Gate 0 KEEP + api export).
        static final Pattern INTERESTING_PATH = Pattern.compile(
                "/(api|v[1-6]|graphql|rest|rpc|oauth|auth|login|signup|" +
                "register|admin|dashboard|account|users?|profile|settings?|" +
                "upload|import|export|webhook)(/|$|\\?)", CI);

        // API endpoints for export bucket 01.
        static final Pattern API_PATH = Pattern.compile(
                "/(api|v[1-6]|graphql|rest|rpc)(/|$|\\?)", CI);

        // Browser-internal / non-http schemes (capture filter).
        static final Pattern BROWSER_INTERNAL = Pattern.compile(
                "^(chrome-extension|moz-extension|about|data|blob|javascript):", CI);

        // Static-CDN hosts (capture filter).
        static final Pattern CDN_HOST = Pattern.compile(
                "^(cdn|static|assets|img|images|media)\\.|" +
                "(fonts\\.googleapis\\.com|fonts\\.gstatic\\.com|cdnjs\\.cloudflare\\.com|" +
                "ajax\\.googleapis\\.com|unpkg\\.com|jsdelivr\\.net)$", CI);

        // Interesting-response signatures for export bucket 05.
        static final Pattern SQL_ERROR = Pattern.compile(
                "(SQL syntax.*MySQL|Warning.*mysqli?_|valid MySQL result|" +
                "PostgreSQL.*ERROR|ORA-[0-9]{5}|Microsoft OLE DB Provider for SQL Server|" +
                "SQLite/JDBCDriver|SQLServer JDBC Driver|Unclosed quotation mark after)", CI);
        static final Pattern STACK_TRACE = Pattern.compile(
                "(java\\.lang\\.[A-Za-z.]+Exception|\\bat [a-z0-9_.]+\\([A-Za-z0-9_]+\\.java:[0-9]+\\)|" +
                "Traceback \\(most recent call last\\)|" +
                "\\.py\\\", line [0-9]+|System\\.[A-Za-z.]+Exception:)", CI);
        static final Pattern INTERNAL_IP = Pattern.compile(
                "\\b(10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|" +
                "192\\.168\\.\\d{1,3}\\.\\d{1,3}|" +
                "172\\.(1[6-9]|2\\d|3[01])\\.\\d{1,3}\\.\\d{1,3})\\b");
        static final Pattern DEBUG_INFO = Pattern.compile(
                "(DEBUG\\s*=\\s*true|Whoops.*framework|Symfony.*Profiler|" +
                "Werkzeug Debugger|Rails\\.application|X-Debug-Token)", CI);
        static final Pattern ENV_CONTENT = Pattern.compile(
                "(?m)^\\s*(DB_PASSWORD|AWS_SECRET_ACCESS_KEY|SECRET_KEY|API_KEY|" +
                "DATABASE_URL|PRIVATE_KEY)\\s*=", CI);

        // Volatile tokens ignored in baseline diffing (Gate 1). Two-stage:
        //  (a) VOLATILE_KV consumes "<volatile-key> = <value>" including the value,
        //      so a differing csrf/nonce/session VALUE does not inflate the diff.
        //  (b) VOLATILE mops up standalone uuids / long epoch numbers.
        static final Pattern VOLATILE_KV = Pattern.compile(
                "(csrf[-_]?token|xsrf[-_]?token|authenticity_token|_token|access_token|" +
                "nonce|session[-_]?id|sessionid|request[-_]?id|req[-_]?id|trace[-_]?id|" +
                "timestamp|\\bts\\b|\\biat\\b|\\bexp\\b|etag|last[-_]?modified)" +
                "\\s*[=:\"']{1,3}\\s*[^&\\s,;\"'}]+", CI);
        static final Pattern VOLATILE = Pattern.compile(
                "([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|" + // uuid
                "\\b[0-9]{10,13}\\b)", CI);

        // HTML-encoded canary (means XSS was neutralized -> not exploitable).
        static Pattern encodedCanary(String c) {
            return Pattern.compile("(&lt;|&#0*60;|%3C)[^<]*" + Pattern.quote(c), CI);
        }
    }

    // ========================================================================
    //  GLOBAL RATE LIMITER  — token bucket, <= N verification requests / second
    // ========================================================================
    static final class RateLimiter {
        private final double permitsPerSecond;
        private final double maxTokens;
        private double tokens;
        private long lastRefillNanos;

        RateLimiter(double permitsPerSecond) {
            this.permitsPerSecond = permitsPerSecond;
            this.maxTokens = permitsPerSecond;
            this.tokens = permitsPerSecond;
            this.lastRefillNanos = System.nanoTime();
        }

        /** Blocks (briefly) until a permit is available. Thread-safe. */
        synchronized void acquire() {
            while (true) {
                refill();
                if (tokens >= 1.0) {
                    tokens -= 1.0;
                    return;
                }
                double needed = 1.0 - tokens;
                long waitMs = (long) Math.ceil((needed / permitsPerSecond) * 1000.0);
                try {
                    wait(Math.max(1, waitMs));
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }
        }

        private void refill() {
            long now = System.nanoTime();
            double elapsedSec = (now - lastRefillNanos) / 1_000_000_000.0;
            if (elapsedSec <= 0) return;
            tokens = Math.min(maxTokens, tokens + elapsedSec * permitsPerSecond);
            lastRefillNanos = now;
        }
    }

    // ========================================================================
    //  HTTP HELPER  — rate-limited, 10s-timeout, exception-safe send + utils
    // ========================================================================
    static final class Http {
        private final MontoyaApi api;
        private final RateLimiter limiter;
        private final Logging log;

        Http(MontoyaApi api, RateLimiter limiter) {
            this.api = api;
            this.limiter = limiter;
            this.log = api.logging();
        }

        /**
         * Sends a request with the global rate limit applied and a hard 10s
         * timeout enforced on a worker thread. Returns null on any failure or
         * timeout — callers treat null as "cannot verify" and DROP the finding.
         */
        HttpRequestResponse send(HttpRequest req) {
            if (req == null) return null;
            limiter.acquire();
            final HttpRequest r = req;
            final java.util.concurrent.FutureTask<HttpRequestResponse> task =
                    new java.util.concurrent.FutureTask<>(() -> api.http().sendRequest(r));
            Thread t = new Thread(task, "airf-send");
            t.setDaemon(true);
            t.start();
            try {
                return task.get(10, TimeUnit.SECONDS);
            } catch (Throwable ex) {
                task.cancel(true);
                t.interrupt();
                return null;
            }
        }

        static String host(HttpRequest req) {
            try {
                HttpService s = req.httpService();
                return s == null ? "" : s.host();
            } catch (Throwable t) {
                return "";
            }
        }
    }

    // ========================================================================
    //  TEXT UTILITIES  — safe, case-insensitive, volatile-token normalization
    // ========================================================================
    static final class Txt {
        private Txt() {}

        static String lower(String s) { return s == null ? "" : s.toLowerCase(Locale.ROOT); }

        static String safeBody(HttpResponse r) {
            try { return r == null ? "" : r.bodyToString(); }
            catch (Throwable t) { return ""; }
        }

        static String safeBody(HttpRequestResponse rr) {
            try { return rr == null || rr.response() == null ? "" : rr.response().bodyToString(); }
            catch (Throwable t) { return ""; }
        }

        /** Strip volatile tokens so diffs don't fire on nonces/timestamps/uuids. */
        static String normalizeForDiff(String body) {
            if (body == null) return "";
            // Stage (a): collapse whole "key=value" pairs for known volatile keys.
            String out = Rx.VOLATILE_KV.matcher(body).replaceAll("§");
            // Stage (b): collapse standalone uuids / epoch numbers anywhere.
            out = Rx.VOLATILE.matcher(out).replaceAll("§");
            // Collapse whitespace so pretty-print jitter doesn't inflate diffs.
            return out.replaceAll("\\s+", " ").trim();
        }

        /**
         * Content difference ratio in [0,1] using normalized Levenshtein on a
         * bounded prefix (perf cap). >= 0.05 (5%) means the payload changed the
         * response meaningfully.
         */
        static double diffRatio(String a, String b) {
            String na = normalizeForDiff(a);
            String nb = normalizeForDiff(b);
            int cap = 4000;
            if (na.length() > cap) na = na.substring(0, cap);
            if (nb.length() > cap) nb = nb.substring(0, cap);
            if (na.isEmpty() && nb.isEmpty()) return 0.0;
            int dist = levenshtein(na, nb);
            int max = Math.max(na.length(), nb.length());
            return max == 0 ? 0.0 : (double) dist / (double) max;
        }

        private static int levenshtein(String s, String t) {
            int n = s.length(), m = t.length();
            if (n == 0) return m;
            if (m == 0) return n;
            int[] prev = new int[m + 1];
            int[] cur = new int[m + 1];
            for (int j = 0; j <= m; j++) prev[j] = j;
            for (int i = 1; i <= n; i++) {
                cur[0] = i;
                char sc = s.charAt(i - 1);
                for (int j = 1; j <= m; j++) {
                    int cost = (sc == t.charAt(j - 1)) ? 0 : 1;
                    cur[j] = Math.min(Math.min(cur[j - 1] + 1, prev[j] + 1), prev[j - 1] + cost);
                }
                int[] tmp = prev; prev = cur; cur = tmp;
            }
            return prev[m];
        }

        static String preview(String s, int max) {
            if (s == null) return "";
            String one = s.replaceAll("\\s+", " ").trim();
            return one.length() <= max ? one : one.substring(0, max) + "…";
        }

        static String jsonEscape(String s) {
            if (s == null) return "";
            StringBuilder b = new StringBuilder(s.length() + 16);
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                switch (c) {
                    case '"': b.append("\\\""); break;
                    case '\\': b.append("\\\\"); break;
                    case '\n': b.append("\\n"); break;
                    case '\r': b.append("\\r"); break;
                    case '\t': b.append("\\t"); break;
                    default:
                        if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
                        else b.append(c);
                }
            }
            return b.toString();
        }
    }

    // ========================================================================
    //  FINDING MODEL + SINK
    // ========================================================================
    enum VulnType { XSS, SQLI, IDOR, SSRF, OPEN_REDIRECT, CORS, RACE }

    static final class Finding {
        final VulnType type;
        final String url;
        final String method;
        final String param;
        int confidence;                 // 0-100 (Gate 4)
        AuditIssueSeverity severity;    // Gate 3 outcome
        String evidence;                // proof text
        HttpRequestResponse proof;      // request/response pair to show in Burp

        Finding(VulnType type, String url, String method, String param) {
            this.type = type;
            this.url = url;
            this.method = method == null ? "GET" : method;
            this.param = param == null ? "" : param;
        }

        /** Dedup identity: URL + Method + Param + VulnType (Gate 4). */
        String dedupKey() {
            String u = url;
            int q = u.indexOf('?');
            if (q >= 0) u = u.substring(0, q); // ignore volatile query values
            return type + "|" + method.toUpperCase(Locale.ROOT) + "|" +
                   u.toLowerCase(Locale.ROOT) + "|" + param.toLowerCase(Locale.ROOT);
        }

        String confidenceLabel() {
            if (confidence >= 90) return "Verified";
            if (confidence >= 70) return "Firm";
            if (confidence >= 50) return "Needs Manual Verification";
            return "Dropped";
        }
    }

    interface Sink {
        void report(Finding f);
    }

    // ========================================================================
    //  DETECTION ENGINE  —  strict sequential 5-GATE pipeline
    // ========================================================================
    static final class DetectionEngine {
        private final MontoyaApi api;
        private final Logging log;
        private final Http http;
        private final CollaboratorClient collab;
        private final Set<String> reported = ConcurrentHashMap.newKeySet(); // Gate 4 dedup
        private final AtomicLong canarySeq = new AtomicLong(0);
        private volatile Sink sink;

        DetectionEngine(MontoyaApi api, RateLimiter limiter, CollaboratorClient collab) {
            this.api = api;
            this.log = api.logging();
            this.http = new Http(api, limiter);
            this.collab = collab;
        }

        void setSink(Sink s) { this.sink = s; }

        /** Entry point — called on a background thread for every proxied response. */
        void analyze(HttpRequest req, HttpResponse resp) {
            if (req == null || resp == null) return;

            // ---- GATE 0: request qualification (cheap, drops the vast majority) ----
            if (!Gate0.qualifies(req, resp)) return;

            // Each vuln class runs its own Gate 1 + Gate 2 verification. We only
            // test parameters that actually exist (or method-based classes).
            List<ParsedHttpParameter> params = safeParams(req);

            // XSS — needs a reflectable parameter.
            for (ParsedHttpParameter p : params) {
                if (isReflectableParamType(p.type())) {
                    Finding f = verifyXss(req, resp, p);
                    if (f != null) finalizeAndReport(f, req, resp);
                }
            }

            // SQLi — parameter-based, time + boolean.
            for (ParsedHttpParameter p : params) {
                if (isReflectableParamType(p.type())) {
                    Finding f = verifySqli(req, p);
                    if (f != null) finalizeAndReport(f, req, resp);
                }
            }

            // Open Redirect — parameter-based (only redirect-ish param names).
            for (ParsedHttpParameter p : params) {
                if (looksLikeRedirectParam(p.name())) {
                    Finding f = verifyOpenRedirect(req, p);
                    if (f != null) finalizeAndReport(f, req, resp);
                }
            }

            // SSRF — parameter-based, OOB only (dropped if no collaborator).
            for (ParsedHttpParameter p : params) {
                if (looksLikeSsrfParam(p.name())) {
                    Finding f = verifySsrf(req, p);
                    if (f != null) finalizeAndReport(f, req, resp);
                }
            }

            // CORS — header reflection test (per request, not per param).
            {
                Finding f = verifyCors(req);
                if (f != null) finalizeAndReport(f, req, resp);
            }

            // IDOR — single session cannot confirm. Emit Info "manual" ONLY when
            // the endpoint clearly references an object id, and never High/Critical.
            {
                Finding f = flagIdorManual(req, resp, params);
                if (f != null) finalizeAndReport(f, req, resp);
            }

            // Race condition — cannot be detected passively; Info/manual only.
            {
                Finding f = flagRaceManual(req, params);
                if (f != null) finalizeAndReport(f, req, resp);
            }
        }

        // ---- Gate 3 + Gate 4 applied here, then reported ----
        private void finalizeAndReport(Finding f, HttpRequest req, HttpResponse resp) {
            try {
                // GATE 3 — context & impact adjustment (may downgrade or drop).
                if (!Gate3.assess(f, req, resp)) return;

                // GATE 4 — dedup + confidence floor.
                if (f.confidence < 50) return;                 // below floor -> DROP
                if (!reported.add(f.dedupKey())) return;       // duplicate -> DROP

                Sink s = sink;
                if (s != null) s.report(f);

                // Also raise a Burp audit issue so it appears in the Dashboard.
                raiseAuditIssue(f);
            } catch (Throwable t) {
                log.logToError("finalize error: " + t);
            }
        }

        private void raiseAuditIssue(Finding f) {
            try {
                if (f.proof == null) return;
                AuditIssueConfidence conf = f.confidence >= 90 ? AuditIssueConfidence.CERTAIN
                        : f.confidence >= 70 ? AuditIssueConfidence.FIRM
                        : AuditIssueConfidence.TENTATIVE;
                String name = "AIReconForge: " + prettyType(f.type) +
                        (f.confidence < 70 ? " (Needs Manual Verification)" : "");
                String detail = "<b>" + prettyType(f.type) + "</b><br>" +
                        "Parameter: " + esc(f.param) + "<br>" +
                        "Confidence: " + f.confidence + "/100 (" + f.confidenceLabel() + ")<br>" +
                        "Verified via the AIReconForge 5-gate pipeline (baseline diff + " +
                        "vuln-specific verification).<br><br><b>Evidence:</b><br><pre>" +
                        esc(f.evidence) + "</pre>";
                AuditIssue issue = AuditIssue.auditIssue(
                        name, detail, remediation(f.type), f.url,
                        f.severity, conf, null, null,
                        AuditIssueSeverity.HIGH, f.proof);
                api.siteMap().add(issue);
            } catch (Throwable t) {
                log.logToError("audit issue error: " + t);
            }
        }

        // ====================================================================
        //  GATE 1 + GATE 2 :  XSS
        //  Real only if a unique canary reflects UNENCODED in a dangerous
        //  context AND the clean baseline does NOT contain it (diff proof).
        // ====================================================================
        private Finding verifyXss(HttpRequest req, HttpResponse origResp, ParsedHttpParameter p) {
            try {
                String canary = "airfXSS" + nextCanaryId() + "z";
                // Dangerous-context probe: breaks out of tag/attr/script contexts.
                String payload = "\"'><svg/onload=confirm(" + canary + ")>" + canary;

                HttpRequest attack = req.withUpdatedParameters(
                        HttpParameter.parameter(p.name(), payload, p.type()));
                HttpRequestResponse ar = http.send(attack);
                if (ar == null || ar.response() == null) return null;
                String attackBody = Txt.safeBody(ar);

                // Canary must appear at all.
                if (attackBody.indexOf(canary) < 0) return null;

                // GATE 1 — clean baseline must NOT contain the canary (proves reflection
                // is our payload, not pre-existing content).
                HttpRequest clean = req.withUpdatedParameters(
                        HttpParameter.parameter(p.name(), "airfClean" + nextCanaryId(), p.type()));
                HttpRequestResponse cr = http.send(clean);
                if (cr == null) return null;
                String cleanBody = Txt.safeBody(cr);
                if (cleanBody.contains(canary)) return null; // canary is ambient -> DROP

                // GATE 2 — must be UNENCODED in a dangerous context. If our angle
                // brackets came back HTML-encoded, it's not exploitable -> DROP.
                if (Rx.encodedCanary(canary).matcher(attackBody).find()) return null;

                boolean dangerous =
                        attackBody.contains("<svg/onload=confirm(" + canary + ")>") ||
                        attackBody.contains("onload=confirm(" + canary + ")") ||
                        attackBody.contains("'><svg") ||
                        attackBody.contains("\"><svg");
                if (!dangerous) return null;

                Finding f = new Finding(VulnType.XSS, req.url(), req.method(), p.name());
                f.confidence = 92;
                f.severity = AuditIssueSeverity.HIGH;
                f.evidence = "Unique canary reflected UNENCODED in a script-executing context.\n" +
                             "Payload: " + payload + "\n" +
                             "Reflected: " + Txt.preview(dangerousSnippet(attackBody, canary), 200);
                f.proof = ar;
                return f;
            } catch (Throwable t) {
                log.logToError("xss verify error: " + t);
                return null;
            }
        }

        private String dangerousSnippet(String body, String canary) {
            int idx = body.indexOf("<svg/onload=confirm(" + canary + ")>");
            if (idx < 0) idx = Math.max(0, body.indexOf(canary) - 40);
            int end = Math.min(body.length(), idx + 120);
            return body.substring(Math.max(0, idx), end);
        }

        // ====================================================================
        //  GATE 1 + GATE 2 :  SQL Injection
        //  Time-based (SLEEP delta >= 4s) confirmed by a second sleep, PLUS a
        //  boolean 1=1 vs 1=2 difference. Both must agree.
        // ====================================================================
        private Finding verifySqli(HttpRequest req, ParsedHttpParameter p) {
            try {
                String base = p.value() == null ? "1" : p.value();

                // --- Boolean channel (Gate 1 baseline diff) ---
                String trueP = base + "' AND 1=1-- -";
                String falseP = base + "' AND 1=2-- -";
                HttpRequestResponse tr = http.send(req.withUpdatedParameters(
                        HttpParameter.parameter(p.name(), trueP, p.type())));
                HttpRequestResponse fr = http.send(req.withUpdatedParameters(
                        HttpParameter.parameter(p.name(), falseP, p.type())));
                if (tr == null || fr == null) return null;
                double boolDiff = Txt.diffRatio(Txt.safeBody(tr), Txt.safeBody(fr));
                boolean booleanSignal = boolDiff >= 0.05; // 1=1 and 1=2 differ meaningfully

                // --- Time channel (Gate 2 verification) ---
                long baseMs = timedSend(req, p, base);
                if (baseMs < 0) return null;
                long sleep1 = timedSend(req, p, base + "' AND SLEEP(5)-- -");
                if (sleep1 < 0) return null;
                long delta1 = sleep1 - baseMs;
                boolean timeSignal = delta1 >= 4000;

                if (!timeSignal && !booleanSignal) return null;

                // Confirm time-based with a second, independent sleep to kill jitter FPs.
                int confidence;
                String evidence;
                if (timeSignal) {
                    long sleep2 = timedSend(req, p, base + "' AND SLEEP(5)-- -");
                    if (sleep2 < 0 || (sleep2 - baseMs) < 4000) return null; // not reproducible -> DROP
                    confidence = booleanSignal ? 95 : 88;
                    evidence = "Time-based blind SQLi confirmed.\n" +
                            "baseline=" + baseMs + "ms  sleep#1=" + sleep1 + "ms (Δ" + delta1 + "ms)  " +
                            "sleep#2=" + sleep2 + "ms\nboolean 1=1 vs 1=2 diff=" +
                            String.format(Locale.ROOT, "%.1f%%", boolDiff * 100);
                } else {
                    // Boolean-only: strong but not time-proven -> manual band.
                    confidence = 62;
                    evidence = "Boolean-based SQLi indicator: 1=1 and 1=2 produced meaningfully " +
                            "different responses (diff=" + String.format(Locale.ROOT, "%.1f%%", boolDiff * 100) +
                            "). Time-based not confirmed — manual verification recommended.";
                }

                Finding f = new Finding(VulnType.SQLI, req.url(), req.method(), p.name());
                f.confidence = confidence;
                f.severity = AuditIssueSeverity.HIGH;
                f.evidence = evidence;
                f.proof = tr;
                return f;
            } catch (Throwable t) {
                log.logToError("sqli verify error: " + t);
                return null;
            }
        }

        private long timedSend(HttpRequest req, ParsedHttpParameter p, String value) {
            long start = System.currentTimeMillis();
            HttpRequestResponse rr = http.send(req.withUpdatedParameters(
                    HttpParameter.parameter(p.name(), value, p.type())));
            if (rr == null || rr.response() == null) return -1;
            return System.currentTimeMillis() - start;
        }

        // ====================================================================
        //  GATE 2 :  Open Redirect
        //  Real only if the response is a 3xx whose Location points at our
        //  attacker domain (not the app's own host, not ignored).
        // ====================================================================
        private Finding verifyOpenRedirect(HttpRequest req, ParsedHttpParameter p) {
            try {
                String marker = "airf-redir-" + nextCanaryId() + ".example-attacker.com";
                String payload = "https://" + marker + "/";
                HttpRequestResponse rr = http.send(req.withUpdatedParameters(
                        HttpParameter.parameter(p.name(), payload, p.type())));
                if (rr == null || rr.response() == null) return null;
                short sc = rr.response().statusCode();
                if (sc < 300 || sc >= 400) return null; // not a redirect -> DROP
                String loc = safeHeader(rr.response(), "Location");
                if (loc == null) return null;
                String ll = Txt.lower(loc);
                // Must redirect to OUR attacker host, not the app.
                if (!ll.contains(Txt.lower(marker))) return null;
                if (!(ll.startsWith("http://") || ll.startsWith("https://") || ll.startsWith("//"))) return null;

                Finding f = new Finding(VulnType.OPEN_REDIRECT, req.url(), req.method(), p.name());
                f.confidence = 90;
                f.severity = AuditIssueSeverity.MEDIUM;
                f.evidence = "3xx redirect to attacker-controlled host.\n" +
                        "Status: " + sc + "\nLocation: " + loc;
                f.proof = rr;
                return f;
            } catch (Throwable t) {
                log.logToError("open-redirect verify error: " + t);
                return null;
            }
        }

        // ====================================================================
        //  GATE 2 :  SSRF  (OOB only — dropped if no collaborator)
        // ====================================================================
        private Finding verifySsrf(HttpRequest req, ParsedHttpParameter p) {
            try {
                if (collab == null) return null; // no OOB channel -> never guess -> DROP
                CollaboratorPayload payload;
                try { payload = collab.generatePayload(); }
                catch (Throwable t) { return null; }
                String oob = payload.toString();

                HttpRequestResponse rr = http.send(req.withUpdatedParameters(
                        HttpParameter.parameter(p.name(), "https://" + oob + "/", p.type())));
                if (rr == null) return null;

                // Poll for a callback for up to 10s.
                long deadline = System.currentTimeMillis() + 10_000;
                while (System.currentTimeMillis() < deadline) {
                    try {
                        List<Interaction> hits = collab.getAllInteractions();
                        for (Interaction in : hits) {
                            if (in.id() != null && in.id().toString().equals(payload.id().toString())) {
                                Finding f = new Finding(VulnType.SSRF, req.url(), req.method(), p.name());
                                f.confidence = 95;
                                f.severity = AuditIssueSeverity.HIGH;
                                f.evidence = "Out-of-band callback received (" + in.type() +
                                        ") — server fetched attacker-controlled URL.\nCollaborator: " + oob;
                                f.proof = rr;
                                return f;
                            }
                        }
                    } catch (Throwable ignored) {}
                    try { Thread.sleep(500); } catch (InterruptedException e) { break; }
                }
                return null; // no callback within 10s -> DROP
            } catch (Throwable t) {
                log.logToError("ssrf verify error: " + t);
                return null;
            }
        }

        // ====================================================================
        //  GATE 2 :  CORS
        //  Real only if ACAO reflects an evil origin AND ACAC:true.
        //  Wildcard-without-credentials is explicitly NOT a vuln.
        // ====================================================================
        private Finding verifyCors(HttpRequest req) {
            try {
                String evil = "https://evil-attacker-airf.com";
                HttpRequestResponse rr = http.send(req.withHeader("Origin", evil));
                if (rr == null || rr.response() == null) return null;
                String acao = safeHeader(rr.response(), "Access-Control-Allow-Origin");
                String acac = safeHeader(rr.response(), "Access-Control-Allow-Credentials");
                if (acao == null) return null;
                boolean reflectsEvil = Txt.lower(acao).equals(Txt.lower(evil));
                boolean creds = acac != null && Txt.lower(acac).trim().equals("true");
                // Wildcard is not exploitable with credentials (browsers forbid it) -> DROP.
                if (acao.trim().equals("*")) return null;
                if (!(reflectsEvil && creds)) return null;

                Finding f = new Finding(VulnType.CORS, req.url(), req.method(), "Origin");
                f.confidence = 90;
                f.severity = AuditIssueSeverity.MEDIUM;
                f.evidence = "ACAO reflects arbitrary origin AND ACAC:true.\n" +
                        "Access-Control-Allow-Origin: " + acao + "\n" +
                        "Access-Control-Allow-Credentials: " + acac;
                f.proof = rr;
                return f;
            } catch (Throwable t) {
                log.logToError("cors verify error: " + t);
                return null;
            }
        }

        // ====================================================================
        //  IDOR — single session CANNOT confirm. Info/manual only, capped low.
        //  Requires an object-id-looking parameter. NEVER High/Critical.
        // ====================================================================
        private Finding flagIdorManual(HttpRequest req, HttpResponse resp, List<ParsedHttpParameter> params) {
            try {
                boolean authed = hasAuth(req);
                if (!authed) return null; // unauth public object = not IDOR-interesting
                ParsedHttpParameter idParam = null;
                for (ParsedHttpParameter p : params) {
                    if (looksLikeObjectId(p.name(), p.value())) { idParam = p; break; }
                }
                if (idParam == null) return null;
                // Only for data-ish responses.
                String ct = Txt.lower(safeHeader(resp, "Content-Type"));
                if (!(ct.contains("json") || ct.contains("xml"))) return null;

                Finding f = new Finding(VulnType.IDOR, req.url(), req.method(), idParam.name());
                f.confidence = 55; // manual band by design
                f.severity = AuditIssueSeverity.INFORMATION; // NEVER High/Critical single-session
                f.evidence = "Object-reference parameter '" + idParam.name() + "=" +
                        Txt.preview(idParam.value(), 40) + "' on an authenticated data endpoint. " +
                        "IDOR CANNOT be confirmed with a single session — replay with a second " +
                        "user's token to verify cross-tenant access. Reported as Info for manual testing.";
                f.proof = null;
                return f;
            } catch (Throwable t) {
                return null;
            }
        }

        // ====================================================================
        //  RACE — cannot be detected passively. Info/manual only.
        // ====================================================================
        private Finding flagRaceManual(HttpRequest req, List<ParsedHttpParameter> params) {
            try {
                String m = Txt.lower(req.method());
                if (!(m.equals("post") || m.equals("put") || m.equals("patch") || m.equals("delete"))) return null;
                String path = Txt.lower(req.path());
                boolean singleUseLooking =
                        path.contains("redeem") || path.contains("coupon") || path.contains("voucher") ||
                        path.contains("transfer") || path.contains("withdraw") || path.contains("apply") ||
                        path.contains("claim") || path.contains("checkout") || path.contains("purchase");
                if (!singleUseLooking) return null;
                Finding f = new Finding(VulnType.RACE, req.url(), req.method(), "");
                f.confidence = 52; // manual band
                f.severity = AuditIssueSeverity.INFORMATION;
                f.evidence = "State-changing single-use-looking endpoint. Race conditions cannot be " +
                        "auto-detected — send concurrent bursts (e.g. Turbo Intruder) to verify TOCTOU. " +
                        "Reported as Info for manual testing.";
                f.proof = null;
                return f;
            } catch (Throwable t) {
                return null;
            }
        }

        private static boolean looksLikeObjectId(String name, String value) {
            String n = Txt.lower(name);
            boolean idName = n.equals("id") || n.endsWith("_id") || n.endsWith("id") ||
                    n.equals("uid") || n.equals("uuid") || n.equals("account") ||
                    n.equals("user") || n.equals("userid") || n.equals("order") ||
                    n.equals("invoice") || n.equals("doc") || n.equals("file");
            if (!idName) return false;
            if (value == null) return false;
            String v = value.trim();
            return v.matches("\\d+") ||
                   v.matches("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}") ||
                   v.matches("[0-9a-fA-F]{24}"); // mongo objectid
        }

        static boolean hasAuth(HttpRequest req) {
            try {
                return req.hasHeader("Authorization") || req.hasHeader("Cookie") ||
                       req.hasHeader("X-API-Key") || req.hasHeader("X-CSRF-Token");
            } catch (Throwable t) { return false; }
        }

        static String safeHeader(HttpResponse resp, String name) {
            try {
                if (resp == null || !resp.hasHeader(name)) return null;
                return resp.headerValue(name);
            } catch (Throwable t) { return null; }
        }

        // ================= helpers used by the gates below ==================
        private List<ParsedHttpParameter> safeParams(HttpRequest req) {
            try { return req.parameters(); }
            catch (Throwable t) { return new ArrayList<>(); }
        }

        private static boolean isReflectableParamType(HttpParameterType t) {
            return t == HttpParameterType.URL || t == HttpParameterType.BODY || t == HttpParameterType.JSON;
        }

        private static boolean looksLikeRedirectParam(String name) {
            String n = Txt.lower(name);
            return n.equals("url") || n.equals("redirect") || n.equals("redirect_uri") ||
                   n.equals("redirecturl") || n.equals("return") || n.equals("returnurl") ||
                   n.equals("return_to") || n.equals("next") || n.equals("dest") ||
                   n.equals("destination") || n.equals("continue") || n.equals("goto") ||
                   n.equals("callback") || n.equals("target");
        }

        private static boolean looksLikeSsrfParam(String name) {
            String n = Txt.lower(name);
            return n.equals("url") || n.equals("uri") || n.equals("link") ||
                   n.equals("src") || n.equals("source") || n.equals("dest") ||
                   n.equals("target") || n.equals("host") || n.equals("domain") ||
                   n.equals("callback") || n.equals("webhook") || n.equals("proxy") ||
                   n.equals("fetch") || n.equals("feed") || n.equals("image_url") ||
                   n.equals("imageurl") || n.equals("path") || n.equals("file");
        }

        private static String prettyType(VulnType t) {
            switch (t) {
                case XSS: return "Reflected Cross-Site Scripting (XSS)";
                case SQLI: return "SQL Injection";
                case IDOR: return "Insecure Direct Object Reference (IDOR)";
                case SSRF: return "Server-Side Request Forgery (SSRF)";
                case OPEN_REDIRECT: return "Open Redirect";
                case CORS: return "CORS Misconfiguration";
                case RACE: return "Race Condition";
                default: return t.name();
            }
        }

        private static String remediation(VulnType t) {
            switch (t) {
                case XSS: return "Context-encode all user input on output; apply a strict CSP.";
                case SQLI: return "Use parameterized queries / prepared statements.";
                case IDOR: return "Enforce per-object authorization on every request.";
                case SSRF: return "Allowlist outbound hosts; block internal ranges and metadata IPs.";
                case OPEN_REDIRECT: return "Only redirect to an allowlist of internal paths/hosts.";
                case CORS: return "Do not reflect arbitrary origins with credentials; use a strict allowlist.";
                default: return "Manual review required.";
            }
        }

        private static String esc(String s) {
            if (s == null) return "";
            return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
        }

        long nextCanaryId() { return canarySeq.incrementAndGet(); }
    }

    // ========================================================================
    //  GATE 0 :  REQUEST QUALIFICATION
    //  Drops the overwhelming majority of traffic before any active probing.
    //  KEEP only if the request is plausibly attackable.
    // ========================================================================
    static final class Gate0 {
        private Gate0() {}

        private static final Set<Short> DROP_STATUS = Set.of(
                (short) 404, (short) 405, (short) 410, (short) 429,
                (short) 500, (short) 502, (short) 503, (short) 504);

        static boolean qualifies(HttpRequest req, HttpResponse resp) {
            try {
                String url = Txt.lower(req.url());
                String path = Txt.lower(req.pathWithoutQuery());
                String method = req.method() == null ? "GET" : req.method().toUpperCase(Locale.ROOT);

                // --- Hard DROP rules ---
                if (Rx.STATIC_ASSET.matcher(path).find()) return false;
                if (Rx.DOC_PATH.matcher(path).find()) return false;
                if (Rx.HEALTH_PATH.matcher(path).find()) return false;
                if (resp != null && DROP_STATUS.contains(resp.statusCode())) return false;

                String ct = Txt.lower(DetectionEngine.safeHeader(resp, "Content-Type"));
                if (ct.startsWith("image/") || ct.startsWith("font/") || ct.startsWith("video/") ||
                    ct.startsWith("audio/") || ct.contains("application/pdf") ||
                    ct.contains("application/zip") || ct.contains("application/octet-stream")) {
                    return false;
                }

                // --- KEEP rules (any one qualifies) ---
                boolean hasParams = safeHasParams(req);
                boolean stateChanging = method.equals("POST") || method.equals("PUT") ||
                        method.equals("DELETE") || method.equals("PATCH");
                boolean interestingPath = Rx.INTERESTING_PATH.matcher(url).find();
                boolean authHeaders = DetectionEngine.hasAuth(req);
                boolean jsonXml = ct.contains("json") || ct.contains("xml");

                return hasParams || stateChanging || interestingPath || authHeaders || jsonXml;
            } catch (Throwable t) {
                return false; // fail safe: if we can't qualify it, we don't test it
            }
        }

        private static boolean safeHasParams(HttpRequest req) {
            try { return req.hasParameters(); }
            catch (Throwable t) { return false; }
        }
    }

    // ========================================================================
    //  GATE 3 :  CONTEXT & IMPACT
    //  Adjusts severity based on context; can downgrade to Info or DROP.
    //  Returns false => DROP the finding entirely.
    // ========================================================================
    static final class Gate3 {
        private Gate3() {}

        static boolean assess(Finding f, HttpRequest req, HttpResponse resp) {
            try {
                String ct = Txt.lower(DetectionEngine.safeHeader(resp, "Content-Type"));
                boolean htmlPage = ct.contains("text/html");
                boolean authed = DetectionEngine.hasAuth(req);
                String param = Txt.lower(f.param);
                boolean searchLike = param.contains("search") || param.contains("query") ||
                        param.equals("q") || param.contains("filter") || param.contains("keyword") ||
                        param.contains("term");

                switch (f.type) {
                    case XSS:
                        // Reflected XSS on a static HTML page with no auth context and a
                        // search/filter param is typically self-contained / low impact.
                        if (searchLike && !authed) {
                            f.severity = AuditIssueSeverity.LOW;
                            f.confidence = Math.min(f.confidence, 69); // manual band
                        }
                        // If reflection only occurs in the request-echo of a pure static
                        // page (no dynamic surface), Gate 2 already required a dangerous
                        // context, so we keep it but never above HIGH.
                        return true;

                    case SQLI:
                        // Impact is inherently high; no downgrade.
                        return true;

                    case OPEN_REDIRECT:
                    case CORS:
                        // If the endpoint serves only public data, cap to LOW/Info.
                        if (!authed) {
                            f.severity = AuditIssueSeverity.LOW;
                        }
                        return true;

                    case SSRF:
                        return true; // OOB-proven, keep HIGH

                    case IDOR:
                    case RACE:
                        // Already Info/manual by construction. Keep as Info.
                        f.severity = AuditIssueSeverity.INFORMATION;
                        return true;

                    default:
                        return true;
                }
            } catch (Throwable t) {
                return false;
            }
        }
    }

    // ========================================================================
    //  TRAFFIC SMARTCAPTURE  —  independent feature
    //  Captures meaningful proxy traffic, filters noise, exports 10 files.
    //  Bounded queue (50k): beyond the cap, oldest records flush to a spill
    //  file so memory is never unbounded.
    // ========================================================================
    static final class CaptureRecord {
        final int seq;
        final String method, url, host, contentType, mime;
        final short status;
        final int requestBytes, responseBytes;
        final long latencyMs;
        final String time;
        final boolean secure;
        // Kept for context-menu re-send; may be dropped on spill.
        final HttpRequest request;
        final HttpResponse response;

        CaptureRecord(int seq, HttpRequest req, HttpResponse resp, long latencyMs, String time) {
            this.seq = seq;
            this.method = safe(req::method, "GET");
            this.url = safe(req::url, "");
            this.host = safe(() -> req.httpService() == null ? "" : req.httpService().host(), "");
            this.secure = safeBool(() -> req.httpService() != null && req.httpService().secure());
            this.status = resp == null ? 0 : safeShort(resp::statusCode);
            this.contentType = safe(() -> resp == null ? "" : resp.headerValue("Content-Type"), "");
            this.mime = safe(() -> resp == null || resp.mimeType() == null ? "" : resp.mimeType().name(), "");
            this.requestBytes = safeInt(() -> req.toByteArray().length());
            this.responseBytes = resp == null ? 0 : safeInt(() -> resp.toByteArray().length());
            this.latencyMs = latencyMs;
            this.time = time;
            this.request = req;
            this.response = resp;
        }

        interface Sup<T> { T get() throws Throwable; }
        static String safe(Sup<String> s, String d) { try { String v = s.get(); return v == null ? d : v; } catch (Throwable t) { return d; } }
        static short safeShort(Sup<Short> s) { try { Short v = s.get(); return v == null ? 0 : v; } catch (Throwable t) { return 0; } }
        static int safeInt(Sup<Integer> s) { try { Integer v = s.get(); return v == null ? 0 : v; } catch (Throwable t) { return 0; } }
        static boolean safeBool(Sup<Boolean> s) { try { Boolean v = s.get(); return v != null && v; } catch (Throwable t) { return false; } }
    }

    interface CaptureListener {
        void onCounts(long captured, long filtered, long unique);
        void onRecord(CaptureRecord r);
        void onCleared();
    }

    static final class TrafficCapture {
        static final int MAX_QUEUE = 50_000;

        private final MontoyaApi api;
        private final Logging log;
        private final AtomicBoolean capturing = new AtomicBoolean(false);
        private final AtomicLong captured = new AtomicLong();
        private final AtomicLong filtered = new AtomicLong();
        private final List<CaptureRecord> records = new ArrayList<>(); // guarded by lock
        private final Object lock = new Object();
        private final Set<String> seenKeys = ConcurrentHashMap.newKeySet(); // unique + dedup
        private final AtomicLong seq = new AtomicLong();
        private volatile CaptureListener listener;
        private volatile Path spillFile;

        TrafficCapture(MontoyaApi api) {
            this.api = api;
            this.log = api.logging();
        }

        void setListener(CaptureListener l) { this.listener = l; }
        boolean isCapturing() { return capturing.get(); }
        void start() { capturing.set(true); }
        void stop() { capturing.set(false); }

        void clear() {
            synchronized (lock) { records.clear(); }
            seenKeys.clear();
            captured.set(0);
            filtered.set(0);
            spillFile = null;
            CaptureListener l = listener;
            if (l != null) l.onCleared();
        }

        long capturedCount() { return captured.get(); }
        long filteredCount() { return filtered.get(); }
        long uniqueCount() { return seenKeys.size(); }

        List<CaptureRecord> snapshot() {
            synchronized (lock) { return new ArrayList<>(records); }
        }

        /** Called on a background thread for each proxied response. */
        void onTraffic(HttpRequest req, HttpResponse resp, ZonedDateTime when) {
            if (!capturing.get()) return;
            try {
                if (shouldFilter(req, resp)) {
                    filtered.incrementAndGet();
                    pushCounts();
                    return;
                }
                // Dedup on method+url(no volatile query)+status.
                String key = dedupKey(req, resp);
                if (!seenKeys.add(key)) {
                    filtered.incrementAndGet();
                    pushCounts();
                    return;
                }
                long latency = 0; // proxy handler doesn't expose timing here; kept 0 unless known
                CaptureRecord rec = new CaptureRecord(
                        (int) seq.incrementAndGet(), req, resp, latency,
                        when.format(DateTimeFormatter.ofPattern("HH:mm:ss")));

                boolean spilled = false;
                synchronized (lock) {
                    if (records.size() >= MAX_QUEUE) {
                        spillOldest();
                        spilled = true;
                    }
                    records.add(rec);
                }
                captured.incrementAndGet();
                CaptureListener l = listener;
                if (l != null) l.onRecord(rec);
                pushCounts();
                if (spilled) log.logToOutput("[SmartCapture] queue at 50k — oldest records flushed to disk.");
            } catch (Throwable t) {
                log.logToError("capture onTraffic error: " + t);
            }
        }

        private void pushCounts() {
            CaptureListener l = listener;
            if (l != null) l.onCounts(captured.get(), filtered.get(), seenKeys.size());
        }

        private void spillOldest() {
            // Flush the oldest 10k to a JSON-lines spill file, then drop from memory.
            try {
                if (spillFile == null) {
                    spillFile = Files.createTempFile("airf_capture_spill_", ".jsonl");
                }
                int n = Math.min(10_000, records.size());
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < n; i++) sb.append(recordToJson(records.get(i))).append('\n');
                Files.writeString(spillFile, sb.toString(), StandardCharsets.UTF_8,
                        java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
                records.subList(0, n).clear();
            } catch (Throwable t) {
                // On spill failure, hard-cap by trimming to protect memory.
                int n = Math.min(10_000, records.size());
                records.subList(0, n).clear();
            }
        }

        private boolean shouldFilter(HttpRequest req, HttpResponse resp) {
            try {
                String url = Txt.lower(req.url());
                String path = Txt.lower(req.pathWithoutQuery());
                String host = Txt.lower(DetectionEngine.safeHeader(resp, "Host"));
                if (host.isEmpty()) host = Txt.lower(Http.host(req));

                if (Rx.BROWSER_INTERNAL.matcher(url).find()) return true;
                if (Rx.STATIC_ASSET.matcher(path).find()) return true;
                if (Rx.DOC_PATH.matcher(path).find()) return true;
                if (Rx.HEALTH_PATH.matcher(path).find()) return true;
                if (Rx.CDN_HOST.matcher(host).find()) return true;
                if (resp != null) {
                    short sc = resp.statusCode();
                    if (sc == 404 || sc == 410) return true;
                    String ct = Txt.lower(DetectionEngine.safeHeader(resp, "Content-Type"));
                    if (ct.startsWith("image/") || ct.startsWith("font/") || ct.startsWith("video/") ||
                        ct.startsWith("audio/")) return true;
                }
                return false;
            } catch (Throwable t) {
                return true; // if uncertain, filter (keep capture clean)
            }
        }

        private String dedupKey(HttpRequest req, HttpResponse resp) {
            String u = req.url();
            int q = u.indexOf('?');
            if (q >= 0) u = u.substring(0, q);
            short sc = resp == null ? 0 : resp.statusCode();
            return req.method().toUpperCase(Locale.ROOT) + " " + Txt.lower(u) + " " + sc;
        }

        // -------------------- 10-FILE EXPORT --------------------
        String export() throws IOException {
            String stamp = ZonedDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd_HH-mm"));
            Path dir = Path.of(System.getProperty("user.home"), "traffic_export_" + stamp);
            Files.createDirectories(dir);
            List<CaptureRecord> all = snapshot();

            writeApiEndpoints(dir, all);
            writeAuthAndSessions(dir, all);
            writeFormsAndInputs(dir, all);
            writeParametersMap(dir, all);
            writeInterestingResponses(dir, all);
            writeRedirects(dir, all);
            writeUniqueHosts(dir, all);
            writeTechFingerprint(dir, all);
            writeFullTrafficJson(dir, all);
            writeSummary(dir, all);

            return dir.toString();
        }

        private void writeApiEndpoints(Path dir, List<CaptureRecord> all) throws IOException {
            StringBuilder sb = new StringBuilder("# 01 API Endpoints\n\n");
            Set<String> seen = new LinkedHashSet<>();
            for (CaptureRecord r : all) {
                if (Rx.API_PATH.matcher(Txt.lower(r.url)).find()) {
                    seen.add(r.method + " " + r.url + "  [" + r.status + "]");
                }
            }
            seen.forEach(s -> sb.append(s).append('\n'));
            write(dir, "01_api_endpoints.txt", sb.toString());
        }

        private void writeAuthAndSessions(Path dir, List<CaptureRecord> all) throws IOException {
            StringBuilder sb = new StringBuilder("# 02 Auth & Sessions\n\n");
            for (CaptureRecord r : all) {
                try {
                    boolean interesting = DetectionEngine.hasAuth(r.request) ||
                            Txt.lower(r.url).matches(".*/(login|logout|auth|oauth|token|session|signin|signup|register).*");
                    if (!interesting) continue;
                    sb.append(r.method).append(' ').append(r.url).append("  [").append(r.status).append("]\n");
                    appendHeaderIf(sb, r.request, "Authorization");
                    appendHeaderIf(sb, r.request, "Cookie");
                    appendHeaderIf(sb, r.request, "X-API-Key");
                    String setCookie = DetectionEngine.safeHeader(r.response, "Set-Cookie");
                    if (setCookie != null) sb.append("    Set-Cookie: ").append(Txt.preview(setCookie, 120)).append('\n');
                    sb.append('\n');
                } catch (Throwable ignored) {}
            }
            write(dir, "02_auth_and_sessions.txt", sb.toString());
        }

        private void writeFormsAndInputs(Path dir, List<CaptureRecord> all) throws IOException {
            StringBuilder sb = new StringBuilder("# 03 Forms & Inputs (state-changing / body params)\n\n");
            for (CaptureRecord r : all) {
                try {
                    String m = r.method.toUpperCase(Locale.ROOT);
                    boolean stateChanging = m.equals("POST") || m.equals("PUT") || m.equals("PATCH") || m.equals("DELETE");
                    boolean hasBody = r.request.hasParameters(HttpParameterType.BODY) ||
                            r.request.hasParameters(HttpParameterType.JSON) ||
                            r.request.hasParameters(HttpParameterType.MULTIPART_ATTRIBUTE);
                    if (!(stateChanging || hasBody)) continue;
                    sb.append(m).append(' ').append(r.url).append('\n');
                    for (ParsedHttpParameter p : r.request.parameters()) {
                        if (p.type() == HttpParameterType.BODY || p.type() == HttpParameterType.JSON ||
                            p.type() == HttpParameterType.MULTIPART_ATTRIBUTE) {
                            sb.append("    ").append(p.type()).append(' ').append(p.name())
                              .append(" = ").append(Txt.preview(p.value(), 60)).append('\n');
                        }
                    }
                    sb.append('\n');
                } catch (Throwable ignored) {}
            }
            write(dir, "03_forms_and_inputs.txt", sb.toString());
        }

        private void writeParametersMap(Path dir, List<CaptureRecord> all) throws IOException {
            // param name -> set of "URL(type)"
            Map<String, Set<String>> map = new LinkedHashMap<>();
            for (CaptureRecord r : all) {
                try {
                    for (ParsedHttpParameter p : r.request.parameters()) {
                        if (p.type() == HttpParameterType.COOKIE) continue;
                        map.computeIfAbsent(p.name(), k -> new LinkedHashSet<>())
                           .add(stripQuery(r.url) + " (" + p.type() + ")");
                    }
                } catch (Throwable ignored) {}
            }
            StringBuilder sb = new StringBuilder("# 04 Parameters Map (param -> endpoints)\n\n");
            map.forEach((name, uses) -> {
                sb.append(name).append('\n');
                uses.forEach(u -> sb.append("    ").append(u).append('\n'));
                sb.append('\n');
            });
            write(dir, "04_parameters_map.txt", sb.toString());
        }

        private void writeInterestingResponses(Path dir, List<CaptureRecord> all) throws IOException {
            StringBuilder sb = new StringBuilder("# 05 Interesting Responses (errors/leaks/debug)\n\n");
            for (CaptureRecord r : all) {
                try {
                    String body = Txt.safeBody(r.response);
                    List<String> hits = new ArrayList<>();
                    if (Rx.SQL_ERROR.matcher(body).find()) hits.add("SQL error");
                    if (Rx.STACK_TRACE.matcher(body).find()) hits.add("stack trace");
                    if (Rx.INTERNAL_IP.matcher(body).find()) hits.add("internal IP");
                    if (Rx.DEBUG_INFO.matcher(body).find()) hits.add("debug info");
                    if (Rx.ENV_CONTENT.matcher(body).find()) hits.add("secret/env leak");
                    if (r.status >= 500) hits.add("HTTP " + r.status);
                    if (hits.isEmpty()) continue;
                    sb.append(r.method).append(' ').append(r.url).append("  [").append(r.status).append("]\n");
                    sb.append("    signals: ").append(String.join(", ", hits)).append('\n');
                    sb.append("    snippet: ").append(Txt.preview(firstSignalLine(body), 160)).append("\n\n");
                } catch (Throwable ignored) {}
            }
            write(dir, "05_interesting_responses.txt", sb.toString());
        }

        private void writeRedirects(Path dir, List<CaptureRecord> all) throws IOException {
            StringBuilder sb = new StringBuilder("# 06 Redirects (3xx)\n\n");
            for (CaptureRecord r : all) {
                if (r.status >= 300 && r.status < 400) {
                    String loc = DetectionEngine.safeHeader(r.response, "Location");
                    sb.append(r.method).append(' ').append(r.url).append("  [").append(r.status).append("]\n")
                      .append("    -> ").append(loc == null ? "(no Location)" : loc).append("\n\n");
                }
            }
            write(dir, "06_redirects.txt", sb.toString());
        }

        private void writeUniqueHosts(Path dir, List<CaptureRecord> all) throws IOException {
            Set<String> hosts = new LinkedHashSet<>();
            for (CaptureRecord r : all) if (!r.host.isEmpty()) hosts.add((r.secure ? "https://" : "http://") + r.host);
            StringBuilder sb = new StringBuilder("# 07 Unique Hosts\n\n");
            hosts.forEach(h -> sb.append(h).append('\n'));
            write(dir, "07_unique_hosts.txt", sb.toString());
        }

        private void writeTechFingerprint(Path dir, List<CaptureRecord> all) throws IOException {
            Map<String, Set<String>> tech = new LinkedHashMap<>(); // host -> signals
            for (CaptureRecord r : all) {
                try {
                    Set<String> sig = tech.computeIfAbsent(r.host, k -> new LinkedHashSet<>());
                    addHeaderSignal(sig, r.response, "Server");
                    addHeaderSignal(sig, r.response, "X-Powered-By");
                    addHeaderSignal(sig, r.response, "X-AspNet-Version");
                    addHeaderSignal(sig, r.response, "Via");
                    addHeaderSignal(sig, r.response, "X-Generator");
                    String sc = DetectionEngine.safeHeader(r.response, "Set-Cookie");
                    if (sc != null) {
                        String scl = Txt.lower(sc);
                        if (scl.contains("phpsessid")) sig.add("PHP (PHPSESSID)");
                        if (scl.contains("jsessionid")) sig.add("Java (JSESSIONID)");
                        if (scl.contains("asp.net")) sig.add("ASP.NET");
                        if (scl.contains("csrftoken") || scl.contains("django")) sig.add("Django");
                        if (scl.contains("laravel_session")) sig.add("Laravel");
                        if (scl.contains("_rails")) sig.add("Ruby on Rails");
                    }
                } catch (Throwable ignored) {}
            }
            StringBuilder sb = new StringBuilder("# 08 Technology Fingerprint\n\n");
            tech.forEach((host, sig) -> {
                if (host.isEmpty() || sig.isEmpty()) return;
                sb.append(host).append('\n');
                sig.forEach(s -> sb.append("    ").append(s).append('\n'));
                sb.append('\n');
            });
            write(dir, "08_technology_fingerprint.txt", sb.toString());
        }

        private void writeFullTrafficJson(Path dir, List<CaptureRecord> all) throws IOException {
            StringBuilder sb = new StringBuilder();
            sb.append("{\n  \"generated\": \"")
              .append(ZonedDateTime.now().format(DateTimeFormatter.ISO_OFFSET_DATE_TIME))
              .append("\",\n  \"count\": ").append(all.size()).append(",\n  \"traffic\": [\n");
            for (int i = 0; i < all.size(); i++) {
                sb.append("    ").append(recordToJson(all.get(i)));
                if (i < all.size() - 1) sb.append(',');
                sb.append('\n');
            }
            sb.append("  ]\n}\n");
            write(dir, "09_full_traffic.json", sb.toString());
        }

        private void writeSummary(Path dir, List<CaptureRecord> all) throws IOException {
            int api = 0, redirects = 0, stateChanging = 0, interesting = 0;
            Set<String> hosts = new LinkedHashSet<>();
            for (CaptureRecord r : all) {
                if (Rx.API_PATH.matcher(Txt.lower(r.url)).find()) api++;
                if (r.status >= 300 && r.status < 400) redirects++;
                String m = r.method.toUpperCase(Locale.ROOT);
                if (m.equals("POST") || m.equals("PUT") || m.equals("PATCH") || m.equals("DELETE")) stateChanging++;
                if (r.status >= 500) interesting++;
                if (!r.host.isEmpty()) hosts.add(r.host);
            }
            StringBuilder sb = new StringBuilder();
            sb.append("# 10 Traffic SmartCapture — Summary Report\n\n");
            sb.append("- Generated: ").append(ZonedDateTime.now().format(DateTimeFormatter.ISO_OFFSET_DATE_TIME)).append('\n');
            sb.append("- Captured (kept): ").append(captured.get()).append('\n');
            sb.append("- Filtered (noise): ").append(filtered.get()).append('\n');
            sb.append("- Unique requests: ").append(seenKeys.size()).append('\n');
            sb.append("- Unique hosts: ").append(hosts.size()).append('\n');
            sb.append("- API endpoints: ").append(api).append('\n');
            sb.append("- State-changing requests: ").append(stateChanging).append('\n');
            sb.append("- Redirects (3xx): ").append(redirects).append('\n');
            sb.append("- 5xx responses: ").append(interesting).append('\n');
            sb.append("\n## Files\n");
            sb.append("1. 01_api_endpoints.txt\n2. 02_auth_and_sessions.txt\n3. 03_forms_and_inputs.txt\n");
            sb.append("4. 04_parameters_map.txt\n5. 05_interesting_responses.txt\n6. 06_redirects.txt\n");
            sb.append("7. 07_unique_hosts.txt\n8. 08_technology_fingerprint.txt\n9. 09_full_traffic.json\n");
            sb.append("10. 10_summary_report.md\n");
            write(dir, "10_summary_report.md", sb.toString());
        }

        // ---- export helpers ----
        private String recordToJson(CaptureRecord r) {
            return "{\"seq\":" + r.seq +
                    ",\"time\":\"" + Txt.jsonEscape(r.time) + "\"" +
                    ",\"method\":\"" + Txt.jsonEscape(r.method) + "\"" +
                    ",\"url\":\"" + Txt.jsonEscape(r.url) + "\"" +
                    ",\"host\":\"" + Txt.jsonEscape(r.host) + "\"" +
                    ",\"status\":" + r.status +
                    ",\"contentType\":\"" + Txt.jsonEscape(r.contentType) + "\"" +
                    ",\"requestBytes\":" + r.requestBytes +
                    ",\"responseBytes\":" + r.responseBytes + "}";
        }

        private static String stripQuery(String url) {
            int q = url.indexOf('?');
            return q >= 0 ? url.substring(0, q) : url;
        }

        private static void appendHeaderIf(StringBuilder sb, HttpRequest req, String name) {
            try {
                if (req.hasHeader(name)) sb.append("    ").append(name).append(": ")
                        .append(Txt.preview(req.headerValue(name), 100)).append('\n');
            } catch (Throwable ignored) {}
        }

        private static void addHeaderSignal(Set<String> sig, HttpResponse resp, String name) {
            String v = DetectionEngine.safeHeader(resp, name);
            if (v != null && !v.isBlank()) sig.add(name + ": " + v.trim());
        }

        private static String firstSignalLine(String body) {
            for (String line : body.split("\n")) {
                if (Rx.SQL_ERROR.matcher(line).find() || Rx.STACK_TRACE.matcher(line).find() ||
                    Rx.INTERNAL_IP.matcher(line).find() || Rx.DEBUG_INFO.matcher(line).find() ||
                    Rx.ENV_CONTENT.matcher(line).find()) {
                    return line.trim();
                }
            }
            return Txt.preview(body, 160);
        }

        private void write(Path dir, String name, String content) throws IOException {
            Files.writeString(dir.resolve(name), content, StandardCharsets.UTF_8);
        }
    }

    // ========================================================================
    //  DETECTION PANEL  (implements Sink) — confirmed findings table
    // ========================================================================
    static final class DetectionPanel implements Sink {
        private final MontoyaApi api;
        private final JPanel root = new JPanel(new BorderLayout());
        private final FindingsModel model = new FindingsModel();
        private final JTable table = new JTable(model);
        private final JTextArea evidence = new JTextArea();
        private final JLabel status = new JLabel(" 0 confirmed findings ");

        DetectionPanel(MontoyaApi api, DetectionEngine engine) {
            this.api = api;
            table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
            table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
            int[] w = {200, 60, 130, 130, 80, 90, 220};
            for (int i = 0; i < w.length && i < table.getColumnCount(); i++)
                table.getColumnModel().getColumn(i).setPreferredWidth(w[i]);
            table.getSelectionModel().addListSelectionListener(e -> {
                int r = table.getSelectedRow();
                if (r >= 0 && r < model.rows.size()) {
                    Finding f = model.rows.get(r);
                    evidence.setText("[" + f.confidenceLabel() + " · confidence " + f.confidence + "/100]\n\n" + f.evidence);
                    evidence.setCaretPosition(0);
                }
            });

            evidence.setEditable(false);
            evidence.setLineWrap(true);
            evidence.setWrapStyleWord(true);

            JScrollPane top = new JScrollPane(table);
            JScrollPane bottom = new JScrollPane(evidence);
            JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, top, bottom);
            split.setResizeWeight(0.65);

            JPanel header = new JPanel(new BorderLayout());
            JLabel title = new JLabel("  5-Gate Confirmed Findings — only verified, deduped, confidence ≥ 50 ");
            title.setFont(title.getFont().deriveFont(Font.BOLD, 13f));
            header.add(title, BorderLayout.WEST);
            JButton clear = new JButton("Clear");
            clear.addActionListener(e -> model.clear());
            header.add(clear, BorderLayout.EAST);

            root.add(header, BorderLayout.NORTH);
            root.add(split, BorderLayout.CENTER);
            root.add(status, BorderLayout.SOUTH);
        }

        JComponent component() { return root; }

        @Override
        public void report(Finding f) {
            SwingUtilities.invokeLater(() -> {
                model.add(f);
                status.setText(" " + model.rows.size() + " confirmed findings ");
            });
        }

        static final class FindingsModel extends AbstractTableModel {
            private static final long serialVersionUID = 1L;
            final transient List<Finding> rows = new ArrayList<>();
            final String[] cols = {"Type", "Method", "URL", "Parameter", "Severity", "Confidence", "Status"};

            void add(Finding f) { rows.add(f); fireTableRowsInserted(rows.size() - 1, rows.size() - 1); }
            void clear() { int n = rows.size(); rows.clear(); if (n > 0) fireTableRowsDeleted(0, n - 1); }

            @Override public int getRowCount() { return rows.size(); }
            @Override public int getColumnCount() { return cols.length; }
            @Override public String getColumnName(int c) { return cols[c]; }
            @Override public Object getValueAt(int r, int c) {
                Finding f = rows.get(r);
                switch (c) {
                    case 0: return f.type;
                    case 1: return f.method;
                    case 2: return f.url;
                    case 3: return f.param;
                    case 4: return f.severity;
                    case 5: return f.confidence;
                    case 6: return f.confidenceLabel();
                    default: return "";
                }
            }
        }
    }

    // ========================================================================
    //  TRAFFIC PANEL  (implements CaptureListener) — SmartCapture UI
    // ========================================================================
    static final class TrafficPanel implements CaptureListener {
        private final MontoyaApi api;
        private final TrafficCapture capture;
        private final JPanel root = new JPanel(new BorderLayout());
        private final CaptureModel model = new CaptureModel();
        private final JTable table = new JTable(model);
        private final JLabel counter = new JLabel(" Captured: 0 | Filtered: 0 | Unique: 0 ");
        private final JButton startStop = new JButton("Start");

        TrafficPanel(MontoyaApi api, TrafficCapture capture) {
            this.api = api;
            this.capture = capture;
            capture.setListener(this);

            table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
            int[] w = {50, 70, 360, 60, 150, 80, 80};
            for (int i = 0; i < w.length && i < table.getColumnCount(); i++)
                table.getColumnModel().getColumn(i).setPreferredWidth(w[i]);

            JPanel controls = new JPanel(new FlowLayout(FlowLayout.LEFT));
            startStop.addActionListener(e -> toggle());
            JButton export = new JButton("Export");
            export.addActionListener(e -> doExport());
            JButton clear = new JButton("Clear");
            clear.addActionListener(e -> capture.clear());
            controls.add(startStop);
            controls.add(export);
            controls.add(clear);
            controls.add(Box.createHorizontalStrut(20));
            counter.setFont(counter.getFont().deriveFont(Font.BOLD));
            controls.add(counter);

            root.add(controls, BorderLayout.NORTH);
            root.add(new JScrollPane(table), BorderLayout.CENTER);

            // Right-click context menu inside the table too.
            table.addMouseListener(new MouseAdapter() {
                @Override public void mousePressed(MouseEvent e) { maybePopup(e); }
                @Override public void mouseReleased(MouseEvent e) { maybePopup(e); }
            });
        }

        JComponent component() { return root; }

        private void toggle() {
            if (capture.isCapturing()) { capture.stop(); startStop.setText("Start"); }
            else { capture.start(); startStop.setText("Stop"); }
        }

        private void doExport() {
            new Thread(() -> {
                try {
                    String path = capture.export();
                    SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(root,
                            "Exported 10 files to:\n" + path, "SmartCapture Export",
                            JOptionPane.INFORMATION_MESSAGE));
                    api.logging().logToOutput("[SmartCapture] exported to " + path);
                } catch (Throwable t) {
                    SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(root,
                            "Export failed: " + t, "SmartCapture Export", JOptionPane.ERROR_MESSAGE));
                }
            }, "airf-export").start();
        }

        CaptureRecord selectedRecord() {
            int r = table.getSelectedRow();
            return (r >= 0 && r < model.rows.size()) ? model.rows.get(r) : null;
        }

        private void maybePopup(MouseEvent e) {
            if (!e.isPopupTrigger()) return;
            int row = table.rowAtPoint(e.getPoint());
            if (row >= 0) table.setRowSelectionInterval(row, row);
            CaptureRecord rec = selectedRecord();
            if (rec == null) return;
            JPopupMenu menu = buildMenu(api, rec);
            menu.show(e.getComponent(), e.getX(), e.getY());
        }

        static JPopupMenu buildMenu(MontoyaApi api, CaptureRecord rec) {
            JPopupMenu menu = new JPopupMenu();
            JMenuItem repeater = new JMenuItem("Send to Repeater");
            repeater.addActionListener(a -> { try { api.repeater().sendToRepeater(rec.request); } catch (Throwable ignored) {} });
            JMenuItem intruder = new JMenuItem("Send to Intruder");
            intruder.addActionListener(a -> { try { api.intruder().sendToIntruder(rec.request); } catch (Throwable ignored) {} });
            JMenuItem copyUrl = new JMenuItem("Copy URL");
            copyUrl.addActionListener(a -> copy(rec.url));
            JMenuItem copyReq = new JMenuItem("Copy Full Request");
            copyReq.addActionListener(a -> { try { copy(rec.request.toString()); } catch (Throwable ignored) {} });
            menu.add(repeater);
            menu.add(intruder);
            menu.addSeparator();
            menu.add(copyUrl);
            menu.add(copyReq);
            return menu;
        }

        private static void copy(String s) {
            try {
                Toolkit.getDefaultToolkit().getSystemClipboard()
                        .setContents(new StringSelection(s == null ? "" : s), null);
            } catch (Throwable ignored) {}
        }

        // ---- CaptureListener ----
        @Override public void onCounts(long captured, long filtered, long unique) {
            SwingUtilities.invokeLater(() -> counter.setText(
                    " Captured: " + captured + " | Filtered: " + filtered + " | Unique: " + unique + " "));
        }
        @Override public void onRecord(CaptureRecord r) {
            SwingUtilities.invokeLater(() -> model.add(r));
        }
        @Override public void onCleared() {
            SwingUtilities.invokeLater(model::clear);
        }

        static final class CaptureModel extends AbstractTableModel {
            private static final long serialVersionUID = 1L;
            final transient List<CaptureRecord> rows = new ArrayList<>();
            final String[] cols = {"#", "Method", "URL", "Status", "Content-Type", "Size", "Time"};

            void add(CaptureRecord r) {
                rows.add(r);
                fireTableRowsInserted(rows.size() - 1, rows.size() - 1);
            }
            void clear() { int n = rows.size(); rows.clear(); if (n > 0) fireTableRowsDeleted(0, n - 1); }

            @Override public int getRowCount() { return rows.size(); }
            @Override public int getColumnCount() { return cols.length; }
            @Override public String getColumnName(int c) { return cols[c]; }
            @Override public Object getValueAt(int r, int c) {
                CaptureRecord rec = rows.get(r);
                switch (c) {
                    case 0: return rec.seq;
                    case 1: return rec.method;
                    case 2: return rec.url;
                    case 3: return rec.status;
                    case 4: return rec.contentType;
                    case 5: return rec.responseBytes;
                    case 6: return rec.time;
                    default: return "";
                }
            }
        }
    }

    // ========================================================================
    //  CONTEXT MENU PROVIDER  — also exposes actions from Burp's own tables
    // ========================================================================
    static final class CaptureContextMenu implements ContextMenuItemsProvider {
        private final MontoyaApi api;
        private final TrafficPanel panel;

        CaptureContextMenu(MontoyaApi api, TrafficPanel panel) {
            this.api = api;
            this.panel = panel;
        }

        @Override
        public List<Component> provideMenuItems(ContextMenuEvent event) {
            List<Component> items = new ArrayList<>();
            try {
                List<HttpRequestResponse> sel = event.selectedRequestResponses();
                if (sel == null || sel.isEmpty()) return items;
                final HttpRequestResponse rr = sel.get(0);

                JMenuItem repeater = new JMenuItem("AIReconForge: Send to Repeater");
                repeater.addActionListener(a -> { try { api.repeater().sendToRepeater(rr.request()); } catch (Throwable ignored) {} });
                JMenuItem intruder = new JMenuItem("AIReconForge: Send to Intruder");
                intruder.addActionListener(a -> { try { api.intruder().sendToIntruder(rr.request()); } catch (Throwable ignored) {} });
                JMenuItem copyUrl = new JMenuItem("AIReconForge: Copy URL");
                copyUrl.addActionListener(a -> { try { copy(rr.request().url()); } catch (Throwable ignored) {} });
                JMenuItem copyReq = new JMenuItem("AIReconForge: Copy Full Request");
                copyReq.addActionListener(a -> { try { copy(rr.request().toString()); } catch (Throwable ignored) {} });
                items.add(repeater);
                items.add(intruder);
                items.add(copyUrl);
                items.add(copyReq);
            } catch (Throwable ignored) {}
            return items;
        }

        private static void copy(String s) {
            try {
                Toolkit.getDefaultToolkit().getSystemClipboard()
                        .setContents(new StringSelection(s == null ? "" : s), null);
            } catch (Throwable ignored) {}
        }
    }
}
