package report

// EXPANSION 5 — INTERACTIVE EMBEDDED DASHBOARD SERVER
//
// A lightweight, zero-dependency (net/http only) web server that parses a
// scan's final_report.json and serves an interactive HTML/CSS/JS dashboard:
//
//   • Total scan summary metrics (subdomains, live hosts, URLs, findings)
//   • Interactive finding filters by severity (Critical/High/Medium/Low/Info)
//   • One-click "Copy HackerOne Report" button per finding
//
// CLI: ./mohammed report --serve --port 8090 [--report path/to/final_report.json]

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ReportData is the parsed shape of final_report.json (see ReportPhase).
type ReportData struct {
	Subdomains int                      `json:"subdomains"`
	LiveHosts  int                      `json:"live_hosts"`
	URLs       int                      `json:"urls"`
	Counts     map[string]int           `json:"counts"`
	Findings   []map[string]interface{} `json:"findings"`
}

// LoadReportData reads and parses a final_report.json file.
func LoadReportData(path string) (*ReportData, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read report %s: %w", path, err)
	}
	var rd ReportData
	if err := json.Unmarshal(data, &rd); err != nil {
		return nil, fmt.Errorf("cannot parse report JSON: %w", err)
	}
	if rd.Counts == nil {
		rd.Counts = map[string]int{}
	}
	return &rd, nil
}

// FindLatestReport walks the output directory and returns the most recently
// modified final_report.json, or "" if none exists.
func FindLatestReport(outputDir string) string {
	var newest string
	var newestMod time.Time
	_ = filepath.Walk(outputDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		if filepath.Base(path) == "final_report.json" && info.ModTime().After(newestMod) {
			newest = path
			newestMod = info.ModTime()
		}
		return nil
	})
	return newest
}

// ServeDashboard starts a blocking HTTP server on addr (e.g. ":8090") that
// renders the dashboard for reportPath. It re-reads the JSON on every request
// so a live scan's updated report is reflected on refresh.
func ServeDashboard(addr, reportPath string) error {
	mux := http.NewServeMux()

	// Silence the browser's automatic favicon request (avoids a 404 in the
	// console) with a 1x1 transparent response.
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		_, _ = w.Write([]byte(`<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16"><text y="14" font-size="14">🛡️</text></svg>`))
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		rd, err := LoadReportData(reportPath)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "Failed to load report: %v", err)
			return
		}
		view := buildView(rd)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := dashboardTmpl.Execute(w, view); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "template error: %v", err)
		}
	})

	// JSON API endpoint for programmatic access / future SPA use.
	mux.HandleFunc("/api/report", func(w http.ResponseWriter, r *http.Request) {
		rd, err := LoadReportData(reportPath)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rd)
	})

	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	return srv.ListenAndServe()
}

// ─────────────────────────────────────────────────────────────────────────
// View model
// ─────────────────────────────────────────────────────────────────────────

type findingView struct {
	Title    string
	Severity string
	URL      string
	Tool     string
	Evidence string
	H1Report string // pre-formatted HackerOne report for the copy button
}

type dashboardView struct {
	Subdomains int
	LiveHosts  int
	URLs       int
	Total      int
	Counts     map[string]int
	Findings   []findingView
	Generated  string
}

// severityRank orders findings Critical→Info in the table.
func severityRank(sev string) int {
	switch strings.ToLower(sev) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	default:
		return 4
	}
}

func str(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok && v != nil {
		return fmt.Sprintf("%v", v)
	}
	return ""
}

// buildView converts raw report data into the template view model, generating
// a HackerOne report body for any finding that does not already carry one.
func buildView(rd *ReportData) dashboardView {
	fv := make([]findingView, 0, len(rd.Findings))
	for _, f := range rd.Findings {
		sev := str(f, "severity")
		if sev == "" {
			sev = "Info"
		}
		h1 := str(f, "h1_report")
		if strings.TrimSpace(h1) == "" {
			h1 = defaultH1Report(str(f, "title"), sev, str(f, "url"), str(f, "tool"), str(f, "evidence"))
		}
		fv = append(fv, findingView{
			Title:    str(f, "title"),
			Severity: sev,
			URL:      str(f, "url"),
			Tool:     str(f, "tool"),
			Evidence: str(f, "evidence"),
			H1Report: h1,
		})
	}
	sort.SliceStable(fv, func(i, j int) bool {
		return severityRank(fv[i].Severity) < severityRank(fv[j].Severity)
	})
	return dashboardView{
		Subdomains: rd.Subdomains,
		LiveHosts:  rd.LiveHosts,
		URLs:       rd.URLs,
		Total:      len(rd.Findings),
		Counts:     rd.Counts,
		Findings:   fv,
		Generated:  time.Now().Format("2006-01-02 15:04:05 MST"),
	}
}

// defaultH1Report generates a generic HackerOne-style report body for findings
// that did not ship their own (EXPANSION 5 copy button).
func defaultH1Report(title, sev, url, tool, evidence string) string {
	return fmt.Sprintf(`## Title
%s

## Severity
%s

## Affected Asset
%s

## Summary
This finding was identified by MOHAMMED (%s) during an authorized security
assessment.

## Evidence
%s

## Steps To Reproduce
1. Navigate to the affected asset: %s
2. Observe the behaviour described in the evidence above.

## Impact
See severity rating. Please review and validate before triage.
`, orNA(title), orNA(sev), orNA(url), orNA(tool), orNA(evidence), orNA(url))
}

func orNA(s string) string {
	if strings.TrimSpace(s) == "" {
		return "(not available)"
	}
	return s
}

// ─────────────────────────────────────────────────────────────────────────
// HTML template (self-contained: inline CSS + JS, no external assets)
// ─────────────────────────────────────────────────────────────────────────

var dashboardTmpl = template.Must(template.New("dashboard").Parse(dashboardHTML))

const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MOHAMMED-V5 · Scan Dashboard</title>
<style>
  :root{--bg:#0d1117;--panel:#161b22;--border:#30363d;--fg:#e6edf3;--muted:#8b949e;
    --crit:#f85149;--high:#ff7b72;--med:#d29922;--low:#3fb950;--info:#58a6ff;}
  *{box-sizing:border-box}
  body{margin:0;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,monospace;
    background:var(--bg);color:var(--fg);}
  header{padding:24px 32px;border-bottom:1px solid var(--border);background:var(--panel);}
  header h1{margin:0;font-size:22px;letter-spacing:1px;}
  header .sub{color:var(--muted);font-size:13px;margin-top:4px;}
  .wrap{padding:24px 32px;max-width:1200px;margin:0 auto;}
  .metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:24px;}
  .metric{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:18px;}
  .metric .n{font-size:30px;font-weight:700;}
  .metric .l{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:1px;margin-top:6px;}
  .sevbar{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:20px;}
  .filter{cursor:pointer;user-select:none;border:1px solid var(--border);background:var(--panel);
    border-radius:20px;padding:6px 14px;font-size:13px;transition:.15s;}
  .filter.active{outline:2px solid var(--info);}
  .filter .dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:6px;}
  .dot.Critical{background:var(--crit)}.dot.High{background:var(--high)}
  .dot.Medium{background:var(--med)}.dot.Low{background:var(--low)}.dot.Info{background:var(--info)}
  table{width:100%;border-collapse:collapse;background:var(--panel);
    border:1px solid var(--border);border-radius:10px;overflow:hidden;}
  th,td{text-align:left;padding:12px 14px;border-bottom:1px solid var(--border);font-size:13px;vertical-align:top;}
  th{color:var(--muted);text-transform:uppercase;font-size:11px;letter-spacing:1px;}
  tr:last-child td{border-bottom:none;}
  .badge{padding:3px 9px;border-radius:6px;font-size:11px;font-weight:700;}
  .badge.Critical{background:rgba(248,81,73,.15);color:var(--crit)}
  .badge.High{background:rgba(255,123,114,.15);color:var(--high)}
  .badge.Medium{background:rgba(210,153,34,.15);color:var(--med)}
  .badge.Low{background:rgba(63,185,80,.15);color:var(--low)}
  .badge.Info{background:rgba(88,166,255,.15);color:var(--info)}
  .url{word-break:break-all;color:var(--info);}
  .ev{color:var(--muted);word-break:break-word;max-width:340px;}
  button.copy{cursor:pointer;background:var(--info);color:#04101f;border:none;border-radius:6px;
    padding:7px 12px;font-size:12px;font-weight:700;white-space:nowrap;}
  button.copy.copied{background:var(--low);color:#04101f;}
  .empty{padding:30px;text-align:center;color:var(--muted);}
  footer{color:var(--muted);font-size:12px;padding:20px 32px;text-align:center;}
</style>
</head>
<body>
<header>
  <h1>🛡️ MOHAMMED-V5 · Interactive Scan Dashboard</h1>
  <div class="sub">Generated {{.Generated}} · zero-dependency embedded server</div>
</header>
<div class="wrap">
  <div class="metrics">
    <div class="metric"><div class="n">{{.Subdomains}}</div><div class="l">Subdomains</div></div>
    <div class="metric"><div class="n">{{.LiveHosts}}</div><div class="l">Live Hosts</div></div>
    <div class="metric"><div class="n">{{.URLs}}</div><div class="l">URLs Crawled</div></div>
    <div class="metric"><div class="n">{{.Total}}</div><div class="l">Total Findings</div></div>
  </div>

  <div class="sevbar">
    <div class="filter active" data-sev="all">All ({{.Total}})</div>
    <div class="filter" data-sev="Critical"><span class="dot Critical"></span>Critical ({{index .Counts "Critical"}})</div>
    <div class="filter" data-sev="High"><span class="dot High"></span>High ({{index .Counts "High"}})</div>
    <div class="filter" data-sev="Medium"><span class="dot Medium"></span>Medium ({{index .Counts "Medium"}})</div>
    <div class="filter" data-sev="Low"><span class="dot Low"></span>Low ({{index .Counts "Low"}})</div>
    <div class="filter" data-sev="Info"><span class="dot Info"></span>Info ({{index .Counts "Info"}})</div>
  </div>

  {{if .Findings}}
  <table id="tbl">
    <thead><tr><th>Severity</th><th>Title</th><th>Asset</th><th>Tool</th><th>Evidence</th><th>Action</th></tr></thead>
    <tbody>
    {{range $i, $f := .Findings}}
      <tr class="row" data-sev="{{$f.Severity}}">
        <td><span class="badge {{$f.Severity}}">{{$f.Severity}}</span></td>
        <td>{{$f.Title}}</td>
        <td class="url">{{$f.URL}}</td>
        <td>{{$f.Tool}}</td>
        <td class="ev">{{$f.Evidence}}</td>
        <td>
          <button class="copy" data-report="{{$f.H1Report}}">Copy HackerOne Report</button>
        </td>
      </tr>
    {{end}}
    </tbody>
  </table>
  {{else}}
  <div class="empty">No findings in this report.</div>
  {{end}}
</div>
<footer>MOHAMMED-V5 · Next-Gen Reconnaissance &amp; Vulnerability Engine</footer>

<script>
  // Severity filtering.
  const filters = document.querySelectorAll('.filter');
  filters.forEach(function(f){
    f.addEventListener('click', function(){
      filters.forEach(function(x){x.classList.remove('active');});
      f.classList.add('active');
      const sev = f.getAttribute('data-sev');
      document.querySelectorAll('.row').forEach(function(row){
        row.style.display = (sev === 'all' || row.getAttribute('data-sev') === sev) ? '' : 'none';
      });
    });
  });

  // One-click "Copy HackerOne Report".
  document.querySelectorAll('button.copy').forEach(function(btn){
    btn.addEventListener('click', function(){
      const text = btn.getAttribute('data-report') || '';
      const done = function(){
        const orig = btn.textContent;
        btn.textContent = '✓ Copied!';
        btn.classList.add('copied');
        setTimeout(function(){ btn.textContent = orig; btn.classList.remove('copied'); }, 1600);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done, function(){ fallbackCopy(text); done(); });
      } else { fallbackCopy(text); done(); }
    });
  });
  function fallbackCopy(text){
    const ta = document.createElement('textarea');
    ta.value = text; document.body.appendChild(ta); ta.select();
    try { document.execCommand('copy'); } catch(e){}
    document.body.removeChild(ta);
  }
</script>
</body>
</html>`
