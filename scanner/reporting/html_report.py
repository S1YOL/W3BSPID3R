from __future__ import annotations
"""
scanner/reporting/html_report.py
----------------------------------
Generates a self-contained, professional HTML vulnerability report.

Features:
  - Single-file output (CSS embedded in <style>) — no external dependencies
  - Severity-coded colour scheme matching CVSS tiers
  - Collapsible finding cards for easy navigation
  - Summary statistics bar chart (pure CSS, no JavaScript required)
  - Print-friendly stylesheet
"""

import html
import logging
from pathlib import Path

from scanner.reporting.models import Finding, ScanSummary, Severity

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Severity → CSS class mapping
# ---------------------------------------------------------------------------
_SEV_CLASS = {
    Severity.CRITICAL: "critical",
    Severity.HIGH:     "high",
    Severity.MEDIUM:   "medium",
    Severity.LOW:      "low",
}


def write_html_report(summary: ScanSummary, output_path: str) -> Path:
    """
    Write a self-contained HTML vulnerability report.

    Args:
        summary     : Completed ScanSummary from the scanner.
        output_path : Destination .html file path.

    Returns:
        Path object of the written report.
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as fh:
        fh.write(_build_html(summary))

    logger.info("HTML report written to %s", path)
    return path


# ---------------------------------------------------------------------------
# HTML builder
# ---------------------------------------------------------------------------

def _build_html(summary: ScanSummary) -> str:
    findings = summary.sorted_findings()
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>W3BSP1D3R — {html.escape(summary.target_url)}</title>
{_CSS}
</head>
<body>
{_build_header(summary)}
{_build_summary_section(summary)}
{_build_findings_section(findings)}
{_build_footer()}
</body>
</html>"""


def _build_header(summary: ScanSummary) -> str:
    return f"""
<header>
  <div class="scanner-badge">W3BSP1D3R v1.0.0 — by S1YOL</div>
  <h1>Web Vulnerability Scan Report</h1>
  <div class="meta-grid">
    <div class="meta-item"><span class="label">Target</span><code>{html.escape(summary.target_url)}</code></div>
    <div class="meta-item"><span class="label">Scan Type</span>{html.escape(summary.scan_type)}</div>
    <div class="meta-item"><span class="label">Started</span>{html.escape(summary.started_at)}</div>
    <div class="meta-item"><span class="label">Finished</span>{html.escape(summary.finished_at)}</div>
  </div>
  <div class="warning-banner">
    ⚠️ AUTHORISED TESTING ONLY — I AM NOT RESPONSIBLE FOR ANYONE USING THIS APP.
    Scanning without authorization is a federal crime under the Computer Fraud and Abuse Act (CFAA, 18 U.S.C. § 1030).
    Only use against systems you own or have explicit written permission to test.
  </div>
</header>"""


def _build_summary_section(summary: ScanSummary) -> str:
    total = summary.total_findings or 1  # avoid division by zero in bar calc

    def bar(count: int, css_class: str) -> str:
        pct = min(int((count / total) * 100), 100)
        return (
            f'<div class="bar-row">'
            f'<span class="bar-label {css_class}">{css_class.upper()}</span>'
            f'<div class="bar-track"><div class="bar-fill {css_class}" style="width:{pct}%"></div></div>'
            f'<span class="bar-count">{count}</span>'
            f'</div>'
        )

    return f"""
<section class="summary">
  <h2>Executive Summary</h2>
  <div class="stats-grid">
    <div class="stat-box"><div class="stat-num">{summary.pages_crawled}</div><div class="stat-label">Pages Crawled</div></div>
    <div class="stat-box"><div class="stat-num">{summary.forms_found}</div><div class="stat-label">Forms Found</div></div>
    <div class="stat-box"><div class="stat-num">{summary.params_tested}</div><div class="stat-label">Params Tested</div></div>
    <div class="stat-box highlight"><div class="stat-num">{summary.total_findings}</div><div class="stat-label">Total Findings</div></div>
  </div>
  <h3>Severity Breakdown</h3>
  <div class="bar-chart">
    {bar(summary.critical_count, 'critical')}
    {bar(summary.high_count,     'high')}
    {bar(summary.medium_count,   'medium')}
    {bar(summary.low_count,      'low')}
  </div>
</section>"""


def _build_findings_section(findings: list[Finding]) -> str:
    if not findings:
        return """
<section class="findings">
  <h2>Findings</h2>
  <p class="no-findings">✅ No vulnerabilities detected during this scan.</p>
</section>"""

    cards = "\n".join(_build_finding_card(i + 1, f) for i, f in enumerate(findings))
    return f"""
<section class="findings">
  <h2>Findings <span class="count-badge">{len(findings)}</span></h2>
  {cards}
</section>"""


def _build_finding_card(idx: int, f: Finding) -> str:
    sev_class = _SEV_CLASS.get(f.severity, "low")
    return f"""
<details class="finding-card {sev_class}" open>
  <summary>
    <span class="finding-num">#{idx}</span>
    <span class="finding-title">{html.escape(f.vuln_type)}</span>
    <span class="sev-badge {sev_class}">{html.escape(f.severity)}</span>
  </summary>
  <div class="finding-body">
    <table class="meta-table">
      <tr><th>URL</th><td><code>{html.escape(f.url)}</code></td></tr>
      <tr><th>Parameter</th><td><code>{html.escape(f.parameter)}</code></td></tr>
      <tr><th>Method</th><td><code>{html.escape(f.method)}</code></td></tr>
      <tr><th>Timestamp</th><td>{html.escape(f.timestamp)}</td></tr>
    </table>
    <h4>Proof-of-Concept Payload</h4>
    <pre class="payload">{html.escape(f.payload)}</pre>
    <h4>Evidence</h4>
    <blockquote class="evidence">{html.escape(f.evidence)}</blockquote>
    <h4>Remediation</h4>
    <div class="remediation">{html.escape(f.remediation)}</div>
  </div>
</details>"""


def _build_footer() -> str:
    return """
<footer>
  <p>Generated by <strong>W3BSP1D3R</strong> — by S1YOL.</p>
  <p class="legal">This report is confidential. Unauthorised distribution may violate applicable law.</p>
</footer>"""


# ---------------------------------------------------------------------------
# Embedded CSS (single-file report — no external dependencies)
# ---------------------------------------------------------------------------
_CSS = """<style>
:root {
  --critical: #dc2626;  --critical-bg: #fee2e2;
  --high:     #ea580c;  --high-bg:     #fff0e6;
  --medium:   #ca8a04;  --medium-bg:   #fef9c3;
  --low:      #2563eb;  --low-bg:      #dbeafe;
  --bg:       #ffffff;
  --surface:  #f5f5f5;
  --border:   #e0e0e0;
  --text:     #111111;
  --muted:    #666666;
  --accent:   #cc0000;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg);
       color: var(--text); line-height: 1.6; padding: 2rem; }
a { color: var(--accent); }
code, pre { font-family: 'Cascadia Code', 'Fira Code', 'Courier New', monospace; }
h1 { font-size: 2rem; margin-bottom: .5rem; color: var(--text); }
h2 { font-size: 1.4rem; color: var(--accent); margin: 2rem 0 1rem;
     border-bottom: 2px solid var(--accent); padding-bottom: .25rem; }
h3 { font-size: 1.1rem; color: var(--muted); margin: 1rem 0 .5rem; }
h4 { font-size: .9rem; color: var(--muted); margin: 1rem 0 .25rem;
     text-transform: uppercase; letter-spacing: .05em; }

/* Header */
header { border-bottom: 2px solid var(--accent); padding-bottom: 1.5rem; margin-bottom: 1.5rem; }
.scanner-badge { display: inline-block; background: var(--accent); color: #ffffff;
                 font-size: .75rem; font-weight: 700; padding: .2rem .6rem;
                 border-radius: 4px; margin-bottom: .75rem; letter-spacing: .05em; }
.meta-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
             gap: .5rem; margin: 1rem 0; }
.meta-item { background: var(--surface); border: 1px solid var(--border);
             border-radius: 6px; padding: .5rem .75rem; }
.label { display: block; font-size: .75rem; color: var(--muted); text-transform: uppercase;
         letter-spacing: .05em; margin-bottom: .15rem; }
.warning-banner { background: #fff5f5; border: 1px solid #cc0000; border-radius: 6px;
                  padding: .75rem 1rem; margin-top: 1rem; color: #991b1b; font-size: .9rem; }

/* Summary */
.summary { background: var(--surface); border: 1px solid var(--border);
           border-radius: 8px; padding: 1.5rem; margin-bottom: 2rem; }
.stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-bottom: 1.5rem; }
.stat-box { text-align: center; background: var(--bg); border: 1px solid var(--border);
            border-radius: 6px; padding: 1rem; }
.stat-box.highlight { border: 2px solid var(--accent); }
.stat-num { font-size: 2rem; font-weight: 700; color: var(--accent); }
.stat-label { font-size: .8rem; color: var(--muted); }

/* Bar chart */
.bar-chart { display: flex; flex-direction: column; gap: .5rem; }
.bar-row { display: grid; grid-template-columns: 80px 1fr 40px; gap: .75rem; align-items: center; }
.bar-label { font-size: .75rem; font-weight: 700; text-align: right; }
.bar-track { background: var(--border); border-radius: 4px; height: 20px; overflow: hidden; }
.bar-fill { height: 100%; border-radius: 4px; transition: width .3s; }
.bar-count { font-size: .85rem; font-weight: 700; }
.bar-label.critical, .bar-fill.critical, .bar-count { color: var(--critical); }
.bar-fill.critical { background: var(--critical); }
.bar-label.high, .bar-fill.high { color: var(--high); }
.bar-fill.high { background: var(--high); }
.bar-label.medium { color: var(--medium); }
.bar-fill.medium { background: var(--medium); }
.bar-label.low { color: var(--low); }
.bar-fill.low { background: var(--low); }

/* Finding cards */
.findings { display: flex; flex-direction: column; gap: 1rem; }
.count-badge { background: var(--accent); color: #ffffff; font-size: .8rem;
               padding: .15rem .5rem; border-radius: 99px; margin-left: .5rem; }
.no-findings { color: #166534; background: #f0fdf4; border: 1px solid #bbf7d0;
               border-radius: 6px; padding: 1rem; }
.finding-card { border-radius: 8px; overflow: hidden; border: 1px solid var(--border);
                box-shadow: 0 1px 3px rgba(0,0,0,.08); }
.finding-card > summary { list-style: none; cursor: pointer; padding: .75rem 1rem;
                           display: flex; align-items: center; gap: .75rem;
                           font-weight: 600; user-select: none; }
.finding-card > summary::-webkit-details-marker { display: none; }
.finding-card.critical > summary { background: var(--critical-bg); color: #7f1d1d; }
.finding-card.high     > summary { background: var(--high-bg);     color: #7c2d12; }
.finding-card.medium   > summary { background: var(--medium-bg);   color: #713f12; }
.finding-card.low      > summary { background: var(--low-bg);      color: #1e3a8a; }
.finding-num { font-size: .8rem; opacity: .7; }
.finding-title { flex: 1; }
.sev-badge { font-size: .75rem; font-weight: 700; padding: .2rem .6rem; border-radius: 4px; }
.sev-badge.critical { background: var(--critical); color: white; }
.sev-badge.high     { background: var(--high);     color: white; }
.sev-badge.medium   { background: var(--medium);   color: white; }
.sev-badge.low      { background: var(--low);      color: white; }
.finding-body { padding: 1rem 1.25rem; background: var(--bg); border-top: 1px solid var(--border); }

.meta-table { width: 100%; border-collapse: collapse; margin-bottom: .75rem; font-size: .9rem; }
.meta-table th { width: 120px; text-align: left; color: var(--muted); padding: .25rem 0;
                 font-weight: 500; }
.meta-table td code { background: var(--surface); border: 1px solid var(--border);
                       padding: .1rem .4rem; border-radius: 4px;
                       font-size: .85rem; word-break: break-all; color: var(--accent); }

.payload { background: #fff5f5; border-left: 3px solid var(--accent);
           padding: .75rem 1rem; border-radius: 0 6px 6px 0; font-size: .85rem;
           overflow-x: auto; white-space: pre-wrap; word-break: break-all;
           color: #991b1b; }

blockquote.evidence { border-left: 3px solid var(--border); padding: .5rem 1rem;
                      color: var(--muted); font-size: .9rem; font-style: italic; margin: .5rem 0; }

.remediation { background: #fff5f5; border: 1px solid #fca5a5; border-radius: 6px;
               padding: .75rem 1rem; color: #991b1b; font-size: .9rem; margin-top: .25rem; }

/* Footer */
footer { border-top: 2px solid var(--accent); margin-top: 3rem; padding-top: 1rem;
         color: var(--muted); font-size: .8rem; }
.legal { margin-top: .25rem; font-style: italic; }

@media print {
  body { background: white; color: black; }
  .finding-card > summary { background: #f3f4f6 !important; color: black !important; }
  .finding-body { background: white !important; }
}
</style>"""
