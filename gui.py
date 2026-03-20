#!/usr/bin/env python3
from __future__ import annotations
"""
gui.py — Streamlit GUI for W3BSP1D3R.

Usage:
  streamlit run gui.py

by S1YOL.

⚠️  LEGAL WARNING ⚠️
  I AM NOT RESPONSIBLE FOR ANYONE USING THIS APP.
  Scanning without authorization is a FEDERAL CRIME under the Computer Fraud
  and Abuse Act (CFAA, 18 U.S.C. § 1030). Only scan systems you own or have
  explicit written permission to test.
"""

import logging
import sys
import time
import threading
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path

import streamlit as st

# ---------------------------------------------------------------------------
# Page configuration — must be the first Streamlit call
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="W3BSP1D3R — Web Vulnerability Scanner",
    page_icon="🕷️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Imports from the scanner package (after sys.path is already correct since
# gui.py lives next to the scanner/ directory)
# ---------------------------------------------------------------------------
from scanner.core import WebVulnScanner
from scanner.reporting.models import Severity

# ---------------------------------------------------------------------------
# Logging — send scanner log output to a buffer we can display
# ---------------------------------------------------------------------------
_log_buffer = StringIO()
logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
    handlers=[logging.StreamHandler(_log_buffer)],
    force=True,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SCAN_TYPES = {
    "Full Scan (all tests)":             "full",
    "Passive Only (headers + files + CVE)": "passive",
    "SQL Injection":                     "sqli",
    "Cross-Site Scripting (XSS)":        "xss",
    "CSRF":                              "csrf",
    "Security Headers":                  "headers",
    "Sensitive Files":                   "files",
    "Path Traversal":                    "traversal",
    "Open Redirect":                     "redirect",
    "Command Injection":                 "cmdi",
    "CVE Lookup":                        "cve",
}

SEV_COLORS = {
    "Critical": "#ff0000",
    "High":     "#ff4444",
    "Medium":   "#ffaa00",
    "Low":      "#00cccc",
}

SEV_EMOJI = {
    "Critical": "🔴",
    "High":     "🟠",
    "Medium":   "🟡",
    "Low":      "🔵",
}

# ---------------------------------------------------------------------------
# Custom CSS
# ---------------------------------------------------------------------------
st.markdown("""
<style>
    /* Dark hacker theme overrides */
    .stApp { background-color: #0a0a0a; }

    .banner-box {
        background: linear-gradient(135deg, #1a0000 0%, #0a0a0a 100%);
        border: 1px solid #ff0000;
        border-radius: 8px;
        padding: 20px;
        margin-bottom: 20px;
        text-align: center;
        font-family: monospace;
    }
    .banner-title {
        color: #ff0000;
        font-size: 2em;
        font-weight: bold;
        letter-spacing: 4px;
    }
    .banner-sub {
        color: #888;
        font-size: 0.9em;
    }

    .finding-card {
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 12px;
        border-left: 4px solid;
    }
    .finding-critical { background: #1a0000; border-left-color: #ff0000; }
    .finding-high     { background: #1a0800; border-left-color: #ff4444; }
    .finding-medium   { background: #1a1400; border-left-color: #ffaa00; }
    .finding-low      { background: #001a1a; border-left-color: #00cccc; }

    .metric-card {
        background: #111;
        border: 1px solid #333;
        border-radius: 8px;
        padding: 16px;
        text-align: center;
    }
    .metric-value {
        font-size: 2em;
        font-weight: bold;
    }
    .metric-label {
        color: #888;
        font-size: 0.85em;
    }

    .warning-box {
        background: #1a0000;
        border: 1px solid #ff0000;
        border-radius: 8px;
        padding: 12px;
        color: #ff4444;
        font-size: 0.85em;
        margin-bottom: 16px;
    }
</style>
""", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
st.markdown("""
<div class="banner-box">
    <div class="banner-title">W3BSP1D3R</div>
    <div class="banner-sub">Web Vulnerability Scanner by S1YOL</div>
</div>
""", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Sidebar — scan configuration
# ---------------------------------------------------------------------------
with st.sidebar:
    st.markdown("## Scan Configuration")

    st.markdown("""
    <div class="warning-box">
        ⚠️ <b>AUTHORISED TESTING ONLY</b><br>
        Only scan systems you own or have explicit written permission to test.
        Unauthorised scanning is illegal under the CFAA.
    </div>
    """, unsafe_allow_html=True)

    # Target URL
    target_url = st.text_input(
        "Target URL",
        placeholder="http://localhost/dvwa",
        help="The base URL of the web application to scan.",
    )

    # Scan type
    scan_type_label = st.selectbox("Scan Type", list(SCAN_TYPES.keys()))
    scan_type = SCAN_TYPES[scan_type_label]

    # Authentication
    st.markdown("#### Authentication (optional)")
    login_user = st.text_input("Username", placeholder="admin")
    login_pass = st.text_input("Password", placeholder="password", type="password")

    # Advanced settings
    with st.expander("Advanced Settings"):
        max_pages = st.slider("Max Pages to Crawl", 1, 500, 50)
        threads = st.slider("Concurrent Threads", 1, 16, 4)
        delay = st.slider("Request Delay (seconds)", 0.0, 5.0, 0.5, step=0.1)
        timeout = st.slider("Request Timeout (seconds)", 1, 60, 10)
        verify_ssl = st.checkbox("Verify SSL Certificates", value=True)
        output_name = st.text_input("Report Filename", value="scan_report",
                                    help="Base name for report files (no extension).")

    # API keys
    with st.expander("API Keys (optional)"):
        vt_api_key = st.text_input(
            "VirusTotal API Key",
            type="password",
            help="Free key from virustotal.com — enables threat intelligence checks.",
        )
        vt_delay = st.number_input("VT Request Delay (sec)", value=15.0, min_value=1.0)
        nvd_api_key = st.text_input(
            "NVD API Key",
            type="password",
            help="Free key from nvd.nist.gov — speeds up CVE lookups.",
        )

    # Start button
    start_scan = st.button("Start Scan", type="primary", use_container_width=True)


# ---------------------------------------------------------------------------
# Helper: run the scan and store results in session state
# ---------------------------------------------------------------------------
def _run_scan():
    """Execute the scanner and put the ScanSummary in session state."""
    # Sanitize output path
    cwd = Path.cwd()
    resolved = (cwd / output_name).resolve()
    try:
        resolved.relative_to(cwd)
    except ValueError:
        st.session_state["scan_error"] = "Invalid report path — must stay within the project directory."
        return
    safe_output = str(resolved.with_suffix(""))

    scanner = WebVulnScanner(
        url=target_url,
        scan_type=scan_type,
        login_user=login_user or None,
        login_pass=login_pass or None,
        output=safe_output,
        max_pages=max_pages,
        delay=delay,
        timeout=timeout,
        verify_ssl=verify_ssl,
        threads=threads,
        vt_api_key=vt_api_key or None,
        vt_delay=vt_delay,
        nvd_api_key=nvd_api_key or None,
    )

    try:
        summary = scanner.scan()
        st.session_state["scan_summary"] = summary
        st.session_state["scan_error"] = None
    except Exception as exc:
        st.session_state["scan_error"] = str(exc)
        st.session_state["scan_summary"] = None


# ---------------------------------------------------------------------------
# Main area — scan execution and results
# ---------------------------------------------------------------------------
if start_scan:
    # Validate inputs
    if not target_url:
        st.error("Please enter a target URL.")
    elif not target_url.startswith(("http://", "https://")):
        st.error("URL must start with **http://** or **https://**")
    elif (bool(login_user) != bool(login_pass)):
        st.error("Provide both username and password, or leave both empty.")
    else:
        with st.spinner("Scanning in progress — this may take a few minutes..."):
            _run_scan()

        if st.session_state.get("scan_error"):
            st.error(f"Scan failed: {st.session_state['scan_error']}")

# ---------------------------------------------------------------------------
# Display results if we have them
# ---------------------------------------------------------------------------
summary = st.session_state.get("scan_summary")

if summary:
    st.markdown("---")
    st.markdown("## Scan Results")

    # ---- Metric cards ----
    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.markdown(f"""<div class="metric-card">
            <div class="metric-value" style="color: #ff0000;">{summary.critical_count}</div>
            <div class="metric-label">Critical</div>
        </div>""", unsafe_allow_html=True)
    with col2:
        st.markdown(f"""<div class="metric-card">
            <div class="metric-value" style="color: #ff4444;">{summary.high_count}</div>
            <div class="metric-label">High</div>
        </div>""", unsafe_allow_html=True)
    with col3:
        st.markdown(f"""<div class="metric-card">
            <div class="metric-value" style="color: #ffaa00;">{summary.medium_count}</div>
            <div class="metric-label">Medium</div>
        </div>""", unsafe_allow_html=True)
    with col4:
        st.markdown(f"""<div class="metric-card">
            <div class="metric-value" style="color: #00cccc;">{summary.low_count}</div>
            <div class="metric-label">Low</div>
        </div>""", unsafe_allow_html=True)
    with col5:
        st.markdown(f"""<div class="metric-card">
            <div class="metric-value" style="color: #ffffff;">{summary.total_findings}</div>
            <div class="metric-label">Total</div>
        </div>""", unsafe_allow_html=True)

    st.markdown("")

    # ---- Scan info ----
    with st.expander("Scan Details", expanded=True):
        info_col1, info_col2 = st.columns(2)
        with info_col1:
            st.markdown(f"**Target:** `{summary.target_url}`")
            st.markdown(f"**Scan Type:** `{summary.scan_type}`")
            st.markdown(f"**Pages Crawled:** {summary.pages_crawled}")
        with info_col2:
            st.markdown(f"**Forms Found:** {summary.forms_found}")
            st.markdown(f"**Parameters Tested:** {summary.params_tested}")
            st.markdown(f"**Started:** {summary.started_at}")
            st.markdown(f"**Finished:** {summary.finished_at}")

    # ---- Findings list ----
    if summary.total_findings == 0:
        st.success("No vulnerabilities found — the target looks clean.")
    else:
        st.markdown("### Findings")

        # Severity filter
        sev_filter = st.multiselect(
            "Filter by severity",
            ["Critical", "High", "Medium", "Low"],
            default=["Critical", "High", "Medium", "Low"],
        )

        for finding in summary.sorted_findings():
            if finding.severity not in sev_filter:
                continue

            sev_class = f"finding-{finding.severity.lower()}"
            emoji = SEV_EMOJI.get(finding.severity, "⚪")
            color = SEV_COLORS.get(finding.severity, "#888")

            st.markdown(f"""
            <div class="finding-card {sev_class}">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                    <span style="font-size: 1.1em; font-weight: bold; color: white;">
                        {emoji} {finding.vuln_type}
                    </span>
                    <span style="color: {color}; font-weight: bold; font-size: 0.9em;">
                        {finding.severity}
                    </span>
                </div>
                <table style="width: 100%; color: #ccc; font-size: 0.9em;">
                    <tr><td style="width: 100px; color: #888;"><b>URL</b></td><td><code>{finding.url}</code></td></tr>
                    <tr><td style="color: #888;"><b>Parameter</b></td><td><code>{finding.parameter}</code></td></tr>
                    <tr><td style="color: #888;"><b>Method</b></td><td>{finding.method}</td></tr>
                    <tr><td style="color: #888;"><b>Payload</b></td><td><code style="color: #ffaa00;">{finding.payload}</code></td></tr>
                    <tr><td style="color: #888;"><b>Evidence</b></td><td style="color: #999;">{finding.evidence[:300]}</td></tr>
                    <tr><td style="color: #888;"><b>Fix</b></td><td style="color: #44cc44;">{finding.remediation}</td></tr>
                </table>
            </div>
            """, unsafe_allow_html=True)

    # ---- Report downloads ----
    st.markdown("### Download Reports")
    dl_col1, dl_col2, dl_col3 = st.columns(3)

    report_base = output_name
    cwd = Path.cwd()

    for col, ext, label, mime in [
        (dl_col1, ".html", "HTML Report", "text/html"),
        (dl_col2, ".md",   "Markdown Report", "text/markdown"),
        (dl_col3, ".json", "JSON Report",  "application/json"),
    ]:
        resolved = (cwd / report_base).resolve().with_suffix(ext)
        if resolved.exists():
            with col:
                st.download_button(
                    label=f"Download {label}",
                    data=resolved.read_bytes(),
                    file_name=resolved.name,
                    mime=mime,
                    use_container_width=True,
                )
        else:
            with col:
                st.button(f"{label} (not found)", disabled=True,
                          use_container_width=True)

elif not start_scan:
    # Landing state — show instructions
    st.markdown("")
    st.markdown("""
    <div style="text-align: center; padding: 60px 20px; color: #555;">
        <div style="font-size: 3em; margin-bottom: 10px;">🕷️</div>
        <div style="font-size: 1.3em; color: #888; margin-bottom: 20px;">
            Configure your scan in the sidebar and click <b>Start Scan</b>
        </div>
        <div style="font-size: 0.9em; color: #555; max-width: 500px; margin: 0 auto;">
            <b>Quick start:</b><br>
            1. Enter the target URL (e.g. <code>http://localhost/dvwa</code>)<br>
            2. Pick a scan type<br>
            3. Add login credentials if needed<br>
            4. Hit <b>Start Scan</b>
        </div>
    </div>
    """, unsafe_allow_html=True)
