from __future__ import annotations
"""
scanner/reporting/models.py
----------------------------
Core data models for vulnerability findings.

Every tester produces Finding objects — a single, consistent schema that
flows through to terminal output, Markdown, HTML, and JSON reports.

OWASP Severity Ratings used:
  Critical  — Immediate, remote exploitation with severe impact
  High      — Significant impact, likely exploitable
  Medium    — Moderate impact, context-dependent exploitability
  Low       — Minimal impact or hard to exploit in practice
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional


# ---------------------------------------------------------------------------
# Severity constants — use these everywhere for consistency
# ---------------------------------------------------------------------------

class Severity:
    CRITICAL = "Critical"
    HIGH     = "High"
    MEDIUM   = "Medium"
    LOW      = "Low"

    # CVSS-aligned colour hints (used by the display layer)
    COLORS: dict[str, str] = {
        "Critical": "bold red",
        "High":     "red",
        "Medium":   "yellow",
        "Low":      "cyan",
    }

    # Rough CVSS score ranges for each tier
    CVSS_RANGES: dict[str, str] = {
        "Critical": "9.0 – 10.0",
        "High":     "7.0 – 8.9",
        "Medium":   "4.0 – 6.9",
        "Low":      "0.1 – 3.9",
    }

    ORDER: dict[str, int] = {
        "Critical": 0,
        "High":     1,
        "Medium":   2,
        "Low":      3,
    }


# ---------------------------------------------------------------------------
# Vulnerability type constants — keeps strings consistent across modules
# ---------------------------------------------------------------------------

class VulnType:
    SQLI_ERROR    = "SQL Injection (Error-Based)"
    SQLI_BOOLEAN  = "SQL Injection (Boolean-Based)"
    SQLI_TIME     = "SQL Injection (Time-Based Blind)"
    SQLI_UNION    = "SQL Injection (UNION-Based)"
    XSS_REFLECTED = "Cross-Site Scripting (Reflected)"
    XSS_STORED    = "Cross-Site Scripting (Stored)"
    CSRF          = "Cross-Site Request Forgery (CSRF)"
    SENSITIVE_FILE  = "Sensitive File Exposure"
    SECURITY_HEADER = "Missing/Weak Security Header"
    OPEN_REDIRECT   = "Open Redirect"
    PATH_TRAVERSAL  = "Path Traversal"
    CMD_INJECTION   = "OS Command Injection"
    VIRUSTOTAL      = "VirusTotal Threat Detection"
    IDOR              = "Insecure Direct Object Reference (IDOR)"
    WAF_DETECTED      = "Web Application Firewall Detected"
    SSTI              = "Server-Side Template Injection (SSTI)"
    CORS_MISCONFIG    = "CORS Misconfiguration"
    SSL_TLS           = "SSL/TLS Configuration Issue"
    COOKIE_SECURITY   = "Insecure Cookie Configuration"
    NOSQL_INJECTION   = "NoSQL Injection"
    SUBDOMAIN_DISCOVERY = "Subdomain Discovery"


# ---------------------------------------------------------------------------
# Finding — the core result object produced by every tester
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """
    Represents a single discovered vulnerability instance.

    Attributes:
        vuln_type    : One of the VulnType constants (e.g. "SQL Injection")
        severity     : One of the Severity constants (Critical/High/Medium/Low)
        url          : The full URL where the issue was discovered
        parameter    : The HTTP parameter (form field name or GET param) that
                       is vulnerable
        method       : HTTP method used (GET or POST)
        payload      : The exact PoC payload that triggered the finding
        evidence     : A short snippet of the response that confirms the issue
                       (e.g. a database error string, or reflected script tag)
        remediation  : OWASP-aligned guidance on how to fix the issue
        timestamp    : ISO-8601 timestamp of when the finding was recorded
        extra        : Optional dict for tester-specific metadata (e.g. blind
                       SQLi timing delta, CSRF token presence flag)
    """

    vuln_type:   str
    severity:    str
    url:         str
    parameter:   str
    method:      str
    payload:     str
    evidence:    str
    remediation: str
    timestamp:   str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    extra:       Optional[dict] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Serialise to a plain dict (used by the JSON reporter)."""
        return asdict(self)

    @property
    def severity_order(self) -> int:
        """Numeric sort key — lower = more severe."""
        return Severity.ORDER.get(self.severity, 99)


# ---------------------------------------------------------------------------
# ScanSummary — aggregate stats attached to reports
# ---------------------------------------------------------------------------

@dataclass
class ScanSummary:
    """
    High-level statistics for an entire scan run.
    Populated by WebVulnScanner after all testers finish.
    """

    target_url:      str
    scan_type:       str
    started_at:      str
    finished_at:     str = ""
    pages_crawled:   int = 0
    forms_found:     int = 0
    params_tested:   int = 0
    total_findings:  int = 0
    critical_count:  int = 0
    high_count:      int = 0
    medium_count:    int = 0
    low_count:       int = 0
    findings:        list[Finding] = field(default_factory=list)

    def add_finding(self, finding: Finding) -> None:
        """Register a finding and update severity counters."""
        self.findings.append(finding)
        self.total_findings += 1
        counter_map = {
            Severity.CRITICAL: "critical_count",
            Severity.HIGH:     "high_count",
            Severity.MEDIUM:   "medium_count",
            Severity.LOW:      "low_count",
        }
        attr = counter_map.get(finding.severity)
        if attr:
            setattr(self, attr, getattr(self, attr) + 1)

    def sorted_findings(self) -> list[Finding]:
        """Return findings sorted by severity (Critical first)."""
        return sorted(self.findings, key=lambda f: f.severity_order)

    def to_dict(self) -> dict:
        """Serialise for JSON export."""
        d = {k: v for k, v in self.__dict__.items() if k != "findings"}
        d["findings"] = [f.to_dict() for f in self.sorted_findings()]
        return d
