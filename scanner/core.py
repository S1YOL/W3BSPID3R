from __future__ import annotations
"""
scanner/core.py
----------------
WebVulnScanner — the main orchestrator class.

This is the "conductor" that:
  1. Initialises the HTTP session (rate limiting, User-Agent, auth cookies)
  2. Authenticates to the target if credentials were provided
  3. Runs the crawler to map the attack surface
  4. Dispatches the appropriate testers based on --scan-type
  5. Aggregates all findings into a ScanSummary
  6. Writes all requested output formats (Markdown, HTML, JSON)

Design principle: core.py knows HOW to orchestrate but not HOW to test.
All vulnerability logic lives in testers/. All output logic lives in reporting/.
Adding a new vulnerability type = add a new tester + register it in _TESTERS.
"""

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Literal, Optional

from scanner.auth import AuthHandler
from scanner.crawler import Crawler
from scanner.reporting.models import Finding, ScanSummary, Severity, VulnType
from scanner.reporting.json_report import write_json_report
from scanner.reporting.markdown_report import write_markdown_report
from scanner.reporting.html_report import write_html_report
from scanner.reporting.sarif_report import write_sarif_report
from scanner.testers.base import BaseTester
from scanner.testers.cmdi import CmdInjectionTester
from scanner.testers.cookie_security import CookieSecurityTester
from scanner.testers.cors import CORSTester
from scanner.testers.csrf import CSRFTester
from scanner.testers.headers import HeadersTester
from scanner.testers.idor import IDORTester
from scanner.testers.nosql_injection import NoSQLInjectionTester
from scanner.testers.open_redirect import OpenRedirectTester
from scanner.testers.path_traversal import PathTraversalTester
from scanner.testers.sensitive_files import SensitiveFileTester
from scanner.testers.sqli import SQLiTester
from scanner.testers.ssl_tls import SSLTLSTester
from scanner.testers.ssti import SSTITester
from scanner.testers.subdomain import SubdomainTester
from scanner.testers.waf import WAFTester
from scanner.testers.xss import XSSTester
from scanner.testers.cve import CveTester
from scanner.utils import http as http_utils
from scanner.utils.display import (
    console,
    make_progress,
    print_banner,
    print_error,
    print_finding,
    print_info,
    print_phase,
    print_scan_start,
    print_success,
    print_summary,
    print_warning,
    print_status,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Scan type → tester mapping
# ---------------------------------------------------------------------------

ScanType = Literal["full", "passive", "sqli", "xss", "csrf",
                   "headers", "files", "traversal", "redirect", "cmdi",
                   "cve", "idor", "waf", "ssti", "cors", "ssl",
                   "cookies", "nosqli", "subdomains"]

_TESTER_MAP: dict[str, type[BaseTester]] = {
    "sqli":       SQLiTester,
    "xss":        XSSTester,
    "csrf":       CSRFTester,
    "headers":    HeadersTester,
    "files":      SensitiveFileTester,
    "traversal":  PathTraversalTester,
    "redirect":   OpenRedirectTester,
    "cmdi":       CmdInjectionTester,
    "cve":        CveTester,
    "idor":       IDORTester,
    "waf":        WAFTester,
    "ssti":       SSTITester,
    "cors":       CORSTester,
    "ssl":        SSLTLSTester,
    "cookies":    CookieSecurityTester,
    "nosqli":     NoSQLInjectionTester,
    "subdomains": SubdomainTester,
}


class WebVulnScanner:
    """
    Main scanner class — instantiate once, call scan() to execute.

    Args:
        url          : Target base URL (e.g. "http://localhost/dvwa").
        scan_type    : "full" | "sqli" | "xss" | "csrf".
        login_user   : Optional username for authenticated scanning.
        login_pass   : Optional password for authenticated scanning.
        output       : Base filename for reports (no extension).
        max_pages    : Maximum pages the crawler will visit.
        delay        : Seconds to wait between HTTP requests (polite scanning).
        timeout      : Per-request timeout in seconds.
        verify_ssl   : Whether to verify TLS certificates.
    """

    VERSION = "1.0.0"

    def __init__(
        self,
        url: str,
        scan_type: ScanType = "full",
        login_user: str | None = None,
        login_pass: str | None = None,
        output: str = "scan_report",
        max_pages: int = 50,
        delay: float = 0.5,
        timeout: int = 10,
        verify_ssl: bool = True,
        threads: int = 4,
        vt_api_key: str | None = None,
        vt_delay: float = 15.0,
        nvd_api_key: str | None = None,
        proxy: str | None = None,
        auth_token: str | None = None,
        fail_on: str | None = None,
    ) -> None:
        self.url        = url.rstrip("/")
        self.scan_type  = scan_type
        self.login_user = login_user
        self.login_pass = login_pass
        self.output     = output
        self.max_pages  = max_pages
        self.threads    = max(1, threads)
        self.vt_api_key  = vt_api_key
        self.vt_delay    = vt_delay
        self.nvd_api_key = nvd_api_key
        self.fail_on     = fail_on    # CI/CD exit code threshold

        # Initialise the shared HTTP session early so auth can use it
        http_utils.init_session(
            delay=delay,
            timeout=timeout,
            verify_ssl=verify_ssl,
            proxy=proxy,
            auth_token=auth_token,
        )

        # SSRF guard: only allow redirects to the target origin
        from urllib.parse import urlparse as _urlparse
        _parsed = _urlparse(self.url)
        _target_origin = f"{_parsed.scheme}://{_parsed.netloc}"
        http_utils.set_allowed_origins({_target_origin})

        # Will be populated during scan()
        self.summary: ScanSummary | None = None

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def scan(self) -> ScanSummary:
        """
        Execute the full scan pipeline and return the completed ScanSummary.

        Pipeline:
          authenticate → crawl → test → report
        """
        print_banner(self.VERSION)

        started_at = datetime.now(timezone.utc).isoformat()
        authenticated = False

        # ---- Step 1: Authenticate ----------------------------------------
        if self.login_user and self.login_pass:
            print_phase("Authentication")
            auth = AuthHandler(self.url, self.login_user, self.login_pass)
            authenticated = auth.login()
            if not authenticated:
                print_warning(
                    "Continuing as unauthenticated — some pages may be inaccessible."
                )
        else:
            print_info("No credentials provided — running unauthenticated scan.")

        print_scan_start(self.url, self.scan_type, authenticated)

        # Initialise the summary object (findings get added as testers run)
        self.summary = ScanSummary(
            target_url=self.url,
            scan_type=self.scan_type,
            started_at=started_at,
        )

        # ---- Step 2: Crawl -----------------------------------------------
        print_phase("Crawling — Mapping Attack Surface")
        pages = self._crawl()
        self.summary.pages_crawled = len(pages)
        self.summary.forms_found   = sum(len(p.forms) for p in pages)
        print_success(
            f"Crawl complete: {self.summary.pages_crawled} pages, "
            f"{self.summary.forms_found} forms discovered."
        )

        if not pages:
            print_error("No pages were crawled. Check the target URL and connectivity.")
            self.summary.finished_at = datetime.now(timezone.utc).isoformat()
            return self.summary

        # ---- Step 3: Run testers (concurrent) ---------------------------
        testers = self._build_testers()
        print_phase(f"Testing — {len(testers)} modules, up to {self.threads} concurrent")
        self._run_testers_concurrent(testers, pages)

        # ---- Step 4: VirusTotal check ------------------------------------
        if self.vt_api_key:
            print_phase("VirusTotal Threat Intelligence")
            self._run_virustotal(pages)
        else:
            print_info("Skipping VirusTotal (no --vt-api-key provided)")

        # ---- Step 5: Finalise summary ------------------------------------
        self.summary.finished_at = datetime.now(timezone.utc).isoformat()
        print_summary(self.summary)

        # ---- Step 6: Write reports ---------------------------------------
        print_phase("Generating Reports")
        self._write_reports()

        return self.summary

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _crawl(self) -> list:
        """Execute the crawler with a rich progress display."""
        crawler = Crawler(base_url=self.url, max_pages=self.max_pages)

        with make_progress() as progress:
            task = progress.add_task(
                "Crawling site…",
                total=self.max_pages,
                status="",
            )

            # We hook into the crawler by subclassing progress updates
            # around the crawl() call. For simplicity we run the crawl
            # and advance based on visited count.
            def _update_progress():
                while not progress.finished:
                    visited = len(crawler._visited)
                    progress.update(
                        task,
                        completed=visited,
                        status=f"{visited} pages visited",
                    )
                    time.sleep(0.3)

            monitor = threading.Thread(target=_update_progress, daemon=True)
            monitor.start()

            pages = crawler.crawl()

            progress.update(task, completed=self.max_pages, status="Done")

        return pages

    def _run_testers_concurrent(self, testers: list[BaseTester], pages: list) -> None:
        """
        Run all testers using a thread pool. Each tester operates on the same
        list of crawled pages independently. Findings are collected thread-safely
        and added to the summary as they arrive.
        """
        _lock = threading.Lock()

        def _run_one(tester: BaseTester):
            findings = tester.run(pages)
            with _lock:
                self.summary.params_tested += tester.params_tested
                for f in findings:
                    self.summary.add_finding(f)
                    print_finding(f)
                # Print inside the lock so it never interleaves with print_finding
                # calls from other still-running tester threads
                print_status(f"{tester.name} complete — {len(findings)} finding(s)")

        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {pool.submit(_run_one, t): t for t in testers}
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as exc:
                    logger.error("Tester error: %s", exc)

    def _run_virustotal(self, pages: list) -> None:
        """Check the target domain and any suspicious file URLs via VirusTotal."""
        from scanner.virustotal import scan_target  # lazy — only when VT is used

        crawled_urls = [p.url for p in pages]

        try:
            flagged = scan_target(
                base_url=self.url,
                crawled_urls=crawled_urls,
                api_key=self.vt_api_key,
                request_delay=self.vt_delay,
            )
        except Exception as exc:
            print_warning(f"VirusTotal check failed: {exc}")
            return

        for result in flagged:
            resource      = result.get("resource", "?")
            resource_type = result.get("resource_type", "?")
            malicious     = result.get("malicious", 0)
            suspicious    = result.get("suspicious", 0)
            total         = result.get("total_engines", 0)
            categories    = result.get("categories", {})

            severity = Severity.CRITICAL if malicious > 2 else (
                Severity.HIGH if malicious > 0 else Severity.MEDIUM
            )
            finding = Finding(
                vuln_type=VulnType.VIRUSTOTAL,
                severity=severity,
                url=resource if resource_type == "url" else self.url,
                parameter=f"{resource_type}: {resource}",
                method="GET",
                payload="(VirusTotal API lookup — no payload sent to target)",
                evidence=(
                    f"VirusTotal: {malicious} malicious, {suspicious} suspicious "
                    f"out of {total} engines. "
                    + (f"Categories: {', '.join(categories.values())}" if categories else "")
                ),
                remediation=(
                    "Investigate the flagged resource at https://www.virustotal.com. "
                    "If the domain/URL is legitimately yours, consider submitting a "
                    "false-positive report to VirusTotal. If confirmed malicious, "
                    "immediately isolate and remediate the affected server."
                ),
                extra=result,
            )
            self.summary.add_finding(finding)
            print_finding(finding)

        if not flagged:
            print_success("VirusTotal: no threats detected for this target")

    def _build_testers(self) -> list[BaseTester]:
        """
        Instantiate the appropriate testers based on --scan-type.

        "full"    = all testers.
        "passive" = headers + sensitive files + CVE lookup (no attack payloads).
        Any other value = only the named tester.
        """
        def _make(cls: type[BaseTester]) -> BaseTester:
            if cls is CveTester:
                return CveTester(nvd_api_key=self.nvd_api_key)
            return cls()

        if self.scan_type == "full":
            return [_make(cls) for cls in _TESTER_MAP.values()]

        if self.scan_type == "passive":
            return [
                HeadersTester(), SensitiveFileTester(), _make(CveTester),
                WAFTester(), CORSTester(), SSLTLSTester(),
                CookieSecurityTester(), SubdomainTester(),
            ]

        tester_cls = _TESTER_MAP.get(self.scan_type)
        if not tester_cls:
            print_error(
                f"Unknown scan type '{self.scan_type}'. "
                f"Valid options: full, passive, {', '.join(_TESTER_MAP.keys())}"
            )
            return []

        return [_make(tester_cls)]

    def should_fail(self) -> bool:
        """
        Check if the scan should return a non-zero exit code based on --fail-on.

        Used for CI/CD pipeline integration — fail the build if findings
        meet or exceed the configured severity threshold.
        """
        if not self.fail_on or not self.summary:
            return False

        threshold = self.fail_on.lower()
        if threshold == "critical" and self.summary.critical_count > 0:
            return True
        if threshold == "high" and (self.summary.critical_count + self.summary.high_count) > 0:
            return True
        if threshold == "medium" and (
            self.summary.critical_count + self.summary.high_count + self.summary.medium_count
        ) > 0:
            return True
        if threshold == "low" and self.summary.total_findings > 0:
            return True
        return False

    def _write_reports(self) -> None:
        """Write all output formats (Markdown, HTML, JSON, SARIF)."""
        if not self.summary:
            return

        base = self.output
        reports = []

        try:
            md_path    = write_markdown_report(self.summary, f"{base}.md")
            html_path  = write_html_report(self.summary, f"{base}.html")
            json_path  = write_json_report(self.summary, f"{base}.json")
            sarif_path = write_sarif_report(self.summary, f"{base}.sarif")
            reports    = [md_path, html_path, json_path, sarif_path]
        except Exception as exc:
            print_error(f"Report generation failed: {exc}")
            logger.exception("Report generation error")
            return

        console.print()
        console.print("[bold white]Reports written:[/bold white]")
        for rpt in reports:
            console.print(f"  [red]→[/red] {rpt}")
        console.print()
