#!/usr/bin/env python3
from __future__ import annotations
"""
main.py — CLI entry point for W3BSP1D3R.

Usage:
  python main.py --url http://localhost/dvwa --login-user admin --login-pass password
  python main.py --url http://localhost:3000 --scan-type xss --output reports/juice_shop
  python main.py --url http://localhost/dvwa --scan-type sqli

Run `python main.py --help` for full usage.

by S1YOL.

⚠️  LEGAL WARNING ⚠️
  I AM NOT RESPONSIBLE FOR ANYONE USING THIS APP.
  Scanning without authorization is a FEDERAL CRIME under the Computer Fraud
  and Abuse Act (CFAA, 18 U.S.C. § 1030). Only scan systems you own or have
  explicit written permission to test.
"""

import argparse
import logging
import os
import platform
import sys
from pathlib import Path

from scanner.core import WebVulnScanner


# ---------------------------------------------------------------------------
# Logging configuration — controlled by --verbose flag
# ---------------------------------------------------------------------------

def _configure_logging(verbose: bool) -> None:
    """
    Set up the root logger.
    Verbose mode (--verbose) shows DEBUG messages from all scanner modules.
    Normal mode shows only WARNING and above (i.e. confirmed findings).
    """
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        handlers=[logging.StreamHandler(sys.stderr)],
    )


# ---------------------------------------------------------------------------
# CLI argument parser
# ---------------------------------------------------------------------------

def _detect_platform() -> str:
    """Detect the current OS platform for help text and diagnostics."""
    system = platform.system().lower()
    if system == "windows":
        return "windows"
    elif system == "darwin":
        return "macos"
    return "linux"


def _build_examples(plat: str) -> str:
    """Build OS-appropriate example commands for --help epilog."""
    if plat == "windows":
        return """
examples:
  # Full authenticated scan against DVWA
  python main.py --url http://localhost/dvwa --login-user admin --login-pass password --scan-type full --output reports\\dvwa_scan

  # SQLi-only scan
  python main.py --url http://localhost/dvwa --scan-type sqli

  # XSS scan against Juice Shop (unauthenticated)
  python main.py --url http://localhost:3000 --scan-type xss

  # Route through Burp Suite proxy
  python main.py --url http://localhost/dvwa --proxy http://127.0.0.1:8080

  # JWT-authenticated API scan
  python main.py --url http://api.example.com --auth-token eyJhbG...

  # CI/CD pipeline — fail build on High+ findings
  python main.py --url http://localhost/dvwa --fail-on high

  # Verbose mode (shows all HTTP requests)
  python main.py --url http://localhost/dvwa --verbose

platform:
  OS:     Windows
  Shell:  cmd.exe / PowerShell
  Venv:   venv\\Scripts\\activate  (cmd)
          .\\venv\\Scripts\\Activate.ps1  (PowerShell)
  Note:   The scanner sends BOTH Unix and Windows attack payloads to the
          target regardless of which OS you run the scanner on. The target
          server determines which payloads succeed, not your local machine.
"""
    elif plat == "macos":
        return """
examples:
  # Full authenticated scan against DVWA
  python main.py --url http://localhost/dvwa \\
                 --login-user admin --login-pass password \\
                 --scan-type full --output reports/dvwa_scan

  # SQLi-only scan
  python main.py --url http://localhost/dvwa --scan-type sqli

  # XSS scan against Juice Shop (unauthenticated)
  python main.py --url http://localhost:3000 --scan-type xss

  # Route through Burp Suite proxy
  python main.py --url http://localhost/dvwa --proxy http://127.0.0.1:8080

  # JWT-authenticated API scan
  python main.py --url http://api.example.com --auth-token eyJhbG...

  # CI/CD pipeline — fail build on High+ findings
  python main.py --url http://localhost/dvwa --fail-on high

  # Verbose mode (shows all HTTP requests)
  python main.py --url http://localhost/dvwa --verbose

platform:
  OS:     macOS (Darwin)
  Shell:  zsh / bash
  Venv:   source venv/bin/activate
  Note:   The scanner sends BOTH Unix and Windows attack payloads to the
          target regardless of which OS you run the scanner on. The target
          server determines which payloads succeed, not your local machine.
"""
    else:
        return """
examples:
  # Full authenticated scan against DVWA
  python main.py --url http://localhost/dvwa \\
                 --login-user admin --login-pass password \\
                 --scan-type full --output reports/dvwa_scan

  # SQLi-only scan
  python main.py --url http://localhost/dvwa --scan-type sqli

  # XSS scan against Juice Shop (unauthenticated)
  python main.py --url http://localhost:3000 --scan-type xss

  # Route through Burp Suite proxy
  python main.py --url http://localhost/dvwa --proxy http://127.0.0.1:8080

  # JWT-authenticated API scan
  python main.py --url http://api.example.com --auth-token eyJhbG...

  # CI/CD pipeline — fail build on High+ findings
  python main.py --url http://localhost/dvwa --fail-on high

  # Verbose mode (shows all HTTP requests)
  python main.py --url http://localhost/dvwa --verbose

platform:
  OS:     Linux
  Shell:  bash / zsh
  Venv:   source venv/bin/activate
  Note:   The scanner sends BOTH Unix and Windows attack payloads to the
          target regardless of which OS you run the scanner on. The target
          server determines which payloads succeed, not your local machine.
"""


def _build_parser() -> argparse.ArgumentParser:
    plat = _detect_platform()

    parser = argparse.ArgumentParser(
        prog="w3bsp1d3r",
        description=(
            "W3BSP1D3R — Web Vulnerability Scanner by S1YOL\n"
            "Tests for SQLi, XSS, CSRF, CMDi, SSTI, NoSQLi, Path Traversal,\n"
            "Open Redirect, IDOR, CORS, SSL/TLS, Cookie Security, Sensitive Files,\n"
            "Security Headers, WAF Detection, Subdomain Enumeration, and CVEs.\n\n"
            f"Running on: {platform.system()} {platform.release()} "
            f"({platform.machine()})\n\n"
            "The author assumes no responsibility or liability for any misuse,\n"
            "damage, or legal consequences arising from the use of this software.\n"
            "Only scan systems you have explicit written authorisation to test."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=_build_examples(plat),
    )

    # Required
    parser.add_argument(
        "--url",
        required=True,
        metavar="URL",
        help="Target base URL (e.g. http://localhost/dvwa)",
    )

    # Authentication
    auth_group = parser.add_argument_group("authentication")
    auth_group.add_argument(
        "--login-user",
        metavar="USERNAME",
        default=None,
        help="Login username for authenticated scanning",
    )
    auth_group.add_argument(
        "--login-pass",
        metavar="PASSWORD",
        default=None,
        help="Login password for authenticated scanning",
    )

    # Scan configuration
    scan_group = parser.add_argument_group("scan configuration")
    scan_group.add_argument(
        "--scan-type",
        choices=["full", "passive", "sqli", "xss", "csrf",
                 "headers", "files", "traversal", "redirect", "cmdi",
                 "cve", "idor", "waf", "ssti", "cors", "ssl",
                 "cookies", "nosqli", "subdomains"],
        default="full",
        metavar="TYPE",
        help=(
            "Scan type (default: full). "
            "full=all | passive=headers+files+cve+waf+cors+ssl+cookies+subdomains "
            "(no attack payloads) | "
            "sqli | xss | csrf | headers | files | traversal | redirect | cmdi | "
            "cve | idor | waf | ssti | cors | ssl | cookies | nosqli | subdomains"
        ),
    )
    scan_group.add_argument(
        "--threads",
        type=int,
        default=4,
        metavar="N",
        help="Number of concurrent tester threads (default: 4)",
    )
    scan_group.add_argument(
        "--max-pages",
        type=int,
        default=50,
        metavar="N",
        help="Maximum pages to crawl (default: 50)",
    )
    scan_group.add_argument(
        "--delay",
        type=float,
        default=0.5,
        metavar="SECS",
        help="Delay between requests in seconds (default: 0.5 — be polite!)",
    )
    scan_group.add_argument(
        "--timeout",
        type=int,
        default=10,
        metavar="SECS",
        help="Per-request timeout in seconds (default: 10)",
    )
    scan_group.add_argument(
        "--no-verify-ssl",
        action="store_true",
        default=False,
        help="Disable TLS certificate verification (use for self-signed certs in labs)",
    )

    # Output
    out_group = parser.add_argument_group("output")
    out_group.add_argument(
        "--output",
        default="scan_report",
        metavar="FILENAME",
        help=(
            "Base filename for reports, without extension "
            "(default: scan_report). "
            "Produces: FILENAME.md, FILENAME.html, FILENAME.json"
        ),
    )
    out_group.add_argument(
        "--verbose",
        action="store_true",
        default=False,
        help="Enable verbose logging (shows all HTTP requests and debug info)",
    )

    # VirusTotal
    vt_group = parser.add_argument_group("virustotal")
    vt_group.add_argument(
        "--vt-api-key",
        default=None,
        metavar="KEY",
        help=(
            "VirusTotal API key for threat intelligence checks. "
            "Free key at virustotal.com. Checks target domain + any file URLs found."
        ),
    )
    vt_group.add_argument(
        "--vt-delay",
        type=float,
        default=15.0,
        metavar="SECS",
        help=(
            "Delay between VirusTotal API requests in seconds (default: 15). "
            "Free tier limit is 4 requests/minute — keep at 15+. "
            "Premium API keys can use a lower value."
        ),
    )

    # NVD / CVE
    nvd_group = parser.add_argument_group("nvd / cve lookup")
    nvd_group.add_argument(
        "--nvd-api-key",
        default=None,
        metavar="KEY",
        help=(
            "NIST NVD API key for CVE lookups (optional). "
            "Without a key: 5 requests / 30 s. "
            "Free key at https://nvd.nist.gov/developers/request-an-api-key "
            "raises the limit to 50 requests / 30 s."
        ),
    )

    # Proxy (Burp Suite / ZAP / mitmproxy integration)
    proxy_group = parser.add_argument_group("proxy")
    proxy_group.add_argument(
        "--proxy",
        default=None,
        metavar="URL",
        help=(
            "HTTP/HTTPS proxy URL to route all traffic through "
            "(e.g. http://127.0.0.1:8080 for Burp Suite). "
            "Supports HTTP, HTTPS, and SOCKS5 proxies."
        ),
    )

    # Token-based authentication
    token_group = parser.add_argument_group("token authentication")
    token_group.add_argument(
        "--auth-token",
        default=None,
        metavar="TOKEN",
        help=(
            "Bearer/JWT token for token-based authentication. "
            "Sets the Authorization header to 'Bearer <TOKEN>' on every request. "
            "Use this for APIs and SPAs that use JWT or API key auth instead of "
            "form-based login."
        ),
    )

    # CI/CD pipeline integration
    ci_group = parser.add_argument_group("ci/cd integration")
    ci_group.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low"],
        default=None,
        metavar="SEVERITY",
        help=(
            "Exit with code 2 if findings at or above this severity are found. "
            "Use in CI/CD pipelines to fail builds on security issues. "
            "Example: --fail-on high → exits 2 if any Critical or High findings exist."
        ),
    )

    return parser


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    """
    Parse arguments, validate inputs, and run the scanner.

    Returns:
        0 on success (even if findings exist — findings ≠ program error).
        1 on configuration or connectivity error.
    """
    parser = _build_parser()
    args   = parser.parse_args()

    _configure_logging(args.verbose)

    # Validate URL has a scheme — a common mistake
    if not args.url.startswith(("http://", "https://")):
        parser.error(
            f"Invalid URL '{args.url}' — must start with http:// or https://"
        )

    # Bounds-check numeric arguments
    if not (1 <= args.threads <= 128):
        parser.error("--threads must be between 1 and 128")
    if not (1 <= args.max_pages <= 10_000):
        parser.error("--max-pages must be between 1 and 10000")
    if args.delay < 0:
        parser.error("--delay cannot be negative")
    if not (1 <= args.timeout <= 300):
        parser.error("--timeout must be between 1 and 300 seconds")

    # Warn if both login args aren't provided together
    if bool(args.login_user) != bool(args.login_pass):
        parser.error(
            "--login-user and --login-pass must both be provided together."
        )

    # Sanitize output path — block directory traversal using resolve()
    try:
        cwd = Path.cwd()
        resolved = (cwd / args.output).resolve()
        resolved.relative_to(cwd)          # raises ValueError if outside cwd
    except ValueError:
        parser.error(
            f"Invalid --output path '{args.output}' — must stay within the current directory."
        )
    args.output = str(resolved.with_suffix(""))  # strip any accidental extension

    # Warn about --no-verify-ssl
    if args.no_verify_ssl:
        print(
            "\n  [!] TLS verification disabled. Only use this in isolated lab environments.\n",
            file=sys.stderr,
        )

    # Warn about proxy usage
    if args.proxy:
        print(
            f"\n  [*] Proxy enabled: routing all traffic through {args.proxy}\n",
            file=sys.stderr,
        )

    scanner = WebVulnScanner(
        url=args.url,
        scan_type=args.scan_type,
        login_user=args.login_user,
        login_pass=args.login_pass,
        output=args.output,
        max_pages=args.max_pages,
        delay=args.delay,
        timeout=args.timeout,
        verify_ssl=not args.no_verify_ssl,
        threads=args.threads,
        vt_api_key=args.vt_api_key,
        vt_delay=args.vt_delay,
        nvd_api_key=args.nvd_api_key,
        proxy=args.proxy,
        auth_token=args.auth_token,
        fail_on=args.fail_on,
    )

    try:
        scanner.scan()
    except KeyboardInterrupt:
        print("\n\n  [!] Scan interrupted by user.", file=sys.stderr)
        return 1
    except Exception as exc:
        logging.getLogger(__name__).exception("Unhandled error during scan")
        print(f"\n  [!] Fatal error: {exc}", file=sys.stderr)
        return 1

    # CI/CD exit code: 2 = security policy violation (findings exceed threshold)
    if scanner.should_fail():
        print(
            f"\n  [!] Security gate FAILED: findings at or above "
            f"'{args.fail_on}' severity detected (exit code 2).",
            file=sys.stderr,
        )
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
