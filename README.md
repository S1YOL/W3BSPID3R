# W3BSP1D3R

**Web vulnerability scanner built in Python — 17 test modules, 4 report formats, built for labs and authorised pentesting.**

```
  ╦ ╦╔═╗╔╗ ╔═╗╔═╗╦╔╦╗╔═╗╦═╗
  ║║║ ═╣╠╩╗╚═╗╠═╝║ ║║ ═╣╠╦╝
  ╚╩╝╚═╝╚═╝╚═╝╩  ╩═╩╝╚═╝╩╚═
```

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-39%20passing-brightgreen.svg)](#running-tests)
[![Status](https://img.shields.io/badge/status-beta-orange.svg)](#)

---

## Legal Disclaimer

> **This tool is provided strictly for authorised security testing and educational purposes.**
>
> You **must** only scan:
> - Systems you have **explicit written authorisation** to test
> - Intentionally vulnerable lab environments (DVWA, Juice Shop, HackTheBox, TryHackMe, etc.)
>
> Unauthorised scanning is a criminal offence under the Computer Fraud and Abuse Act (CFAA, 18 U.S.C. § 1030), the Computer Misuse Act 1990 (UK), and equivalent legislation in your jurisdiction. **The author of this software bears no responsibility whatsoever for any damages, legal consequences, or misuse arising from the use of this tool.** By downloading or using W3BSP1D3R, you agree that you assume all responsibility for your actions and that the author shall not be held liable under any circumstances.

---

## What It Does

W3BSP1D3R crawls a target website, maps every form and URL parameter, fires attack payloads against each one, and reports what's vulnerable — with the exact payload that triggered it and how to fix it.

### Test Modules

| Category | Modules |
|----------|---------|
| **Injection** | SQL Injection (error, UNION, boolean-blind, time-blind) · NoSQL Injection · Command Injection · SSTI |
| **Client-Side** | Reflected XSS · Stored XSS · CSRF · Open Redirect |
| **Access Control** | Path Traversal · IDOR · Sensitive File Exposure (`.env`, `.git/`, backups, admin panels) |
| **Configuration** | Security Headers · Cookie Security · CORS Misconfiguration · SSL/TLS · WAF Detection |
| **Recon** | Subdomain Enumeration · CVE Lookup (NVD) · VirusTotal Threat Intelligence |

### Detection Quality

This isn't a grep-for-strings scanner. It uses real detection techniques to minimise false positives:

- **Baseline comparison** — fetches a clean response before injecting, skips error signatures that already exist in normal output
- **3-way boolean SQLi** — TRUE must match baseline AND FALSE must differ, plus a recheck gate
- **Structural XSS verification** — confirms payload elements (tags, event handlers) survived encoding in the response
- **Regex-confirmed command injection** — matches `uid=\d+\(\w+\) gid=\d+` format, not just the substring "uid="
- **SSRF protection** — the scanner itself blocks redirects to private IPs and out-of-scope origins
- **XXE-safe XML parsing** — sitemap parsing uses defusedxml to prevent the scanner from being attacked

---

## Requirements

- **Python 3.10 or newer**
- **pip** (comes with Python)
- **Docker** (optional — only needed to run DVWA / Juice Shop targets)
- **Git** (optional — you can also download the .zip)

### Check your Python version

```bash
python3 --version       # Linux / macOS
python --version        # Windows
```

If you don't have Python, download it from [python.org](https://www.python.org/downloads/).

> **Windows users:** During installation, check **"Add Python to PATH"** — if you skip this, nothing will work from the command line.

---

## Installation

### Option 1: Git Clone (all platforms)

```bash
git clone https://github.com/S1YOL/W3BSPID3R.git
cd W3BSPID3R
```

### Option 2: Download from Releases

Go to [Releases](https://github.com/S1YOL/W3BSPID3R/releases) and download:
- **Windows** → `W3BSP1D3R-beta.zip` — right-click → Extract All
- **macOS / Linux** → `W3BSP1D3R-beta.tar.gz` — extract with `tar -xzf W3BSP1D3R-beta.tar.gz`

Then `cd` into the extracted folder.

---

## Setup

### Linux

```bash
chmod +x setup.sh
./setup.sh
source venv/bin/activate
```

Or manually:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### macOS

```bash
chmod +x setup.sh
./setup.sh
source venv/bin/activate
```

Or manually:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

> **macOS note:** If you get `xcrun: error: invalid active developer path`, run `xcode-select --install` first to install command line tools.

### Windows (Command Prompt)

```cmd
setup.bat
venv\Scripts\activate
```

Or manually:

```cmd
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

### Windows (PowerShell)

```powershell
.\setup.bat
.\venv\Scripts\Activate.ps1
```

> **PowerShell note:** If you get a script execution error, run `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser` first.

### Verify it works (all platforms)

```bash
python main.py --help
```

You should see the full help output with all available options. If you see an error, make sure your virtual environment is activated (you should see `(venv)` at the start of your terminal prompt).

---

## Setting Up a Target

You need a deliberately vulnerable app to scan. **Do not scan any system without explicit authorisation. The author is not responsible for any consequences resulting from unauthorised use.**

### DVWA (recommended for beginners)

Requires [Docker](https://docs.docker.com/get-docker/).

```bash
docker run --rm -d -p 80:80 --name dvwa vulnerables/web-dvwa
```

Go to `http://localhost/dvwa/setup.php` → click **Create / Reset Database** → login with `admin` / `password`.

> **Windows:** If port 80 is taken (common with IIS or Skype), use `-p 8080:80` instead and scan `http://localhost:8080/dvwa`.

### OWASP Juice Shop

```bash
docker run --rm -d -p 3000:3000 --name juiceshop bkimminich/juice-shop
```

### Both at once (Docker Compose)

```yaml
# docker-compose.yml
version: "3.9"
services:
  dvwa:
    image: vulnerables/web-dvwa
    ports: ["80:80"]
  juiceshop:
    image: bkimminich/juice-shop
    ports: ["3000:3000"]
```

```bash
docker compose up -d
```

---

## Usage

### Run Your First Scan

**Linux / macOS:**
```bash
python main.py \
  --url http://localhost/dvwa \
  --login-user admin \
  --login-pass password \
  --scan-type full
```

**Windows (Command Prompt):**
```cmd
python main.py --url http://localhost/dvwa --login-user admin --login-pass password --scan-type full
```

**Windows (PowerShell):**
```powershell
python main.py `
  --url http://localhost/dvwa `
  --login-user admin `
  --login-pass password `
  --scan-type full
```

The scanner will:
1. Log in to DVWA automatically
2. Crawl the site to find all pages and forms
3. Test everything it finds
4. Print colour-coded findings to your terminal
5. Save reports: `scan_report.md`, `scan_report.html`, `scan_report.json`, `scan_report.sarif`

Open `scan_report.html` in your browser for a readable report.

### Cheat Sheet

| What you want | Command |
|---------------|---------|
| Full scan (everything) | `python main.py --url http://localhost/dvwa --login-user admin --login-pass password` |
| SQL Injection only | `python main.py --url http://localhost/dvwa --scan-type sqli` |
| XSS only | `python main.py --url http://localhost/dvwa --scan-type xss` |
| Passive only (no payloads) | `python main.py --url http://localhost/dvwa --scan-type passive` |
| Custom report name | `python main.py --url http://localhost/dvwa --output reports/my_scan` |
| Verbose logging | `python main.py --url http://localhost/dvwa --verbose` |
| Through Burp Suite proxy | `python main.py --url http://localhost/dvwa --proxy http://127.0.0.1:8080` |
| JWT/API token auth | `python main.py --url http://api.example.com --auth-token eyJhbG...` |
| VirusTotal threat intel | `python main.py --url http://target.com --vt-api-key YOUR_KEY` |
| CVE lookup | `python main.py --url http://localhost/dvwa --nvd-api-key YOUR_KEY` |
| Self-signed HTTPS cert | `python main.py --url https://localhost:8443 --no-verify-ssl` |
| Slow polite scan | `python main.py --url http://localhost/dvwa --delay 2.0 --threads 1` |
| CI/CD — fail on High+ | `python main.py --url http://localhost/dvwa --fail-on high` |

### Streamlit GUI

```bash
pip install streamlit
streamlit run gui.py
```

---

## CLI Reference

```
python main.py --url URL [options]

Required:
  --url URL                   Target base URL (http:// or https://)

Authentication:
  --login-user USERNAME       Form-based login username
  --login-pass PASSWORD       Form-based login password
  --auth-token TOKEN          Bearer/JWT token (Authorization header)

Scan Configuration:
  --scan-type TYPE            full | passive | sqli | xss | csrf | headers | files |
                              traversal | redirect | cmdi | cve | idor | waf | ssti |
                              cors | ssl | cookies | nosqli | subdomains  (default: full)
  --threads N                 Concurrent tester threads (default: 4)
  --max-pages N               Max pages to crawl (default: 50)
  --delay SECS                Delay between requests (default: 0.5)
  --timeout SECS              Per-request timeout (default: 10)
  --no-verify-ssl             Disable TLS verification

Output:
  --output FILENAME           Report base filename, no extension (default: scan_report)
  --verbose                   Debug logging — shows every HTTP request

Integrations:
  --vt-api-key KEY            VirusTotal API key
  --vt-delay SECS             Delay between VT requests (default: 15)
  --nvd-api-key KEY           NIST NVD API key for CVE lookups
  --proxy URL                 HTTP/HTTPS/SOCKS5 proxy (e.g. http://127.0.0.1:8080)
  --fail-on SEVERITY          Exit code 2 if findings >= severity (critical|high|medium|low)
```

---

## Report Formats

Every scan produces 4 report files:

| Format | File | Use Case |
|--------|------|----------|
| **Markdown** | `scan_report.md` | GitHub PRs, bug bounty submissions, `pandoc` to PDF |
| **HTML** | `scan_report.html` | Self-contained single file — open in any browser, share with clients |
| **JSON** | `scan_report.json` | CI/CD pipelines, SIEM ingestion, custom tooling |
| **SARIF** | `scan_report.sarif` | GitHub Code Scanning, VS Code SARIF Viewer, CI/CD security gates |

---

## Reading the Output

Findings are colour-coded in the terminal:

| Severity | Meaning | Examples |
|----------|---------|---------|
| **CRITICAL** | Full compromise likely | SQLi, command injection, .env exposed |
| **HIGH** | Significant risk | Stored XSS, path traversal, NoSQL injection |
| **MEDIUM** | Should fix before production | CSRF, missing CSP, CORS misconfiguration |
| **LOW** | Minor info leak | Missing minor headers, server version disclosure |

Each finding includes: **URL**, **parameter**, **HTTP method**, **exact payload**, **evidence** from the response, and **remediation** steps.

---

## SQLi Detection Methods

| Method | How It Works | Speed |
|--------|-------------|-------|
| **Error-based** | Injects syntax-breaking characters, looks for DB error strings (MySQL, MSSQL, Oracle, PostgreSQL, SQLite). Skips signatures already in baseline. | Fast |
| **UNION-based** | Injects `UNION SELECT` with a unique marker, checks if marker appears in response | Fast |
| **Boolean-blind** | Compares TRUE vs FALSE condition responses against a clean baseline. Requires both absolute (50B) AND percentage (15%) thresholds plus a recheck. | Medium |
| **Time-based blind** | Injects `SLEEP(5)` / `WAITFOR DELAY` / `pg_sleep(5)`, measures response time delta against baseline | Slow |

---

## Troubleshooting

### "python" or "python3" not found

| OS | Fix |
|----|-----|
| **Windows** | Reinstall Python from [python.org](https://www.python.org/downloads/) and check **"Add Python to PATH"** |
| **macOS** | `brew install python` or download from [python.org](https://www.python.org/downloads/) |
| **Linux (Debian/Ubuntu)** | `sudo apt install python3 python3-venv python3-pip` |
| **Linux (Arch)** | `sudo pacman -S python` |
| **Linux (Fedora)** | `sudo dnf install python3` |

### "No module named venv" (Linux)

```bash
sudo apt install python3-venv    # Debian / Ubuntu
```

### PowerShell script execution error (Windows)

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### "xcrun: error" (macOS)

```bash
xcode-select --install
```

### Port 80 already in use (Windows)

DVWA needs port 80, but Windows often has IIS or Skype using it. Use a different port:

```cmd
docker run --rm -d -p 8080:80 --name dvwa vulnerables/web-dvwa
python main.py --url http://localhost:8080/dvwa --login-user admin --login-pass password
```

### Scanner can't connect / timeout errors

- Make sure the target is running: open the URL in your browser first
- If using Docker, check `docker ps` to confirm the container is up
- If behind a corporate proxy, try `--proxy http://your-proxy:port`
- For self-signed HTTPS certs, add `--no-verify-ssl`

### Rich terminal colours look broken

- **Windows:** Use [Windows Terminal](https://aka.ms/terminal) instead of the old `cmd.exe` — it supports full colour
- **macOS / Linux:** Should work out of the box. If not, try `export TERM=xterm-256color`

---

## Project Structure

```
W3BSP1D3R/
├── main.py                          CLI entry point
├── gui.py                           Streamlit GUI
├── setup.sh                         Setup script (Linux / macOS)
├── setup.bat                        Setup script (Windows)
├── requirements.txt
├── pyproject.toml
│
├── scanner/
│   ├── core.py                      Orchestrator: auth → crawl → test → report
│   ├── crawler.py                   BFS crawler: links, forms, GET params, sitemap, robots.txt
│   ├── auth.py                      DVWA + generic form-based auth
│   ├── virustotal.py                VirusTotal API v3
│   │
│   ├── testers/
│   │   ├── base.py                  BaseTester — template method pattern
│   │   ├── sqli.py                  SQL injection (4 methods)
│   │   ├── xss.py                   Reflected + stored XSS
│   │   ├── csrf.py                  Token analysis
│   │   ├── cmdi.py                  Command injection (output + time-based)
│   │   ├── path_traversal.py        15+ encoding variants
│   │   ├── open_redirect.py         3xx + body reflection
│   │   ├── sensitive_files.py       60+ path probes
│   │   ├── headers.py               Security header checks
│   │   ├── nosql_injection.py       MongoDB/CouchDB injection
│   │   ├── ssti.py                  Server-side template injection
│   │   ├── idor.py                  Insecure direct object references
│   │   ├── cors.py                  CORS misconfiguration
│   │   ├── ssl_tls.py              SSL/TLS configuration
│   │   ├── cookie_security.py       Cookie flags analysis
│   │   ├── waf.py                   WAF detection
│   │   ├── subdomain.py             Subdomain enumeration
│   │   └── cve.py                   NVD CVE lookup
│   │
│   ├── reporting/
│   │   ├── models.py                Finding + ScanSummary dataclasses
│   │   ├── markdown_report.py
│   │   ├── html_report.py
│   │   ├── json_report.py
│   │   └── sarif_report.py          SARIF v2.1.0
│   │
│   └── utils/
│       ├── http.py                  Thread-safe session, SSRF guard, rate limiting
│       └── display.py               Rich terminal UI
│
├── tests/                           39 unit tests
│   ├── test_baseline_error.py       Baseline FP suppression (SQLi, NoSQL, CMDi, PathTraversal)
│   ├── test_sqli_boolean.py         3-way boolean SQLi logic
│   ├── test_xss_reflected.py        Structural XSS verification
│   ├── test_crawler_xxe.py          XXE-safe XML parsing
│   ├── test_http_safety.py          SSRF guard + response size limit
│   └── test_sensitive_files.py      .env detection
│
└── examples/
    └── dvwa_scan.sh
```

---

## Running Tests

**Linux / macOS:**
```bash
source venv/bin/activate
python -m pytest tests/ -v
```

**Windows:**
```cmd
venv\Scripts\activate
python -m pytest tests/ -v
```

```
39 passed in 0.17s
```

Tests cover: boolean SQLi logic, XSS structural verification, baseline false-positive suppression across all error-based testers, SSRF redirect blocking, XXE prevention, response size limits, and sensitive file detection.

---

## Extending the Scanner

Add a new vulnerability tester in 3 steps:

**1.** Create `scanner/testers/my_tester.py`:

```python
from scanner.testers.base import BaseTester
from scanner.crawler import CrawledPage
from scanner.reporting.models import Finding

class MyTester(BaseTester):
    def __init__(self):
        super().__init__(name="My Tester")

    def run(self, pages: list[CrawledPage]) -> list[Finding]:
        # Your detection logic here
        # Use self._inject_form(), self._inject_get_param(), self._log_finding()
        return self.findings
```

**2.** Register it in `scanner/core.py`:

```python
from scanner.testers.my_tester import MyTester

_TESTER_MAP["mytester"] = MyTester
```

**3.** Add `"mytester"` to the `--scan-type` choices in `main.py`.

---

## Dependencies

| Library | Purpose |
|---------|---------|
| [requests](https://github.com/psf/requests) | HTTP sessions, cookies, auth |
| [Beautiful Soup 4](https://www.crummy.com/software/BeautifulSoup/) | HTML parsing, form extraction |
| [lxml](https://lxml.de/) | Fast HTML/XML parser backend |
| [Rich](https://github.com/Textualize/rich) | Terminal colours, panels, progress bars |
| [defusedxml](https://github.com/tiran/defusedxml) | XXE-safe XML parsing |
| [Streamlit](https://streamlit.io/) | GUI (optional) |

---

## Credits

### Lab Environments
- [DVWA](https://github.com/digininja/DVWA) — Ryan Dewhurst & contributors
- [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) — Bjorn Kimminich & OWASP

### References
- [OWASP Top 10](https://owasp.org/Top10/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [VirusTotal API v3](https://docs.virustotal.com/reference/overview)
- [NIST NVD](https://nvd.nist.gov/)

---

## License

MIT License — see [LICENSE](LICENSE) for details.

**The author assumes no responsibility or liability for any misuse, damage, or legal consequences arising from the use of this software. By using W3BSP1D3R you acknowledge that you do so entirely at your own risk.**

---

*Built by S1YOL.*
