from __future__ import annotations
"""
scanner/utils/http.py
----------------------
Shared HTTP session manager.

Responsibilities:
  - Maintain a single requests.Session across the entire scan (preserves
    cookies / authentication state automatically)
  - Thread-safe: all session access is protected by a lock
  - Enforce a polite rate-limit between requests
  - SSRF guard: redirect destinations are validated against allowed origins
  - Response size cap (MAX_RESPONSE_BYTES) prevents OOM from malicious targets
  - Set a custom User-Agent so the target can identify scanner traffic in logs
"""

import ipaddress
import threading
import time
import logging
from typing import Optional
from urllib.parse import urlparse

import requests
from requests import Response, Session

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level singleton session — created once, reused everywhere
# ---------------------------------------------------------------------------

_session: Optional[Session] = None
_lock = threading.Lock()  # Protects _session access across threads

# Default scanner identity string — be transparent about what you are
SCANNER_UA = (
    "W3BSP1D3R/1.0 (Educational Security Research Tool; "
    "by S1YOL - github.com/siyol/web-vuln-scanner)"
)

# Default delays (seconds) — configurable at init time
DEFAULT_DELAY   = 0.5   # between every request
DEFAULT_TIMEOUT = 10    # per-request timeout

# Maximum response body size — prevents OOM from malicious targets (5 MB)
MAX_RESPONSE_BYTES = 5 * 1024 * 1024

# Allowed redirect origins — populated by init_session()
_allowed_origins: set[str] = set()

# Private/reserved IP ranges that redirects must never reach (SSRF protection)
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local / AWS metadata
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def _is_private_ip(hostname: str) -> bool:
    """Return True if hostname resolves to or is a private/reserved IP."""
    try:
        addr = ipaddress.ip_address(hostname)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return False


def _check_redirect(resp: Response) -> None:
    """
    Validate that a response's redirect chain stayed within allowed origins.
    Raises ValueError if any redirect went to a disallowed host.
    """
    if not _allowed_origins:
        return  # Not yet configured — skip check

    for historical in resp.history:
        loc = historical.headers.get("Location", "")
        if not loc:
            continue
        parsed = urlparse(loc)
        redirect_origin = f"{parsed.scheme}://{parsed.netloc}"
        redirect_host = parsed.hostname or ""

        # Block redirects to private/internal IPs (SSRF)
        if _is_private_ip(redirect_host):
            raise ValueError(
                f"SSRF blocked: redirect to private IP {redirect_host} "
                f"(from {historical.url})"
            )

        # Block redirects to origins not in our scope
        if redirect_origin and redirect_origin not in _allowed_origins:
            raise ValueError(
                f"Out-of-scope redirect blocked: {redirect_origin} "
                f"(from {historical.url})"
            )


def _enforce_size_limit(resp: Response) -> None:
    """Truncate response content if it exceeds MAX_RESPONSE_BYTES."""
    if len(resp.content) > MAX_RESPONSE_BYTES:
        logger.warning(
            "Response from %s exceeds %d bytes (%d) — truncating",
            resp.url, MAX_RESPONSE_BYTES, len(resp.content),
        )
        # Replace the oversized content with a truncated version
        resp._content = resp.content[:MAX_RESPONSE_BYTES]


def init_session(
    delay: float = DEFAULT_DELAY,
    timeout: int  = DEFAULT_TIMEOUT,
    user_agent: str = SCANNER_UA,
    verify_ssl: bool = True,
    proxy: str | None = None,
    auth_token: str | None = None,
) -> Session:
    """
    Initialise (or re-initialise) the global session.

    Call this once from WebVulnScanner.__init__() before any testers run.

    Args:
        delay      : Seconds to sleep between requests (polite scanning).
        timeout    : Per-request timeout in seconds.
        verify_ssl : Set False only when testing self-signed certs in labs.
        user_agent : Custom UA string injected into every request header.
        proxy      : HTTP/SOCKS proxy URL (e.g. http://127.0.0.1:8080 for Burp Suite).
        auth_token : Bearer/API token for token-based authentication.

    Returns:
        The configured requests.Session instance.
    """
    global _session, _delay, _timeout

    _delay   = delay
    _timeout = timeout

    _session = requests.Session()
    _session.headers.update({
        "User-Agent": user_agent,
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,*/*;q=0.8"
        ),
        "Accept-Language": "en-US,en;q=0.5",
    })

    if proxy:
        _session.proxies = {
            "http":  proxy,
            "https": proxy,
        }
        logger.debug("Proxy configured: %s", proxy)

    if auth_token:
        _session.headers["Authorization"] = f"Bearer {auth_token}"
        logger.debug("Authorization header set (Bearer token)")

    if not verify_ssl:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        _session.verify = False

    logger.debug("HTTP session initialised (delay=%.2fs, timeout=%ds)", delay, timeout)
    return _session


def set_allowed_origins(origins: set[str]) -> None:
    """Configure the set of origins that redirects are allowed to reach."""
    global _allowed_origins
    _allowed_origins = origins


def get_session() -> Session:
    """
    Return the module-level session, creating a default one if needed.
    Testers should call this rather than instantiating their own sessions.
    """
    global _session
    if _session is None:
        _session = init_session()
    return _session


# ---------------------------------------------------------------------------
# Rate-limited, thread-safe, size-capped, SSRF-guarded request helpers
# ---------------------------------------------------------------------------

_delay:   float = DEFAULT_DELAY
_timeout: int   = DEFAULT_TIMEOUT


def get(url: str, **kwargs) -> Response:
    """Rate-limited, thread-safe GET with SSRF guard and size cap."""
    time.sleep(_delay)
    kwargs.setdefault("timeout", _timeout)
    kwargs.setdefault("allow_redirects", True)
    with _lock:
        session = get_session()
        try:
            resp = session.get(url, **kwargs)
        except requests.RequestException as exc:
            logger.warning("GET %s failed: %s", url, exc)
            raise
    _check_redirect(resp)
    _enforce_size_limit(resp)
    logger.debug("GET %s → %d (%d bytes)", url, resp.status_code, len(resp.content))
    return resp


def post(url: str, data: dict | None = None, **kwargs) -> Response:
    """Rate-limited, thread-safe POST with SSRF guard and size cap."""
    time.sleep(_delay)
    kwargs.setdefault("timeout", _timeout)
    kwargs.setdefault("allow_redirects", True)
    with _lock:
        session = get_session()
        try:
            resp = session.post(url, data=data, **kwargs)
        except requests.RequestException as exc:
            logger.warning("POST %s failed: %s", url, exc)
            raise
    _check_redirect(resp)
    _enforce_size_limit(resp)
    logger.debug("POST %s → %d (%d bytes)", url, resp.status_code, len(resp.content))
    return resp


def timed_get(url: str, **kwargs) -> tuple[Response, float]:
    """
    GET that also returns the elapsed wall-clock time in seconds.
    Used by the time-based blind SQL injection tester.
    """
    time.sleep(_delay)
    kwargs.setdefault("timeout", max(_timeout, 35))
    kwargs.setdefault("allow_redirects", True)
    with _lock:
        session = get_session()
        start = time.monotonic()
        resp = session.get(url, **kwargs)
        elapsed = time.monotonic() - start
    _check_redirect(resp)
    _enforce_size_limit(resp)
    logger.debug("Timed GET %s → %.2fs", url, elapsed)
    return resp, elapsed


def timed_post(url: str, data: dict | None = None, **kwargs) -> tuple[Response, float]:
    """POST that also returns elapsed wall-clock time."""
    time.sleep(_delay)
    kwargs.setdefault("timeout", max(_timeout, 35))
    kwargs.setdefault("allow_redirects", True)
    with _lock:
        session = get_session()
        start = time.monotonic()
        resp = session.post(url, data=data, **kwargs)
        elapsed = time.monotonic() - start
    _check_redirect(resp)
    _enforce_size_limit(resp)
    logger.debug("Timed POST %s → %.2fs", url, elapsed)
    return resp, elapsed
