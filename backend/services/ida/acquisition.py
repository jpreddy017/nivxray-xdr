"""
IDA · Resource Acquisition Engine (IDA-3)
─────────────────────────────────────────
Frozen 2026-03-01 · P0 · Rule R19.

Rule R19 · **Acquirable Resources Must Be Acquired**

    If IUE classifies an input as an acquirable resource, AND IDA
    has a compatible acquisition engine, THEN the Workspace MUST
    attempt acquisition automatically before investigation.
    Planning alone is not a terminal state.

This module is that acquisition engine.  It behaves like a browser:
resolve → fetch → extract main content → discard boilerplate → hand
the clean article to downstream extractors.

Safety envelope (non-negotiable):
    · Only http / https schemes accepted.
    · No private / loopback / link-local host resolution.
    · 10-second connect + read timeout.
    · 5 MB response cap; larger bodies are truncated + flagged.
    · Only `text/html` and `text/plain` content-types accepted.
    · No redirect to a different scheme (https → file:// blocked).
    · Deterministic: same URL + same HTML → same extracted article.

Downstream tolerance: acquisition failures are RESULTS, not
exceptions.  The engine returns a structured record with
`ok=false` and a machine-readable error code so the SSOT can carry
the failure into the acquisition-plan surface.

Rule R14 · IDA-3 is the ONLY engine allowed to acquire resources.
"""
from __future__ import annotations
import ipaddress
import socket
import time
from dataclasses import dataclass, asdict, field
from typing import Any, Dict, List, Optional

import httpx
import trafilatura


# ══════════════════════════════════════════════════════════════════
# 1. Safety constants
# ══════════════════════════════════════════════════════════════════
_ALLOWED_SCHEMES  = ("http", "https")
_ALLOWED_TYPES    = ("text/html", "application/xhtml+xml", "text/plain")
_MAX_BYTES        = 5 * 1024 * 1024      # 5 MB
_TIMEOUT_SECONDS  = 10.0
_USER_AGENT       = (
    "NivXRay-IDA/1.0 (+https://nivxray.local; investigation-only "
    "resource acquisition; safe-fetch; deterministic)"
)


# ══════════════════════════════════════════════════════════════════
# 2. Result dataclass
# ══════════════════════════════════════════════════════════════════
@dataclass
class AcquiredResource:
    """The outcome of IDA-3 for a single URL.  Written into the SSOT
    as `acquired_document{}` and consumed by IDA-3.5 / IDA-4."""
    ok:              bool
    url:             str
    final_url:       str = ""
    status_code:     int = 0
    content_type:    str = ""
    fetched_bytes:   int = 0
    truncated:       bool = False
    duration_ms:     int = 0

    # Extracted article (main-content only, boilerplate discarded)
    title:           str = ""
    author:          str = ""
    published_date:  str = ""
    sitename:        str = ""
    language:        str = ""
    article_text:    str = ""          # cleaned plain-text body
    article_chars:   int = 0
    outbound_links:  List[str] = field(default_factory=list)

    # Structured content blocks — raw text pulled from <code>, <pre>,
    # and <td> elements BEFORE trafilatura strips the HTML structure.
    # Threat-report authors publish command samples in exactly these
    # containers; without this list the command extractor would miss
    # them (see the eSentire UNC6692 write-up for a live example).
    structured_blocks: List[str] = field(default_factory=list)

    # Failure semantics
    error_code:      str = ""          # blocked_scheme · private_host · timeout · http_error · content_type · empty · exception
    error_detail:    str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ══════════════════════════════════════════════════════════════════
# 3. Public entry point
# ══════════════════════════════════════════════════════════════════
def acquire_url(url: str) -> AcquiredResource:
    """Safely fetch `url` and return an `AcquiredResource`.

    NEVER raises — every failure lands in `error_code` / `error_detail`.
    """
    started = time.perf_counter()
    result = AcquiredResource(ok=False, url=url or "")

    try:
        # 1. Scheme guard
        scheme, sep, rest = (url or "").partition("://")
        if not sep or scheme.lower() not in _ALLOWED_SCHEMES:
            result.error_code   = "blocked_scheme"
            result.error_detail = f"Only {_ALLOWED_SCHEMES} allowed; got {scheme!r}."
            return _finalise(result, started)

        # 2. Host guard (private / loopback / link-local blocked)
        host = _host_of(url)
        if not host:
            result.error_code   = "invalid_host"
            result.error_detail = "Could not parse host from URL."
            return _finalise(result, started)
        if _is_private_host(host):
            result.error_code   = "private_host"
            result.error_detail = f"Host {host!r} resolves to private / loopback IP space."
            return _finalise(result, started)

        # 3. Fetch with strict safety envelope
        try:
            client = httpx.Client(
                timeout=_TIMEOUT_SECONDS,
                headers={"User-Agent": _USER_AGENT,
                         "Accept": "text/html,application/xhtml+xml,text/plain"},
                follow_redirects=True,
                max_redirects=5,
            )
            with client:
                # `stream` so we can cap bytes without buffering the
                # full response first.
                with client.stream("GET", url) as r:
                    result.status_code = r.status_code
                    result.final_url   = str(r.url)
                    result.content_type = (r.headers.get("content-type") or "").split(";")[0].strip().lower()

                    if r.status_code >= 400:
                        result.error_code   = "http_error"
                        result.error_detail = f"HTTP {r.status_code} from {result.final_url}."
                        return _finalise(result, started)

                    if result.content_type and not any(
                        result.content_type == t or result.content_type.startswith(t + ";")
                        for t in _ALLOWED_TYPES
                    ):
                        result.error_code   = "content_type"
                        result.error_detail = f"Unsupported content-type {result.content_type!r}."
                        return _finalise(result, started)

                    buf: List[bytes] = []
                    total = 0
                    for chunk in r.iter_bytes():
                        buf.append(chunk)
                        total += len(chunk)
                        if total >= _MAX_BYTES:
                            result.truncated = True
                            break
                    body_bytes = b"".join(buf)[:_MAX_BYTES]
        except httpx.TimeoutException as e:
            result.error_code   = "timeout"
            result.error_detail = f"Fetch timed out after {_TIMEOUT_SECONDS}s: {e!s}"
            return _finalise(result, started)
        except httpx.RequestError as e:
            result.error_code   = "network"
            result.error_detail = f"Network failure: {e!s}"
            return _finalise(result, started)

        result.fetched_bytes = len(body_bytes)
        html = _decode_bytes(body_bytes)

        # 4. Extract main content (trafilatura is the vendor)
        extracted = trafilatura.extract(
            html,
            include_comments=False,
            include_tables=True,
            favor_precision=True,
            deduplicate=True,
        ) or ""
        result.article_text  = extracted
        result.article_chars = len(extracted)

        if not extracted.strip():
            result.error_code   = "empty"
            result.error_detail = "Main-content extractor returned no text (page may be JS-rendered or paywalled)."
            return _finalise(result, started)

        # 5. Metadata (title, author, date, sitename, language)
        try:
            meta = trafilatura.extract_metadata(html)
            if meta:
                result.title          = (meta.title or "").strip()
                result.author         = (meta.author or "").strip() if isinstance(meta.author, str) else ""
                result.published_date = (meta.date or "").strip() if isinstance(meta.date, str) else ""
                result.sitename       = (meta.sitename or "").strip()
        except Exception:
            pass

        # 6. Outbound links (deterministic, deduped, order-preserving)
        result.outbound_links = _extract_links(html)

        # 6b. Structured content blocks (code / pre / td / li).
        # Threat-report authors publish commands and IOCs inside these
        # HTML containers; trafilatura strips the surrounding structure,
        # so we grab them explicitly BEFORE running IDA-4 extractors.
        result.structured_blocks = _extract_structured_blocks(html)

        result.ok = True
        return _finalise(result, started)

    except Exception as e:  # noqa: BLE001 — belt & braces
        result.error_code   = "exception"
        result.error_detail = f"{type(e).__name__}: {e!s}"
        return _finalise(result, started)


# ══════════════════════════════════════════════════════════════════
# 4. Helpers
# ══════════════════════════════════════════════════════════════════
def _finalise(r: AcquiredResource, started_at: float) -> AcquiredResource:
    r.duration_ms = int((time.perf_counter() - started_at) * 1000)
    return r


def _host_of(url: str) -> str:
    _, _, rest = url.partition("://")
    host_and_path = rest.split("/", 1)[0]
    host = host_and_path.split("@", 1)[-1]     # strip userinfo
    host = host.split(":", 1)[0]               # strip port
    return host.lower().rstrip(".")


def _is_private_host(host: str) -> bool:
    """True when the host resolves to a private / loopback / link-local
    IP (SSRF guard).  DNS is *not* skipped — we resolve, then classify."""
    try:
        # Fast-path for literal IPs
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        # If DNS fails the fetch will fail — let the caller see the
        # network error rather than blocking on our guard.
        return False
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                return True
        except ValueError:
            continue
    return False


def _decode_bytes(body: bytes) -> str:
    """Best-effort bytes → str.  Prefer utf-8, fall back to
    ISO-8859-1 (which never errors), so downstream extractors never
    crash on encoding."""
    if not body:
        return ""
    try:
        return body.decode("utf-8")
    except UnicodeDecodeError:
        pass
    try:
        return body.decode("latin-1")
    except Exception:
        return body.decode("utf-8", errors="replace")


def _extract_links(html: str) -> List[str]:
    """Return unique outbound href list (order-preserving)."""
    from bs4 import BeautifulSoup
    try:
        soup = BeautifulSoup(html, "lxml")
    except Exception:
        soup = BeautifulSoup(html, "html.parser")
    seen: set = set()
    out: List[str] = []
    for a in soup.find_all("a", href=True):
        href = (a.get("href") or "").strip()
        if not href or href.startswith("#") or href.startswith("javascript:"):
            continue
        if href in seen:
            continue
        seen.add(href)
        out.append(href)
    return out


def _extract_structured_blocks(html: str) -> List[str]:
    """Return the text of every `<code>`, `<pre>`, `<td>` and `<li>`
    element in reading order.  Filters:
      · Duplicates are removed (identical text — vendors often repeat
        the same command in a summary + table).
      · Blocks shorter than 3 chars are dropped (empty cells / dashes).
      · Very long blocks (>2000 chars) are truncated at 2000 chars so
        one runaway block cannot dominate downstream extractors.
    Order-preserving so provenance stays deterministic.
    """
    from bs4 import BeautifulSoup
    try:
        soup = BeautifulSoup(html, "lxml")
    except Exception:
        soup = BeautifulSoup(html, "html.parser")

    # Strip noise elements before harvesting containers.
    for tag in soup(("script", "style", "noscript", "svg", "img")):
        tag.decompose()

    seen: set = set()
    blocks: List[str] = []
    for element in soup.find_all(("code", "pre", "td", "li")):
        text = element.get_text(" ", strip=True)
        if not text or len(text) < 3:
            continue
        if len(text) > 2000:
            text = text[:2000]
        if text in seen:
            continue
        seen.add(text)
        blocks.append(text)
    return blocks
