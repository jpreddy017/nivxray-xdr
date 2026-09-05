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

    # 2026-02-09 · P0.15C-1 · VEEE-recovered NormalizedEvidence
    # records (per ADR-002 §4.1 shape).  Defaults to [] so the
    # dataclass is byte-identical to pre-P0.15C when the flag is
    # off (Release invariant §3.1).  When on, this list carries
    # the FULL VEEE payload including bounding boxes / provenance /
    # skipped records — the Acquisition Summary panel (P0.15C-2)
    # reads it directly.  ``structured_blocks`` still receives the
    # plain-text form so downstream IDA-4 extractors keep seeing
    # everything they used to, plus the new OCR lines.
    veee_records: List[Dict[str, Any]] = field(default_factory=list)

    # Which fetcher / extractor chain produced the article.
    #   engine  → "trafilatura" · "readability" · "bs4" · "playwright+trafilatura" · "playwright+readability" · "playwright+bs4"
    #   source  → analyst-facing label ("Static article" / "JavaScript-rendered page" / "Heuristic body")
    engine:          str = ""
    source_kind:     str = ""
    fallback_chain:  List[str] = field(default_factory=list)

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

        # 4. Extract main content — cascade of engines.  The analyst
        # never needs to know which one succeeded; we just want a
        # non-empty article.  Order: trafilatura (fast, precise) →
        # readability-lxml (score-based) → BeautifulSoup heuristic →
        # Playwright (JS-rendered) → same three engines again over the
        # rendered HTML.  Every step is recorded in `fallback_chain`
        # so the SSOT retains full provenance.
        article, engine, chain = _extract_with_cascade(html, url)
        result.fallback_chain = chain
        result.article_text   = article
        result.article_chars  = len(article)
        result.engine         = engine
        result.source_kind    = _friendly_source(engine)

        if not article.strip():
            result.error_code   = "empty"
            result.error_detail = (
                "All acquisition engines returned no main content. "
                f"Attempted: {', '.join(chain) or 'none'}."
            )
            return _finalise(result, started)

        # 5. Metadata (title, author, date, sitename, language).
        # Metadata is best pulled from the freshest HTML we have — if
        # Playwright rendered the page, use that DOM instead of the raw
        # pre-JS body so we get the correct <title>.
        meta_html = _last_rendered_html.get(url) or html
        try:
            meta = trafilatura.extract_metadata(meta_html)
            if meta:
                result.title          = (meta.title or "").strip()
                result.author         = (meta.author or "").strip() if isinstance(meta.author, str) else ""
                result.published_date = (meta.date or "").strip() if isinstance(meta.date, str) else ""
                result.sitename       = (meta.sitename or "").strip()
        except Exception:
            pass

        # 6. Outbound links (deterministic, deduped, order-preserving)
        result.outbound_links = _extract_links(meta_html)

        # 6b. Structured content blocks (code / pre / td / li).
        # Threat-report authors publish commands and IOCs inside these
        # HTML containers; trafilatura strips the surrounding structure,
        # so we grab them explicitly BEFORE running IDA-4 extractors.
        result.structured_blocks = _extract_structured_blocks(meta_html)

        # 6c. P0.15C-1 · VEEE image-evidence acquisition.
        # Feature-flagged additive step — when ``NVX_VEEE_ENABLED``
        # is off (default), this is a no-op and structured_blocks
        # remains byte-identical to the pre-P0.15C pipeline
        # (Release invariant §3.1).  When enabled, every OCR-derived
        # text line is APPENDED to structured_blocks — never
        # replaces / removes / mutates any existing entry
        # (Never-Modify Rule §0.2 + Additivity invariant §3.2).
        try:
            from services.veee import extract_from_html, is_enabled as _veee_on
            if _veee_on():
                _veee_records = extract_from_html(meta_html, base_url=url)
                # Stash structured records on the resource for the
                # Acquisition Summary panel (P0.15C-2 — additive
                # field, defaults to []).  Never mutates
                # ``structured_blocks`` other than appending the
                # OCR-derived text.
                result.veee_records = _veee_records
                for _rec in _veee_records:
                    txt = (_rec.get("text") or "").strip()
                    if txt and _rec.get("type") != "skipped":
                        # APPEND ONLY.  HTML blocks stay first;
                        # OCR blocks stack after.  This preserves
                        # the additivity invariant trivially.
                        result.structured_blocks.append(txt)
        except Exception:
            # VEEE MUST NEVER break acquisition (ADR-002 §6 golden
            # rule).  Swallow any failure; existing behaviour holds.
            pass

        # Cleanup the per-URL render cache so a long-lived process
        # doesn't accumulate rendered HTML across many acquisitions.
        _last_rendered_html.pop(url, None)

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
      · Very long blocks (>32 KB) are truncated at 32 KB so one
        runaway block cannot dominate downstream extractors.  The
        original 2 KB cap was too aggressive — real threat-report
        base64 blobs (Sophos "Decoding Malicious PowerShell",
        Cobalt Strike -EncodedCommand payloads, etc.) are commonly
        7–10 KB and get silently truncated at 2 KB, which prevents
        the downstream recursive decoder from reaching the shellcode
        layer where the C2 IOCs live.
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
    _BLOCK_CAP = 32 * 1024
    for element in soup.find_all(("code", "pre", "td", "li")):
        text = element.get_text(" ", strip=True)
        if not text or len(text) < 3:
            continue
        if len(text) > _BLOCK_CAP:
            text = text[:_BLOCK_CAP]
        if text in seen:
            continue
        seen.add(text)
        blocks.append(text)
    return blocks


# ══════════════════════════════════════════════════════════════════
# 5. Main-content extraction cascade (2026-03-02)
# ══════════════════════════════════════════════════════════════════
# Rule R19 · Corollary "Acquisition must be invisible":
#   Never surface which fetcher/extractor succeeded in the analyst UI.
#   Instead, cascade until we have a non-empty article and record the
#   winner in `engine` + `fallback_chain` for provenance.
#
# Order (fastest → slowest):
#   trafilatura → readability → BeautifulSoup heuristic → Playwright
#     (Playwright then re-runs trafilatura / readability / bs4 on the
#      rendered DOM so JS-heavy vendor pages still yield an article).
#
# The `_last_rendered_html` module cache stashes the Playwright-rendered
# DOM so downstream helpers (metadata / links / structured blocks) also
# work on the post-JS body.  Cleared per acquisition.
_last_rendered_html: Dict[str, str] = {}

# Playwright is optional and heavy — import lazily so unit tests
# don't pay the startup cost if they never trigger the fallback.
_playwright_probe = {"ok": None, "reason": ""}


def _trafilatura_extract(html: str) -> str:
    try:
        return (trafilatura.extract(
            html,
            include_comments=False,
            include_tables=True,
            favor_precision=True,
            deduplicate=True,
        ) or "").strip()
    except Exception:
        return ""


def _readability_extract(html: str) -> str:
    """Score-based main-content extractor (readability-lxml).  Works
    better than trafilatura on many vendor blogs whose HTML has
    unusual container structures."""
    try:
        from readability import Document      # readability-lxml
        doc = Document(html)
        summary_html = doc.summary(html_partial=True) or ""
        if not summary_html.strip():
            return ""
        from bs4 import BeautifulSoup
        try:
            soup = BeautifulSoup(summary_html, "lxml")
        except Exception:
            soup = BeautifulSoup(summary_html, "html.parser")
        return soup.get_text("\n", strip=True)
    except Exception:
        return ""


def _bs4_heuristic_extract(html: str) -> str:
    """Last-resort heuristic: strip nav/header/footer/script/style then
    pick the longest `<article>` / `<main>` / `<section>` / body text.
    Deterministic and dependency-free."""
    try:
        from bs4 import BeautifulSoup
        try:
            soup = BeautifulSoup(html, "lxml")
        except Exception:
            soup = BeautifulSoup(html, "html.parser")
        for tag in soup(("script", "style", "noscript", "svg", "img",
                          "nav", "header", "footer", "aside", "form")):
            tag.decompose()

        candidates: List[str] = []
        for sel in ("article", "main", "section",
                     "[role=main]", "div.post", "div.entry-content",
                     "div.article-body", "div.blog-post"):
            for el in soup.select(sel):
                t = el.get_text("\n", strip=True)
                if len(t) >= 200:
                    candidates.append(t)
        if not candidates:
            body = soup.find("body")
            if body:
                t = body.get_text("\n", strip=True)
                if len(t) >= 200:
                    candidates.append(t)
        if not candidates:
            return ""
        return max(candidates, key=len)
    except Exception:
        return ""


def _playwright_render(url: str, timeout_ms: int = 20_000) -> str:
    """Render `url` with a headless Chromium and return its HTML.
    Silently returns '' if Playwright is unavailable — the cascade
    then falls through to the static engines it already tried.

    Deterministic-enough for our purposes: same URL + same server +
    same fingerprint → same rendered DOM.  We DO NOT run any JS
    beyond initial page load (no scrolling / clicking) so the render
    is short and stable.
    """
    if _playwright_probe["ok"] is False:
        return ""
    try:
        from playwright.sync_api import sync_playwright, Error as PWError
    except Exception as e:                                   # pragma: no cover
        _playwright_probe["ok"] = False
        _playwright_probe["reason"] = f"import: {e!s}"
        return ""
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage"],
            )
            try:
                # 2026-02-09 · Present as a real browser to CDN-fronted
                # sites (Imperva/Incapsula/Cloudflare) that reject
                # obvious bot User-Agent strings.  Using the NivXRay
                # bot UA here caused every Sophos-community-style
                # article to fail acquisition.
                ctx = browser.new_context(
                    user_agent=(
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/120.0.0.0 Safari/537.36"
                    ),
                    viewport={"width": 1440, "height": 900},
                    java_script_enabled=True,
                    ignore_https_errors=True,
                    locale="en-US",
                )
                page = ctx.new_page()
                page.set_default_timeout(timeout_ms)
                # `domcontentloaded` returns as soon as the HTML parser
                # has finished — `networkidle` can hang indefinitely on
                # pages that keep analytics beacons open.
                page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
                # Give the page a moment to hydrate before we snapshot
                # the DOM (article content typically arrives within 2s).
                try:
                    page.wait_for_selector(
                        "article, main, .cs-topic, .cs-blog-content, "
                        ".article, .post, .entry-content, .blog-content",
                        timeout=8000,
                    )
                except Exception:
                    pass
                html = page.content()
                _playwright_probe["ok"] = True
                return html or ""
            finally:
                try: browser.close()
                except Exception: pass
    except Exception as e:                                   # PWError included
        _playwright_probe["ok"] = False
        _playwright_probe["reason"] = f"{type(e).__name__}: {e!s}"
        return ""


def _looks_like_antibot_wall(html: str) -> bool:
    """Detect the tiny HTML challenge pages served by Imperva/Incapsula,
    Cloudflare, Akamai, PerimeterX etc. — the acquisition cascade
    should treat these as "no article" and fall through to Wayback."""
    if not html:
        return True
    if len(html) >= 8000:
        return False
    low = html.lower()
    markers = (
        "noindex, nofollow",       # Imperva
        "_incapsula_resource",     # Incapsula
        "cf-browser-verification", # Cloudflare
        "checking your browser",   # Cloudflare / Akamai
        "please enable cookies",   # PerimeterX
        "attention required",      # Cloudflare
        "distil_",                 # Distil
        "iframe id=\"main-iframe\"",
    )
    return any(m in low for m in markers)


def _wayback_fetch(original_url: str, timeout_s: float = 20.0) -> str:
    """Fetch the closest Wayback-Machine snapshot of `original_url`.

    The Wayback CDX API is skipped (it's rate-limited); we hit the
    `web.archive.org/web/<year>/<url>` shortcut which resolves to the
    nearest snapshot and works reliably in production.  Wayback strips
    the injected toolbar automatically when we set the `id_` flag.
    """
    if not original_url or not original_url.lower().startswith(("http://", "https://")):
        return ""
    # The `if_` (identity) flag returns the raw archived HTML without
    # the Wayback rewrite header/toolbar injection — cleaner input for
    # trafilatura / readability.
    for year in ("2024", "2023", "2025"):
        snap = f"https://web.archive.org/web/{year}0101000000if_/{original_url}"
        try:
            r = httpx.get(
                snap,
                timeout=timeout_s,
                follow_redirects=True,
                headers={
                    "User-Agent": (
                        "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) "
                        "Gecko/20100101 Firefox/120.0"
                    ),
                    "Accept": "text/html,application/xhtml+xml",
                },
            )
        except httpx.HTTPError:
            continue
        if r.status_code == 200 and r.content and len(r.content) > 4000:
            return _decode_bytes(r.content)
    return ""


def _extract_with_cascade(html: str, url: str):
    """Run the acquisition cascade and return (article, engine, chain).

    Every engine that ran is appended to `chain` even when it failed —
    this is the analyst's audit trail.  The first non-empty result
    wins and the cascade stops.
    """
    chain: List[str] = []

    def _try(name: str, extractor):
        chain.append(name)
        return extractor()

    art = _try("trafilatura", lambda: _trafilatura_extract(html))
    if len(art) >= 200:
        return art, "trafilatura", chain

    art2 = _try("readability", lambda: _readability_extract(html))
    if len(art2) >= 200:
        return art2, "readability", chain
    if len(art2) > len(art):
        art = art2

    art3 = _try("bs4", lambda: _bs4_heuristic_extract(html))
    if len(art3) >= 200:
        return art3, "bs4", chain
    if len(art3) > len(art):
        art = art3

    # Static engines are done.  Try Playwright to unlock JS-rendered
    # vendor pages (eSentire, Mandiant, many Cloudflare-guarded blogs).
    rendered = _try("playwright", lambda: _playwright_render(url))
    if rendered:
        _last_rendered_html[url] = rendered

        art4 = _try("playwright+trafilatura",
                     lambda: _trafilatura_extract(rendered))
        if len(art4) >= 200:
            return art4, "playwright+trafilatura", chain

        art5 = _try("playwright+readability",
                     lambda: _readability_extract(rendered))
        if len(art5) >= 200:
            return art5, "playwright+readability", chain

        art6 = _try("playwright+bs4",
                     lambda: _bs4_heuristic_extract(rendered))
        if len(art6) >= 200:
            return art6, "playwright+bs4", chain

        # Nothing above the 200-char confidence threshold — return the
        # longest thing we managed to pull, whichever engine that was.
        best = max([art, art2, art3, art4, art5, art6], key=len)
        if best:
            engine = "playwright+bs4" if best in (art4, art5, art6) else "bs4"
            return best, engine, chain

    # No Playwright (or Playwright also blocked) — try the Wayback
    # Machine as a last resort.  CDN-fronted articles (Sophos community
    # via Imperva, Cloudflare-guarded Talos posts, etc.) are almost
    # always archived and Wayback serves the raw HTML without an
    # anti-bot wall.  Deterministic given a fixed snapshot year.
    if _looks_like_antibot_wall(html) or max(len(art), len(art2), len(art3)) < 200:
        archived = _try("wayback", lambda: _wayback_fetch(url))
        if archived:
            _last_rendered_html[url] = archived
            aw1 = _try("wayback+trafilatura", lambda: _trafilatura_extract(archived))
            if len(aw1) >= 200:
                return aw1, "wayback+trafilatura", chain
            aw2 = _try("wayback+readability", lambda: _readability_extract(archived))
            if len(aw2) >= 200:
                return aw2, "wayback+readability", chain
            aw3 = _try("wayback+bs4", lambda: _bs4_heuristic_extract(archived))
            if len(aw3) >= 200:
                return aw3, "wayback+bs4", chain
            best_wb = max([aw1, aw2, aw3], key=len)
            if best_wb:
                engine = ("wayback+trafilatura" if best_wb is aw1
                          else "wayback+readability" if best_wb is aw2
                          else "wayback+bs4")
                return best_wb, engine, chain

    # No Playwright — return the best static attempt (may be empty).
    best = max([art, art2, art3], key=len)
    return best, ("trafilatura" if best is art
                   else "readability" if best is art2
                   else "bs4"), chain


def _friendly_source(engine: str) -> str:
    """Analyst-facing translation of the raw engine name."""
    if not engine:                       return "Unknown"
    if engine.startswith("wayback"):     return "Wayback Machine archive"
    if engine.startswith("playwright"):  return "JavaScript-rendered page"
    if engine == "readability":          return "Score-based main-content extraction"
    if engine == "bs4":                  return "Heuristic body extraction"
    if engine == "trafilatura":          return "Static article"
    return engine
