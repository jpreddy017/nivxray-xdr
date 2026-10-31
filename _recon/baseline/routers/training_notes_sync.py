"""Training-note URL sync — fetch a public URL, extract clean article text,
and ask the LLM to condense it into a training-note-ready directive.

Endpoint:
  POST /api/admin/training-notes/sync-url  {url}
  → {title, body, ref_url, ref_source, model, fetched_chars, summary_chars}

The synthesis prompt is deliberately biased toward *directive* language
("ALWAYS", "TREAT ... AS", "PRIORITISE ...") so the resulting body drops
straight into the always-on training-note channel.

Supported content types:
  - HTML / plain text / XML / JSON / Markdown  → stripped with `_strip_html`
  - PDF (`application/pdf`, `.pdf`)            → extracted with `pypdf`
"""
from __future__ import annotations
import html
import io
import re
from typing import Dict
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from deps import require_admin, llm_json

router = APIRouter()

_UA = {
    # Modern Chrome UA — Cloudflare-fronted sites (redcanary.com etc.) refuse
    # bot-shaped User-Agents outright. Real browser UA + Accept header pair
    # bypasses the vast majority of the "invalid or incomplete response" 502s
    # Cloudflare returns when the origin has bot protection enabled.
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
    ),
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/avif,image/webp,application/pdf;q=0.8,*/*;q=0.7"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Sec-Fetch-Site":  "none",
    "Sec-Fetch-Mode":  "navigate",
    "Sec-Fetch-User":  "?1",
    "Sec-Fetch-Dest":  "document",
    "Upgrade-Insecure-Requests": "1",
}
_TIMEOUT = httpx.Timeout(30.0, connect=8.0)
_MAX_FETCH_BYTES = 8_000_000     # 8 MB — enough for most CTI ebooks
_MAX_LLM_CHARS   = 18_000        # trimmed content passed to the LLM


class SyncIn(BaseModel):
    url: str = Field(..., min_length=8, max_length=2048)


def _strip_html(raw: str) -> str:
    """Extract readable article text from crude HTML.

    Pure-Python, no BeautifulSoup dependency — the caller only needs a
    dense text blob to summarise, not perfect structural fidelity.
    """
    # Remove script/style/noscript blocks in full.
    txt = re.sub(r"(?is)<(script|style|noscript|svg|iframe)\b[^>]*>.*?</\1>", " ", raw)
    # Drop nav / footer / aside / header structural blocks entirely.
    txt = re.sub(r"(?is)<(nav|footer|aside|header|form|button)\b[^>]*>.*?</\1>",
                 " ", txt)
    # Preserve headings + paragraph breaks so the LLM sees structure.
    txt = re.sub(r"(?i)</(h[1-6]|p|li|div|br|tr)>", "\n", txt)
    txt = re.sub(r"(?i)<li[^>]*>", " • ", txt)
    # Kill everything else that looks like a tag.
    txt = re.sub(r"<[^>]+>", " ", txt)
    txt = html.unescape(txt)
    # Collapse whitespace but keep newlines.
    txt = re.sub(r"[ \t\r\f]+", " ", txt)
    txt = re.sub(r"\n[ \n]+", "\n", txt)
    return txt.strip()


def _extract_pdf(binary: bytes, max_pages: int = 60) -> str:
    """Extract concatenated text from a PDF byte stream via pypdf.

    Caps at `max_pages` — CTI ebooks are usually front-loaded, and past
    ~60 pages the LLM window is saturated anyway.
    """
    try:
        from pypdf import PdfReader
    except Exception as e:  # pragma: no cover — pypdf ships in reqs
        raise HTTPException(status_code=500,
                            detail=f"PDF support unavailable: {e}")
    try:
        reader = PdfReader(io.BytesIO(binary))
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"unreadable PDF: {e}")
    chunks = []
    for i, page in enumerate(reader.pages):
        if i >= max_pages:
            break
        try:
            t = page.extract_text() or ""
        except Exception:
            continue
        t = re.sub(r"[ \t\r\f]+", " ", t)
        t = re.sub(r"\n[ \n]+", "\n", t)
        chunks.append(t.strip())
    return "\n\n".join(c for c in chunks if c)


@router.post("/admin/training-notes/sync-url")
async def sync_training_note_url(body: SyncIn, user=Depends(require_admin)):
    """Return **HTTP 200** always — success or failure. Errors are surfaced
    via `{"ok": false, "error": "...", "hint": "..."}` in the body.

    Rationale (Feb 2026): Cloudflare (fronting the Emergent preview URL)
    replaces our JSON body with its own generic HTML error page whenever
    the origin returns any 5xx status. That masks the true reason (LLM
    budget exhausted, origin bot-block, etc.) and shows the analyst
    "origin web server returned an invalid or incomplete response" instead.
    Returning 200 with an error envelope keeps our real detail intact.
    """
    url = body.url.strip()
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return {"ok": False, "error": "url must be an absolute http(s) URL"}

    # ── 1. Fetch the page (size-capped, content-type-routed) ─────────
    async def _fetch():
        # httpx defaults to HTTP/1.1 (h2 extra not installed) — browser-like
        # headers alone bypass most Cloudflare "invalid response" 502s.
        async with httpx.AsyncClient(
            timeout=_TIMEOUT,
            follow_redirects=True,
            headers=_UA,
        ) as c:
            r = await c.get(url)
            r.raise_for_status()
            return r

    try:
        r = await _fetch()
        ctype = (r.headers.get("content-type") or "").lower()
        is_pdf = "application/pdf" in ctype or url.lower().endswith(".pdf")
        is_text = any(x in ctype for x in ("text/", "html", "xml", "json", "markdown"))
        if not is_pdf and not is_text:
            return {"ok": False,
                    "error": f"unsupported content-type: {ctype or 'unknown'}",
                    "hint": "SYNC only reads HTML / PDF / plain-text pages."}
        raw_bytes = r.content
        if len(raw_bytes) > _MAX_FETCH_BYTES:
            raw_bytes = raw_bytes[: _MAX_FETCH_BYTES]
    except httpx.HTTPStatusError as e:
        code = e.response.status_code
        hint = ""
        if code in (403, 429, 503):
            hint = (f"origin ({parsed.netloc}) blocked our fetch (Cloudflare "
                    "bot protection). Copy the article text into DIRECTIVE manually.")
        return {"ok": False,
                "error": f"HTTP {code} fetching {url}",
                "hint": hint or "The origin server returned an HTTP error."}
    except Exception as e:
        return {"ok": False,
                "error": f"fetch failed for {parsed.netloc}: {e}",
                "hint": "The origin server rejected our request. Paste the article text into DIRECTIVE manually."}

    if is_pdf:
        article = _extract_pdf(raw_bytes)
        source_kind = "pdf"
    else:
        try:
            raw_text = raw_bytes.decode(r.encoding or "utf-8", errors="replace")
        except Exception:
            raw_text = raw_bytes.decode("utf-8", errors="replace")
        article = _strip_html(raw_text)
        source_kind = "web"

    if len(article) < 200:
        return {"ok": False,
                "error": "page had no extractable content (< 200 chars)",
                "hint": "Site likely requires JavaScript rendering. Paste text into DIRECTIVE manually."}
    trimmed = article[:_MAX_LLM_CHARS]

    # ── 2. LLM condensation into directive form ──────────────────────
    system = (
        "You are the NivXRay Training-Notes Editor. You convert third-party "
        "security-research articles into concise ALWAYS-ON directives for "
        "the NivXRay AI investigation prompt. Output must be JSON with keys "
        "`title` (≤ 90 chars, no emojis), `directive` (200–1200 chars, use "
        "imperative language like 'ALWAYS', 'TREAT ... AS', 'PRIORITISE', "
        "'FLAG', 'MAP TO T####'; group tips into short bullet lines starting "
        "with '- '), `tags` (array of ≤ 8 short kebab-case tags relevant to "
        "the article — e.g. 'powershell', 'T1059.001', 'lolbas'). "
        "NEVER invent facts not in the source. If the article covers "
        "detection tradecraft, prefer emitting concrete MITRE T-IDs, "
        "Windows Event IDs, cmdlet/binary names, and short regex-friendly "
        "keywords the analyst can grep for."
    )
    user_msg = (
        f"URL: {url}\n"
        f"Source domain: {parsed.netloc}\n"
        f"Source type: {source_kind}\n"
        f"---{source_kind.upper()}-TEXT-BEGIN---\n{trimmed}\n---{source_kind.upper()}-TEXT-END---\n\n"
        "Return the JSON object now."
    )
    session_id = f"training-note-sync-{parsed.netloc}"

    try:
        result = await llm_json(session_id, system, user_msg, retries=1)
    except HTTPException as e:
        # LLM/parse failure — surface the REAL reason as 200 body so Cloudflare
        # doesn't replace it with a generic error page.
        detail = str(e.detail) if e.detail else "unknown LLM failure"
        low = detail.lower()
        hint = ""
        if "spend limit" in low or "budget" in low or "quota" in low:
            hint = ("Your Emergent Universal Key hit its daily spend limit. "
                    "Top up at Profile → Universal Key → Add Balance, or paste "
                    "the article text into DIRECTIVE manually.")
        elif "safety" in low or "refused" in low:
            hint = ("The LLM refused this content (safety filter). Paste the "
                    "article text into DIRECTIVE manually.")
        return {"ok": False,
                "error": f"LLM condensation failed: {detail}",
                "hint": hint or "Retry later or paste the article text manually.",
                "fetched_chars": len(article),
                "source_kind": source_kind}

    title = (result.get("title") or "").strip()[:120]
    directive = (result.get("directive") or "").strip()
    tags = result.get("tags") or []
    if not isinstance(tags, list):
        tags = []
    tags = [str(t).strip().lower()[:32] for t in tags if str(t).strip()][:8]

    if not title:
        title = f"REF · {parsed.netloc}"
    if len(directive) < 60:
        return {"ok": False,
                "error": "LLM returned an unusably short directive",
                "hint": "Try again or paste the article text into DIRECTIVE manually.",
                "fetched_chars": len(article)}

    # Pin the source URL onto the body so the note remains auditable.
    body_out = directive.rstrip() + f"\n\n— Source: {url}"

    return {
        "ok":            True,
        "title":         title,
        "body":          body_out,
        "ref_url":       url,
        "ref_source":    parsed.netloc,
        "source_kind":   source_kind,
        "tags":          tags,
        "model":         "claude-sonnet-4-5-20250929",
        "fetched_chars": len(article),
        "summary_chars": len(directive),
    }
