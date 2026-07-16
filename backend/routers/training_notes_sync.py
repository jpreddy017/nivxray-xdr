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

_UA = {"User-Agent": "NivXRay/1.0 (+training-notes-url-sync)"}
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
    url = body.url.strip()
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise HTTPException(status_code=422,
                            detail="url must be an absolute http(s) URL")

    # ── 1. Fetch the page (size-capped, content-type-routed) ─────────
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True,
                                      headers=_UA) as c:
            r = await c.get(url)
            r.raise_for_status()
            ctype = (r.headers.get("content-type") or "").lower()
            is_pdf = "application/pdf" in ctype or url.lower().endswith(".pdf")
            is_text = any(x in ctype for x in ("text/", "html", "xml", "json", "markdown"))
            if not is_pdf and not is_text:
                raise HTTPException(status_code=415,
                                    detail=f"unsupported content-type: {ctype or 'unknown'}")
            raw_bytes = r.content
            if len(raw_bytes) > _MAX_FETCH_BYTES:
                raw_bytes = raw_bytes[: _MAX_FETCH_BYTES]
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=502,
                            detail=f"HTTP {e.response.status_code} fetching {url}")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"fetch failed: {e}")

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
        raise HTTPException(status_code=422,
                            detail="page had no extractable content (< 200 chars)")
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
        # Bubble up LLM/parse failures as 502 so the UI can show a clear error.
        raise HTTPException(status_code=502,
                            detail=f"LLM condensation failed: {e.detail}")

    title = (result.get("title") or "").strip()[:120]
    directive = (result.get("directive") or "").strip()
    tags = result.get("tags") or []
    if not isinstance(tags, list):
        tags = []
    tags = [str(t).strip().lower()[:32] for t in tags if str(t).strip()][:8]

    if not title:
        title = f"REF · {parsed.netloc}"
    if len(directive) < 60:
        raise HTTPException(status_code=502,
                            detail="LLM returned an unusably short directive")

    # Pin the source URL onto the body so the note remains auditable.
    body_out = directive.rstrip() + f"\n\n— Source: {url}"

    return {
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
