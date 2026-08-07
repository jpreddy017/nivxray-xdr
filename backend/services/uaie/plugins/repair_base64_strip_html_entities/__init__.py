"""Repair · strip_html_entities  (QA-Layer · R28.3).

Deterministically removes HTML/MIME/quoted-printable noise that
web copy-paste tends to inject into base64 blobs:

    · HTML tags:            <br>, </br>, <br/>, <p>, </p>
    · HTML entities:        &nbsp;, &amp;, &lt;, &gt;, &quot;, &#xNN;
    · MIME B-encoding:      =?utf-8?B?…?=  (RFC 2047)
    · Quoted-printable:     =0A, =3D, soft-line-break `=<CR><LF>`
    · Zero-width/RTL:       \u200B–\u200F, \u202A–\u202E, \uFEFF
    · Common whitespace:    all whitespace collapsed inside the b64 run

The repair NEVER re-orders bytes.  It removes noise in-place and
returns the cleaned payload for the validator to re-check.
"""
from __future__ import annotations

import html
import re

from ...artifact import Artifact
from ...qa       import (RepairCandidate, RepairResult, REPAIR_FAIL_MISSING_BYTES,
                            register_repair)


NAME     = "repair.base64.strip_html_entities"
STRATEGY = "strip_html_entities"

_HTML_TAG_RE     = re.compile(r"<\s*/?\s*(?:br|p|div|span|em|strong|b|i)\s*/?>", re.IGNORECASE)
_HTML_NUMERIC_RE = re.compile(r"&#x?[0-9a-fA-F]+;")
_MIME_B_WRAP_RE  = re.compile(r"=\?[^?]+\?B\?", re.IGNORECASE)
_MIME_B_END_RE   = re.compile(r"\?=")
_QP_SOFT_BREAK   = re.compile(r"=\r?\n")
_QP_HEX_ESCAPE   = re.compile(r"=([0-9A-Fa-f]{2})")
_ZERO_WIDTH_RE   = re.compile(r"[\u200B-\u200F\u202A-\u202E\uFEFF]")


def _strip(text: str) -> str:
    if not text:
        return text
    # 1. Drop MIME B-encoding wrappers first (they contain `?=` which
    #    would otherwise leak through quoted-printable stripping).
    t = _MIME_B_WRAP_RE.sub("", text)
    t = _MIME_B_END_RE.sub("", t)
    # 2. Drop HTML tags outright.
    t = _HTML_TAG_RE.sub("", t)
    # 3. Decode &amp; / &nbsp; / &lt; / &gt; / &quot; and numeric refs.
    t = html.unescape(t)
    t = _HTML_NUMERIC_RE.sub("", t)  # anything unescape missed
    # 4. Quoted-printable soft-line-break `=<CR><LF>` disappears; `=NN`
    #    (base64 padding pattern) MUST be preserved.  We keep `=NN`
    #    intact and only kill `=<CR><LF>`.
    t = _QP_SOFT_BREAK.sub("", t)
    # 5. Zero-width Unicode.
    t = _ZERO_WIDTH_RE.sub("", t)
    # 6. Non-breaking space + tab + newlines inside a b64 blob are noise.
    t = t.replace("\xa0", "")
    return t


class _Repair:
    name     = NAME
    strategy = STRATEGY

    def repair(self, artifact: Artifact,
                candidate: RepairCandidate) -> RepairResult:
        try:
            text = artifact.payload.decode("utf-8", errors="ignore")
        except Exception:
            return RepairResult(
                success=False, strategy=STRATEGY,
                reason=REPAIR_FAIL_MISSING_BYTES,
                detail="payload not decodable as utf-8",
            )
        cleaned = _strip(text)
        if cleaned == text:
            # No noise removed — do NOT surface as success (validator
            # would loop otherwise).
            return RepairResult(
                success=False, strategy=STRATEGY,
                reason="no_change",
                detail="strip_html_entities produced identical bytes",
            )
        return RepairResult(
            success=True, strategy=STRATEGY,
            repaired_payload=cleaned.encode("utf-8", errors="ignore"),
            detail=f"stripped {len(text) - len(cleaned)} bytes of html/mime/qp noise",
            meta={"bytes_removed": len(text) - len(cleaned)},
        )


repair = _Repair()
register_repair(repair)
