"""Plugin · Base64 Text Validator  (QA-Layer · R28.3).

Diagnoses base64-shaped text artifacts (``base64``, ``bare_base64``,
``ps_encodedcommand``, and any ``text`` artifact whose payload is
predominantly a base64 blob) and produces ranked repair candidates
when the blob is invalid.

The validator NEVER modifies bytes.  It only reports:
    · what is wrong                       (canonical INVALID_* code)
    · how confident it is in the diagnosis
    · which repair strategies to try, ranked by confidence

Repair strategies emitted (matching plugins ship in
``plugins/repair_base64_*``):
    · strip_html_entities   — remove <br>, &nbsp;, &amp;, &#xNN;,
                               =?utf-8?B?…?=, zero-width, quoted-printable
    · url_safe_alphabet     — replace ``_`` → ``/`` and ``-`` → ``+``
    · normalize_padding     — trim to /4 and add ``=`` padding
    · strip_whitespace      — collapse whitespace (very cheap)
"""
from __future__ import annotations

import re
from typing import List

from ...artifact import Artifact
from ...qa       import (INVALID_BAD_ALPHABET, INVALID_BAD_PADDING,
                            INVALID_HTML_MANGLED, INVALID_STRUCTURAL,
                            RepairCandidate, ValidationResult,
                            register_validator)


NAME = "validator.base64_text"

# ── Diagnostics ─────────────────────────────────────────────────────
# Standard base64 alphabet.  URL-safe base64 substitutes ``-`` for ``+``
# and ``_`` for ``/``.  Both alphabets are legal; any OTHER byte is
# noise.
_STD_B64 = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
_URL_B64 = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=")

# HTML entity noise commonly injected by web copy-paste (Sophos-style).
_HTML_MARKERS = (
    "&nbsp;", "&amp;", "&lt;", "&gt;", "&quot;", "&#",
    "<br", "</br>", "<br/>", "&#x",
    # MIME B-encoding wrapper
    "=?utf-8?B?", "=?UTF-8?B?", "?=",
)

# Zero-width / directional Unicode injected by many web renderers.
_ZERO_WIDTH_RE = re.compile(r"[\u200B-\u200F\u202A-\u202E\uFEFF]")

# What "looks like a base64 blob" — a run of alphabet chars >= 32 chars.
_B64_RUN_RE = re.compile(r"[A-Za-z0-9+/_\-]{32,}=*")


def _artifact_text(art: Artifact) -> str:
    """Best-effort textualisation without ever throwing."""
    try:
        return art.payload.decode("utf-8", errors="ignore")
    except Exception:
        return ""


def _looks_like_base64(text: str) -> bool:
    """Heuristic: an artifact 'looks like base64' if it contains a
    long alphabet run OR its overall alphabet ratio (relative to
    ``_STD_B64 ∪ _URL_B64``) exceeds 0.85."""
    if not text:
        return False
    if _B64_RUN_RE.search(text):
        return True
    interesting = [c for c in text if not c.isspace()]
    if len(interesting) < 32:
        return False
    b64ish = sum(1 for c in interesting if c in _STD_B64 or c in _URL_B64)
    return (b64ish / len(interesting)) >= 0.85


class _Validator:
    name = NAME
    validates_artifact_type = ["base64", "bare_base64", "ps_encodedcommand"]

    def validate(self, artifact: Artifact) -> ValidationResult:
        text = _artifact_text(artifact)
        if not _looks_like_base64(text):
            # Not our concern — accept, let downstream capabilities
            # figure it out.  (Universal validator behaviour.)
            return ValidationResult(
                valid=True, validator=NAME, confidence=0.0,
                detail="artifact does not look like base64",
            )

        # Extract the longest b64-shape run (the actual payload).
        m = max(_B64_RUN_RE.findall(text), key=len, default=text)
        candidates: List[RepairCandidate] = []
        reasons: List[str] = []

        # ── Diagnostic 1 · HTML entity injection (Sophos-shape) ────
        html_hits = [tok for tok in _HTML_MARKERS if tok in text]
        if html_hits:
            reasons.append(f"html_markers={html_hits[:3]}")
            candidates.append(RepairCandidate(
                strategy="strip_html_entities",
                confidence=0.95,
                reason=INVALID_HTML_MANGLED,
                detail=f"detected {html_hits[:3]}",
                meta={"markers": html_hits},
            ))

        # ── Diagnostic 2 · Zero-width / RTL injection ──────────────
        zw = _ZERO_WIDTH_RE.findall(text)
        if zw:
            reasons.append(f"zero_width={len(zw)}")
            candidates.append(RepairCandidate(
                strategy="strip_html_entities",   # same repair strips zw too
                confidence=0.90,
                reason=INVALID_HTML_MANGLED,
                detail=f"zero_width_count={len(zw)}",
                meta={"zero_width_count": len(zw)},
            ))

        # ── Diagnostic 3 · URL-safe alphabet in a std-b64 slot ─────
        # (only firing when the run has NO ``+`` / ``/`` but HAS
        # ``-`` / ``_``)
        has_url_only = ("-" in m or "_" in m) and ("+" not in m and "/" not in m)
        if has_url_only:
            reasons.append("url_safe_alphabet_detected")
            candidates.append(RepairCandidate(
                strategy="url_safe_alphabet",
                confidence=0.85,
                reason=INVALID_BAD_ALPHABET,
                detail="run uses `-`/`_` (URL-safe) instead of `+`/`/`",
            ))

        # ── Diagnostic 4 · Non-alphabet contaminant in the run ─────
        # (whitespace-tolerant; whitespace triggers a different fix)
        contaminated = [
            ch for ch in m
            if ch not in _STD_B64 and ch not in _URL_B64 and not ch.isspace()
        ]
        if contaminated and not html_hits:
            reasons.append(f"contaminant_chars={list(set(contaminated))[:5]}")
            candidates.append(RepairCandidate(
                strategy="strip_html_entities",
                confidence=0.70,
                reason=INVALID_HTML_MANGLED,
                detail=f"non-b64 chars found: {list(set(contaminated))[:5]}",
            ))

        # ── Diagnostic 5 · Length not divisible by 4 (padding) ─────
        stripped = re.sub(r"\s+", "", m)
        if len(stripped) % 4 != 0:
            reasons.append(f"len%4={len(stripped) % 4}")
            candidates.append(RepairCandidate(
                strategy="normalize_padding",
                confidence=0.75,
                reason=INVALID_BAD_PADDING,
                detail=f"len={len(stripped)} mod4={len(stripped) % 4}",
                meta={"length": len(stripped)},
            ))

        # ── Diagnostic 6 · Whitespace-only contamination ───────────
        whitespace_in_run = sum(1 for c in m if c.isspace())
        if whitespace_in_run and not html_hits:
            reasons.append(f"whitespace_in_run={whitespace_in_run}")
            candidates.append(RepairCandidate(
                strategy="strip_whitespace",
                confidence=0.80,
                reason=INVALID_STRUCTURAL,
                detail=f"whitespace_count={whitespace_in_run}",
            ))

        if not candidates:
            return ValidationResult(
                valid=True, validator=NAME, confidence=0.90,
                detail="base64 blob looks well-formed",
            )
        return ValidationResult(
            valid=False, validator=NAME, confidence=0.90,
            reason=INVALID_HTML_MANGLED if html_hits or zw else (
                INVALID_BAD_PADDING if any(c.reason == INVALID_BAD_PADDING for c in candidates)
                else INVALID_STRUCTURAL),
            detail=" · ".join(reasons),
            repair_candidates=candidates,
        )


validator = _Validator()
register_validator(validator)
