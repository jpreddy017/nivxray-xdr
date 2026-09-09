"""Repair · normalize_padding + strip_whitespace + url_safe_alphabet
(QA-Layer · R28.3).

Three deterministic surgical repairs for base64 blobs, each
registered as its own strategy so the validator/planner can rank
them independently:

    · strip_whitespace     — collapses ALL whitespace inside the blob
    · normalize_padding    — trims to /4 (drops the final partial
                              chunk) and re-adds ``=`` padding to make
                              the length a multiple of 4
    · url_safe_alphabet    — swaps ``-`` → ``+`` and ``_`` → ``/`` so
                              a URL-safe blob parses with the standard
                              base64 decoder
"""
from __future__ import annotations

import re

from ...artifact import Artifact
from ...qa       import (RepairCandidate, RepairResult,
                            register_repair, REPAIR_FAIL_MISSING_BYTES)


_WHITESPACE_RE = re.compile(r"\s+")


def _text(a: Artifact) -> str:
    try:
        return a.payload.decode("utf-8", errors="ignore")
    except Exception:
        return ""


# ══════════════════════════════════════════════════════════════════
# 1. strip_whitespace
# ══════════════════════════════════════════════════════════════════
class _StripWhitespace:
    name     = "repair.base64.strip_whitespace"
    strategy = "strip_whitespace"

    def repair(self, artifact: Artifact,
                candidate: RepairCandidate) -> RepairResult:
        text = _text(artifact)
        if not text:
            return RepairResult(success=False, strategy=self.strategy,
                                  reason=REPAIR_FAIL_MISSING_BYTES,
                                  detail="empty payload")
        cleaned = _WHITESPACE_RE.sub("", text)
        if cleaned == text:
            return RepairResult(success=False, strategy=self.strategy,
                                  reason="no_change",
                                  detail="no whitespace found")
        return RepairResult(
            success=True, strategy=self.strategy,
            repaired_payload=cleaned.encode("utf-8", errors="ignore"),
            detail=f"stripped {len(text) - len(cleaned)} whitespace bytes",
        )


# ══════════════════════════════════════════════════════════════════
# 2. normalize_padding
# ══════════════════════════════════════════════════════════════════
class _NormalizePadding:
    name     = "repair.base64.normalize_padding"
    strategy = "normalize_padding"

    def repair(self, artifact: Artifact,
                candidate: RepairCandidate) -> RepairResult:
        text = _text(artifact)
        if not text:
            return RepairResult(success=False, strategy=self.strategy,
                                  reason=REPAIR_FAIL_MISSING_BYTES,
                                  detail="empty payload")
        # Strip existing padding first, then re-pad to length % 4 == 0.
        # If the length %4 == 1 (impossible for valid base64), trim one
        # char rather than emit invalid padding.
        core = text.rstrip("=")
        rem = len(core) % 4
        if rem == 1:
            # Trim the trailing char and retry — one stray char never
            # produces valid base64.
            core = core[:-1]
            rem = len(core) % 4
        pad = ("=" * (4 - rem)) if rem else ""
        cleaned = core + pad
        if cleaned == text:
            return RepairResult(success=False, strategy=self.strategy,
                                  reason="no_change",
                                  detail="padding already normalised")
        return RepairResult(
            success=True, strategy=self.strategy,
            repaired_payload=cleaned.encode("utf-8", errors="ignore"),
            detail=(f"len={len(text)} → {len(cleaned)} "
                      f"pad_added={len(pad)}"),
            meta={"padded_bytes": len(pad)},
        )


# ══════════════════════════════════════════════════════════════════
# 3. url_safe_alphabet
# ══════════════════════════════════════════════════════════════════
class _UrlSafeAlphabet:
    name     = "repair.base64.url_safe_alphabet"
    strategy = "url_safe_alphabet"

    def repair(self, artifact: Artifact,
                candidate: RepairCandidate) -> RepairResult:
        text = _text(artifact)
        if not text:
            return RepairResult(success=False, strategy=self.strategy,
                                  reason=REPAIR_FAIL_MISSING_BYTES,
                                  detail="empty payload")
        cleaned = text.replace("-", "+").replace("_", "/")
        if cleaned == text:
            return RepairResult(success=False, strategy=self.strategy,
                                  reason="no_change",
                                  detail="no url-safe chars found")
        return RepairResult(
            success=True, strategy=self.strategy,
            repaired_payload=cleaned.encode("utf-8", errors="ignore"),
            detail="swapped `-`→`+` and `_`→`/`",
        )


strip_whitespace   = _StripWhitespace()
normalize_padding  = _NormalizePadding()
url_safe_alphabet  = _UrlSafeAlphabet()

register_repair(strip_whitespace)
register_repair(normalize_padding)
register_repair(url_safe_alphabet)
