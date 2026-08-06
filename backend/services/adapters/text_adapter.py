"""Text Adapter — the simplest deterministic adapter.

Pass-through of pasted plain text.  Every command / URL / IP / hash /
domain / registry key / file path in the pasted body becomes a
canonical IEPArtifact with per-line ``source_ref``.

This is the reference implementation of the Adapter Contract — every
downstream adapter (PDF, DOCX, EML, ZIP, Image) follows exactly the
same shape.
"""
from __future__ import annotations

from typing import Any, List

from models.iep import IEPArtifact, IEPContent, IEPSource
from services.ida.artifact_splitter import split_artifacts

from .base import EvidenceAdapter


class TextAdapter(EvidenceAdapter):
    name    = "adapter.text"
    version = "1.0"

    # ── Detection ────────────────────────────────────────────────────
    def can_handle(self, raw: Any) -> bool:
        return isinstance(raw, str) and not raw.strip().startswith(("http://", "https://"))

    # ── Extraction (pure) ────────────────────────────────────────────
    def extract(self, raw: Any) -> IEPContent:
        text = raw if isinstance(raw, str) else str(raw)
        blocks = [
            {"kind": "line", "index": i, "text": line}
            for i, line in enumerate(text.splitlines(), start=1)
            if line.strip()
        ]
        return IEPContent(text=text, blocks=blocks)

    # ── Normalization (pure) ─────────────────────────────────────────
    def normalize(self, content: IEPContent) -> List[IEPArtifact]:
        text = content.text or ""
        # Reuse the mature deterministic splitter from IDA — every
        # artifact it emits carries a `line_no` we translate into a
        # canonical `source_ref`.
        raw_arts = split_artifacts(text) or []
        out: List[IEPArtifact] = []
        for a in raw_arts:
            atype = self._map_type(getattr(a, "type", None))
            value = getattr(a, "value", None)
            if not (atype and value):
                continue
            line_no = getattr(a, "line", None) or getattr(a, "line_no", None)
            out.append(IEPArtifact(
                type=atype,
                value=value,
                canonical=getattr(a, "canonical", None) or None,
                confidence=getattr(a, "confidence", None) or 1.0,
                source_ref=f"text.line.{line_no}" if line_no else "text",
            ))
        return out

    # ── Source detection ─────────────────────────────────────────────
    def _infer_source(self, raw: Any) -> IEPSource:
        s = raw if isinstance(raw, str) else str(raw)
        return IEPSource(
            kind="text",
            size_bytes=len(s.encode("utf-8", errors="ignore")),
            raw_preview=s[:256],
        )

    # ── Splitter type → canonical IEP artifact type ──────────────────
    _TYPE_MAP = {
        "command":       "command",
        "url":           "url",
        "ip":            "ip",
        "domain":        "domain",
        "hash":          "hash",
        "file_path":     "file_path",
        "registry_key":  "registry_key",
        "email":         "email_address",
        "cve":           "cve",
    }

    def _map_type(self, splitter_type: Any) -> str:
        if not splitter_type:
            return "unknown"
        return self._TYPE_MAP.get(splitter_type, splitter_type)
