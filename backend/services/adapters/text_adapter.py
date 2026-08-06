"""Text Adapter — the simplest deterministic adapter.

Pass-through of pasted plain text.  Every command / URL / IP / hash /
domain / registry key / file path in the pasted body becomes a
canonical IEPArtifact with per-line ``source_ref``.

This is the reference implementation of the Adapter Contract — every
downstream adapter (PDF, DOCX, EML, ZIP, Image) follows exactly the
same shape.
"""
from __future__ import annotations

from typing import Any, Dict, List

from models.iep import IEPArtifact, IEPContent, IEPRelationship, IEPSource
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

    # ── Relationship discovery (R8 — structural edges only) ─────────
    def discover_relationships(self, content, artifacts):
        """Emit obvious structural edges the text adapter already knows.
        No inference — same rules as the URL adapter."""
        rels = []
        by_type = {}
        for a in artifacts:
            by_type.setdefault(a.type, []).append(a)

        # URL → hosted_on → domain
        for u in by_type.get("url", []):
            try:
                from urllib.parse import urlparse
                host = urlparse(u.value).hostname or ""
            except Exception:
                host = ""
            if host:
                rels.append(IEPRelationship(
                    from_ref=u.value, to_ref=host, verb="hosted_on",
                    source_ref=u.source_ref,
                ))

        # command → downloads → URL if on same line
        by_line: Dict[str, List[IEPArtifact]] = {}
        for a in artifacts:
            key = a.source_ref or ""
            by_line.setdefault(key, []).append(a)

        _DL_HEADS = ("curl", "wget", "certutil", "bitsadmin", "iex",
                        "invoke-webrequest", "downloadstring")
        for line_ref, arts in by_line.items():
            cmds = [x for x in arts if x.type == "command"]
            urls = [x for x in arts if x.type == "url"]
            for c in cmds:
                cv = (c.value or "").lower()
                if any(h in cv for h in _DL_HEADS):
                    for u in urls:
                        rels.append(IEPRelationship(
                            from_ref=c.value, to_ref=u.value,
                            verb="downloads", source_ref=line_ref,
                        ))
        return rels

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
