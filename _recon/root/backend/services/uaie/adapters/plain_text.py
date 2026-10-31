"""Plain-text adapter — always claims text-shaped payloads with the
lowest priority so it's the fallback when nothing more specific
matches.  Emits a single ``text`` artifact carrying the UTF-8 decoded
content."""
from __future__ import annotations
from typing import Optional
from ..artifact import make_artifact
from ._base import Adapter, AdapterResult, register_adapter


class _PlainTextAdapter:
    name = "adapter.plain_text"
    priority = 1

    def sniff(self, payload: bytes, *, filename=None, declared_mime=None) -> int:
        if not payload:
            return 0
        # Reject clearly binary payloads.
        sample = payload[:2048]
        if b"\x00" in sample:
            return 0
        # Printable ratio > 85 % → treat as text.
        try:
            txt = sample.decode("utf-8", errors="ignore")
        except Exception:
            return 0
        if not txt:
            return 0
        printable = sum(1 for c in txt if c.isprintable() or c in "\r\n\t")
        return 20 if (printable / len(txt)) > 0.85 else 0

    def extract(self, payload: bytes, *, filename: Optional[str] = None) -> AdapterResult:
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError:
            text = payload.decode("utf-8", errors="replace")
        art = make_artifact(
            text.encode("utf-8"), "text",
            discovered_by=self.name,
            meta={"filename": filename, "chars": len(text)},
        )
        return AdapterResult(artifacts=[art],
                                meta={"format": "text/plain"})


register_adapter(_PlainTextAdapter())
