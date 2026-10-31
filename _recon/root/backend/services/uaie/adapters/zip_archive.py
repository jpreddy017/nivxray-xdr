"""Generic ZIP archive adapter — unpacks every entry as an
``archive_entry`` artifact so the UAIE orchestrator's re-recognition
loop can identify PDFs, PEs, PowerShell, further archives, etc.
inside the archive.

Sniff() explicitly runs AFTER the OOXML DOCX adapter (which handles
the well-known Word/Excel/PowerPoint variants) — priority=75 so a
plain ZIP with random contents still gets extracted."""
from __future__ import annotations
import io, zipfile
from typing import Optional
from ..artifact import make_artifact
from ._base import Adapter, AdapterResult, register_adapter


class _ZipAdapter:
    name = "adapter.zip"
    priority = 75

    def sniff(self, payload: bytes, *, filename=None, declared_mime=None) -> int:
        if payload[:4] != b"PK\x03\x04":
            return 0
        # Let OOXML win when it applies.
        head = payload[:min(len(payload), 4096)]
        if b"[Content_Types].xml" in head:
            return 40   # loses to DOCX (95) — wins as fallback if DOCX fails
        return 85

    def extract(self, payload: bytes, *, filename: Optional[str] = None) -> AdapterResult:
        artifacts, diagnostics = [], []
        meta = {"format": "application/zip"}
        try:
            zf = zipfile.ZipFile(io.BytesIO(payload))
        except Exception as e:
            diagnostics.append({"code": "DX_ZIP_OPEN",
                                    "severity": "warn", "reason": str(e)})
            artifacts.append(make_artifact(
                payload, "raw_bytes",
                discovered_by=self.name,
                meta={"reason": "zip_open_failed"}))
            return AdapterResult(artifacts=artifacts,
                                    diagnostics=diagnostics, meta=meta)
        names = zf.namelist()
        meta["entry_count"] = len(names)
        for n in names:
            if n.endswith("/"):
                continue
            try:
                data = zf.read(n)
            except Exception as e:
                diagnostics.append({"code": "DX_ZIP_READ_ENTRY",
                                        "severity": "warn",
                                        "reason": f"{n}: {e}"})
                continue
            if not data:
                continue
            artifacts.append(make_artifact(
                data, "archive_entry",
                discovered_by=self.name,
                meta={"source": "zip_entry",
                        "entry_name": n,
                        "entry_size": len(data)}))
        if not artifacts:
            artifacts.append(make_artifact(
                payload, "raw_bytes",
                discovered_by=self.name,
                meta={"reason": "zip_empty"}))
        return AdapterResult(artifacts=artifacts,
                                diagnostics=diagnostics, meta=meta)


register_adapter(_ZipAdapter())
