"""PDF adapter — extracts text + embedded URLs + metadata into
child artifacts.  Uses pypdf (installed) for the primary parse and
falls back to pdfminer.six for stubborn PDFs."""
from __future__ import annotations
import io, re
from typing import Optional
from ..artifact import make_artifact
from ._base import Adapter, AdapterResult, register_adapter


class _PdfAdapter:
    name = "adapter.pdf"
    priority = 90

    def sniff(self, payload: bytes, *, filename=None, declared_mime=None) -> int:
        if payload[:4] == b"%PDF":
            return 100
        if (declared_mime or "").lower() == "application/pdf":
            return 80
        if (filename or "").lower().endswith(".pdf"):
            return 60
        return 0

    def extract(self, payload: bytes, *, filename: Optional[str] = None) -> AdapterResult:
        artifacts = []
        diagnostics = []
        meta = {"format": "application/pdf"}
        text = ""
        page_count = 0
        try:
            import pypdf
            reader = pypdf.PdfReader(io.BytesIO(payload))
            page_count = len(reader.pages)
            for p in reader.pages:
                try:
                    text += (p.extract_text() or "") + "\n"
                except Exception:
                    continue
            meta["extractor"] = "pypdf"
            info = reader.metadata or {}
            meta["pdf_metadata"] = {
                k: str(v) for k, v in (info.items() if info else [])
            }
        except Exception as e:
            diagnostics.append({"code": "DX_PDF_PARSE",
                                    "severity": "warn",
                                    "reason": f"pypdf failed: {e}"})
            try:
                from pdfminer.high_level import extract_text as pm_extract
                text = pm_extract(io.BytesIO(payload)) or ""
                meta["extractor"] = "pdfminer"
            except Exception as e2:
                diagnostics.append({"code": "DX_PDF_FALLBACK_FAIL",
                                        "severity": "warn",
                                        "reason": f"pdfminer failed: {e2}"})
        if text.strip():
            artifacts.append(make_artifact(
                text.encode("utf-8"), "text",
                discovered_by=self.name,
                meta={"source": "pdf_text", "pages": page_count,
                        "filename": filename},
            ))
        # Extract URLs from the raw payload — annotations, JS,
        # embedded /URI actions all live at this level.
        urls = set(re.findall(
            rb"https?://[A-Za-z0-9.\-_/?%=&+~#:@]{4,300}", payload))
        for u in urls:
            artifacts.append(make_artifact(
                u, "url",
                discovered_by=self.name,
                meta={"source": "pdf_embedded_url"},
            ))
        if not artifacts:
            artifacts.append(make_artifact(
                payload, "raw_bytes",
                discovered_by=self.name,
                meta={"reason": "pdf_no_text_no_urls"},
            ))
        return AdapterResult(artifacts=artifacts, diagnostics=diagnostics, meta=meta)


register_adapter(_PdfAdapter())
