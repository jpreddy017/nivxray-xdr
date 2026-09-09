"""DOCX / OOXML adapter — extracts document text + embedded VBA
macros + embedded images + hyperlinks into typed child artifacts.

Also covers XLSX/PPTX (all ZIP-based OOXML) — see ``_looks_like_ooxml``.
"""
from __future__ import annotations
import io, re, zipfile
from typing import Optional
from ..artifact import make_artifact
from ._base import Adapter, AdapterResult, register_adapter


_OOXML_MARKERS = (b"[Content_Types].xml", b"word/", b"xl/", b"ppt/")


class _DocxAdapter:
    name = "adapter.docx"
    priority = 85

    def _looks_like_ooxml(self, payload: bytes) -> bool:
        if payload[:4] != b"PK\x03\x04":
            return False
        # Peek deeper for OOXML markers to distinguish from generic ZIP.
        head = payload[:min(len(payload), 8192)]
        return any(m in head for m in _OOXML_MARKERS) or b"[Content_Types]" in head

    def sniff(self, payload: bytes, *, filename=None, declared_mime=None) -> int:
        if self._looks_like_ooxml(payload):
            # Look for explicit format hints
            head = payload[:min(len(payload), 8192)]
            if b"word/" in head:      return 95
            if b"xl/"   in head:      return 95
            if b"ppt/"  in head:      return 95
            return 80
        fn = (filename or "").lower()
        if fn.endswith((".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm")):
            return 70
        return 0

    def extract(self, payload: bytes, *, filename: Optional[str] = None) -> AdapterResult:
        artifacts, diagnostics = [], []
        meta = {"format": "application/ooxml"}
        try:
            zf = zipfile.ZipFile(io.BytesIO(payload))
        except Exception as e:
            diagnostics.append({"code": "DX_OOXML_UNZIP",
                                    "severity": "warn", "reason": str(e)})
            artifacts.append(make_artifact(
                payload, "raw_bytes",
                discovered_by=self.name,
                meta={"reason": "ooxml_unzip_failed"}))
            return AdapterResult(artifacts=artifacts, diagnostics=diagnostics, meta=meta)
        names = zf.namelist()
        meta["ooxml_files"] = len(names)
        # 1. Extract text from document.xml / sheet.xml / slide.xml
        aggregated_text = []
        for n in names:
            low = n.lower()
            if low.endswith((".xml", ".rels")) and any(
                seg in low for seg in ("document.xml", "sheet", "slide",
                                          "sharedstrings", "footnotes",
                                          "endnotes", "comments")
            ):
                try:
                    xml = zf.read(n).decode("utf-8", errors="replace")
                except Exception:
                    continue
                # Strip XML tags — deterministic, no parser dep.
                stripped = re.sub(r"<[^>]+>", " ", xml)
                stripped = re.sub(r"\s+", " ", stripped).strip()
                if stripped:
                    aggregated_text.append(stripped)
        if aggregated_text:
            joined = "\n\n".join(aggregated_text)
            artifacts.append(make_artifact(
                joined.encode("utf-8"), "text",
                discovered_by=self.name,
                meta={"source": "ooxml_document_text"}))
        # 2. VBA macros — ``vbaProject.bin`` is the OLE stream.
        for n in names:
            if n.lower().endswith("vbaproject.bin"):
                try:
                    bin_bytes = zf.read(n)
                    artifacts.append(make_artifact(
                        bin_bytes, "vba_project_bin",
                        discovered_by=self.name,
                        meta={"source": "ooxml_vba", "name": n}))
                except Exception:
                    continue
        # 3. Embedded objects — .bin, .emf, .wmf, .ole10Native
        for n in names:
            low = n.lower()
            if low.startswith(("word/embeddings/", "xl/embeddings/",
                                 "ppt/embeddings/")):
                try:
                    b = zf.read(n)
                    artifacts.append(make_artifact(
                        b, "embedded_object",
                        discovered_by=self.name,
                        meta={"source": "ooxml_embedded", "name": n}))
                except Exception:
                    continue
        # 4. Hyperlinks live in .rels files
        for n in names:
            if n.endswith(".rels"):
                try:
                    xml = zf.read(n).decode("utf-8", errors="replace")
                except Exception:
                    continue
                for u in re.findall(
                    r'Target="(https?://[^"]+)"', xml
                ):
                    artifacts.append(make_artifact(
                        u.encode(), "url",
                        discovered_by=self.name,
                        meta={"source": "ooxml_hyperlink"}))
        if not artifacts:
            artifacts.append(make_artifact(
                payload, "raw_bytes",
                discovered_by=self.name,
                meta={"reason": "ooxml_no_content_found"}))
        return AdapterResult(artifacts=artifacts, diagnostics=diagnostics, meta=meta)


register_adapter(_DocxAdapter())
