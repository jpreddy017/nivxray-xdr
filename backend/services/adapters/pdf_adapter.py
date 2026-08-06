"""PDF Evidence Adapter — Phase 3A.

Extracts every forensically valuable component of a PDF and emits
them as canonical IEP artifacts.  Rule R8: this adapter never
reasons about *what the PDF means* — it only reports what is there.

Scope (per frozen architecture doc):

  · Text, tables, metadata, hyperlinks
  · Embedded files (attachments)
  · Embedded JavaScript
  · Launch actions
  · Annotations
  · Form fields
  · Digital signatures
  · Embedded images (indices only — never the raw bytes)

Every artifact carries ``source_ref = "pdf.page.<N>[.block.<M>]"`` so
Rule R6 (provenance) is satisfied.
"""
from __future__ import annotations

import io
import re
from typing import Any, Dict, List, Optional

from models.iep import (
    IEPArtifact,
    IEPContent,
    IEPRelationship,
    IEPSource,
    IEPWarning,
    RelationshipType,
)
from services.ida.artifact_splitter import split_artifacts

from .base import EvidenceAdapter


class PDFAdapter(EvidenceAdapter):
    name         = "adapter.pdf"
    version      = "1.0"
    capabilities = ["text", "tables", "metadata", "hyperlinks",
                     "embedded_files", "javascript", "launch_actions",
                     "annotations", "form_fields", "digital_signatures",
                     "image_counts"]

    _MAGIC = b"%PDF-"

    # ── Detection ────────────────────────────────────────────────────
    def can_handle(self, raw: Any) -> bool:
        if isinstance(raw, (bytes, bytearray)):
            return raw[:5] == self._MAGIC
        if isinstance(raw, str):
            # Base64-embedded PDF or hex — skip for now; UIL is the
            # right place to decode envelopes first.
            return False
        return False

    # ── Extraction ───────────────────────────────────────────────────
    def extract(self, raw: Any) -> IEPContent:
        data = bytes(raw)
        blocks: List[Dict[str, Any]] = []
        text_parts: List[str] = []
        pdf_meta: Dict[str, Any] = {}
        embedded_files: List[Dict[str, Any]] = []
        js_snippets:    List[Dict[str, Any]] = []
        annotations:    List[Dict[str, Any]] = []
        launch_actions: List[Dict[str, Any]] = []
        form_fields:    List[Dict[str, Any]] = []
        digital_sigs:   List[Dict[str, Any]] = []
        hyperlinks:     List[Dict[str, Any]] = []
        image_counts:   List[Dict[str, Any]] = []
        warnings: List[Dict[str, Any]] = []

        # ── pdfplumber: text + tables + metadata (deterministic) ────
        try:
            import pdfplumber  # local import so tests without libs still work
        except Exception as e:
            warnings.append({"code": "pdfplumber_unavailable",
                               "severity": "warn",
                               "message": f"pdfplumber import failed: {e}"})
        else:
            try:
                with pdfplumber.open(io.BytesIO(data)) as pdf:
                    pdf_meta.update(pdf.metadata or {})
                    for i, page in enumerate(pdf.pages, start=1):
                        try:
                            t = page.extract_text() or ""
                        except Exception:
                            t = ""
                        if t.strip():
                            text_parts.append(t)
                            blocks.append({
                                "kind": "page_text",
                                "page": i,
                                "text": t,
                            })
                        try:
                            for j, tbl in enumerate(page.extract_tables() or [], start=1):
                                blocks.append({
                                    "kind":  "table",
                                    "page":  i,
                                    "index": j,
                                    "rows":  tbl,
                                })
                        except Exception:
                            pass
            except Exception as e:
                warnings.append({"code": "pdfplumber_parse_failed",
                                   "severity": "warn",
                                   "message": f"pdfplumber failed: {e}"})

        # ── PyMuPDF (fitz): hyperlinks + embedded files + annotations
        #     + form fields + signatures + JavaScript + launch actions
        try:
            import fitz  # PyMuPDF
        except Exception as e:
            warnings.append({"code": "pymupdf_unavailable",
                               "severity": "warn",
                               "message": f"PyMuPDF import failed: {e}"})
        else:
            try:
                doc = fitz.open(stream=data, filetype="pdf")
                # Metadata fallback
                for k, v in (doc.metadata or {}).items():
                    pdf_meta.setdefault(k, v)
                # Encrypted?
                if doc.is_encrypted:
                    warnings.append({
                        "code":     "pdf_encrypted",
                        "severity": "warn",
                        "message":  "PDF is encrypted — extraction may be incomplete.",
                    })
                # Digital signatures
                try:
                    sig_count = getattr(doc, "signature_count", 0) or 0
                    for si in range(sig_count):
                        digital_sigs.append({"index": si + 1})
                except Exception:
                    pass
                # Embedded files (attachments)
                try:
                    for k in range(doc.embfile_count()):
                        info = doc.embfile_info(k) or {}
                        embedded_files.append({
                            "index":    k + 1,
                            "filename": info.get("filename"),
                            "size":     info.get("size"),
                            "desc":     info.get("desc"),
                        })
                except Exception:
                    pass
                # Form fields
                try:
                    for w in doc.load_widgets():
                        form_fields.append({
                            "name":  getattr(w, "field_name", None),
                            "type":  getattr(w, "field_type_string", None),
                            "value": getattr(w, "field_value", None),
                        })
                except Exception:
                    pass
                # Per-page: hyperlinks, annotations, launch actions, images, JS
                for i in range(doc.page_count):
                    page = doc.load_page(i)
                    pno  = i + 1
                    # Hyperlinks
                    try:
                        for lk in (page.get_links() or []):
                            url = lk.get("uri")
                            if url:
                                hyperlinks.append({"page": pno, "url": url})
                            if lk.get("kind") == getattr(fitz, "LINK_LAUNCH", 3):
                                launch_actions.append({
                                    "page":   pno,
                                    "target": lk.get("file") or lk.get("uri"),
                                })
                    except Exception:
                        pass
                    # Annotations
                    try:
                        annot = page.first_annot
                        while annot:
                            annotations.append({
                                "page":     pno,
                                "type":     annot.type[1] if getattr(annot, "type", None) else None,
                                "content":  (annot.info or {}).get("content") if hasattr(annot, "info") else None,
                            })
                            annot = annot.next
                    except Exception:
                        pass
                    # Images (count only — never raw bytes)
                    try:
                        image_counts.append({"page": pno,
                                                "images": len(page.get_images(full=False) or [])})
                    except Exception:
                        pass
                # Whole-doc JavaScript
                try:
                    for name, js in (doc.embfile_names_javascript() or {}).items() \
                            if hasattr(doc, "embfile_names_javascript") else []:
                        js_snippets.append({"name": name, "code": js[:500]})
                except Exception:
                    pass
                # Alternative JS extraction via xref
                try:
                    for xref in range(1, doc.xref_length()):
                        obj = doc.xref_object(xref) or ""
                        if "/JavaScript" in obj or "/JS" in obj:
                            js_snippets.append({
                                "xref": xref,
                                "code": obj[:500],
                            })
                except Exception:
                    pass
                doc.close()
            except Exception as e:
                warnings.append({"code": "pymupdf_parse_failed",
                                   "severity": "warn",
                                   "message": f"PyMuPDF failed: {e}"})

        # ── Consolidate into IEPContent ─────────────────────────────
        full_text = "\n".join(text_parts)
        content = IEPContent(text=full_text, blocks=blocks)
        # Stash extraction context for normalize / discover_relationships.
        content.__dict__["_pdf"] = {
            "metadata":       pdf_meta,
            "hyperlinks":     hyperlinks,
            "embedded_files": embedded_files,
            "js_snippets":    js_snippets,
            "annotations":    annotations,
            "launch_actions": launch_actions,
            "form_fields":    form_fields,
            "digital_sigs":   digital_sigs,
            "image_counts":   image_counts,
            "warnings":       warnings,
        }
        return content

    # ── Normalization ────────────────────────────────────────────────
    def normalize(self, content: IEPContent) -> List[IEPArtifact]:
        pdf = getattr(content, "_pdf", {}) or {}
        out: List[IEPArtifact] = []

        # 1. Body text → run the deterministic splitter so URLs / IPs /
        # hashes / commands / registry keys / file paths inside the PDF
        # text are all promoted to first-class artifacts.
        for b in (content.blocks or []):
            if b.get("kind") != "page_text":
                continue
            page = b.get("page")
            src = f"pdf.page.{page}"
            for a in (split_artifacts(b.get("text") or "") or []):
                t = self._map_splitter_type(getattr(a, "type", None))
                v = getattr(a, "value", None)
                if not (t and v):
                    continue
                out.append(IEPArtifact(
                    type=t,
                    value=v,
                    canonical=getattr(a, "canonical", None) or None,
                    confidence=getattr(a, "confidence", 1.0) or 1.0,
                    source_ref=src,
                ))

        # 2. Hyperlinks discovered by PyMuPDF (never mind the text — an
        #    action target might not be printed as body text).
        for link in pdf.get("hyperlinks") or []:
            out.append(IEPArtifact(
                type="url",
                value=link["url"],
                source_ref=f"pdf.page.{link.get('page')}",
                attributes={"origin": "hyperlink"},
            ))

        # 3. Embedded files (attachments)
        for ef in pdf.get("embedded_files") or []:
            out.append(IEPArtifact(
                type="file_path",
                value=ef.get("filename") or f"embedded_file_{ef.get('index')}",
                source_ref="pdf.embedded",
                attributes={
                    "origin":      "embedded_file",
                    "size":        ef.get("size"),
                    "description": ef.get("desc"),
                    "index":       ef.get("index"),
                },
            ))

        # 4. Embedded JavaScript — surface as a `unknown` typed artifact
        #    with the code truncated to 500 chars (deterministic evidence,
        #    NOT execution).
        for i, js in enumerate(pdf.get("js_snippets") or [], start=1):
            out.append(IEPArtifact(
                type="unknown",
                value=(js.get("code") or "")[:500] or "(empty js)",
                source_ref=f"pdf.js.{i}",
                tags=["pdf_javascript"],
                confidence=0.8,
                attributes={"name": js.get("name"), "xref": js.get("xref")},
            ))

        # 5. Launch actions — surface as executable file_path targets.
        for la in pdf.get("launch_actions") or []:
            tgt = la.get("target") or ""
            if tgt:
                out.append(IEPArtifact(
                    type="file_path",
                    value=tgt,
                    source_ref=f"pdf.page.{la.get('page')}.launch",
                    tags=["pdf_launch_action"],
                ))

        # 6. Form fields — expose names + values (Rule R8: no inference).
        for i, ff in enumerate(pdf.get("form_fields") or [], start=1):
            if not (ff.get("name") or ff.get("value")):
                continue
            out.append(IEPArtifact(
                type="unknown",
                value=f"{ff.get('name') or ''}={ff.get('value') or ''}",
                source_ref=f"pdf.form.{i}",
                tags=["pdf_form_field"],
            ))

        # 7. Digital signatures — presence, count.
        for sig in pdf.get("digital_sigs") or []:
            out.append(IEPArtifact(
                type="certificate",
                value=f"digital_signature_{sig.get('index')}",
                source_ref="pdf.signature",
                tags=["pdf_signature"],
            ))

        return out

    # ── Relationships (R8: structural only) ──────────────────────────
    def discover_relationships(self, content, artifacts):
        pdf = getattr(content, "_pdf", {}) or {}
        rels: List[IEPRelationship] = []
        pdf_ref = "pdf.document"

        # article/pdf → contains → hyperlink URLs
        for link in pdf.get("hyperlinks") or []:
            rels.append(IEPRelationship(
                from_ref=pdf_ref, to_ref=link["url"],
                verb=RelationshipType.CONTAINS,
                source_ref=f"pdf.page.{link.get('page')}",
            ))
        # pdf → attaches → embedded file
        for ef in pdf.get("embedded_files") or []:
            fname = ef.get("filename") or f"embedded_file_{ef.get('index')}"
            rels.append(IEPRelationship(
                from_ref=pdf_ref, to_ref=fname,
                verb=RelationshipType.ATTACHES,
                source_ref="pdf.embedded",
            ))
        # pdf → embeds → JavaScript
        for i, _ in enumerate(pdf.get("js_snippets") or [], start=1):
            rels.append(IEPRelationship(
                from_ref=pdf_ref, to_ref=f"pdf.js.{i}",
                verb=RelationshipType.EMBEDS,
                source_ref=f"pdf.js.{i}",
            ))
        # pdf → executes → launch action target (structural — action
        # is declared, not necessarily fired)
        for la in pdf.get("launch_actions") or []:
            tgt = la.get("target")
            if tgt:
                rels.append(IEPRelationship(
                    from_ref=pdf_ref, to_ref=tgt,
                    verb=RelationshipType.EXECUTES,
                    source_ref=f"pdf.page.{la.get('page')}.launch",
                ))
        # pdf → signed_by → signature (presence of digital sig)
        for sig in pdf.get("digital_sigs") or []:
            rels.append(IEPRelationship(
                from_ref=pdf_ref, to_ref=f"digital_signature_{sig.get('index')}",
                verb=RelationshipType.SIGNED_BY,
                source_ref="pdf.signature",
            ))
        return rels

    # ── Warnings (adapter-level caveats) ─────────────────────────────
    def validate(self, iep) -> List[IEPWarning]:
        pdf = getattr(iep.content, "_pdf", {}) or {}
        out: List[IEPWarning] = []
        for w in pdf.get("warnings") or []:
            out.append(IEPWarning(**w))
        if pdf.get("js_snippets"):
            out.append(IEPWarning(
                severity="info",
                code="pdf_contains_javascript",
                message=f"PDF contains {len(pdf['js_snippets'])} JavaScript object(s).",
            ))
        if pdf.get("launch_actions"):
            out.append(IEPWarning(
                severity="warn",
                code="pdf_contains_launch_actions",
                message=f"PDF declares {len(pdf['launch_actions'])} launch action(s).",
            ))
        if pdf.get("embedded_files"):
            out.append(IEPWarning(
                severity="info",
                code="pdf_contains_embedded_files",
                message=f"PDF has {len(pdf['embedded_files'])} embedded file(s).",
            ))
        return out

    # ── Recursion — embedded files each become a child IEP ───────────
    def recurse(self, iep) -> List[IEPArtifact]:
        return [a for a in iep.artifacts
                if "pdf_launch_action" in (a.tags or [])
                or (a.type == "file_path" and (a.attributes or {}).get("origin") == "embedded_file")]

    # ── Source detection ─────────────────────────────────────────────
    def _infer_source(self, raw: Any) -> IEPSource:
        data = bytes(raw)
        import hashlib
        return IEPSource(
            kind="pdf",
            size_bytes=len(data),
            sha256=hashlib.sha256(data).hexdigest(),
            mime_type="application/pdf",
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
    def _map_splitter_type(self, t: Any) -> str:
        if not t:
            return "unknown"
        return self._TYPE_MAP.get(t, t)

    # ── Override make_iep to merge PDF metadata + relationships ──────
    def make_iep(self, raw, *, source=None, parent_iep_id=None,
                   pipeline_depth=0, metadata=None):
        content       = self.extract(raw)
        artifacts     = self.normalize(content)
        relationships = self.discover_relationships(content, artifacts)
        src           = source or self._infer_source(raw)

        md = dict(metadata or {})
        pdf_meta = (getattr(content, "_pdf", {}) or {}).get("metadata") or {}
        if pdf_meta:
            md["pdf"] = {
                "title":        pdf_meta.get("Title") or pdf_meta.get("title"),
                "author":       pdf_meta.get("Author") or pdf_meta.get("author"),
                "producer":     pdf_meta.get("Producer") or pdf_meta.get("producer"),
                "creator":      pdf_meta.get("Creator") or pdf_meta.get("creator"),
                "creationDate": pdf_meta.get("CreationDate") or pdf_meta.get("creationDate"),
                "modDate":      pdf_meta.get("ModDate")      or pdf_meta.get("modDate"),
            }
        md.setdefault("adapter", {})
        md["adapter"].update({
            "name":         self.name,
            "version":      self.version,
            "capabilities": list(self.capabilities),
        })
        from models.iep import make_iep as _mk
        iep = _mk(
            source=src, content=content, artifacts=artifacts,
            relationships=relationships, metadata=md,
            adapter=self.name, adapter_version=self.version,
            parent_iep_id=parent_iep_id, pipeline_depth=pipeline_depth,
        )
        iep.warnings.extend(self.validate(iep))
        iep.metadata.data["adapter"]["warnings"] = [w.code for w in iep.warnings]
        return iep
