"""PDF analyzer plugin — deterministic PDF static analysis.

Phase 3 · Cycle A · owner-approved 2026-02.

Extracts analyst-facing signals that matter for phishing / dropper
investigations:

    ▸ Overview          — PDF version, page count, encryption flag,
                          producer, creation/modify timestamps.
    ▸ JavaScript        — every /JavaScript action (script text + refs)
    ▸ Actions           — /OpenAction / /AA (additional actions)
    ▸ Launch actions    — /Launch entries (URLs, commands)
    ▸ Embedded files    — /EmbeddedFile names + sizes + sha256
    ▸ Forms             — /AcroForm presence
    ▸ URLs              — every URL found in the raw stream
    ▸ Findings          — analyst-oriented severity-sorted signals

Optional capability: `pypdf`. When missing, `is_available()` returns
False and the router surfaces the graceful "capability unavailable"
card. Deterministic — Rule 21 (identical bytes → identical report).
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, List, Optional

try:
    import pypdf
    from pypdf import PdfReader
    from pypdf.generic import IndirectObject
    _HAS_PYPDF = True
except Exception:
    pypdf = None  # type: ignore
    _HAS_PYPDF = False


# ─── Regexes for a raw-stream fallback pass ───────────────────────────
_URL_RX = re.compile(rb"https?://[^\s<>\"'()\\]{4,200}", re.IGNORECASE)
_JS_KEY_RX     = re.compile(rb"/JavaScript[\s\r\n]", re.IGNORECASE)
_OPENACT_RX    = re.compile(rb"/OpenAction[\s\r\n]", re.IGNORECASE)
_LAUNCH_RX     = re.compile(rb"/Launch[\s\r\n]", re.IGNORECASE)
_EMBED_RX      = re.compile(rb"/EmbeddedFile[\s\r\n]", re.IGNORECASE)
_AA_RX         = re.compile(rb"/AA[\s\r\n<]", re.IGNORECASE)
_ACROFORM_RX   = re.compile(rb"/AcroForm[\s\r\n<]", re.IGNORECASE)


class PDFAnalyzer:
    artifact_type = "pdf"
    display_name  = "Adobe PDF"

    def magic_matcher(self, data: bytes) -> Optional[int]:
        # Standard PDF header is `%PDF-` within the first 1024 bytes.
        head = data[:1024]
        idx = head.find(b"%PDF-")
        if idx < 0:
            return None
        # High confidence when the header sits within the first 32 bytes.
        return 99 if idx <= 32 else 80

    def is_available(self) -> bool:
        return _HAS_PYPDF

    def analyze(self, data: bytes) -> Dict[str, Any]:
        if not _HAS_PYPDF:
            return {
                "available": False,
                "reason":   "pypdf_not_installed",
                "message":  "PDF analysis capability unavailable — install pypdf to enable.",
            }
        # Every failure path returns a diagnostic dict — never raises.
        try:
            return _build_report(data)
        except Exception as e:
            return _fallback_report(data, error=type(e).__name__, message=str(e))


# ─── Report builder ───────────────────────────────────────────────────
def _build_report(data: bytes) -> Dict[str, Any]:
    from io import BytesIO
    reader = PdfReader(BytesIO(data), strict=False)

    # ── Overview ──────────────────────────────────────────────────
    version = _pdf_version(data)
    encrypted = bool(getattr(reader, "is_encrypted", False))
    metadata  = _safe_metadata(reader)
    page_count = _safe_page_count(reader)

    # ── JavaScript / OpenAction / Launch / Embedded files ─────────
    javascript = _extract_javascript(reader)
    open_actions = _extract_open_actions(reader)
    launch_actions = _extract_launch_actions(reader)
    embedded = _extract_embedded_files(reader)
    additional_actions = _extract_additional_actions(reader)
    acroform_present = _has_acroform(reader)

    # ── URL extraction (best-effort from raw content streams) ─────
    urls = sorted({u.decode("latin-1", errors="replace") for u in _URL_RX.findall(data)})[:100]

    # ── Findings ─────────────────────────────────────────────────
    findings = _compute_findings(
        javascript=javascript,
        open_actions=open_actions,
        launch_actions=launch_actions,
        embedded=embedded,
        additional_actions=additional_actions,
        acroform=acroform_present,
        encrypted=encrypted,
        raw_data=data,
    )

    return {
        "available": True,
        "overview": {
            "pdf_version":       version,
            "page_count":        page_count,
            "encrypted":         encrypted,
            "producer":          metadata.get("/Producer"),
            "creator":           metadata.get("/Creator"),
            "author":            metadata.get("/Author"),
            "title":             metadata.get("/Title"),
            "creation_date":     metadata.get("/CreationDate"),
            "modification_date": metadata.get("/ModDate"),
            "file_size":         len(data),
            "has_acroform":      acroform_present,
        },
        "javascript":          javascript,
        "open_actions":        open_actions,
        "launch_actions":      launch_actions,
        "additional_actions":  additional_actions,
        "embedded_files":      embedded,
        "urls":                urls,
        "findings":            findings,
    }


def _fallback_report(data: bytes, error: str, message: str) -> Dict[str, Any]:
    """Even when pypdf refuses the payload, produce a useful raw-scan
    report so analysts still get URLs + suspicious-key signals."""
    urls = sorted({u.decode("latin-1", errors="replace") for u in _URL_RX.findall(data)})[:100]
    findings: List[Dict[str, Any]] = [{
        "severity": "medium", "code": "pdf_parse_failed",
        "title":  f"pypdf could not parse the PDF ({error})",
        "detail": message[:300],
    }]
    for rx, code, title, sev in [
        (_JS_KEY_RX,   "javascript_key",    "PDF contains a /JavaScript key",           "high"),
        (_OPENACT_RX,  "openaction_key",    "PDF contains an /OpenAction key",          "high"),
        (_LAUNCH_RX,   "launch_key",        "PDF contains a /Launch action key",        "high"),
        (_EMBED_RX,    "embed_key",         "PDF contains an /EmbeddedFile key",        "medium"),
        (_AA_RX,       "additional_action", "PDF contains /AA (additional actions)",    "medium"),
    ]:
        if rx.search(data):
            findings.append({
                "severity": sev, "code": code, "title": title,
                "detail": "Raw-scan fallback — pypdf parse failed but the keyword was found in the PDF stream.",
            })
    _sort_findings(findings)
    return {
        "available": True,
        "error":   "pdf_parse_failed",
        "message": f"{error}: {message}",
        "urls":    urls,
        "findings": findings,
    }


# ─── PDF helpers ──────────────────────────────────────────────────────
_PDF_VERSION_RX = re.compile(rb"%PDF-(\d\.\d)")


def _pdf_version(data: bytes) -> Optional[str]:
    m = _PDF_VERSION_RX.search(data[:1024])
    return m.group(1).decode("ascii", errors="replace") if m else None


def _safe_metadata(reader) -> Dict[str, Any]:
    try:
        md = reader.metadata or {}
    except Exception:
        return {}
    out: Dict[str, Any] = {}
    for k, v in md.items():
        try:
            out[str(k)] = str(v)
        except Exception:
            out[str(k)] = repr(v)[:200]
    return out


def _safe_page_count(reader) -> int:
    try:
        return len(reader.pages)
    except Exception:
        return 0


def _resolve(obj):
    """Deref every IndirectObject we encounter."""
    seen = set()
    while isinstance(obj, IndirectObject):
        ident = (obj.idnum, obj.generation)
        if ident in seen:
            return None
        seen.add(ident)
        try:
            obj = obj.get_object()
        except Exception:
            return None
    return obj


def _extract_javascript(reader) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    try:
        root = reader.trailer.get("/Root")
        root = _resolve(root) or {}
    except Exception:
        return out

    # /Names → /JavaScript name tree
    try:
        names = _resolve(root.get("/Names")) or {}
        js_tree = _resolve(names.get("/JavaScript")) or {}
        entries = js_tree.get("/Names") or []
        for i in range(0, len(entries), 2):
            name = entries[i]
            action = _resolve(entries[i + 1] if i + 1 < len(entries) else None)
            if not action:
                continue
            js = _resolve(action.get("/JS"))
            js_text = _as_text(js) if js is not None else ""
            out.append({
                "name": str(name),
                "length": len(js_text),
                "preview": js_text[:400],
                "sha256":  hashlib.sha256(js_text.encode("utf-8", errors="replace")).hexdigest() if js_text else None,
            })
    except Exception:
        pass

    # Per-page /AA javascript
    try:
        for pnum, page in enumerate(reader.pages):
            aa = _resolve(page.get("/AA")) or {}
            for trigger, action in (aa.items() if hasattr(aa, "items") else []):
                action = _resolve(action) or {}
                js = _resolve(action.get("/JS"))
                if js:
                    js_text = _as_text(js)
                    out.append({
                        "name": f"page{pnum}:{trigger}",
                        "length": len(js_text),
                        "preview": js_text[:400],
                        "sha256":  hashlib.sha256(js_text.encode("utf-8", errors="replace")).hexdigest(),
                    })
    except Exception:
        pass

    return out


def _extract_open_actions(reader) -> List[Dict[str, Any]]:
    try:
        root = _resolve(reader.trailer.get("/Root")) or {}
        oa = _resolve(root.get("/OpenAction"))
        if oa is None:
            return []
        return [_describe_action(oa)]
    except Exception:
        return []


def _extract_launch_actions(reader) -> List[Dict[str, Any]]:
    """Walk every action in the catalog / pages and pluck /Launch entries."""
    out: List[Dict[str, Any]] = []
    try:
        root = _resolve(reader.trailer.get("/Root")) or {}
        _collect_launch(root, out, seen=set())
    except Exception:
        pass
    return out


def _collect_launch(obj, out, seen: set, depth: int = 0):
    if depth > 6 or obj is None:
        return
    obj = _resolve(obj)
    if obj is None:
        return
    oid = id(obj)
    if oid in seen:
        return
    seen.add(oid)
    if hasattr(obj, "items"):
        for k, v in obj.items():
            if str(k) == "/S" and str(v) == "/Launch":
                out.append(_describe_action(obj))
            _collect_launch(v, out, seen, depth + 1)
    elif isinstance(obj, list):
        for item in obj:
            _collect_launch(item, out, seen, depth + 1)


def _extract_additional_actions(reader) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    try:
        root = _resolve(reader.trailer.get("/Root")) or {}
        for k in ("/AA", "/Perms"):
            v = _resolve(root.get(k))
            if v:
                out.append({"key": k, "kind": type(v).__name__})
    except Exception:
        pass
    return out


def _has_acroform(reader) -> bool:
    try:
        root = _resolve(reader.trailer.get("/Root")) or {}
        return "/AcroForm" in (getattr(root, "keys", lambda: [])())
    except Exception:
        return False


def _extract_embedded_files(reader) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    try:
        root = _resolve(reader.trailer.get("/Root")) or {}
        names = _resolve(root.get("/Names")) or {}
        ef_tree = _resolve(names.get("/EmbeddedFiles")) or {}
        entries = ef_tree.get("/Names") or []
        for i in range(0, len(entries), 2):
            name = entries[i]
            spec = _resolve(entries[i + 1] if i + 1 < len(entries) else None) or {}
            ef = _resolve(spec.get("/EF")) or {}
            file_ref = _resolve(ef.get("/F"))
            data = b""
            if file_ref is not None:
                try:
                    data = file_ref.get_data() or b""
                except Exception:
                    data = b""
            out.append({
                "name":     str(name),
                "size":     len(data),
                "sha256":   hashlib.sha256(data).hexdigest() if data else None,
                "mime":     spec.get("/Type") and str(spec.get("/Type")),
            })
    except Exception:
        pass
    return out


def _describe_action(action) -> Dict[str, Any]:
    action = _resolve(action) or {}
    result: Dict[str, Any] = {"kind": type(action).__name__}
    for key in ("/S", "/JS", "/URI", "/F", "/D", "/T"):
        try:
            v = action.get(key)
        except Exception:
            v = None
        if v is None:
            continue
        v = _resolve(v)
        if key == "/JS":
            txt = _as_text(v)
            result["javascript_preview"] = txt[:300]
            result["javascript_length"] = len(txt)
        else:
            try:
                result[key.strip("/").lower()] = str(v)[:300]
            except Exception:
                result[key.strip("/").lower()] = repr(v)[:300]
    return result


def _as_text(obj) -> str:
    obj = _resolve(obj)
    if obj is None:
        return ""
    if isinstance(obj, (bytes, bytearray)):
        return obj.decode("utf-8", errors="replace")
    if hasattr(obj, "get_data"):
        try:
            return obj.get_data().decode("utf-8", errors="replace")
        except Exception:
            return ""
    try:
        return str(obj)
    except Exception:
        return ""


# ─── Findings engine (analyst-oriented signals) ───────────────────────
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _sort_findings(findings: List[Dict[str, Any]]) -> None:
    findings.sort(key=lambda f: (_SEV_ORDER.get(f.get("severity"), 99), f.get("code", "")))


def _compute_findings(
    javascript, open_actions, launch_actions, embedded,
    additional_actions, acroform, encrypted, raw_data,
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    if javascript:
        findings.append({
            "severity": "high", "code": "javascript_present",
            "title":  f"PDF contains {len(javascript)} JavaScript action(s)",
            "detail": "Legitimate PDFs rarely require JavaScript. This is a strong signal in phishing / dropper PDFs.",
        })
    if launch_actions:
        findings.append({
            "severity": "critical", "code": "launch_action",
            "title":  f"PDF carries {len(launch_actions)} /Launch action(s)",
            "detail": "Launch actions attempt to execute an external command/URL when the PDF is opened. Historically abused (CVE-2010-1240 and downstream).",
        })
    if open_actions:
        findings.append({
            "severity": "high", "code": "open_action",
            "title":  "PDF fires an /OpenAction on load",
            "detail": "The action runs automatically when the PDF is opened — inspect the JS/URI it points to.",
        })
    if embedded:
        findings.append({
            "severity": "high", "code": "embedded_files",
            "title":  f"PDF has {len(embedded)} embedded file(s)",
            "detail": "Embedded files can carry secondary payloads (macros, scripts, PE binaries). Enumerate each entry's sha256.",
        })
    if additional_actions:
        findings.append({
            "severity": "medium", "code": "additional_actions",
            "title":  "Additional actions (/AA) present",
            "detail": "Actions run on triggers other than open (focus, print, close) — inspect for JS.",
        })
    if acroform:
        findings.append({
            "severity": "medium", "code": "acroform_present",
            "title":  "PDF contains an /AcroForm dictionary",
            "detail": "Interactive forms — legitimate in many workflows, but occasionally abused for phishing (credential harvesting).",
        })
    if encrypted:
        findings.append({
            "severity": "medium", "code": "encrypted_pdf",
            "title":  "PDF is encrypted",
            "detail": "Some analyzers cannot inspect encrypted PDFs. Verify the password requirement is legitimate.",
        })

    # Suspicious keys via raw scan even when higher-level extraction found nothing.
    if not javascript and _JS_KEY_RX.search(raw_data):
        findings.append({
            "severity": "medium", "code": "raw_javascript_key",
            "title":  "Raw stream contains a /JavaScript key (extraction produced none)",
            "detail": "pypdf couldn't resolve the JavaScript object — the payload may be obfuscated or corrupt. Inspect raw stream manually.",
        })

    _sort_findings(findings)
    return findings


__all__ = ["PDFAnalyzer"]
