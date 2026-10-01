"""Office OOXML analyzer plugin — deterministic static analysis for
.docx / .xlsx / .pptx and their macro-enabled variants.

Phase 3 · Cycle B · owner-approved 2026-02.

Detects:
    ▸ Macros:                word/xl/ppt/vbaProject.bin
    ▸ XLM macros:            xl/macrosheets/**
    ▸ DDE:                   `DDEAUTO` / `DDE` field codes
    ▸ OLE objects:           */embeddings/oleObject*.bin
    ▸ External templates:    webSettings.xml.rels · settings.xml.rels
    ▸ External URLs:         every Target="http…" reference
    ▸ Embedded files:        */embeddings/**
    ▸ Auto-Open triggers:    AutoOpen / Document_Open / Workbook_Open /
                              AutoExec / Auto_Open (searched in vbaProject
                              blob without a VBA disassembler)

Metadata extraction:
    ▸ docProps/core.xml   → title, creator, last-modified-by, timestamps
    ▸ docProps/app.xml    → application, application version

Standards library only — no `olefile` / `oletools` dependency. Rule 21
determinism enforced (sorted lists, stable field order).
"""
from __future__ import annotations

import hashlib
import io
import re
import zipfile
from typing import Any, Dict, List, Optional


# ─── Directory-hint mapping to Office family ───────────────────────────
_FAMILY_HINTS = (
    ("word/",  "docx", "Microsoft Word document"),
    ("xl/",    "xlsx", "Microsoft Excel workbook"),
    ("ppt/",   "pptx", "Microsoft PowerPoint presentation"),
)

_MACRO_TRIGGERS = (
    b"AutoOpen", b"Document_Open", b"Workbook_Open",
    b"AutoExec", b"Auto_Open", b"AutoClose", b"Document_Close",
)

_DDE_KEYWORDS = (b"DDEAUTO", b"DDE ")

# ▲ Script-invocation regexes for VBA macro static extraction.
# Deterministic — Office Analyzer *declares* child scripts; the RTE
# decodes them (Rule: analyzers never decode). Patterns are
# intentionally broad to catch common loader wrappers:
#     Shell("powershell -enc <b64>")
#     WScript.Shell.Run "cmd /c ..."
# Matches are returned verbatim so the RTE handles all decoding.
# Applied to (a) the raw blob and (b) a "null-stripped" copy so both
# latin-1 and UTF-16LE string storage inside vbaProject.bin surface.
_SCRIPT_RXS = (
    (re.compile(
        rb"(?:powershell(?:\.exe)?|pwsh(?:\.exe)?)\s+[^\r\n\x00]{6,4096}",
        re.IGNORECASE), "powershell"),
    (re.compile(
        rb"(?:cmd(?:\.exe)?)\s+/[a-z]\s+[^\r\n\x00]{4,2048}",
        re.IGNORECASE), "cmd"),
    (re.compile(
        rb"(?:wscript\.shell|shell\.application)[^\r\n\x00]{0,512}",
        re.IGNORECASE), "wsh"),
)

_URL_RX = re.compile(rb"https?://[^\s<>\"'()\\]{4,300}", re.IGNORECASE)
_TARGET_RX = re.compile(rb'Target="([^"]+)"', re.IGNORECASE)


class OfficeAnalyzer:
    artifact_type = "office"
    display_name  = "Microsoft Office (OOXML)"

    def magic_matcher(self, data: bytes) -> Optional[int]:
        # OOXML files are ZIP archives with a specific inner structure.
        if not data.startswith(b"PK\x03\x04"):
            return None
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                names = set(zf.namelist())
        except zipfile.BadZipFile:
            return None
        except Exception:
            return None
        if "[Content_Types].xml" not in names:
            return None
        # Confirm one of the three OOXML top-level directories exists.
        for prefix, _, _ in _FAMILY_HINTS:
            if any(n.startswith(prefix) for n in names):
                return 99
        return None

    def is_available(self) -> bool:
        # stdlib zipfile is always available — no optional dependency.
        return True

    def analyze(self, data: bytes) -> Dict[str, Any]:
        try:
            return _build_report(data)
        except Exception as e:
            return {
                "available": True,
                "error":   "office_analyzer_exception",
                "message": f"{type(e).__name__}: {e}",
            }


# ─── Report builder ───────────────────────────────────────────────────
def _build_report(data: bytes) -> Dict[str, Any]:
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        names = sorted(zf.namelist())

        # Identify Office family.
        family, subtype = "unknown", "OOXML"
        for prefix, fam, label in _FAMILY_HINTS:
            if any(n.startswith(prefix) for n in names):
                family, subtype = fam, label
                break

        metadata = _read_metadata(zf, names)
        macros   = _detect_macros(zf, names)
        xlm      = _detect_xlm(zf, names)
        dde      = _detect_dde(zf, names)
        ole      = _detect_ole(zf, names)
        embedded = _list_embedded(zf, names)
        ext_urls = _extract_external_urls(zf, names)
        ext_tpl  = _extract_external_templates(zf, names)

    # ── Analyst-oriented findings ────────────────────────────────
    findings = _compute_findings(
        family=family, macros=macros, xlm=xlm, dde=dde, ole=ole,
        embedded=embedded, ext_urls=ext_urls, ext_tpl=ext_tpl,
    )

    return {
        "available": True,
        "overview": {
            "family":       family,
            "subtype":      subtype,
            "file_count":   len(names),
            "file_size":    len(data),
            "has_macros":   bool(macros["found"]),
            "has_xlm":      bool(xlm["found"]),
            "has_dde":      bool(dde["found"]),
            "has_ole":      bool(ole["objects"]),
            "external_url_count":       len(ext_urls),
            "external_template_count":  len(ext_tpl),
            "embedded_file_count":      len(embedded),
            "extracted_script_count":   len(macros.get("extracted_scripts") or []),
        },
        "metadata":            metadata,
        "macros":              macros,
        "xlm":                 xlm,
        "dde":                 dde,
        "ole":                 ole,
        "embedded_files":      embedded,
        "external_urls":       ext_urls,
        "external_templates":  ext_tpl,
        "findings":            findings,
    }


# ─── Metadata (core.xml + app.xml) ────────────────────────────────────
_META_TAG_RX = re.compile(
    rb"<(?:[\w:]+:)?"
    rb"(title|creator|lastModifiedBy|created|modified|revision|description|subject|"
    rb"keywords|application|appVersion|Company|category)>"
    rb"([^<]+)</",
    re.IGNORECASE,
)


def _read_metadata(zf, names) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for path in ("docProps/core.xml", "docProps/app.xml"):
        if path not in names:
            continue
        try:
            blob = zf.read(path)
        except Exception:
            continue
        for m in _META_TAG_RX.finditer(blob):
            key = m.group(1).decode("ascii", errors="replace")
            val = m.group(2).decode("utf-8", errors="replace")
            # dict-insertion order preserved — deterministic.
            result[key] = val
    return result


# ─── Macros (VBA project blob) ────────────────────────────────────────
def _detect_macros(zf, names) -> Dict[str, Any]:
    macro_paths = [n for n in names if n.endswith("/vbaProject.bin")]
    found: List[Dict[str, Any]] = []
    triggers: List[str] = []
    extracted_scripts: List[Dict[str, Any]] = []
    for path in macro_paths:
        try:
            blob = zf.read(path)
        except Exception:
            continue
        h = hashlib.sha256(blob).hexdigest()
        found.append({"path": path, "size": len(blob), "sha256": h})
        for trig in _MACRO_TRIGGERS:
            if trig in blob and trig.decode("ascii", errors="replace") not in triggers:
                triggers.append(trig.decode("ascii", errors="replace"))
        # ▲ P2.3b · surface embedded script invocations for the
        # Recursive Child Artifact Pipeline. Deterministic scan —
        # matches are declared verbatim; the RTE decodes them.
        extracted_scripts.extend(_extract_scripts_from_blob(blob, path))
    triggers.sort()
    # Deterministic ordering — (language, snippet) — so two runs of the
    # same document always produce the same declaration list.
    extracted_scripts.sort(key=lambda s: (s["language"], s["command"]))
    return {
        "found": bool(found),
        "vba_projects": found,
        "triggers": triggers,
        "extracted_scripts": extracted_scripts,
    }


def _extract_scripts_from_blob(blob: bytes, source_path: str
                               ) -> List[Dict[str, Any]]:
    """Scan a vbaProject.bin blob for embedded script-invocation strings.

    Runs each pattern against (a) the raw blob (latin-1 storage) and
    (b) a null-stripped copy (UTF-16LE storage). Deduplicates by
    (language, command). Preserves the original byte offset for
    provenance so analysts can inspect the exact location.
    """
    stripped = blob.replace(b"\x00", b"")
    out: List[Dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for scan_variant, offset_source in (
        (blob, "raw"), (stripped, "utf16le_stripped"),
    ):
        for rx, language in _SCRIPT_RXS:
            for m in rx.finditer(scan_variant):
                raw = m.group(0)
                try:
                    command = raw.decode("latin-1", errors="replace").strip()
                except Exception:
                    continue
                # Collapse repeated whitespace so trivially-different
                # spacings don't produce duplicate declarations.
                command = re.sub(r"\s+", " ", command).strip()
                if len(command) < 8:
                    continue
                key = (language, command)
                if key in seen:
                    continue
                seen.add(key)
                out.append({
                    "language":    language,
                    "command":     command,
                    "source_path": source_path,
                    "byte_offset": m.start(),
                    "storage":     offset_source,
                })
    return out


def _detect_xlm(zf, names) -> Dict[str, Any]:
    """Excel 4 macros live as `xl/macrosheets/*.xml`."""
    xlm_paths = [n for n in names if n.startswith("xl/macrosheets/")]
    return {"found": bool(xlm_paths), "paths": xlm_paths}


def _detect_dde(zf, names) -> Dict[str, Any]:
    """DDEAUTO field abuse in Word documents."""
    hits: List[Dict[str, Any]] = []
    for name in names:
        if not name.endswith(".xml"):
            continue
        try:
            blob = zf.read(name)
        except Exception:
            continue
        matched = [k.decode("ascii", errors="replace") for k in _DDE_KEYWORDS if k in blob]
        if matched:
            hits.append({"path": name, "keywords": sorted(set(matched))})
    return {"found": bool(hits), "hits": hits}


def _detect_ole(zf, names) -> Dict[str, Any]:
    """Embedded OLE objects — a classic Emotet delivery vector."""
    ole_paths = [n for n in names if "/embeddings/oleObject" in n.lower()]
    objects: List[Dict[str, Any]] = []
    for p in ole_paths:
        try:
            blob = zf.read(p)
        except Exception:
            continue
        objects.append({
            "path":   p,
            "size":   len(blob),
            "sha256": hashlib.sha256(blob).hexdigest(),
        })
    return {"objects": objects}


def _list_embedded(zf, names) -> List[Dict[str, Any]]:
    embed: List[Dict[str, Any]] = []
    for name in names:
        if "/embeddings/" not in name:
            continue
        try:
            blob = zf.read(name)
        except Exception:
            continue
        embed.append({
            "path":   name,
            "size":   len(blob),
            "sha256": hashlib.sha256(blob).hexdigest(),
        })
    embed.sort(key=lambda x: x["path"])
    return embed


def _extract_external_urls(zf, names) -> List[str]:
    urls: set = set()
    for name in names:
        if not name.endswith(".rels"):
            continue
        try:
            blob = zf.read(name)
        except Exception:
            continue
        for m in _TARGET_RX.finditer(blob):
            tgt = m.group(1).decode("utf-8", errors="replace")
            if tgt.startswith(("http://", "https://")):
                urls.add(tgt)
        # Also scavenge any http URL inside the file (some external refs
        # sit inside content XML rather than .rels).
        for m in _URL_RX.finditer(blob):
            urls.add(m.group(0).decode("latin-1", errors="replace"))
    return sorted(urls)


def _extract_external_templates(zf, names) -> List[Dict[str, Any]]:
    templates: List[Dict[str, Any]] = []
    for candidate in (
        "word/_rels/settings.xml.rels",
        "word/_rels/webSettings.xml.rels",
        "xl/_rels/workbook.xml.rels",
        "ppt/_rels/presentation.xml.rels",
    ):
        if candidate not in names:
            continue
        try:
            blob = zf.read(candidate)
        except Exception:
            continue
        for m in _TARGET_RX.finditer(blob):
            tgt = m.group(1).decode("utf-8", errors="replace")
            if tgt.startswith(("http://", "https://", "\\\\")):
                templates.append({"in_file": candidate, "target": tgt})
    return templates


# ─── Findings engine ─────────────────────────────────────────────────
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _compute_findings(*, family, macros, xlm, dde, ole, embedded, ext_urls, ext_tpl) -> List[Dict[str, Any]]:
    f: List[Dict[str, Any]] = []

    if macros["found"]:
        f.append({
            "severity": "critical", "code": "vba_macros_present",
            "title": f"{family} contains a VBA project ({len(macros['vba_projects'])} blob)",
            "detail": (
                "vbaProject.bin is present — the document is macro-enabled. "
                "Macros are a very common initial-access vector "
                "(Emotet, Qakbot, Dridex, Trickbot, and many APT loaders)."
            ),
        })
        if macros["triggers"]:
            f.append({
                "severity": "critical", "code": "macro_autoexec_trigger",
                "title": f"Auto-execution trigger(s) detected: {', '.join(macros['triggers'])}",
                "detail": "These callbacks run automatically when the document/workbook is opened.",
            })
        if macros.get("extracted_scripts"):
            langs = sorted({s["language"] for s in macros["extracted_scripts"]})
            f.append({
                "severity": "critical", "code": "macro_script_invocation",
                "title": (f"Embedded script invocation(s) in VBA macro: "
                          f"{', '.join(langs)}"),
                "detail": (
                    "Macro static extraction surfaced command-line invocations "
                    "(powershell / cmd / WScript.Shell). These are handed to "
                    "the Recursive Child Artifact Pipeline for RTE decoding."
                ),
            })
    if xlm["found"]:
        f.append({
            "severity": "critical", "code": "xlm_macros_present",
            "title": f"Excel 4 (XLM) macro sheets present ({len(xlm['paths'])})",
            "detail": "XLM macros bypass most Office macro-security policies and are heavily abused by TA505 / Qakbot droppers.",
        })
    if dde["found"]:
        f.append({
            "severity": "critical", "code": "dde_present",
            "title": f"DDE / DDEAUTO field(s) detected in {len(dde['hits'])} document part(s)",
            "detail": "DDE field codes can invoke arbitrary commands on document open (CVE-2017-11826 lineage).",
        })
    if ole["objects"]:
        f.append({
            "severity": "high", "code": "ole_objects_present",
            "title": f"{len(ole['objects'])} embedded OLE object(s)",
            "detail": "OLE embeddings can carry secondary payloads (packaged executables, LNKs, MSIs).",
        })
    if ext_tpl:
        f.append({
            "severity": "high", "code": "external_template",
            "title": f"{len(ext_tpl)} external template reference(s)",
            "detail": "Remote-template injection is a common initial-access technique — the template can carry macros retrieved on open.",
        })
    if ext_urls:
        f.append({
            "severity": "medium", "code": "external_urls_present",
            "title": f"{len(ext_urls)} external URL reference(s)",
            "detail": "External URLs may fetch remote content on open (images, templates, drive-by C2 beacons).",
        })
    if embedded:
        f.append({
            "severity": "medium", "code": "embedded_files_present",
            "title": f"{len(embedded)} embedded file(s)",
            "detail": "Inspect each embedded object — attackers hide LNKs, MSIs, and secondary PEs inside Office documents.",
        })

    f.sort(key=lambda x: (_SEV_ORDER.get(x["severity"], 99), x["code"]))
    return f


__all__ = ["OfficeAnalyzer"]
