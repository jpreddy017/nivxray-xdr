"""Deterministic synthetic `.docm` builder for the P2.3b flagship.

Produces `docm_ps_to_pe_chain.docm` in this same directory. The
`.docm` is a valid OOXML archive whose `word/vbaProject.bin` contains
the exact `powershell.exe -EncodedCommand <utf-16 b64>` wrapper from
`workspace_ps_to_pe_chain.txt` — proving Office → VBA → PowerShell →
UTF-16 → base64 → gzip → PE is one deterministic investigation.

Design principles:
    • Self-sufficient — no external samples, no third-party libraries.
    • Deterministic — the same source PS wrapper always produces the
      exact same `.docm` bytes (fixed ZIP dates, stable ordering).
    • Analyst-safe — no real malware; the PE inside the gzip is our
      1024-byte MZ stub that only echoes a marker string.
    • Rule 21 — every field committed to the archive is reproducible.

Note: this file is checked into git alongside the .docm it generates
so any future contributor can regenerate the fixture and diff the
result byte-for-byte.
"""
from __future__ import annotations

import io
import os
import re
import zipfile
from datetime import datetime
from pathlib import Path

_HERE = Path(__file__).resolve().parent

# ── Payload extracted verbatim from the workspace-only flagship ──────
_PS_SAMPLE_PATH = _HERE / "workspace_ps_to_pe_chain.txt"


def _read_workspace_powershell() -> str:
    """Read the flagship PowerShell wrapper (single source of truth).

    Keeping the payload in one place guarantees that whatever the
    workspace flagship recovers is *bit-identical* to what this
    synthetic .docm carries — the Multi-Origin Equivalence contract
    depends on this.
    """
    if not _PS_SAMPLE_PATH.exists():
        raise FileNotFoundError(
            f"missing PS sample at {_PS_SAMPLE_PATH} — the flagship "
            f"workspace sample must be built first"
        )
    return _PS_SAMPLE_PATH.read_text(encoding="utf-8").strip()


# ── Minimal OOXML file bodies ────────────────────────────────────────
_CONTENT_TYPES = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.ms-word.document.macroEnabled.main+xml"/>
  <Override PartName="/word/vbaProject.bin" ContentType="application/vnd.ms-office.vbaProject"/>
  <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
  <Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>
</Types>
"""

_ROOT_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
  <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>
</Relationships>
"""

_WORD_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject" Target="vbaProject.bin"/>
</Relationships>
"""

_DOCUMENT_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p><w:r><w:t>NivXRay golden-corpus synthetic .docm — VBA macro drops a PE via PowerShell.</w:t></w:r></w:p>
  </w:body>
</w:document>
"""

_CORE_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties
    xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
    xmlns:dc="http://purl.org/dc/elements/1.1/"
    xmlns:dcterms="http://purl.org/dc/terms/"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <dc:title>NivXRay Golden Corpus · docm_ps_to_pe_chain</dc:title>
  <dc:creator>nivxray-golden-corpus</dc:creator>
  <cp:lastModifiedBy>nivxray-golden-corpus</cp:lastModifiedBy>
  <dcterms:created xsi:type="dcterms:W3CDTF">2026-02-16T00:00:00Z</dcterms:created>
  <dcterms:modified xsi:type="dcterms:W3CDTF">2026-02-16T00:00:00Z</dcterms:modified>
</cp:coreProperties>
"""

_APP_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">
  <Application>NivXRayGoldenCorpus</Application>
  <AppVersion>1.0</AppVersion>
</Properties>
"""


def _build_vba_project(ps_command: str) -> bytes:
    """Build a synthetic vbaProject.bin that carries an AutoOpen macro
    invoking the PowerShell wrapper.

    Format is *not* a real MS-OVBA compressed container — it's a
    deterministic byte-for-byte layout that:
      1. Contains VBA identifiers (`AutoOpen`, `Document_Open`) so the
         Office analyzer's trigger scanner fires.
      2. Contains the PowerShell command as visible latin-1 bytes so
         the Office analyzer's script extractor surfaces it as a
         declared child artifact.
      3. Is prefixed with the OLE Compound Document header bytes so a
         hex-viewer identifies the blob as OLE.

    Real-world VBA CompressedContainer streams can legitimately carry
    long string literals in raw (uncompressed) chunks — mimicking that
    behaviour here keeps the fixture analyst-safe and doesn't require
    a full VBA compiler.
    """
    # OLE Compound Document header — analyst-safe magic bytes only.
    ole_header = bytes.fromhex("d0cf11e0a1b11ae1") + b"\x00" * 24
    # VBA identifiers (satisfy auto-execution-trigger scan).
    identifiers = b"\r\nAttribute VB_Name = \"Module1\"\r\n"
    identifiers += b"Sub Document_Open()\r\n"
    identifiers += b"    Call AutoOpen\r\n"
    identifiers += b"End Sub\r\n\r\n"
    identifiers += b"Sub AutoOpen()\r\n"
    identifiers += b"    Dim s As Object\r\n"
    identifiers += b"    Set s = CreateObject(\"WScript.Shell\")\r\n"
    identifiers += b"    s.Run \""
    # Embed the powershell wrapper as visible latin-1 bytes.
    identifiers += ps_command.encode("latin-1", errors="replace")
    identifiers += b"\", 0, False\r\n"
    identifiers += b"End Sub\r\n"
    # Padding so the blob passes a "looks like a VBA project" size heuristic.
    padding = b"\x00" * max(0, 2048 - len(ole_header) - len(identifiers))
    return ole_header + identifiers + padding


def _add_deterministic(zf: zipfile.ZipFile, arcname: str, data: bytes) -> None:
    """Write with fixed timestamp + no compression so byte-identical
    across runs and file systems."""
    info = zipfile.ZipInfo(arcname, date_time=(2026, 2, 16, 0, 0, 0))
    info.compress_type = zipfile.ZIP_STORED
    info.external_attr = (0o644 & 0xFFFF) << 16
    zf.writestr(info, data)


def build(out_path: Path | None = None) -> Path:
    ps_command = _read_workspace_powershell()

    out_path = out_path or (_HERE / "docm_ps_to_pe_chain.docm")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        # File order matters for byte-stable output — sorted for determinism.
        _add_deterministic(zf, "[Content_Types].xml",   _CONTENT_TYPES.encode("utf-8"))
        _add_deterministic(zf, "_rels/.rels",           _ROOT_RELS.encode("utf-8"))
        _add_deterministic(zf, "docProps/app.xml",      _APP_XML.encode("utf-8"))
        _add_deterministic(zf, "docProps/core.xml",     _CORE_XML.encode("utf-8"))
        _add_deterministic(zf, "word/_rels/document.xml.rels", _WORD_RELS.encode("utf-8"))
        _add_deterministic(zf, "word/document.xml",     _DOCUMENT_XML.encode("utf-8"))
        _add_deterministic(zf, "word/vbaProject.bin",   _build_vba_project(ps_command))

    out_path.write_bytes(buf.getvalue())
    return out_path


if __name__ == "__main__":
    path = build()
    print(f"wrote {path} · {path.stat().st_size} bytes")
