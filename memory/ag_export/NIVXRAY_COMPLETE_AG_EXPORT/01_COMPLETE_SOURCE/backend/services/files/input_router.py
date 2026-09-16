"""Input Router · P1 (ADR-0008 §5.2).

Given a stored file's metadata, decide which existing analyzer / adapter
consumes it. This module does NOT invent new analyzers — it dispatches
to whatever is already live in the codebase (see ADR-0010 §5).

For inputs we do not currently support, the router returns a
deterministic ``UNSUPPORTED_INPUT`` verdict — never a mysterious failure.
"""
from __future__ import annotations
from typing import Literal

from services.files.store import FileRecord


Route = Literal[
    "text",         # plain text / prose / commands → services/die/analyze
    "archive",      # PK-signature → safe_iter_zip_members + text extract
    "pdf",          # PDF adapter
    "office",       # DOCX/PPTX/XLSX → archive text extractor
    "pe",           # Windows executable → pe_analyzer
    "image",        # image metadata/strings
    "email",        # EML → eml_adapter
    "csv",          # tabular → csv_edr_analyzer
    "unsupported",  # fail-loud deterministic
]


def route_for(sha256_head: bytes, mime: str, filename: str) -> Route:
    """Determine the route by content magic first, MIME second, name third.

    Content-magic beats filename/extension — the client cannot rename
    an EXE to `.txt` and bypass the PE path.
    """
    n = (filename or "").lower()

    # --- Binary magic ----------------------------------------------------
    if sha256_head.startswith(b"MZ"):
        return "pe"
    if sha256_head.startswith(b"%PDF"):
        return "pdf"
    if sha256_head.startswith(b"PK\x03\x04"):
        # ZIP-family: Office documents vs generic archive
        if n.endswith((".docx", ".pptx", ".xlsx")):
            return "office"
        return "archive"
    if sha256_head[:4] in (b"\xff\xd8\xff\xe0", b"\xff\xd8\xff\xe1", b"\x89PNG"):
        return "image"
    if sha256_head.startswith((b"From ", b"Received:", b"Return-Path:")):
        return "email"

    # --- MIME hints ------------------------------------------------------
    m = (mime or "").lower()
    if m.startswith("text/csv") or n.endswith(".csv"):
        return "csv"
    if m.startswith("message/rfc822") or n.endswith(".eml"):
        return "email"
    if m.startswith("text/") or m in ("application/json", "application/xml"):
        return "text"

    # --- Filename fallback ----------------------------------------------
    if n.endswith((".ps1", ".sh", ".bat", ".cmd", ".vbs", ".js", ".py", ".txt", ".log")):
        return "text"

    # Unknown / binary blob with no discriminator
    return "unsupported"


def route_for_record(rec: FileRecord, first_bytes: bytes) -> Route:
    return route_for(first_bytes[:16], rec.mime, rec.filename)
