"""v2/ingestion/format_detector.py · byte-level format sniffing.

Zero external dependencies. Uses magic bytes + light content probing to
identify one of: `zip`, `evtx`, `xml`, `json`, `ndjson`, `csv`, `txt`,
`unknown`.

Filenames are respected but never authoritative — a `.txt` full of JSON
is still classified as JSON.
"""
from __future__ import annotations
import json

# Magic bytes
_MAGIC = {
    b"PK\x03\x04": "zip",
    b"ElfFile\x00": "evtx",   # EVTX file header
}


def _peek(data: bytes, n: int = 4096) -> str:
    return data[:n].decode("utf-8", errors="ignore").lstrip("\ufeff").strip()


def detect_format(data: bytes, *, filename: str = "") -> str:
    """Deterministic format classifier."""
    if not data:
        return "unknown"

    for magic, fmt in _MAGIC.items():
        if data.startswith(magic):
            return fmt

    head = _peek(data)
    if not head:
        return "unknown"

    # XML
    if head.startswith("<?xml") or head.startswith("<Events") or head.startswith("<Event "):
        return "xml"

    # JSON / NDJSON
    if head.startswith("{") or head.startswith("["):
        try:
            json.loads(head[:8000])
            return "json"
        except Exception:
            pass
        # Try NDJSON
        first_line = head.splitlines()[0].strip()
        if first_line.startswith("{") or first_line.startswith("["):
            try:
                json.loads(first_line)
                return "ndjson"
            except Exception:
                pass

    # CSV heuristic: first line looks like headers.
    first_line = head.splitlines()[0].strip() if head else ""
    if "," in first_line and not first_line.startswith("<") and not first_line.startswith("{"):
        return "csv"

    # Filename hints as last resort
    fn = (filename or "").lower()
    if fn.endswith(".csv"): return "csv"
    if fn.endswith(".json"): return "json"
    if fn.endswith(".ndjson"): return "ndjson"
    if fn.endswith(".xml"): return "xml"
    if fn.endswith(".zip"): return "zip"
    if fn.endswith(".evtx"): return "evtx"

    return "txt"
