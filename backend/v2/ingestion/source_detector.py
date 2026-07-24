"""v2/ingestion/source_detector.py · Identify the telemetry SOURCE.

`format` tells you HOW it's encoded (XML/JSON/CSV). `source` tells you
WHAT it is (Sysmon vs Windows-Security vs generic vs canonical). The
same CSV file might be a Sysmon export or a CrowdStrike export — this
module decides.
"""
from __future__ import annotations
import re

# Canonical source ids (used to pick the normalizer).
SOURCE_SYSMON = "sysmon"
SOURCE_WINDOWS_SECURITY = "windows_security"
SOURCE_CANONICAL_JSON = "canonical"
SOURCE_GENERIC_CSV = "generic_csv"
SOURCE_UNKNOWN = "unknown"


# ─── XML sniffers ────────────────────────────────────────────────────
_SYSMON_XML_RE = re.compile(
    r"Provider\s+Name=[\"']Microsoft-Windows-Sysmon[\"']", re.IGNORECASE
)
_WINSEC_XML_RE = re.compile(
    r"Provider\s+Name=[\"']Microsoft-Windows-Security-Auditing[\"']", re.IGNORECASE
)


def detect_source(data: bytes, *, fmt: str, filename: str = "") -> str:
    """Return one of the SOURCE_* constants."""
    head = data[:16384].decode("utf-8", errors="ignore")

    if fmt in ("xml",):
        if _SYSMON_XML_RE.search(head):
            return SOURCE_SYSMON
        if _WINSEC_XML_RE.search(head):
            return SOURCE_WINDOWS_SECURITY
        # Generic Windows event log XML — treat as Win Security by default
        if "<Event" in head and "http://schemas.microsoft.com/win/2004/08/events/event" in head:
            return SOURCE_WINDOWS_SECURITY

    if fmt in ("json", "ndjson"):
        # Canonical (our own CES export) always has "provider" AND "event_id".
        h = head.lower()
        if "\"provider\"" in h and "\"event_id\"" in h and "\"timestamp\"" in h:
            return SOURCE_CANONICAL_JSON
        if "microsoft-windows-sysmon" in h:
            return SOURCE_SYSMON
        if "microsoft-windows-security-auditing" in h:
            return SOURCE_WINDOWS_SECURITY
        # JSON with our CES shape (subset)
        if "\"command_line\"" in h and "\"image\"" in h:
            return SOURCE_CANONICAL_JSON

    if fmt == "csv":
        first_line = head.splitlines()[0] if head else ""
        cols = {c.strip().strip('"').lower() for c in first_line.split(",")}
        # Any subset match → generic canonical CSV
        canonical_hints = {"timestamp", "provider", "event_id", "image", "command_line", "computer"}
        if canonical_hints & cols:
            return SOURCE_GENERIC_CSV

    fn = (filename or "").lower()
    if "sysmon" in fn:
        return SOURCE_SYSMON
    if "security" in fn or "winsec" in fn:
        return SOURCE_WINDOWS_SECURITY

    return SOURCE_UNKNOWN
