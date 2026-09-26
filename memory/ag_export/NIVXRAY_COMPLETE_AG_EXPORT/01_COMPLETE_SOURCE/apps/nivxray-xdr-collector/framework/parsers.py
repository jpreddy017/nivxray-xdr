"""
Transport parsers · Phase B.

Each parser transforms the vendor payload into a partial canonical
envelope — enough for the authoritative NivXRay backend to make
security decisions.  Parsers NEVER decide "is this malicious"; they
only extract fields.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing   import Any, Dict, Optional


# ── JSON path extraction ───────────────────────────────────────────
def get_path(obj: Any, path: str, default: Any = None) -> Any:
    """Minimal dotted-path extractor.

    Supports:
      • dotted keys      "a.b.c"
      • list indices     "items.0.id"
      • wildcard segment "results[*].id" → returns first non-None
    """
    if not path:
        return obj
    cur: Any = obj
    for seg in path.replace("[*]", ".*").split("."):
        if cur is None:
            return default
        if seg == "*":
            if isinstance(cur, list):
                for it in cur:
                    if it is not None:
                        return it
                return default
            return default
        if isinstance(cur, list):
            try:
                idx = int(seg)
                cur = cur[idx]
                continue
            except (ValueError, IndexError):
                return default
        if isinstance(cur, dict):
            cur = cur.get(seg, default if seg == path.split(".")[-1] else None)
        else:
            return default
    return cur if cur is not None else default


# ── RFC3164 (BSD syslog) ───────────────────────────────────────────
# Example:  <34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8
_RFC3164_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>"
    r"(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<tag>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:?\s*"
    r"(?P<msg>.*)$"
)


def parse_rfc3164(line: str) -> Dict[str, Any]:
    m = _RFC3164_RE.match(line.strip())
    if not m:
        return {"parser": "rfc3164", "parsed": False, "raw_line": line}
    pri  = int(m.group("pri"))
    return {
        "parser":     "rfc3164",
        "parsed":     True,
        "facility":   pri >> 3,
        "severity":   pri & 0x07,
        "timestamp":  m.group("ts"),
        "host":       m.group("host"),
        "app":        m.group("tag"),
        "pid":        int(m.group("pid")) if m.group("pid") else None,
        "message":    m.group("msg"),
    }


# ── RFC5424 (IETF syslog) ──────────────────────────────────────────
# <165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 - BOM'su root' failed
_RFC5424_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<ver>\d{1,2})\s+"
    r"(?P<ts>\S+)\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<app>\S+)\s+"
    r"(?P<procid>\S+)\s+"
    r"(?P<msgid>\S+)\s+"
    r"(?P<sd>-|\[[^\]]*\](?:\[[^\]]*\])*)\s*"
    r"(?P<msg>.*)$"
)


def parse_rfc5424(line: str) -> Dict[str, Any]:
    m = _RFC5424_RE.match(line.strip())
    if not m:
        return {"parser": "rfc5424", "parsed": False, "raw_line": line}
    pri = int(m.group("pri"))
    return {
        "parser":     "rfc5424",
        "parsed":     True,
        "version":    int(m.group("ver")),
        "facility":   pri >> 3,
        "severity":   pri & 0x07,
        "timestamp":  m.group("ts"),
        "host":       m.group("host"),
        "app":        m.group("app"),
        "procid":     m.group("procid") if m.group("procid") != "-" else None,
        "msgid":      m.group("msgid")  if m.group("msgid")  != "-" else None,
        "structured": m.group("sd")     if m.group("sd")     != "-" else None,
        "message":    m.group("msg"),
    }


def parse_syslog_auto(line: str) -> Dict[str, Any]:
    """Try RFC5424 first (has a version octet); fall back to RFC3164."""
    if not line:
        return {"parser": "none", "parsed": False, "raw_line": line}
    # RFC5424 always has "<pri>N " with N being the version.
    if re.match(r"^<\d{1,3}>\d{1,2}\s", line):
        return parse_rfc5424(line)
    return parse_rfc3164(line)


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
