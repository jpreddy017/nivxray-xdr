"""CEF / LEEF payload parsers · P1.10.

These are PAYLOAD parsers, not transports.  A CEF or LEEF event arrives
over the syslog receiver that already exists; the syslog header is parsed
first, then the message body is handed here.  No second transport is
created.

Boundary: acquire → parse → normalise → provenance → deliver.  Nothing
here scores, correlates or classifies — that is the core's job
(Canonical Evidence → IUE → Detection → ICE → IKG → VEEE).

Formats implemented to spec:
  CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|ext=...
      · pipes escaped as `\\|`, backslashes as `\\\\`
      · extension values escaped as `\\=`
  LEEF:1.0|Vendor|Product|Version|EventID|[delim]|key=value<delim>...
  LEEF:2.0 adds an explicit delimiter field (literal char, `x09`, `\\t`).
"""
from __future__ import annotations

import re
from typing import Any, Dict, Optional

CEF_PREFIX_RE = re.compile(r"^CEF:(?P<version>\d+)\|")
LEEF_PREFIX_RE = re.compile(r"^LEEF:(?P<version>\d+(?:\.\d+)?)\|")

# CEF severity is 0-10; map to the canonical band without inventing a verdict.
def _cef_severity_band(raw: Optional[str]) -> Optional[str]:
    try:
        n = int(str(raw).strip())
    except (TypeError, ValueError):
        return None
    if n <= 3:  return "low"
    if n <= 6:  return "medium"
    if n <= 8:  return "high"
    return "critical"


def _split_escaped_pipes(s: str) -> list[str]:
    out, buf, i = [], [], 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            nxt = s[i + 1]
            if nxt in ("|", "\\"):
                buf.append(nxt); i += 2; continue
        if c == "|":
            out.append("".join(buf)); buf = []; i += 1; continue
        buf.append(c); i += 1
    out.append("".join(buf))
    return out


def _parse_cef_extension(ext: str) -> Dict[str, str]:
    """`k=v k2=v2` where a value may contain spaces and `\\=` escapes."""
    fields: Dict[str, str] = {}
    if not ext:
        return fields
    keys = [(m.start(), m.end(), m.group(1))
            for m in re.finditer(r"(?:^|\s)([A-Za-z][\w\.\[\]]*)=", ext)]
    for idx, (start, end, key) in enumerate(keys):
        stop = keys[idx + 1][0] if idx + 1 < len(keys) else len(ext)
        raw = ext[end:stop]
        fields[key] = raw.replace("\\=", "=").replace("\\\\", "\\").strip()
    return fields


def is_cef(msg: str) -> bool:
    return bool(msg) and bool(CEF_PREFIX_RE.match(msg.strip()))


def is_leef(msg: str) -> bool:
    return bool(msg) and bool(LEEF_PREFIX_RE.match(msg.strip()))


def parse_cef(msg: str) -> Dict[str, Any]:
    """Return the parsed CEF record, or `{"parser": "cef", "parse_error": …}`.

    A malformed line is NEVER discarded: the error is recorded and the raw
    line is preserved so the evidence still reaches the core.
    """
    text = (msg or "").strip()
    m = CEF_PREFIX_RE.match(text)
    if not m:
        return {"parser": "cef", "parse_error": "missing CEF: prefix"}
    body = text[m.end():]
    parts = _split_escaped_pipes(body)
    if len(parts) < 6:
        return {"parser": "cef", "parse_error": f"expected 6 header fields, got {len(parts)}",
                "cef_version": m.group("version")}
    vendor, product, version, sig, name, severity = parts[:6]
    ext = "|".join(parts[6:]) if len(parts) > 6 else ""
    fields = _parse_cef_extension(ext)
    return {
        "parser":         "cef",
        "cef_version":    m.group("version"),
        "device_vendor":  vendor,
        "device_product": product,
        "device_version": version,
        "signature_id":   sig,
        "name":           name,
        "severity_raw":   severity,
        "severity":       _cef_severity_band(severity),
        "extension":      fields,
        # Common Event Format standard keys, surfaced without renaming
        # anything the sender did not send.
        "src_ip":         fields.get("src"),
        "dst_ip":         fields.get("dst"),
        "src_port":       fields.get("spt"),
        "dst_port":       fields.get("dpt"),
        "src_user":       fields.get("suser"),
        "dst_user":       fields.get("duser"),
        "host":           fields.get("dvchost") or fields.get("dhost"),
        "process":        fields.get("dproc") or fields.get("sproc"),
        "file_path":      fields.get("filePath") or fields.get("fname"),
        "file_hash":      fields.get("fileHash"),
        "action":         fields.get("act"),
        "protocol":       fields.get("proto"),
        "request_url":    fields.get("request"),
        "message":        fields.get("msg"),
        "device_event_class": sig,
        "source_timestamp": fields.get("rt") or fields.get("end") or fields.get("start"),
    }


def _leef_delimiter(version: str, parts: list[str]) -> tuple[str, int]:
    """LEEF 2.0 carries an explicit delimiter as the 6th header field."""
    if version.startswith("2") and len(parts) >= 5:
        d = (parts[4] or "").strip()
        if d.lower() in ("x09", "\\t", "0x09"):  return "\t", 5
        if d:                                    return d[0], 5
        return "\t", 5
    return "\t", 4


def parse_leef(msg: str) -> Dict[str, Any]:
    text = (msg or "").strip()
    m = LEEF_PREFIX_RE.match(text)
    if not m:
        return {"parser": "leef", "parse_error": "missing LEEF: prefix"}
    version = m.group("version")
    parts = text[m.end():].split("|")
    if len(parts) < 5:
        return {"parser": "leef", "parse_error": f"expected 5 header fields, got {len(parts)}",
                "leef_version": version}
    vendor, product, prod_version, event_id = parts[:4]
    delim, attr_index = _leef_delimiter(version, parts)
    attr_blob = "|".join(parts[attr_index:]) if len(parts) > attr_index else parts[4]

    fields: Dict[str, str] = {}
    chunks = attr_blob.split(delim) if delim in attr_blob else re.split(r"\s+", attr_blob)
    for chunk in chunks:
        if "=" not in chunk:
            continue
        k, v = chunk.split("=", 1)
        k = k.strip()
        if k:
            fields[k] = v.strip()

    return {
        "parser":          "leef",
        "leef_version":    version,
        "device_vendor":   vendor,
        "device_product":  product,
        "device_version":  prod_version,
        "event_id":        event_id,
        "delimiter":       "tab" if delim == "\t" else delim,
        "attributes":      fields,
        "src_ip":          fields.get("src"),
        "dst_ip":          fields.get("dst"),
        "src_port":        fields.get("srcPort"),
        "dst_port":        fields.get("dstPort"),
        "src_user":        fields.get("usrName") or fields.get("srcUserName"),
        "protocol":        fields.get("proto"),
        "action":          fields.get("action") or fields.get("cat"),
        "severity_raw":    fields.get("sev"),
        "severity":        _cef_severity_band(fields.get("sev")),
        "host":            fields.get("identHostName") or fields.get("devTime") and None,
        "message":         fields.get("msg"),
        "source_timestamp": fields.get("devTime"),
    }


def detect_and_parse(msg: str) -> Optional[Dict[str, Any]]:
    """CEF/LEEF payload detection. `None` when the body is neither."""
    if is_cef(msg):
        return parse_cef(msg)
    if is_leef(msg):
        return parse_leef(msg)
    return None
