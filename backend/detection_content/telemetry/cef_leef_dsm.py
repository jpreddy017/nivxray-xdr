"""
NivXRay XDR — CEF / LEEF DSM, Parser & Normalizer  ·  P1.10.

Live telemetry arrives from `nivxray-xdr-collector` over the syslog
receiver.  The collector's own parse is provenance, NOT authority: this
module RE-PARSES the verbatim raw line so the core remains the single
source of truth (INGEST_CONTRACT §2.1 — "the base backend MUST NOT trust
`canonical` exclusively").

Honest-state rule: CEF and LEEF carry no parent process id, and usually
no process id or file hash.  Those fields stay `None` and an explicit
`*_state = "UNKNOWN"` is recorded.  Nothing is fabricated, and no event
is discarded merely because process identity is absent.

Formats:
  CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|ext=...
  LEEF:1.0|Vendor|Product|Version|EventID|key=value<TAB>...
  LEEF:2.0|Vendor|Product|Version|EventID|delim|key=value<delim>...
"""
from __future__ import annotations

import hashlib
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .models import (
    CanonicalTelemetryEvent,
    FileEntity,
    HostEntity,
    IdentityEntity,
    NetworkEntity,
    ProcessEntity,
    ProvenanceEnvelope,
)

CEF_AT = re.compile(r"CEF:(?P<version>\d+)\|")
LEEF_AT = re.compile(r"LEEF:(?P<version>\d+(?:\.\d+)?)\|")

UNKNOWN = "UNKNOWN"
OBSERVED = "OBSERVED"


class CefLeefParserError(Exception):
    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")


def _raw_line(ev: Dict[str, Any]) -> str:
    """The verbatim line as the sender emitted it."""
    for key in ("line", "message", "msg", "raw_line"):
        v = ev.get(key)
        if isinstance(v, str) and v.strip():
            return v
    raw = ev.get("raw")
    if isinstance(raw, dict):
        v = raw.get("line") or raw.get("message")
        if isinstance(v, str) and v.strip():
            return v
    if isinstance(raw, str) and raw.strip():
        return raw
    return ""


def _locate(line: str) -> Tuple[Optional[str], int, str]:
    """Return (format, payload_start_index, version) for a CEF/LEEF line."""
    m = CEF_AT.search(line)
    if m:
        return "cef", m.start(), m.group("version")
    m = LEEF_AT.search(line)
    if m:
        return "leef", m.start(), m.group("version")
    return None, -1, ""


def _split_escaped_pipes(s: str) -> List[str]:
    out: List[str] = []
    buf: List[str] = []
    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s) and s[i + 1] in ("|", "\\"):
            buf.append(s[i + 1])
            i += 2
            continue
        if c == "|":
            out.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(c)
        i += 1
    out.append("".join(buf))
    return out


def _cef_extension(ext: str) -> Tuple[Dict[str, str], List[str]]:
    """`k=v k2=v2` — a value may contain spaces and `\\=` escapes.

    The CEF spec requires an `=` inside a value to be escaped, but real
    senders emit unescaped base64 (`cs1=SQBFAFgA==`), which makes a naive
    `\\w+=` scan treat the payload as a new key.  A candidate is therefore
    only accepted as a key boundary when it is a known CEF/LEEF key, a
    self-describing custom slot, or a short plausible vendor key.  Every
    rejected candidate is returned so the decision stays auditable.
    """
    fields: Dict[str, str] = {}
    notes: List[str] = []
    if not ext:
        return fields, notes
    candidates = [(m.start(), m.end(), m.group(1))
                  for m in re.finditer(r"(?:^|\s)([A-Za-z][\w.\[\]]*)=", ext)]
    keys = []
    for start, end, key in candidates:
        if _is_key(key):
            keys.append((start, end, key))
        else:
            notes.append(f"not_a_key:{key}")
    for idx, (start, end, key) in enumerate(keys):
        stop = keys[idx + 1][0] if idx + 1 < len(keys) else len(ext)
        fields[key] = ext[end:stop].replace("\\=", "=").replace("\\\\", "\\").strip()
    return fields, notes


# ArcSight CEF extension dictionary + the LEEF predefined attributes +
# the vendor-common process/file keys.  Anything outside this set is
# accepted only when it is short enough to be a plausible key rather
# than a run of unescaped base64.
_KNOWN_KEYS = {
    # CEF core
    "act", "app", "cnt", "dst", "dhost", "dmac", "dntdom", "dpid", "dpriv",
    "dproc", "dpt", "dvc", "dvchost", "dvcmac", "dvcpid", "end", "fname",
    "fsize", "in", "msg", "out", "outcome", "proto", "reason", "request",
    "rt", "shost", "smac", "sntdom", "spid", "spriv", "sproc", "spt", "src",
    "start", "suser", "duser", "suid", "duid", "dlat", "dlong", "slat",
    "slong", "cat", "catdt", "sev", "type", "amac", "ahost", "art", "at",
    # CEF file
    "fileHash", "filePath", "filePermission", "fileType", "fileCreateTime",
    "fileModificationTime", "fileId", "oldFileHash", "oldFilePath",
    "oldFileName", "oldFileSize", "oldFileType", "oldFilePermission",
    "oldFileCreateTime", "oldFileModificationTime", "fileName",
    "fileHashSha256", "fhash", "sha256", "sha1", "md5",
    # CEF long-form
    "externalId", "eventId", "deviceDirection", "deviceEventCategory",
    "deviceEventClassId", "deviceExternalId", "deviceFacility",
    "deviceInboundInterface", "deviceOutboundInterface", "deviceNtDomain",
    "devicePayloadId", "deviceProcessName", "deviceProcessId",
    "deviceTranslatedAddress", "deviceAddress", "deviceOsName",
    "deviceAction", "destinationDnsDomain", "destinationServiceName",
    "destinationTranslatedAddress", "destinationTranslatedPort",
    "destinationAddress", "destinationPort", "destinationUserName",
    "sourceDnsDomain", "sourceServiceName", "sourceTranslatedAddress",
    "sourceTranslatedPort", "sourceAddress", "sourcePort", "sourceUserName",
    "agentDnsDomain", "agentNtDomain", "agentTranslatedAddress",
    "agentZoneURI", "requestClientApplication", "requestContext",
    "requestCookies", "requestMethod", "requestUrl",
    # LEEF predefined + vendor-common process keys
    "devTime", "devTimeFormat", "identHostName", "identSrc", "identMAC",
    "usrName", "srcUserName", "dstUserName", "srcPort", "dstPort",
    "srcPreNAT", "dstPreNAT", "srcPostNAT", "dstPostNAT", "action",
    "protocol", "domain", "os", "devname", "cmd", "command", "commandLine",
    "processName", "process", "processId", "processCmdLine", "dprocPath",
    "dnsQuery", "parentProcessName", "parentProcessId",
}
_CUSTOM_SLOT = re.compile(
    r"^(?:cs|cn|cfp|c6a|flex(?:String|Number|Date))\d+(?:Label)?$"
    r"|^device(?:Custom(?:String|Number|Date|FloatingPoint|IPv6Address)"
    r"\d+(?:Label)?)$"
    r"|^flexDate1(?:Label)?$")


def _is_key(token: str) -> bool:
    if token in _KNOWN_KEYS or _CUSTOM_SLOT.match(token):
        return True
    # Unknown vendor key: accept only when it cannot plausibly be a run
    # of unescaped base64/hex from the preceding value.
    return len(token) <= 11 and bool(re.fullmatch(r"[A-Za-z][A-Za-z0-9_.]*", token))


def _leef_delimiter(version: str, parts: List[str]) -> Tuple[str, int]:
    if version.startswith("2") and len(parts) >= 5:
        d = (parts[4] or "").strip()
        if d.lower() in ("x09", "\\t", "0x09"):
            return "\t", 5
        if d:
            return d[0], 5
        return "\t", 5
    return "\t", 4


class CefLeefParser:
    id = "cef-leef-parser"

    def parse(self, ev: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(ev, dict):
            raise CefLeefParserError("INVALID_EVENT", "event is not a dict")
        line = _raw_line(ev)
        if not line:
            raise CefLeefParserError("NO_RAW_LINE",
                                     "no verbatim CEF/LEEF line on the event")
        fmt, idx, version = _locate(line)
        if fmt is None:
            raise CefLeefParserError("NOT_CEF_OR_LEEF",
                                     "line carries neither a CEF: nor a LEEF: payload")
        syslog_header = line[:idx].strip()
        payload = line[idx:]
        if fmt == "cef":
            header, fields, notes = self._parse_cef(payload, version)
        else:
            header, fields, notes = self._parse_leef(payload, version)
        return {
            "payload_format": fmt,
            "payload_version": version,
            "syslog_header": syslog_header,
            "header": header,
            "fields": fields,
            "parse_notes": notes,
            "raw": ev,
            "raw_line": line,
        }

    def _parse_cef(self, payload: str, version: str
                   ) -> Tuple[Dict[str, Any], Dict[str, str], List[str]]:
        body = payload[CEF_AT.match(payload).end():]
        parts = _split_escaped_pipes(body)
        if len(parts) < 6:
            raise CefLeefParserError(
                "CEF_HEADER_INCOMPLETE",
                f"expected 6 CEF header fields, got {len(parts)}")
        vendor, product, dev_version, sig, name, severity = parts[:6]
        ext = "|".join(parts[6:]) if len(parts) > 6 else ""
        fields, notes = _cef_extension(ext)
        return ({"vendor": vendor, "product": product,
                 "device_version": dev_version, "signature_id": sig,
                 "name": name, "severity": severity,
                 "cef_version": version},
                fields, notes)

    def _parse_leef(self, payload: str, version: str
                    ) -> Tuple[Dict[str, Any], Dict[str, str], List[str]]:
        body = payload[LEEF_AT.match(payload).end():]
        parts = body.split("|")
        if len(parts) < 5:
            raise CefLeefParserError(
                "LEEF_HEADER_INCOMPLETE",
                f"expected 5 LEEF header fields, got {len(parts)}")
        vendor, product, dev_version, event_id = parts[:4]
        delim, attr_index = _leef_delimiter(version, parts)
        blob = "|".join(parts[attr_index:]) if len(parts) > attr_index else parts[4]
        notes: List[str] = []
        if delim not in blob:
            # The declared delimiter is absent. Fall back to the LEEF
            # default (tab) when present rather than splitting on any
            # whitespace, which would truncate values containing spaces.
            if "\t" in blob:
                notes.append(f"declared_delimiter_absent:{delim!r}:used_tab")
                delim = "\t"
            else:
                notes.append(f"declared_delimiter_absent:{delim!r}:used_space")
        fields: Dict[str, str] = {}
        chunks = blob.split(delim) if delim in blob else re.split(r"\s+", blob)
        for chunk in chunks:
            if "=" not in chunk:
                continue
            k, v = chunk.split("=", 1)
            if k.strip():
                fields[k.strip()] = v.strip()
        return ({"vendor": vendor, "product": product,
                 "device_version": dev_version, "signature_id": event_id,
                 "name": fields.get("cat") or event_id,
                 "severity": fields.get("sev"),
                 "leef_version": version},
                fields, notes)


# ── field resolution helpers ─────────────────────────────────────────
def _first(fields: Dict[str, str], *keys: str) -> Tuple[str, Optional[str]]:
    """Return (value, key_used).  Empty string when nothing is present."""
    for k in keys:
        v = fields.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip(), k
    return "", None


def _labelled_custom(fields: Dict[str, str], *needles: str) -> Tuple[str, Optional[str]]:
    """CEF/LEEF custom strings are self-describing: `cs1Label=CommandLine
    cs1=<value>`.  Only accept a custom slot whose label says so — never
    guess that an unlabelled slot holds a command line."""
    for key, value in fields.items():
        if not key.endswith("Label"):
            continue
        label = (value or "").lower().replace(" ", "")
        if any(n in label for n in needles):
            slot = key[:-len("Label")]
            v = fields.get(slot)
            if isinstance(v, str) and v.strip():
                return v.strip(), slot
    return "", None


def _int_or_none(raw: str) -> Optional[int]:
    try:
        return int(str(raw).strip())
    except (TypeError, ValueError):
        return None


def _hash_bucket(value: str) -> Tuple[str, str]:
    """CEF `fileHash` is untyped — classify by length, never relabel."""
    v = (value or "").strip().lower()
    if re.fullmatch(r"[0-9a-f]{64}", v):
        return "sha256", v
    if re.fullmatch(r"[0-9a-f]{40}", v):
        return "sha1", v
    if re.fullmatch(r"[0-9a-f]{32}", v):
        return "md5", v
    return "", ""


def _iso(ts: str) -> str:
    """CEF `rt` may be epoch-ms or a free-form device time.  Convert only
    when the value is unambiguously epoch milliseconds."""
    raw = (ts or "").strip()
    if not raw:
        return ""
    if re.fullmatch(r"\d{13}", raw):
        return datetime.fromtimestamp(int(raw) / 1000.0, tz=timezone.utc).isoformat()
    if re.fullmatch(r"\d{10}", raw):
        return datetime.fromtimestamp(int(raw), tz=timezone.utc).isoformat()
    return raw


_SEVERITY_BAND = (("low", 3), ("medium", 6), ("high", 8))


def _severity_band(raw: Optional[str]) -> str:
    n = _int_or_none(raw or "")
    if n is None:
        return ""
    for band, ceiling in _SEVERITY_BAND:
        if n <= ceiling:
            return band
    return "critical"


class CefLeefNormalizer:
    id = "cef-leef-normalizer"

    def normalize(self, parsed: Dict[str, Any], dsm_id: str,
                  collector_id: str, integration_id: str,
                  trace_id: str,
                  tenant_id: Optional[str] = "default") -> Dict[str, Any]:
        raw = parsed["raw"] if isinstance(parsed.get("raw"), dict) else {}
        resolved_tenant = (raw.get("tenant_id")
                           or parsed.get("tenant_id")
                           or tenant_id)
        if not resolved_tenant or not str(resolved_tenant).strip():
            raise ValueError("tenant_id is required: NO tenant fallback permitted")
        resolved_tenant = str(resolved_tenant).strip()

        header = parsed["header"]
        fields: Dict[str, str] = parsed["fields"]
        now_iso = datetime.now(timezone.utc).isoformat()
        epistemic: Dict[str, str] = {}
        sources: Dict[str, str] = {}

        def _take(name: str, *keys: str) -> str:
            value, key = _first(fields, *keys)
            epistemic[name] = OBSERVED if value else UNKNOWN
            if key:
                sources[name] = key
            return value

        # ── host ─────────────────────────────────────────────
        hostname = _take("hostname", "dvchost", "dhost", "identHostName",
                         "shost", "devname")
        host_ip = _take("host_ip", "dvc", "deviceAddress", "identSrc")
        host = HostEntity(
            hostname=hostname,
            host_id=hostname or host_ip,
            ip_addresses=[host_ip] if host_ip else [],
            os_family=_take("os_family", "deviceOsName", "os"),
        )

        # ── identity ─────────────────────────────────────────
        username = _take("username", "duser", "suser", "usrName",
                         "srcUserName", "destinationUserName")
        identity = IdentityEntity(
            principal_id=username,
            username=username,
            domain=_take("user_domain", "dntdom", "sntdom", "domain"),
        )

        # ── process (pid/ppid are usually absent — stay honest) ──
        proc_name = _take("process_name", "dproc", "sproc",
                          "deviceProcessName", "processName", "process")
        pid_raw = _take("pid", "dpid", "spid", "processId", "deviceProcessId")
        pid = _int_or_none(pid_raw)
        if pid is None:
            epistemic["pid"] = UNKNOWN
            sources.pop("pid", None)
        # CEF and LEEF have NO parent-process-id field in either spec.
        epistemic["ppid"] = UNKNOWN
        cmd, cmd_key = _first(fields, "cmd", "command", "processCmdLine",
                              "commandLine")
        if not cmd:
            cmd, cmd_key = _labelled_custom(fields, "commandline", "command",
                                            "cmdline", "processcommand")
        epistemic["command_line"] = OBSERVED if cmd else UNKNOWN
        if cmd_key:
            sources["command_line"] = cmd_key

        hashes: Dict[str, str] = {}
        for hk in ("fileHash", "fhash", "sha256", "sha1", "md5",
                   "fileHashSha256"):
            hv = fields.get(hk)
            if not hv:
                continue
            kind, norm = _hash_bucket(hv)
            if kind:
                hashes[kind] = norm
                sources.setdefault(f"file_{kind}", hk)
        for kind in ("sha256", "sha1", "md5"):
            epistemic[f"file_{kind}"] = OBSERVED if kind in hashes else UNKNOWN

        process = ProcessEntity(
            name=proc_name,
            pid=pid,
            ppid=None,
            parent_name="",
            executable_path=_take("process_path", "dprocPath", "filePath"),
            command_line=cmd,
            hashes=dict(hashes),
        )

        # ── network ──────────────────────────────────────────
        network = NetworkEntity(
            src_ip=_take("src_ip", "src", "sourceAddress"),
            src_port=_int_or_none(_take("src_port", "spt", "srcPort",
                                        "sourcePort")),
            dest_ip=_take("dst_ip", "dst", "destinationAddress"),
            dest_port=_int_or_none(_take("dst_port", "dpt", "dstPort",
                                         "destinationPort")),
            protocol=_take("protocol", "proto", "protocol"),
            dns_query=_take("dns_query", "destinationDnsDomain", "dnsQuery"),
        )

        # ── file ─────────────────────────────────────────────
        file_entity = FileEntity(
            path=_take("file_path", "filePath", "fname", "fileName"),
            name=_take("file_name", "fname", "fileName"),
            action=_take("file_action", "act", "action", "deviceAction"),
            hashes=dict(hashes),
        )

        event_time = _iso(_take("event_time", "rt", "end", "start", "devTime")) or now_iso
        epistemic["event_time"] = OBSERVED if event_time != now_iso else UNKNOWN

        signature_id = str(header.get("signature_id") or "")
        source_event_id = (_take("source_event_id", "externalId", "eventId")
                           or signature_id
                           or hashlib.sha256(
                               parsed["raw_line"].encode()).hexdigest()[:24])

        provenance = ProvenanceEnvelope(
            trace_id=trace_id,
            collector_id=collector_id,
            integration_id=integration_id,
            dsm_id=dsm_id,
            parser_id=CefLeefParser.id,
            normalizer_id=self.id,
            ingest_time=now_iso,
        )

        canonical = CanonicalTelemetryEvent(
            event_id=str(uuid.uuid4()),
            tenant_id=resolved_tenant,
            source_vendor=str(header.get("vendor") or ""),
            source_product=str(header.get("product") or ""),
            source_event_id=str(source_event_id),
            event_type=parsed["payload_format"] + "_event",
            event_time=str(event_time),
            ingest_time=now_iso,
            host=host,
            identity=identity,
            process=process,
            network=network,
            file=file_entity,
            raw_ref={"line": parsed["raw_line"],
                     "syslog_header": parsed["syslog_header"],
                     "collector_provenance": {
                         k: raw.get(k) for k in
                         ("connector_id", "collector_id", "collection_method",
                          "parser_version", "source", "collection_timestamp")
                         if raw.get(k) is not None}},
            provenance=provenance,
            additional_fields={
                "payload_format": parsed["payload_format"],
                "payload_version": parsed["payload_version"],
                "signature_id": signature_id,
                "signature_name": str(header.get("name") or ""),
                "severity_raw": header.get("severity"),
                "severity_band": _severity_band(header.get("severity")),
                "device_version": header.get("device_version"),
                "extension_keys": sorted(fields.keys()),
                "parse_notes": parsed.get("parse_notes") or [],
                # Honest-state ledger: which fields were OBSERVED and
                # which are genuinely UNKNOWN in this wire format.
                "epistemic_state": epistemic,
                "field_sources": sources,
                "origin": "collector-live",
            },
        )
        out = canonical.to_dict()
        # Root-level epistemic markers so no consumer can mistake a
        # missing identity for a real one.
        out["pid_state"] = epistemic.get("pid", UNKNOWN)
        out["ppid_state"] = UNKNOWN
        out["file_sha256_state"] = epistemic.get("file_sha256", UNKNOWN)
        out["command_line_state"] = epistemic.get("command_line", UNKNOWN)
        out["security"] = {
            "signature": {"id": signature_id,
                          "name": str(header.get("name") or "")},
            "category": fields.get("cat") or fields.get("deviceEventCategory"),
            "severity": header.get("severity"),
            # CEF/LEEF severity is a 0-10 scale, NOT the Suricata 1-4
            # scale IUE defaults to.  Hand IUE an explicit band so the
            # sender's number can never be misread.
            "severity_scale": "cef_0_10",
            "severity_band": (_severity_band(header.get("severity")) or "").upper()
                             or "INFORMATIONAL",
        }
        out["action"] = file_entity.action
        return out


class CefLeefDSM:
    id = "cef-leef"
    vendor = "Multi-vendor"
    product = "CEF / LEEF over Syslog"
    version = "1"
    source_type = "LOG_PAYLOAD"

    def supports(self, ev: Dict[str, Any]) -> bool:
        if not isinstance(ev, dict):
            return False
        fmt = ev.get("payload_format")
        if isinstance(fmt, str) and fmt.lower() in ("cef", "leef"):
            return True
        line = _raw_line(ev)
        if not line:
            return False
        return _locate(line)[0] is not None

    def select_parser(self) -> CefLeefParser:
        return CefLeefParser()

    def select_normalizer(self) -> CefLeefNormalizer:
        return CefLeefNormalizer()

    def identity(self) -> Dict[str, Any]:
        return {"id": self.id, "vendor": self.vendor,
                "product": self.product, "version": self.version,
                "source_type": self.source_type}
