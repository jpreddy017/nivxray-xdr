"""NivXRay Investigation — Vendor Normalization Layer.

The Investigation Model must be vendor-agnostic. Any input source
(Cisco XDR, Cisco Secure Endpoint, CrowdStrike Falcon, Microsoft
Defender, SentinelOne, Sysmon, QRadar, Splunk, or generic JSON) must
be flattened into a canonical stream of `IncidentEvent` records before
the narrative engine runs.

This module owns that translation. Deterministic, regex + JSON-key
mapping only. NO LLM.

Public entry point:
    normalize(raw_text) -> list[IncidentEvent]

Behaviour:
  · If `raw_text` contains a JSON body → parse it and dispatch to the
    matching vendor adapter (auto-detected by signature keys).
  · Otherwise → fall back to the existing regex-based
    `mdr.incident_parser.parse_events()`.
"""
from __future__ import annotations

import json
import re
from typing import Any

from v2.mdr.incident_parser import IncidentEvent, parse_events as _regex_parse


# ── Vendor signatures ─────────────────────────────────────────────
# Each entry maps a set of signature keys to a canonical vendor name.
_VENDOR_SIGNATURES: list[tuple[str, set[str]]] = [
    ("Cisco XDR",             {"incident_id", "sighting_id", "observables", "targets"}),
    ("Cisco XDR",             {"incident_ref", "casebook", "confidence"}),
    ("Cisco Secure Endpoint", {"connector_guid", "computer", "detection"}),
    ("CrowdStrike Falcon",    {"falcon_host_link", "device_id", "behaviors"}),
    ("CrowdStrike Falcon",    {"event_simpleName", "aid", "SHA256HashData"}),
    ("Microsoft Defender",    {"AlertId", "MachineId", "Category", "IncidentId"}),
    ("Microsoft Defender",    {"deviceId", "detectionSource", "evidence"}),
    ("SentinelOne",           {"agentDetectionInfo", "threatInfo", "indicators"}),
    ("Sysmon",                {"EventID", "System", "EventData"}),
    ("Sysmon",                {"Image", "ParentImage", "CommandLine", "ProcessId"}),
    ("QRadar",                {"qid", "categoryid", "log_source_id"}),
    ("Splunk",                {"sourcetype", "_time", "index", "search_name"}),
]


# ── JSON detection helper ────────────────────────────────────────
_JSON_START = re.compile(r"[\{\[]")


def _extract_json_blocks(text: str) -> list[Any]:
    """Return every top-level JSON object/array present in `text`. Robust
    to prose surrounding the JSON."""
    blocks: list[Any] = []
    i = 0
    n = len(text)
    while i < n:
        m = _JSON_START.search(text, i)
        if not m:
            break
        start = m.start()
        depth = 0
        opener = text[start]
        closer = "}" if opener == "{" else "]"
        j = start
        in_str = False
        esc = False
        while j < n:
            c = text[j]
            if in_str:
                if esc:
                    esc = False
                elif c == "\\":
                    esc = True
                elif c == '"':
                    in_str = False
            else:
                if c == '"':
                    in_str = True
                elif c == opener:
                    depth += 1
                elif c == closer:
                    depth -= 1
                    if depth == 0:
                        chunk = text[start:j + 1]
                        try:
                            blocks.append(json.loads(chunk))
                        except Exception:
                            pass
                        break
            j += 1
        i = max(j + 1, start + 1)
    return blocks


def _detect_vendor(doc: dict) -> str:
    keys = set(doc.keys())
    for vendor, sig in _VENDOR_SIGNATURES:
        if sig & keys and len(sig & keys) >= max(2, len(sig) // 2):
            return vendor
    # Loose match — any single strong signal
    if "falcon_host_link" in keys or "event_simpleName" in keys:
        return "CrowdStrike Falcon"
    if "AlertId" in keys or "detectionSource" in keys:
        return "Microsoft Defender"
    if "agentDetectionInfo" in keys or "threatInfo" in keys:
        return "SentinelOne"
    if "EventID" in keys and "EventData" in keys:
        return "Sysmon"
    return "Generic JSON"


# ── Adapter helpers ───────────────────────────────────────────────
def _mk(**kw) -> IncidentEvent:
    """Build an IncidentEvent from a dict of clean fields."""
    return IncidentEvent(**{k: v for k, v in kw.items() if v is not None})


def _get(doc: dict, *keys, default=""):
    for k in keys:
        v = doc
        for part in k.split("."):
            if isinstance(v, dict) and part in v:
                v = v[part]
            else:
                v = None
                break
        if v not in (None, "", []):
            return v
    return default


# ── Adapters (one per vendor) ─────────────────────────────────────
def _adapt_cisco_xdr(doc: dict) -> list[IncidentEvent]:
    obs = doc.get("observables") or []
    targets = doc.get("targets") or []
    tgt = targets[0] if targets else {}
    ts = _get(doc, "created", "occurred_at", "start_time")
    hostname = _get(tgt, "hostname", "name")
    user = _get(tgt, "user")
    ev = _mk(
        ts_raw=ts, ts=ts, source="Cisco XDR",
        detection_name=_get(doc, "title", "short_description"),
        threat_name=_get(doc, "reason", "confidence"),
        hostname=hostname, user=user,
        message=(doc.get("description") or doc.get("short_description") or "")[:200],
    )
    # Pull first process observable if any
    for o in obs or []:
        t = (o.get("type") or "").lower()
        val = o.get("value") or ""
        if t == "file_name" and not ev.path:
            ev.path = val
        elif t in ("sha256", "sha-256") and not ev.sha256:
            ev.sha256 = val.lower()
        elif t == "md5" and not ev.md5:
            ev.md5 = val.lower()
        elif t == "process_name" and not ev.process:
            ev.process = val
    return [ev]


def _adapt_cisco_secure_endpoint(doc: dict) -> list[IncidentEvent]:
    ev = _mk(
        ts_raw=_get(doc, "timestamp", "date"), source="Cisco Secure Endpoint",
        detection_name=_get(doc, "detection", "event_type"),
        threat_name=_get(doc, "detection", "threat_name", "file.disposition"),
        hostname=_get(doc, "computer.hostname", "computer.name"),
        user=_get(doc, "user"),
        parent_process=_get(doc, "file.parent.identity.file_name",
                             "file.parent.file_name"),
        process=_get(doc, "file.file_name", "file.identity.file_name"),
        sha256=_get(doc, "file.identity.sha256", "file.sha256").lower() or "",
        path=_get(doc, "file.file_path", "file.path"),
        action=_get(doc, "file.disposition", "action").lower(),
    )
    return [ev]


def _adapt_crowdstrike(doc: dict) -> list[IncidentEvent]:
    beh = doc.get("behaviors") or [{}]
    b = beh[0] if beh else {}
    ev = _mk(
        ts_raw=_get(doc, "created_timestamp", "start"), source="CrowdStrike Falcon",
        detection_name=_get(b, "scenario", "description", "name")
                       or _get(doc, "event_simpleName", "detection_name"),
        threat_name=_get(b, "objective", "tactic"),
        hostname=_get(doc, "device.hostname", "ComputerName"),
        user=_get(b, "user_name") or _get(doc, "UserName"),
        parent_process=_get(b, "parent_details.filename", "ParentImageFileName"),
        process=_get(b, "filename", "ImageFileName"),
        command_line=_get(b, "cmdline", "CommandLine"),
        sha256=(_get(b, "sha256", "SHA256HashData") or "").lower(),
        md5=(_get(b, "md5", "MD5HashData") or "").lower(),
        path=_get(b, "filepath", "ImageFileName"),
        action=_get(b, "pattern_disposition_details.action_taken").lower(),
    )
    mitre_ids = _get(b, "technique_id") or []
    if isinstance(mitre_ids, str):
        ev.mitre = [mitre_ids]
    elif isinstance(mitre_ids, list):
        ev.mitre = mitre_ids
    return [ev]


def _adapt_defender(doc: dict) -> list[IncidentEvent]:
    ev_list: list[IncidentEvent] = []
    evidence = doc.get("evidence") or []
    ts = _get(doc, "alertCreationTime", "firstEventTime")
    detection = _get(doc, "title", "alertName", "category")
    threat = _get(doc, "threatName", "threatFamilyName")
    machine = _get(doc, "computerDnsName", "machineName", "MachineId")
    user = _get(doc, "userName", "AccountName")
    for e in evidence or [{}]:
        ev_list.append(_mk(
            ts_raw=ts, source="Microsoft Defender",
            detection_name=detection, threat_name=threat,
            hostname=machine, user=user,
            parent_process=_get(e, "parentProcessImageFile", "parentProcessName"),
            process=_get(e, "processImageFile", "processName", "fileName"),
            command_line=_get(e, "processCommandLine", "cmdLine"),
            sha256=(_get(e, "sha256") or "").lower(),
            md5=(_get(e, "md5") or "").lower(),
            path=_get(e, "filePath", "fileFullPath"),
            action=_get(e, "remediationAction", "detectionStatus").lower(),
        ))
    return ev_list or [_mk(source="Microsoft Defender", ts_raw=ts,
                             detection_name=detection, hostname=machine, user=user)]


def _adapt_sentinelone(doc: dict) -> list[IncidentEvent]:
    ti = doc.get("threatInfo") or {}
    ai = doc.get("agentDetectionInfo") or {}
    ev = _mk(
        ts_raw=_get(ti, "createdAt", "identifiedAt"), source="SentinelOne",
        detection_name=_get(ti, "threatName", "classification"),
        threat_name=_get(ti, "malwareFamilies") or _get(ti, "threatName"),
        hostname=_get(ai, "agentComputerName", "agentDomain"),
        user=_get(ai, "agentDetectionState") or _get(ti, "originatorProcess"),
        process=_get(ti, "originatorProcess", "processName"),
        command_line=_get(ti, "commandLine"),
        sha256=(_get(ti, "sha256") or "").lower(),
        md5=(_get(ti, "md5") or "").lower(),
        path=_get(ti, "filePath"),
        action=_get(ti, "mitigationStatus", "confidenceLevel").lower(),
    )
    return [ev]


def _adapt_sysmon(doc: dict) -> list[IncidentEvent]:
    ed = doc.get("EventData") or {}
    sys = doc.get("System") or {}
    return [_mk(
        ts_raw=_get(sys, "TimeCreated", "@SystemTime"), source="Sysmon",
        detection_name=f"Sysmon Event {_get(sys, 'EventID', 'EventID')}",
        parent_process=_get(ed, "ParentImage", "ParentCommandLine"),
        process=_get(ed, "Image"),
        command_line=_get(ed, "CommandLine"),
        sha256=(_get(ed, "Hashes.SHA256", "SHA256") or "").lower(),
        md5=(_get(ed, "Hashes.MD5", "MD5") or "").lower(),
        path=_get(ed, "Image", "TargetFilename"),
        user=_get(ed, "User"),
        hostname=_get(sys, "Computer"),
    )]


def _adapt_qradar(doc: dict) -> list[IncidentEvent]:
    return [_mk(
        ts_raw=_get(doc, "start_time", "starttime"), source="QRadar",
        detection_name=_get(doc, "offense_source", "description"),
        hostname=_get(doc, "hostname"),
        user=_get(doc, "username"),
        process=_get(doc, "process"),
        command_line=_get(doc, "command_line"),
    )]


def _adapt_splunk(doc: dict) -> list[IncidentEvent]:
    return [_mk(
        ts_raw=_get(doc, "_time", "time"), source="Splunk",
        detection_name=_get(doc, "search_name", "sourcetype"),
        hostname=_get(doc, "host", "dest"),
        user=_get(doc, "user", "src_user"),
        process=_get(doc, "process", "process_name"),
        command_line=_get(doc, "process_command_line", "command"),
        sha256=(_get(doc, "file_hash", "sha256") or "").lower(),
    )]


def _adapt_generic(doc: dict) -> list[IncidentEvent]:
    """Best-effort adapter for any JSON alert. Looks up common field
    names by alias."""
    ev = _mk(
        ts_raw=_get(doc, "timestamp", "time", "date", "created", "occurred_at"),
        source=_get(doc, "source", "vendor", "product") or "Generic JSON",
        detection_name=_get(doc, "detection_name", "alert_name", "rule_name",
                             "title", "name", "detection"),
        threat_name=_get(doc, "threat_name", "malware_family", "threat",
                          "signature"),
        hostname=_get(doc, "hostname", "host", "device", "machine",
                       "computer_name"),
        user=_get(doc, "user", "username", "account", "user_name"),
        parent_process=_get(doc, "parent_process", "parent",
                             "parent_process_name", "ppimage"),
        process=_get(doc, "process", "process_name", "image", "executable"),
        command_line=_get(doc, "command_line", "cmdline", "command", "cmd"),
        sha256=(_get(doc, "sha256", "hash", "filehash") or "").lower(),
        md5=(_get(doc, "md5") or "").lower(),
        path=_get(doc, "path", "file_path", "target", "filename"),
        action=(_get(doc, "action", "status", "disposition", "verdict")
                or "").lower(),
    )
    return [ev]


_ADAPTERS = {
    "Cisco XDR":              _adapt_cisco_xdr,
    "Cisco Secure Endpoint":  _adapt_cisco_secure_endpoint,
    "CrowdStrike Falcon":     _adapt_crowdstrike,
    "Microsoft Defender":     _adapt_defender,
    "SentinelOne":            _adapt_sentinelone,
    "Sysmon":                 _adapt_sysmon,
    "QRadar":                 _adapt_qradar,
    "Splunk":                 _adapt_splunk,
    "Generic JSON":           _adapt_generic,
}


# ── Public entry point ───────────────────────────────────────────
def normalize(raw_text: str) -> list[IncidentEvent]:
    """Return vendor-normalised `IncidentEvent` records from any input.

    Order of preference:
      1) JSON payload → vendor adapter (auto-detected)
      2) Regex parser (existing implementation) — the fallback for text
    """
    if not raw_text or not raw_text.strip():
        return []
    events: list[IncidentEvent] = []
    for block in _extract_json_blocks(raw_text):
        docs = block if isinstance(block, list) else [block]
        for doc in docs:
            if not isinstance(doc, dict):
                continue
            vendor = _detect_vendor(doc)
            adapter = _ADAPTERS.get(vendor, _adapt_generic)
            for ev in adapter(doc):
                if any([ev.detection_name, ev.threat_name, ev.process,
                        ev.command_line, ev.sha256, ev.hostname, ev.user,
                        ev.path]):
                    events.append(ev)
    # Always run the regex parser too — text-only fields (references,
    # attacker URLs, IPs) come from the regex layer.
    text_events = _regex_parse(raw_text)
    events.extend(text_events)
    return events
