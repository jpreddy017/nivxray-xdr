"""v2/ingestion/canonical.py · Canonical Event Schema (CES).

The stable contract between ingestion and every downstream investigation
component (IKG builder, verdict engine, attack story, ATT&CK, IKB,
reports). Locked shape — evolves only via a new schema version.

Every ingestion normalizer emits `CanonicalEventRecord` instances.
Every downstream consumer reads only CES via `ces_to_cem_dict()`
(which produces the CEM v1 shape the existing pipeline already accepts).

Fields intentionally mirror the Sysmon + Windows Security union so
almost every enterprise EDR/XDR export normalizes into it cleanly.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any


# ─── Provenance envelope carried on every CES record ─────────────────
@dataclass
class IngestionProvenance:
    origin: str = "customer-upload"        # "customer-upload" | "api" | "golden-corpus"
    format: str = ""                        # "sysmon_xml" | "windows_security_xml" | "json" | "csv" | "zip"
    source: str = ""                        # "sysmon" | "windows_security" | "canonical" | "generic_csv" | ...
    filename: str = ""
    ingest_job_id: str = ""
    ingested_at: str = ""                   # ISO-8601 UTC
    normalizer: str = ""                    # "sysmon_xml@1.0" etc.

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ─── Canonical Event Schema (CES v1) ─────────────────────────────────
# ORDER MATTERS — this dataclass literally IS the schema documentation.
@dataclass
class CanonicalEventRecord:
    # Time & source
    timestamp: str = ""                     # ISO-8601 UTC
    provider: str = ""                      # "Microsoft-Windows-Sysmon" | "Microsoft-Windows-Security-Auditing" | ...
    event_id: int | None = None             # Sysmon or Win-Sec Event ID
    channel: str = ""                       # e.g. "Microsoft-Windows-Sysmon/Operational"
    # Host & identity
    computer: str = ""                      # hostname
    device_id: str = ""                     # stable device iid (derived from computer)
    user: str = ""
    sid: str = ""
    logon_id: str = ""
    # Process context
    process_guid: str = ""
    process_id: str = ""
    parent_process_guid: str = ""
    parent_process_id: str = ""
    parent_image: str = ""
    image: str = ""                         # full path
    command_line: str = ""
    current_directory: str = ""
    integrity_level: str = ""
    # File
    file_path: str = ""
    file_hash_md5: str = ""
    file_hash_sha1: str = ""
    file_hash_sha256: str = ""
    # Registry
    registry_key: str = ""
    registry_value: str = ""
    registry_data: str = ""
    # Network
    src_ip: str = ""
    src_port: str = ""
    dst_ip: str = ""
    dst_port: str = ""
    protocol: str = ""
    dns_query: str = ""
    dns_answer: str = ""
    url: str = ""
    # Windows service / task / logon
    service: str = ""
    task_name: str = ""
    logon_type: str = ""
    # Original raw record (unchanged, for provenance)
    raw_event: dict[str, Any] = field(default_factory=dict)
    # Ingestion provenance
    provenance: IngestionProvenance | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d


# Field names in CES order — used by the field-mapping UI + docs.
CES_FIELDS: tuple[str, ...] = tuple(
    f.name for f in CanonicalEventRecord.__dataclass_fields__.values()
    if f.name not in ("raw_event", "provenance")
)


# ─── CES → CEM v1 mapping ────────────────────────────────────────────
# Both Sysmon and Win-Sec Event IDs collapse into the CEM v1 kind enum.
# This is the ONE place event-id semantics live. Every normalizer just
# fills CES; kind resolution happens here.
SYSMON_KIND: dict[int, str] = {
    1: "process_create",
    2: "file_write",                # FileCreateTime -> proxy
    3: "network_connect",
    4: "process_exit",              # service state change; kept mapped to process_exit
    5: "process_exit",
    6: "driver_load",
    7: "image_load",
    8: "remote_thread_create",
    9: "file_write",                # RawAccessRead - proxy
    10: "process_access",
    11: "file_create",
    12: "registry_create",
    13: "registry_value_set",
    14: "registry_delete",          # RegistryKey rename mapped to delete-ish
    15: "file_create",              # FileCreateStreamHash
    17: "named_pipe_create",
    18: "named_pipe_create",
    19: "wmi_subscribe",
    20: "wmi_subscribe",
    21: "wmi_subscribe",
    22: "dns_query",
    23: "file_delete",
    24: "file_write",               # ClipboardChange -> proxy
    25: "process_access",           # ProcessTampering
    26: "file_delete",
    255: "alert",
}

WINSEC_KIND: dict[int, str] = {
    4624: "logon_success",
    4625: "logon_failure",
    4634: "logon_success",          # logoff paired w/ 4624
    4672: "privilege_escalation",   # special privileges
    4688: "process_create",
    4697: "service_install",
    4698: "scheduled_task_create",
    4700: "scheduled_task_create",
    4720: "detection",              # user account created
    4732: "detection",              # member added to sensitive group
    4738: "detection",              # user account changed
    4776: "logon_success",          # NTLM auth
    5140: "smb_share_access",
    5145: "smb_share_access",
    5156: "network_connect",        # Windows Filtering Platform
    7045: "service_install",        # System channel
    1102: "alert",                  # audit log cleared
    "*": "alert",
}


def _blake_iid(prefix: str, value: str) -> str:
    """Deterministic short id for opaque canonical identifiers."""
    h = hashlib.blake2s(value.lower().encode(), digest_size=6).hexdigest()
    return f"{prefix}_{h}"


def _basename(path: str) -> str:
    if not path:
        return ""
    p = path.replace("\\", "/").split("/")[-1]
    return p.lower().strip()


def _resolve_kind(ces: CanonicalEventRecord) -> str:
    """Deterministic CES → CEM event kind."""
    prov = (ces.provider or "").lower()
    eid = ces.event_id
    if "sysmon" in prov and isinstance(eid, int):
        return SYSMON_KIND.get(eid, "detection")
    if ("security-auditing" in prov or "microsoft-windows-security" in prov) and isinstance(eid, int):
        return WINSEC_KIND.get(eid, "detection")
    # Heuristic fallback based on populated fields.
    if ces.dns_query:
        return "dns_query"
    if ces.dst_ip or ces.src_ip:
        return "network_connect"
    if ces.registry_key:
        return "registry_value_set"
    if ces.file_path and ces.image:
        return "file_write"
    if ces.image and ces.command_line:
        return "process_create"
    return "detection"


def ces_to_cem_dict(ces: CanonicalEventRecord, *, case_id: str,
                    sequence: int = 0) -> dict[str, Any]:
    """Turn ONE CES record into a CEM v1 event dict ready to persist to
    `v2_shadow_observations`. This is the ONLY bridge between the
    ingestion layer and the rest of NivXRay.

    Deterministic. Same CES + same case_id + same sequence → identical
    output on every invocation.
    """
    # Deterministic IIDs
    computer = ces.computer or "unknown-host"
    device_iid = ces.device_id or _blake_iid("dev", computer)
    proc_key = ces.process_guid or f"{computer}:{ces.process_id}:{_basename(ces.image)}"
    process_iid = _blake_iid("proc", proc_key) if (ces.image or ces.process_guid) else ""
    parent_key = ces.parent_process_guid or (
        f"{computer}:{ces.parent_process_id}:{_basename(ces.parent_image)}"
        if (ces.parent_process_id or ces.parent_image) else ""
    )
    parent_iid = _blake_iid("proc", parent_key) if parent_key else ""

    actor_iid = _blake_iid("user", f"{computer}:{ces.user or ces.sid or ''}") if (ces.user or ces.sid) else ""

    artefacts_iids: list[str] = []
    artefacts: dict[str, list[dict[str, Any]]] = {}

    if ces.file_path:
        fid = _blake_iid("file", ces.file_path)
        artefacts.setdefault("file", []).append({
            "iid": fid, "path": ces.file_path,
            "sha256": ces.file_hash_sha256 or "",
        })
        artefacts_iids.append(fid)
    if ces.registry_key:
        rid = _blake_iid("reg", f"{ces.registry_key}:{ces.registry_value}")
        artefacts.setdefault("registry", []).append({
            "iid": rid, "key": ces.registry_key,
            "value": ces.registry_value, "data": ces.registry_data,
        })
        artefacts_iids.append(rid)
    if ces.dst_ip or ces.dns_query or ces.url:
        target = ces.url or ces.dns_query or f"{ces.dst_ip}:{ces.dst_port}"
        nid = _blake_iid("net", target)
        artefacts.setdefault("network", []).append({
            "iid": nid,
            "dst_ip": ces.dst_ip, "dst_port": ces.dst_port,
            "protocol": ces.protocol,
            "dns": ces.dns_query, "url": ces.url,
        })
        artefacts_iids.append(nid)
    if ces.command_line:
        cid = _blake_iid("cmd", ces.command_line)
        artefacts_iids.append(cid)

    kind = _resolve_kind(ces)
    prov = (ces.provenance.to_dict() if ces.provenance else {})
    prov["adapter"] = prov.get("normalizer") or "ingestion"
    prov["confidence"] = 1.0
    # Attach analyst-friendly fields the trajectory→signals pipeline reads
    prov["cmdline"] = ces.command_line
    prov["parent_name"] = _basename(ces.parent_image)
    prov["target"] = ces.file_path or ces.dns_query or ces.dst_ip or ces.registry_key or ces.url

    # Lazy MITRE tagging — deterministic keyword mapper. Only imported
    # here so `canonical.py` stays a pure data module.
    from .mitre_map import tag as _mitre_tag
    mitre_tags = _mitre_tag(ces)

    # Rule-label so the trajectory builder emits a nice sentence.
    label_parts: list[str] = []
    if _basename(ces.image):
        label_parts.append(_basename(ces.image))
    if kind:
        label_parts.append(kind.replace("_", " "))
    if ces.dns_query:
        label_parts.append(f"→ {ces.dns_query}")
    elif ces.dst_ip:
        label_parts.append(f"→ {ces.dst_ip}:{ces.dst_port}")
    elif ces.file_path:
        label_parts.append(f"→ {ces.file_path}")
    elif ces.registry_key:
        label_parts.append(f"→ {ces.registry_key}")
    rule_label = " · ".join(label_parts)[:180]

    # Deterministic evt iid
    evt_key = "|".join([
        ces.timestamp, ces.provider, str(ces.event_id or ""),
        computer, ces.image, ces.command_line[:200],
        ces.file_path, ces.registry_key, ces.dns_query, ces.dst_ip,
    ])
    evt_iid = "evt_" + hashlib.blake2s(evt_key.encode(), digest_size=8).hexdigest()

    return {
        "iid":            evt_iid,
        "case_id":        case_id,
        "adapter":        prov.get("adapter") or prov.get("normalizer") or "ingestion",
        "adapter_version":"1.0",
        "ts":             ces.timestamp,
        "sequence":       sequence,
        "kind":           kind,
        "device_iid":     device_iid,
        "actor_iid":      actor_iid or None,
        "session_iid":    ces.logon_id or None,
        "process_iid":    process_iid or None,
        "artefacts_iids": tuple(artefacts_iids),
        "artefacts":      artefacts,
        "labels":         (),
        "mitre":          tuple(mitre_tags),
        "raw": {
            "provider":      ces.provider,
            "event_id":      ces.event_id,
            "computer":      ces.computer,
            "user":          ces.user,
            "rule_label":    rule_label,
            "action":        kind,
            "entity":        _basename(ces.image) or (ces.dns_query or ces.dst_ip or ces.file_path or ces.registry_key),
            "target":        ces.file_path or ces.dns_query or ces.dst_ip or ces.registry_key or ces.url,
            "command_line":  ces.command_line,
            "parent_image":  _basename(ces.parent_image),
            "sha256":        hashlib.sha256(evt_key.encode()).hexdigest(),
        },
        "process": {
            "name":       _basename(ces.image),
            "image":      ces.image,
            "iid":        process_iid,
            "parent_iid": parent_iid or None,
            "parent_name":_basename(ces.parent_image),
        } if (ces.image or process_iid) else {},
        "trust":       {},
        "provenance":  prov,
    }
