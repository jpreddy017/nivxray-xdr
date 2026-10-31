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
    parent_command_line: str = ""
    image: str = ""                         # full path
    #: B1 · the PE metadata name the vendor compiled in (Sysmon
    #: `OriginalFileName`). A renamed binary keeps it, which is exactly
    #: what masquerading detections read — so it is NOT `image` and it is
    #: never collapsed into it.
    original_file_name: str = ""
    command_line: str = ""
    current_directory: str = ""
    integrity_level: str = ""
    process_start_time: str = ""
    #: B1 · the identity QUALITY the source gave us, verbatim from
    #: `ProcessEntity.attribution_state`. A PID-only observation must never
    #: reach a consumer looking like an authoritative process identity.
    process_attribution_state: str = ""
    process_attribution_reason: str = ""
    #: B3 · the hash OF THE PROCESS IMAGE. Kept strictly separate from the
    #: file-content hashes below: "the exe that ran is known" and "the
    #: bytes that were written are known" are different facts, and the
    #: projection used to collapse them into one set of fields.
    process_hash_md5: str = ""
    process_hash_sha1: str = ""
    process_hash_sha256: str = ""
    # File
    file_path: str = ""
    file_name: str = ""
    file_action: str = ""
    file_size: str = ""
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
    #: B1 · canonical field name → the EXACT wire field that produced it,
    #: as the DSM recorded it. Provenance is part of the evidence: without
    #: it a preserved value cannot be traced to the source's own
    #: vocabulary, so it travels through the projection rather than being
    #: dropped at it.
    field_provenance: dict[str, str] = field(default_factory=dict)
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
    if f.name not in ("raw_event", "provenance", "field_provenance")
)


#: B3 · HASH STATE VOCABULARY. One place, so no module invents a fourth
#: value and no absence is read as a hash.
#:
#: PROCESS IMAGE HASH != FILE-CREATE HASH != FILE CONTENT IDENTITY.
#: A process-image SHA-256 says the executable that ran is known. It says
#: NOTHING about the bytes that process later wrote to disk.
HASH_OBSERVED = "HASH_OBSERVED"
HASH_NOT_OBSERVED = "HASH_NOT_OBSERVED"
#: There is no file and no process image on this observation at all (a
#: logon, a registry set). Absence of a hash here is not a gap.
HASH_NOT_APPLICABLE = "HASH_NOT_APPLICABLE"
HASH_STATES = (HASH_OBSERVED, HASH_NOT_OBSERVED, HASH_NOT_APPLICABLE)


# ─── CES → CEM v1 mapping ────────────────────────────────────────────
# Both Sysmon and Win-Sec Event IDs collapse into the CEM v1 kind enum.
# This is the ONE place event-id semantics live. Every normalizer just
# fills CES; kind resolution happens here.
SYSMON_KIND: dict[int, str] = {
    1: "process_create",
    # FileCreateTime: a process CHANGED a file's creation time. Calling
    # that a write misstates what happened — and timestomping evidence is
    # exactly the thing a behavioural engine will want to see as itself.
    2: "file_creation_time_changed",
    3: "network_connect",
    # Sysmon's own SERVICE STATE changed. This is sensor lifecycle
    # telemetry about Sysmon, not the exit of an observed process; mapping
    # it to `process_exit` invented a process death that never happened.
    4: "sensor_service_state_changed",
    5: "process_exit",
    6: "driver_load",
    7: "image_load",
    8: "remote_thread_create",
    # RawAccessRead: a raw read of a DISK/volume device, bypassing the
    # file system. It is not a file write in either direction.
    9: "raw_disk_access_read",
    10: "process_access",
    11: "file_create",
    12: "registry_create",
    13: "registry_value_set",
    # RegistryRename. The key still exists under a new name; `registry_delete`
    # claimed a deletion the source never reported.
    14: "registry_rename",
    15: "file_create",              # FileCreateStreamHash
    17: "named_pipe_create",
    18: "named_pipe_create",
    19: "wmi_subscribe",
    20: "wmi_subscribe",
    21: "wmi_subscribe",
    22: "dns_query",
    23: "file_delete",
    # ClipboardChange has no file and no path. It was resolving to
    # `file_write`, which is a different subsystem entirely.
    24: "clipboard_change",
    # ProcessTampering: Sysmon observed the process image being modified
    # (hollowing / herpaderping shape). It is stronger than a handle open,
    # so `process_access` understated it — but it is still an OBSERVATION.
    25: "process_image_tampering",
    26: "file_delete",
    # Sysmon reporting its OWN error. `alert` made the sensor's self-report
    # a NivXForge security claim; a NivXForge alert comes from an
    # authoritative detection mechanism, never from a sensor hiccup.
    255: "sensor_error",
}

#: WINDOWS SECURITY · OBSERVATIONS, NOT CONCLUSIONS.
#:
#: `event.kind` states WHAT WAS OBSERVED. A detection is what a detection
#: engine CONCLUDED, a compromise is what an authoritative correlation /
#: IOC mechanism concluded, and a response state is what response actually
#: did. `kind` is not a shortcut for "Windows emitted an interesting
#: event", so no Event ID in this table may resolve to a security claim.
#:
#: 4720 / 4732 / 4738 used to map to `detection` — an account creation, a
#: group-membership change and an account change were therefore presented
#: as detections simply because Windows logged them. They are now the
#: facts they are; whether any of them is suspicious depends on the target
#: group, the actor, the host, the time and correlated activity, and that
#: judgement belongs to an engine with its own evidence and authority.
#:
#: Names are REUSED from the project's existing Windows Security
#: vocabulary (`detection_content/telemetry/windows_security_dsm.py`
#: `event_type`) so no duplicate vocabulary is introduced.
WINSEC_KIND: dict[int, str] = {
    4624: "logon_success",              # the ID itself states success
    4625: "logon_failure",              # the ID itself states failure
    4634: "logoff",                     # an account was logged OFF
    4672: "special_privileges_assigned",  # NOT privilege escalation
    4688: "process_create",
    #: B2 · process TERMINATION, stated by the source. Lifetime semantics
    #: need a termination EVENT: without one the lifetime is UNKNOWN, and
    #: `last_seen` must never be read as an exit. 4689 was absent from
    #: this table, so a collected termination could not be recognised as
    #: one — it fell through to `unclassified_telemetry`.
    4689: "process_exit",
    4697: "service_install",
    4698: "scheduled_task_create",
    4700: "scheduled_task_enabled",     # enabled, not created
    4720: "user_account_created",       # was: detection
    4732: "security_group_member_added",  # was: detection
    4738: "user_account_changed",       # was: detection
    4776: "credential_validation",      # NTLM; outcome is in Status, not the ID
    5140: "smb_share_access",
    5145: "smb_share_access",
    5156: "network_connect",            # Windows Filtering Platform
    7045: "service_install",            # System channel
    1102: "audit_log_cleared",          # was: alert
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


#: Kinds that are a POSITIVE SECURITY CLAIM. Absence of classification is
#: evidence for neither maliciousness nor benignness, so no unknown,
#: unclassified, unsupported, missing, malformed or unparseable input may
#: ever resolve to one of these. Read by the regression invariant.
SECURITY_CLAIM_KINDS: frozenset[str] = frozenset({
    "detection", "malicious", "ioc", "compromise", "clean", "benign",
    "blocked", "contained", "verified", "alert",
})

#: The honest kind for telemetry we received but could not classify.
UNCLASSIFIED = "unclassified_telemetry"


def event_id_int(value: Any) -> int | None:
    """The authoritative Windows / Sysmon Event ID as an int, or None.

    `12` and `"12"` are the SAME identifier in two representations, so
    both resolve — that conversion is deterministic and lossless. Anything
    else (a bool, a float, `"12abc"`, `"0x0c"`, `""`, `None`) is REFUSED
    rather than coerced, because a guessed Event ID is a guessed event
    meaning and the guess would then be presented as source truth.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if text.isdigit():
            return int(text)
    return None


def resolve_kind(ces: CanonicalEventRecord) -> tuple[str, str]:
    """`(kind, basis)` — the kind AND how it was arrived at.

    The basis travels with the evidence so a consumer can tell an
    authoritative source-stated classification from one we derived from
    the fields that happened to be populated, and both from an honest
    failure to classify.
    """
    prov = (ces.provider or "").lower()
    eid = event_id_int(ces.event_id)
    if "sysmon" in prov and eid is not None:
        kind = SYSMON_KIND.get(eid)
        if kind:
            return kind, f"SOURCE_EVENT_ID:sysmon:{eid}"
        return UNCLASSIFIED, f"EVENT_ID_NOT_SUPPORTED:sysmon:{eid}"
    if ("security-auditing" in prov
            or "microsoft-windows-security" in prov) and eid is not None:
        kind = WINSEC_KIND.get(eid)
        if kind:
            return kind, f"SOURCE_EVENT_ID:winsec:{eid}"
        return UNCLASSIFIED, f"EVENT_ID_NOT_SUPPORTED:winsec:{eid}"
    # Derived from the fields the source actually populated. This is a
    # weaker claim than a source-stated Event ID and says so.
    if ces.dns_query:
        return "dns_query", "DERIVED_FROM_OBSERVED_FIELDS:dns_query"
    if ces.dst_ip or ces.src_ip:
        return "network_connect", "DERIVED_FROM_OBSERVED_FIELDS:ip_endpoint"
    if ces.registry_key:
        return (("registry_value_set",
                 "DERIVED_FROM_OBSERVED_FIELDS:registry_key+registry_value")
                if ces.registry_value else
                ("registry_create",
                 "DERIVED_FROM_OBSERVED_FIELDS:registry_key"))
    if ces.file_path and ces.image:
        return "file_write", "DERIVED_FROM_OBSERVED_FIELDS:file_path+image"
    if ces.file_path:
        return "file_write", "DERIVED_FROM_OBSERVED_FIELDS:file_path"
    if ces.image and ces.command_line:
        return ("process_create",
                "DERIVED_FROM_OBSERVED_FIELDS:image+command_line")
    #: A KIND IS NOT A VERDICT. `detection` was the catch-all default here,
    #: so any observation this classifier could not place — on the real
    #: Windows corpus, 3120 Sysmon events whose Event ID never reached the
    #: CES — was stamped as a detection and then drew compromise markers it
    #: had no evidence for. An unplaced observation is telemetry we failed
    #: to classify; it is never a detection claim.
    return UNCLASSIFIED, "UNCLASSIFIED_INSUFFICIENT_EVIDENCE"


def _resolve_kind(ces: CanonicalEventRecord) -> str:
    """Deterministic CES → CEM event kind. One classifier, one basis."""
    return resolve_kind(ces)[0]


#: OBSERVATION IDENTITY vs CONTENT IDENTITY.
#:
#: `event.iid` is a CONTENT hash and keeps that meaning unchanged: it
#: answers "is this the same observed activity". It is NOT an observation
#: identity — on the real Windows corpus 2,250 of 3,299 genuinely distinct
#: records hash identically, because a registry value set twice in the
#: same millisecond by the same image on the same key IS identical content.
#:
#: `observation_id` answers a different question: "WHICH recorded
#: observation is this one". A compromise that names
#: `contributing_event_refs[]` must be able to point at one specific
#: record, so it is derived from AUTHORITATIVE SOURCE IDENTITY and never
#: from content alone.
OBS_ID_BY_SOURCE_RECORD = "UNIQUE_BY_SOURCE_RECORD_IDENTITY"
OBS_ID_BY_RAW_EVIDENCE = "UNIQUE_BY_RAW_EVIDENCE_IDENTITY"
OBS_ID_NOT_PROVEN = "NOT_PROVEN_UNIQUE"


def observation_identity(event: dict[str, Any], *, tenant_id: str
                         ) -> tuple[str, str, str]:
    """`(observation_id, identity_state, identity_key)` for one observation.

    Deterministic and idempotent: replaying the SAME source record always
    yields the same id, and two distinct records with identical content
    yield different ids because the discriminator is the source's own
    record identity, not the content.

    When the source carried no unique identity the state is
    `NOT_PROVEN_UNIQUE` and the id is explicitly NOT claimed to be unique
    — nothing is invented to manufacture uniqueness, and a contributor
    reference must refuse to target such an observation.
    """
    raw = event.get("raw") or {}
    ident = raw.get("source_identity") or {}
    device_iid = event.get("device_iid") or ""
    scope = f"{tenant_id}|{device_iid}"

    # A Windows record's EventRecordID is unique per channel per computer,
    # which is exactly the discriminator the content hash lacks.
    record_id = ident.get("record_id")
    computer = ident.get("computer") or ""
    if record_id not in (None, "") and computer:
        key = "|".join([scope, str(ident.get("provider") or ""),
                        str(ident.get("channel") or ""), str(computer),
                        str(record_id)])
        return _blake_iid("obs", key), OBS_ID_BY_SOURCE_RECORD, key

    # The retained raw evidence row id. Deliberately NOT
    # `canonical_event_id`: the normalizers mint that with a fresh uuid4
    # per pass, so it changes on replay and cannot be an identity.
    ref = raw.get("raw_evidence_ref") or {}
    raw_id = ref.get("raw_id")
    if raw_id:
        key = f"{scope}|{ref.get('collection') or ''}|{raw_id}"
        return _blake_iid("obs", key), OBS_ID_BY_RAW_EVIDENCE, key

    key = f"{scope}|{event.get('iid') or ''}|{event.get('sequence') or 0}"
    return _blake_iid("obs", key), OBS_ID_NOT_PROVEN, key


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
        # B3 · the FILE-CONTENT hash, and ONLY that. The process-image
        # hash is not promoted here: a file does not acquire a content
        # identity because the process that wrote it has one.
        file_hashes = {k: v for k, v in (("md5", ces.file_hash_md5),
                                         ("sha1", ces.file_hash_sha1),
                                         ("sha256", ces.file_hash_sha256))
                       if v}
        artefacts.setdefault("file", []).append({
            "iid": fid, "path": ces.file_path,
            "name": ces.file_name or _basename(ces.file_path),
            "sha256": ces.file_hash_sha256 or "",
            "hashes": file_hashes,
            "hash_state": HASH_OBSERVED if file_hashes else HASH_NOT_OBSERVED,
            "size": ces.file_size or None,
            "action": ces.file_action or None,
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

    kind, kind_basis = resolve_kind(ces)
    prov = (ces.provenance.to_dict() if ces.provenance else {})
    prov["adapter"] = prov.get("normalizer") or "ingestion"
    # HOW this kind was arrived at travels with the evidence: an
    # authoritative source-stated Event ID, a weaker derivation from the
    # fields that happened to be populated, or an honest failure to
    # classify. Without it a consumer cannot tell them apart.
    prov["kind_basis"] = kind_basis
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
            # Real observed identifiers. They were being dropped here, so
            # ancestry could be linked but never shown: an analyst could
            # see the tree without seeing which pid was which.
            "pid":           ces.process_id or None,
            "ppid":          ces.parent_process_id or None,
            "image_path":    ces.image or None,
            # ── B1 · SECURITY-SEMANTIC FIELDS THAT USED TO DIE HERE ────
            # Every one of these exists in canonical evidence and was
            # being dropped by this projection, so a consumer could not
            # tell a renamed binary from its real name, could not read the
            # source's own process identity, and could not see a hash the
            # sensor actually reported.
            "process_guid":        ces.process_guid or None,
            "parent_process_guid": ces.parent_process_guid or None,
            "original_file_name":  ces.original_file_name or None,
            "parent_image_path":   ces.parent_image or None,
            "parent_command_line": ces.parent_command_line or None,
            "process_start_time":  ces.process_start_time or None,
            "process_attribution_state": ces.process_attribution_state or None,
            "process_attribution_reason": (ces.process_attribution_reason
                                           or None),
            "current_directory":   ces.current_directory or None,
            "integrity_level":     ces.integrity_level or None,
            # B3 · the hash OF THE IMAGE THAT RAN. Never merged with the
            # file-content hash block below.
            "process_image_hashes": {k: v for k, v in (
                ("md5", ces.process_hash_md5),
                ("sha1", ces.process_hash_sha1),
                ("sha256", ces.process_hash_sha256)) if v},
            "process_image_hash_state": (
                HASH_OBSERVED if (ces.process_hash_sha256
                                  or ces.process_hash_md5
                                  or ces.process_hash_sha1)
                else (HASH_NOT_OBSERVED if (ces.image or ces.process_guid)
                      else HASH_NOT_APPLICABLE)),
            # B3 · the file this observation is ABOUT, and whether its
            # CONTENT is identified. `HASH_NOT_OBSERVED` is a fact, not a
            # gap to be filled from somewhere else.
            "file": ({k: v for k, v in (
                ("path", ces.file_path or None),
                ("name", ces.file_name or _basename(ces.file_path) or None),
                ("action", ces.file_action or None),
                ("size", ces.file_size or None),
            ) if v} | {
                "hashes": {k: v for k, v in (
                    ("md5", ces.file_hash_md5), ("sha1", ces.file_hash_sha1),
                    ("sha256", ces.file_hash_sha256)) if v},
                "hash_state": (HASH_OBSERVED if (ces.file_hash_sha256
                                                 or ces.file_hash_md5
                                                 or ces.file_hash_sha1)
                               else HASH_NOT_OBSERVED),
            }) if ces.file_path else None,
            # B1 · which wire field produced which canonical field.
            "field_provenance": dict(ces.field_provenance or {}) or None,
            # Named explicitly so a lane can key on the evidence class it
            # actually is. `target` collapses five different things into
            # one string and cannot tell a registry key from a file path.
            "registry_key":  ces.registry_key or None,
            "registry_value":ces.registry_data or None,
            "dns_query":     ces.dns_query or None,
            "dns_answer":    ces.dns_answer or None,
            "logon_type":    ces.logon_type or None,
            "sid":           ces.sid or None,
            # WHERE this observation came from, preserved so the canonical
            # projection stays traceable to the exact source record, and
            # the Windows evidence blocks the source actually wrote. These
            # were being assembled and then dropped, so a registry / DNS /
            # authentication / account observation reached the store with
            # its own source detail missing.
            "source_identity": {
                **{k: v for k, v in (
                    ("provider", ces.provider or None),
                    ("channel", ces.channel or None),
                    ("event_id", event_id_int(ces.event_id)),
                    ("computer", ces.computer or None),
                    ("source_time", ces.timestamp or None),
                ) if v not in (None, "")},
                **((ces.raw_event or {}).get("source_identity") or {}),
            },
            **{block: (ces.raw_event or {})[block]
               for block in ("registry", "dns", "authentication", "winlog",
                             "account_context", "raw_evidence_ref")
               if (ces.raw_event or {}).get(block)},
            "sha256":        hashlib.sha256(evt_key.encode()).hexdigest(),
            # B1 · the SAME value under an unambiguous name. `raw.sha256`
            # is the CONTENT-IDENTITY digest of this observation's own
            # fields — it is NOT a file hash and NOT a process-image hash,
            # and a consumer that reads it as one is reading a fabricated
            # hash. The honest name is kept alongside the historical one.
            "content_digest_sha256": hashlib.sha256(
                evt_key.encode()).hexdigest(),
        },
        "process": {
            "name":       _basename(ces.image),
            "image":      ces.image,
            "iid":        process_iid,
            "parent_iid": parent_iid or None,
            "parent_name":_basename(ces.parent_image),
            # B1/B2 · the SOURCE's own process identity travels with the
            # process block. `iid` is ours and is derived; `guid` is the
            # source's and is authoritative where it exists.
            "guid":              ces.process_guid or None,
            "parent_guid":       ces.parent_process_guid or None,
            "pid":               ces.process_id or None,
            "ppid":              ces.parent_process_id or None,
            "parent_image":      ces.parent_image or None,
            "original_file_name": ces.original_file_name or None,
            "command_line":      ces.command_line or None,
            "parent_command_line": ces.parent_command_line or None,
            "start_time":        ces.process_start_time or None,
            "attribution_state": ces.process_attribution_state or None,
            "image_hashes": {k: v for k, v in (
                ("md5", ces.process_hash_md5),
                ("sha1", ces.process_hash_sha1),
                ("sha256", ces.process_hash_sha256)) if v},
        } if (ces.image or process_iid) else {},
        "trust":       {},
        "provenance":  prov,
    }
