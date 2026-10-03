"""§d normalized evidence row  ->  `edr_behavior.contracts.EvidenceRecord`.

A MAPPING, not an ingestion path. The row handed in has already been read,
resolved and tenant-scoped by E1; this module adds no store, no resolver, no
clock and no inference. It imports the E3 CONTRACT TYPES only — never the
matcher, engine, rules, provider or store — so converting evidence cannot start
the Behavior runtime.

Authority rules enforced here, by construction:

* `tenant_id` and `endpoint_id` arrive from E1's RESOLVED identity. They are
  never read out of the row and never out of a request header. The row's own
  tenant is compared against the resolved one and a disagreement fails closed.
* `endpoint_id` is the platform-minted `ep_…`. The row's `device_id` is an
  ADDRESSING alias (device_iid / collector_id / computer) and may legitimately
  be a substituted hostname, so it is never promoted to an identity.
* event time is the STORED OBSERVATION time, at the highest precision the row
  carries (`observed_us`, else `observed_ms`). `ingested_ms` is read for
  provenance only and can never order or identify evidence.
* a parent process is carried only when the evidence itself states one. No PID
  reuse guess, no time-proximity guess, no lineage inference.
* anything required and missing returns None with a stated reason. A partial
  EvidenceRecord is never fabricated.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from edr_behavior.contracts import (EVIDENCE_KINDS, KIND_AUTH, KIND_DETECTION,
                                    KIND_DNS, KIND_FILE, KIND_NETWORK,
                                    KIND_PROCESS, KIND_PROCESS_TERMINATION,
                                    KIND_REGISTRY, STORE_SHADOW_OBSERVATION,
                                    STORE_UNSPECIFIED, STORE_XDR_CANONICAL,
                                    EvidenceRecord, EvidenceRef, ProcessRef)

#: §d activity family  ->  Behavior evidence kind. Only families the Behavior
#: contract already declares are mapped; anything else is refused rather than
#: squeezed into a kind whose predicates would then mean something untrue.
KIND_MAP: Dict[str, str] = {
    "PROCESS_START": KIND_PROCESS,
    "PROCESS_END": KIND_PROCESS_TERMINATION,
    "FILE_CREATE": KIND_FILE,
    "FILE_WRITE": KIND_FILE,
    "FILE_DELETE": KIND_FILE,
    "FILE_MOVE": KIND_FILE,
    "FILE_EXECUTE": KIND_FILE,
    "NETWORK_CONNECT": KIND_NETWORK,
    "DNS_QUERY": KIND_DNS,
    "REGISTRY_SET": KIND_REGISTRY,
    "AUTH": KIND_AUTH,
    "DETECTION": KIND_DETECTION,
}

#: §d store name  ->  the E3 EvidenceRef store tag.
STORE_TAG: Dict[str, str] = {
    "v2_shadow_observations": STORE_SHADOW_OBSERVATION,
    "xdr_canonical_evidence": STORE_XDR_CANONICAL,
}

REFUSED_NO_TENANT = "NO_RESOLVED_TENANT"
REFUSED_TENANT_CONFLICT = "ROW_TENANT_DISAGREES_WITH_RESOLVED_TENANT"
REFUSED_NO_ENDPOINT = "NO_RESOLVED_ENDPOINT_ID"
REFUSED_NO_TIME = "NO_STORED_OBSERVATION_TIME"
REFUSED_KIND = "ACTIVITY_FAMILY_NOT_SUPPORTED_BY_BEHAVIOR_CONTRACT"
REFUSED_NO_RAW_REF = "NO_DURABLE_RAW_EVIDENCE_REFERENCE"
REFUSED_FIELD_SHAPE = "SOURCE_FIELD_STRUCTURALLY_INCOMPATIBLE"
REFUSED_FIELD_COLLISION = "SOURCE_FIELDS_COLLIDE_ON_ONE_CANONICAL_PATH"

#: Owner decision E14. Exactly one non-conversion reason is OUT_OF_SCOPE: the
#: §d row is valid evidence, but its activity family is outside the current
#: Behavior EvidenceRecord contract. The row stays in §d untouched, no
#: EvidenceRecord is manufactured, and it is NOT an adapter defect.
OUT_OF_SCOPE_REASONS = frozenset({REFUSED_KIND})

#: Every other non-conversion reason is an evidence-integrity, identity,
#: tenancy, timestamp or schema DEFECT and stays fail-closed (E8).
DEFECT_REASONS = frozenset({
    REFUSED_NO_TENANT, REFUSED_TENANT_CONFLICT, REFUSED_NO_ENDPOINT,
    REFUSED_NO_TIME, REFUSED_NO_RAW_REF, REFUSED_FIELD_SHAPE,
    REFUSED_FIELD_COLLISION,
})


def is_out_of_scope(reason: Optional[str]) -> bool:
    """True only for the explicitly named unsupported-activity-family reason.
    Any unknown or new reason is treated as a defect, never as out of scope."""
    return reason in OUT_OF_SCOPE_REASONS

#: The §d row containers this adapter reads. Each must be an object when
#: present: a scalar where the evidence contract says object is a source defect,
#: not something to coerce.
CONTAINERS = ("process", "parent", "file", "network", "detection")


class _FieldCollision(Exception):
    pass


def _base(p: Optional[str]) -> Optional[str]:
    """Basename, exactly as `edr_behavior.normalize` derives `process.name`."""
    return p.replace("\\", "/").rsplit("/", 1)[-1] if p else None


def _put(tree: Dict[str, Any], path: str, value: Any) -> None:
    """Place one leaf on the canonical path. Absent stays absent, and two source
    fields may never silently overwrite one canonical path."""
    if value is None or value == "" or value == [] or value == {}:
        return
    parts = path.split(".")
    node = tree
    for part in parts[:-1]:
        nxt = node.setdefault(part, {})
        if not isinstance(nxt, dict):
            raise _FieldCollision(path)
        node = nxt
    leaf = parts[-1]
    if leaf in node and node[leaf] != value:
        raise _FieldCollision(path)
    node[leaf] = value


def _s(v: Any) -> Optional[str]:
    if v is None:
        return None
    s = str(v).strip()
    return s or None


def _event_time(row: Dict[str, Any]) -> Optional[datetime]:
    """Stored observation time, full precision first. Never ingest time."""
    us = row.get("observed_us")
    if isinstance(us, int):
        return datetime.fromtimestamp(us / 1_000_000, tz=timezone.utc)
    ms = row.get("observed_ms")
    if isinstance(ms, int):
        return datetime.fromtimestamp(ms / 1_000, tz=timezone.utc)
    return None


def _process_ref(row: Dict[str, Any]) -> Optional[ProcessRef]:
    """Process identity from stated evidence only.

    A parent is carried when the evidence names one (GUID or PID as the sensor
    reported it). Nothing is inferred: no PID-reuse resolution, no
    time-proximity parenting, no synthesised GUID.
    """
    p = row.get("process") or {}
    par = row.get("parent") or {}
    present = {"process_iid": _s(row.get("process_key")),
               "pid": _s(p.get("pid")),
               "process_guid": _s(p.get("guid")),
               "parent_pid": _s(par.get("pid")),
               "parent_process_guid": _s(par.get("guid")),
               "start_time": _s(p.get("start_time")),
               "attribution_state": _s(row.get("process_identity"))}
    if not any(present.values()):
        return None
    return ProcessRef(**present)


def _fields(row: Dict[str, Any], kind: str) -> Dict[str, Any]:
    """The CANONICAL nested Behavior field namespace.

    This is not a schema choice made here: it is the namespace
    `edr_behavior.normalize` already produces, `predicates.FIELD_PREFIXES`
    already permits, and the shipped rules already address
    (`process.name`, `process.command_line`, `process.executable_path`,
    `process.signer`, `file.path`, `file.operation`, `registry.key`,
    `network.dest_ip`, `network.dest_hostname`, `dns.query_name`). A flat key
    such as `image` is unreachable by any valid predicate, which is why the
    earlier representation silently evaluated nothing.

    Only what the §d row actually carries is mapped. Nothing is invented: the §d
    row has no registry, auth, signer, integrity-level, current-directory or DNS
    answer data, so those canonical paths stay ABSENT rather than empty.
    """
    p = row.get("process") or {}
    par = row.get("parent") or {}
    f = row.get("file") or {}
    n = row.get("network") or {}
    image, parent_image = _s(p.get("image")), _s(par.get("image"))
    path = _s(f.get("path"))
    tree: Dict[str, Any] = {}
    _put(tree, "process.executable_path", image)
    _put(tree, "process.name", _base(image))
    _put(tree, "process.command_line", p.get("command_line"))
    _put(tree, "process.sha256", p.get("sha256"))
    _put(tree, "parent.executable_path", parent_image)
    _put(tree, "parent.name", _base(parent_image))
    # §d carries the acting user on the process object; canonically it is
    # identity, exactly as the normalizer emits `user.name`.
    _put(tree, "user.name", p.get("user"))
    _put(tree, "file.path", path)
    _put(tree, "file.name", _base(path))
    _put(tree, "file.previous_path", _s(f.get("prev_path")))
    _put(tree, "file.operation", f.get("operation"))
    _put(tree, "file.sha256", f.get("sha256"))
    _put(tree, "network.dest_ip", n.get("dest_ip"))
    _put(tree, "network.dest_port", n.get("dest_port"))
    _put(tree, "network.src_ip", n.get("src_ip"))
    _put(tree, "network.protocol", n.get("protocol"))
    _put(tree, "network.initiated", n.get("initiated"))
    # §d keeps the DNS question on the network object; its canonical home is
    # `dns.query_name`. Same datum, canonical name — not a new field.
    _put(tree, "dns.query_name", n.get("query"))
    if kind == KIND_DETECTION:
        _put(tree, "detection", row.get("detection"))
    return {k: v for k, v in tree.items() if v not in (None, "", [], {})}


def _tuple(row: Dict[str, Any], key: str) -> Tuple[str, ...]:
    v = row.get(key)
    if isinstance(v, (list, tuple)):
        return tuple(str(x) for x in v)
    return ()


def to_evidence_record(row: Dict[str, Any], *, tenant_id: Optional[str],
                       endpoint_id: Optional[str],
                       raw_id: Optional[str] = None
                       ) -> Tuple[Optional[EvidenceRecord], Optional[str]]:
    """Convert ONE §d row. Returns `(record, None)` or `(None, reason)`.

    Pure: no DB, no network, no resolver, no clock-derived evidence field, no
    engine call, and the input row is not mutated.
    """
    tenant = _s(tenant_id)
    if not tenant:
        return None, REFUSED_NO_TENANT
    row_tenant = _s(row.get("tenant_id"))
    if row_tenant and row_tenant != tenant:
        return None, REFUSED_TENANT_CONFLICT
    endpoint = _s(endpoint_id)
    if not endpoint:
        return None, REFUSED_NO_ENDPOINT

    kind = KIND_MAP.get(str(row.get("kind") or ""))
    if kind not in EVIDENCE_KINDS:
        return None, REFUSED_KIND

    for name in CONTAINERS:
        value = row.get(name)
        if value is not None and not isinstance(value, dict):
            return None, REFUSED_FIELD_SHAPE
    try:
        fields = _fields(row, kind)
    except _FieldCollision:
        return None, REFUSED_FIELD_COLLISION

    when = _event_time(row)
    if when is None:
        return None, REFUSED_NO_TIME

    prov = dict(row.get("provenance") or {})
    store = STORE_TAG.get(str(prov.get("store") or ""), STORE_UNSPECIFIED)
    ref_value = _s(prov.get("ref"))
    activity_identity = _s(row.get("event_id"))

    # The durable raw-event pointer now travels on the §d row itself
    # (provenance.raw_ref). The explicit argument stays as an override for a
    # caller that already holds the raw id; neither is ever substituted from
    # another identifier.
    raw = _s(raw_id) or _s(prov.get("raw_ref"))
    if not raw:
        return None, REFUSED_NO_RAW_REF

    ref = EvidenceRef(
        tenant_id=tenant,
        raw_id=raw,
        canonical_event_id=ref_value if store == STORE_XDR_CANONICAL else None,
        generation=None,
        store=store,
        record_id=ref_value if store == STORE_SHADOW_OBSERVATION else None,
        sub_key=activity_identity)

    return EvidenceRecord(
        tenant_id=tenant,
        endpoint_id=endpoint,
        kind=kind,
        event_time=when,
        ref=ref,
        fields=fields,
        process=_process_ref(row),
        source=str(prov.get("store") or ""),
        not_observed=_tuple(row, "not_observed"),
        not_supported=_tuple(row, "not_supported"),
        truncated_fields=_tuple(row, "truncated_fields"),
        provenance={**prov,
                    "evidence_stores": list(row.get("sources") or []),
                    "observation_time_authority": "STORED_OBSERVATION_TIME",
                    "ingested_at": row.get("ingested_at"),
                    # §d's own activity family and severity are provenance, not
                    # evidence fields: no predicate can address them, so keeping
                    # them in `fields` would be a second, unreachable namespace.
                    "sd_severity": row.get("severity"),
                    "sd_activity_family": row.get("kind")}), None
