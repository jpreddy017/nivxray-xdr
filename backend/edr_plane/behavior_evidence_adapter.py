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
    """Only keys the evidence actually holds. An absent field is OMITTED, so a
    predicate reads "not collected" instead of matching an empty string."""
    p = row.get("process") or {}
    f = row.get("file") or {}
    n = row.get("network") or {}
    candidates = {
        "activity_family": row.get("kind"),
        "severity": row.get("severity"),
        "image": p.get("image"),
        "command_line": p.get("command_line"),
        "user": p.get("user"),
        "process_sha256": p.get("sha256"),
        "parent_image": (row.get("parent") or {}).get("image"),
        "file_path": f.get("path"),
        "file_previous_path": f.get("prev_path"),
        "file_sha256": f.get("sha256"),
        "file_operation": f.get("operation"),
        "dest_ip": n.get("dest_ip"),
        "dest_port": n.get("dest_port"),
        "protocol": n.get("protocol"),
        "src_ip": n.get("src_ip"),
        "dns_query": n.get("query"),
    }
    out = {k: v for k, v in candidates.items() if v not in (None, "", [], {})}
    if kind == KIND_DETECTION and row.get("detection"):
        out["detection"] = row["detection"]
    return out


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
        fields=_fields(row, kind),
        process=_process_ref(row),
        source=str(prov.get("store") or ""),
        not_observed=_tuple(row, "not_observed"),
        not_supported=_tuple(row, "not_supported"),
        truncated_fields=_tuple(row, "truncated_fields"),
        provenance={**prov,
                    "evidence_stores": list(row.get("sources") or []),
                    "observation_time_authority": "STORED_OBSERVATION_TIME",
                    "ingested_at": row.get("ingested_at"),
                    "sd_activity_family": row.get("kind")}), None
