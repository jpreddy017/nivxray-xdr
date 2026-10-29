"""Store-independent EvidenceProvider: read-only adapters for v2_shadow_observations and
xdr_canonical_evidence. Neither store is selected as authority here (E1 decision).

A "collection" is anything with async `find(filter, projection)` returning an async iterator
(motor collection or a test double). No adapter writes, updates or deletes.
"""
from __future__ import annotations

from collections.abc import AsyncIterator, Sequence
from typing import Any, Protocol

from .contracts import event, iso, parse_instant, require_tenant
from .identity import (dedupe, fallback_event_id, identity_keys,
                       process_key)

STORE_SHADOW = "v2_shadow_observations"
STORE_CANONICAL = "xdr_canonical_evidence"

_FILE_OPS = {"create": "FILE_CREATE", "write": "FILE_WRITE", "modify": "FILE_WRITE", "delete": "FILE_DELETE",
             "rename": "FILE_MOVE", "move": "FILE_MOVE", "execute": "FILE_EXECUTE"}
_SEV = ("NONE", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")


#: The source's OWN authentication class token -> activity family.
#: This vocabulary is the authoritative one already used by the top-level window
#: projection (`edr_plane.trajectory_window._AUTH_KINDS`); it is repeated here so §d
#: classifies an authentication record the same way the rest of the platform does
#: instead of collapsing it into OTHER.
_AUTH_FAMILY = {"logon_success": "AUTH_LOGON_SUCCESS",
                "logon_failure": "AUTH_LOGON_FAILURE",
                "logon_failed": "AUTH_LOGON_FAILURE",
                "logon": "AUTH_LOGON",
                "logoff": "AUTH_LOGOFF",
                "credential_validation": "AUTH_CREDENTIAL_VALIDATION"}

#: The source's own class token -> activity family, for every family §d renders.
#: `activity_type`/`operation` is NOT written by the Windows sensor path (it carries only
#: `AUTHENTICATION`, `PROCESS`, `FILE`, ... on canonical evidence and NOTHING on the shadow
#: observation), so the class token is the only statement of class many real records carry.
#: An execute flag is still not a process start, and an unlisted token is still OTHER.
_CLASS_FAMILY = {**_AUTH_FAMILY,
                 "process_create": "PROCESS_START", "process_start": "PROCESS_START",
                 "process_end": "PROCESS_END", "process_terminate": "PROCESS_END",
                 "process_exit": "PROCESS_END",
                 "file_create": "FILE_CREATE", "file_write": "FILE_WRITE",
                 "file_modify": "FILE_WRITE", "file_delete": "FILE_DELETE",
                 "file_rename": "FILE_MOVE", "file_move": "FILE_MOVE",
                 "file_execute": "FILE_EXECUTE",
                 "network_connect": "NETWORK_CONNECT",
                 "dns_query": "DNS_QUERY",
                 "registry_value_set": "REGISTRY_SET", "registry_create": "REGISTRY_SET",
                 "registry_delete": "REGISTRY_SET", "registry_rename": "REGISTRY_SET",
                 "detection": "DETECTION"}


def _kind(activity: str | None, op: str | None, event_class: str | None = None) -> str:
    """Activity family from the evidence.

    `event_class` is the class token the SOURCE states for this record
    (`xdr_canonical_evidence.event_type` / `v2_shadow_observations.event.kind`) — the same
    vocabulary the top-level window projection classifies from
    (`edr_plane.trajectory_window`). For AUTHENTICATION it is the only field that carries the
    outcome, so it is authoritative there: `activity_type` says only that an authentication
    record exists, never whether the sign-in succeeded. For every other family the
    `activity_type`/`operation` pair is used when the writer populated it, and the class token
    is the fallback for the records that carry no such pair.

    Nothing is promoted beyond what the source stated: an authentication record with no stated
    outcome, and any unlisted token, stay OTHER.
    """
    cls = str(event_class or "").strip().lower()
    fam = _AUTH_FAMILY.get(cls)
    if fam:
        return fam
    a, o = (activity or "").upper(), (op or "").lower()
    if a == "PROCESS":
        return "PROCESS_END" if o in ("end", "terminate", "termination", "exit") else "PROCESS_START"
    if a == "FILE":
        return _FILE_OPS.get(o, "FILE_WRITE")
    direct = {"NETWORK": "NETWORK_CONNECT", "DNS": "DNS_QUERY", "REGISTRY": "REGISTRY_SET",
              "DETECTION": "DETECTION"}.get(a)
    return direct or _CLASS_FAMILY.get(cls, "OTHER")


def _sev(v: Any) -> str:
    s = str(v or "NONE").upper()
    return s if s in _SEV else "NONE"


def _sha256(h: Any) -> str | None:
    if isinstance(h, dict):
        v = h.get("sha256") or h.get("SHA256")
        return v.lower() if isinstance(v, str) else None
    return None


def _str(v: Any) -> str | None:
    """A reference is a non-empty string or it is absent. Never coerced."""
    if v is None:
        return None
    s = str(v).strip()
    return s or None


def _raw_ref_canonical(doc: dict[str, Any]) -> str | None:
    """The durable `edr_raw_events` id this canonical evidence was derived from.

    `provenance.trace_id` is stamped with the raw id by the canonical bridge, and
    `raw_ref.raw_id` records the same durable pointer explicitly. Either is the real stored
    value; nothing else is accepted, and no identifier is substituted for it.
    """
    prov = doc.get("provenance") or {}
    rr = doc.get("raw_ref")
    return _str(prov.get("trace_id")) or (
        _str(rr.get("raw_id")) if isinstance(rr, dict) else None)


def _raw_ref_shadow(doc: dict[str, Any]) -> str | None:
    """Same durable raw id as carried on a shadow observation.

    The shadow writer stores it as `ingest_job_id` (taken from the canonical
    `provenance.trace_id`); some rows also carry an explicit `provenance.trace_id`. The
    observation id is NOT a fallback — it identifies the observation, not the raw delivery.
    """
    prov = doc.get("provenance") or {}
    return _str(doc.get("ingest_job_id")) or _str(prov.get("trace_id"))


def from_canonical(doc: dict[str, Any]) -> dict[str, Any]:
    af, p, f, n = (doc.get("additional_fields") or {}), (doc.get("process") or {}), (doc.get("file") or {}), \
        (doc.get("network") or {})
    host, prov = doc.get("host") or {}, doc.get("provenance") or {}
    tenant, device = doc.get("tenant_id"), prov.get("collector_id") or host.get("host_id") or host.get("hostname")
    ev = event(
        tenant_id=tenant, device_id=device,
        kind=_kind(af.get("activity_type"), af.get("operation"), doc.get("event_type")),
        observed_ms=parse_instant(doc.get("event_time")), ingested_ms=parse_instant(doc.get("ingest_time")),
        severity=_sev(af.get("severity")), boot_id=af.get("boot_id"),
        process={"pid": p.get("pid"), "guid": p.get("process_guid"), "start_time": p.get("start_time"),
                 "image": p.get("executable_path"), "command_line": p.get("command_line"),
                 "user": (doc.get("identity") or {}).get("username"), "sha256": _sha256(p.get("hashes"))},
        parent={"pid": p.get("parent_pid"), "guid": p.get("parent_process_guid"),
                "start_time": p.get("parent_start_time"), "image": p.get("parent_executable_path")},
        creator=dict(af.get("creator") or {}),
        file={"path": f.get("path"), "prev_path": f.get("previous_path"), "sha256": _sha256(f.get("hashes")),
              "operation": af.get("operation")} if f else {},
        network={"dest_ip": n.get("dest_ip"), "dest_port": n.get("dest_port"), "protocol": n.get("protocol"),
                 "src_ip": n.get("src_ip"), "initiated": n.get("initiated"), "query": (doc.get("dns") or {}).get("query")}
        if (n or doc.get("dns")) else {},
        authentication=dict(doc.get("authentication") or {}),
        detection=af.get("detection"), sources=[STORE_CANONICAL],
        provenance={"store": STORE_CANONICAL, "ref": doc.get("event_id"), "label": af.get("data_label"),
                    "raw_ref": _raw_ref_canonical(doc)})
    # The canonical event id is the identity the authenticated ingest boundary assigned to this
    # delivery; the shadow observation carries the SAME value as `canonical_event_id`. Both
    # stated identities travel so one activity collapses to one row across stores.
    ev["identity_keys"] = identity_keys(doc.get("event_id"), af.get("activity_identity"))
    ev["event_id"] = ev["identity_keys"][0][1] if ev["identity_keys"] \
        else fallback_event_id(tenant, device, ev)
    return ev


def from_shadow(doc: dict[str, Any]) -> dict[str, Any]:
    e = doc.get("event") or {}
    p, f, n = e.get("process") or {}, e.get("file") or {}, e.get("network") or {}
    r = e.get("raw") if isinstance(e.get("raw"), dict) else {}
    tenant, device = doc.get("tenant_id"), e.get("device_iid") or doc.get("collector_id") or e.get("computer")
    ev = event(
        tenant_id=tenant, device_id=device,
        kind=_kind(e.get("activity"), e.get("op"), e.get("kind") or doc.get("kind")),
        observed_ms=parse_instant(e.get("ts") or doc.get("captured_at")),
        ingested_ms=parse_instant(doc.get("ingest_time") or e.get("ingested_at")),
        severity=_sev(e.get("severity")), boot_id=e.get("boot_id"),
        process={"pid": p.get("pid"), "guid": p.get("guid") or doc.get("process_guid"),
                 "start_time": p.get("start_time"), "image": p.get("image"), "command_line": p.get("cmdline"),
                 "user": p.get("user"), "sha256": (p.get("sha256") or None)},
        parent={"pid": p.get("ppid"), "guid": p.get("parent_guid") or doc.get("parent_process_guid"),
                "start_time": p.get("parent_start_time"), "image": p.get("parent_image")},
        creator=dict(e.get("creator") or {}),
        file={"path": f.get("path"), "prev_path": f.get("prev_path"), "sha256": f.get("sha256"),
              "operation": e.get("op")} if f else {},
        network={"dest_ip": n.get("dest_ip"), "dest_port": n.get("dest_port"), "protocol": n.get("proto"),
                 "src_ip": n.get("src_ip"), "initiated": n.get("initiated"), "query": n.get("query")} if n else {},
        authentication=dict(r.get("authentication") or {}),
        detection=e.get("detection"), sources=[STORE_SHADOW],
        provenance={"store": STORE_SHADOW, "ref": doc.get("observation_id"), "label": e.get("data_label"),
                    # The DURABLE raw-event pointer the store already holds. Carried, never
                    # derived: the observation id identifies the observation, not the delivery,
                    # and substituting it would break the raw join.
                    "raw_ref": _raw_ref_shadow(doc)})
    ev["identity_keys"] = identity_keys(doc.get("canonical_event_id"), doc.get("activity_identity"))
    ev["event_id"] = ev["identity_keys"][0][1] if ev["identity_keys"] \
        else fallback_event_id(tenant, device, ev)
    return ev


def finalize(ev: dict[str, Any]) -> dict[str, Any]:
    ev["process_key"], ev["process_identity"] = process_key(ev["tenant_id"], ev["device_id"], ev["process"], ev["boot_id"])
    ev["parent_key"], ev["parent_identity"] = process_key(ev["tenant_id"], ev["device_id"], ev["parent"], ev["boot_id"]) \
        if ev["parent"] and any(ev["parent"].get(k) is not None for k in ("pid", "guid")) else (None, None)
    ev["observed_at"], ev["ingested_at"] = iso(ev["observed_ms"]), iso(ev["ingested_ms"])
    return ev


class EvidenceProvider(Protocol):
    async def events(self, tenant_id: str, device_id: str, t0_ms: int | None = None,
                     t1_ms: int | None = None) -> list[dict[str, Any]]: ...


class MongoStoreProvider:
    """Read-only adapter over one store. `device_fields` = the store's endpoint-keyed fields."""

    def __init__(self, collection: Any, store: str) -> None:
        self.c, self.store = collection, store
        self.normalize = from_shadow if store == STORE_SHADOW else from_canonical
        self.device_fields = (["event.device_iid", "collector_id", "event.computer"] if store == STORE_SHADOW
                              else ["provenance.collector_id", "host.host_id", "host.hostname"])

    async def events(self, tenant_id: str, device_id: str, t0_ms: int | None = None,
                     t1_ms: int | None = None) -> list[dict[str, Any]]:
        tenant = require_tenant(tenant_id)
        flt = {"tenant_id": tenant, "$or": [{f: device_id} for f in self.device_fields]}
        out: list[dict[str, Any]] = []
        cursor: AsyncIterator = self.c.find(flt, {"_id": 0})
        async for doc in cursor:
            ev = finalize(self.normalize(doc))
            if ev["tenant_id"] != tenant:            # defence in depth: never trust the filter alone
                continue
            t = ev["observed_ms"]
            if t is not None and ((t0_ms is not None and t < t0_ms) or (t1_ms is not None and t > t1_ms)):
                continue
            out.append(ev)
        return out


class MergedProvider:
    """Union of candidate stores with duplicate suppression by stable event identity."""

    def __init__(self, providers: Sequence[Any]) -> None:
        self.providers = list(providers)
        self.last_suppressed = 0

    async def events(self, tenant_id: str, device_id: str, t0_ms: int | None = None,
                     t1_ms: int | None = None) -> list[dict[str, Any]]:
        tenant = require_tenant(tenant_id)
        rows: list[dict[str, Any]] = []
        for p in self.providers:
            rows.extend(await p.events(tenant, device_id, t0_ms, t1_ms))
        merged, self.last_suppressed = dedupe(rows)
        return [finalize(e) for e in merged]


class ListCollection:
    """In-memory read-only collection double (fixtures/tests). Supports the filter shape used above."""

    def __init__(self, docs: Sequence[dict[str, Any]]) -> None:
        self._docs = list(docs)

    @staticmethod
    def _get(doc: dict[str, Any], path: str) -> Any:
        cur: Any = doc
        for part in path.split("."):
            cur = cur.get(part) if isinstance(cur, dict) else None
        return cur

    def _match(self, doc: dict[str, Any], flt: dict[str, Any]) -> bool:
        for k, v in flt.items():
            if k == "$or":
                if not any(self._match(doc, sub) for sub in v):
                    return False
            elif self._get(doc, k) != v:
                return False
        return True

    def find(self, flt: dict[str, Any], projection: dict[str, Any] | None = None):
        docs = [d for d in self._docs if self._match(d, flt)]

        async def gen():
            for d in docs:
                yield d
        return gen()
