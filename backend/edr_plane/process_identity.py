"""B2 · PROCESS IDENTITY — the authoritative answer to "which process".

```
ProcessGuid / native process identity          ← preferred authority
        ↓
canonical process entity  (this module)
        ↓
endpoint + pid + start identity                ← supporting authority
        ↓
pid alone                                       ← CONTEXT, never identity
```

Three rules this module exists to enforce.

**A PID is not a process.** Windows and Linux both reuse a PID within
minutes. So a PID alone never mints an authoritative identity, and two
observations that share a PID but not a lifetime are two processes.

**Lineage is source-stated or it does not exist.** A parent is accepted
only when the SOURCE named it on the event itself. Timestamp proximity,
filename similarity, trajectory-row adjacency and PID coincidence outside
a valid identity scope are never parentage.

**A process is not dead until something said so.** `last_seen` is the
last time we HEARD about a process. Termination is an event
(Sysmon EID 5 / Security 4689). With no termination evidence the lifetime
is `PROCESS_LIFETIME_UNKNOWN` — never "exited", never "still running".
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

# ── identity authority ladder ────────────────────────────────────────
#: The source itself minted an identifier that is unique for the
#: process's whole lifetime (Sysmon/Windows `ProcessGuid`).
AUTHORITY_SOURCE_GUID = "SOURCE_PROCESS_GUID"
#: No native identifier, but endpoint + pid + process start time together
#: identify one lifetime and survive PID reuse.
AUTHORITY_ENDPOINT_PID_START = "ENDPOINT_PID_START_TIME"
#: A PID with no lifetime evidence. Usable as CONTEXT, never as identity.
AUTHORITY_PID_ONLY = "PID_ONLY_NOT_AUTHORITATIVE"
#: No process was resolved at all.
AUTHORITY_NOT_OBSERVED = "NOT_OBSERVED"

IDENTITY_AUTHORITIES = (AUTHORITY_SOURCE_GUID, AUTHORITY_ENDPOINT_PID_START,
                        AUTHORITY_PID_ONLY, AUTHORITY_NOT_OBSERVED)
#: The two authorities that may be used for ATTRIBUTION.
AUTHORITATIVE = (AUTHORITY_SOURCE_GUID, AUTHORITY_ENDPOINT_PID_START)

# ── lineage basis ────────────────────────────────────────────────────
PARENT_BY_SOURCE_GUID = "PARENT_STATED_BY_SOURCE_PROCESS_GUID"
PARENT_BY_SOURCE_PID = "PARENT_STATED_BY_SOURCE_PID_ONLY"
PARENT_NOT_OBSERVED = "PARENT_NOT_OBSERVED"
PARENT_KERNEL_BOUNDARY = "ROOT_KERNEL_BOUNDARY"

# ── lifetime semantics ───────────────────────────────────────────────
PROCESS_START_OBSERVED = "PROCESS_START_OBSERVED"
PROCESS_START_NOT_OBSERVED = "PROCESS_START_NOT_OBSERVED"
PROCESS_TERMINATION_OBSERVED = "PROCESS_TERMINATION_OBSERVED"
PROCESS_TERMINATION_NOT_OBSERVED = "PROCESS_TERMINATION_NOT_OBSERVED"
PROCESS_LIFETIME_UNKNOWN = "PROCESS_LIFETIME_UNKNOWN"

#: Kinds that are SOURCE-STATED process start / termination. Nothing else
#: may be read as either.
START_KINDS = frozenset({"process_create"})
TERMINATION_KINDS = frozenset({"process_exit", "process_terminate"})


def _s(v: Any) -> str:
    return "" if v is None else str(v).strip()


def _key(*parts: Any) -> str:
    joined = "\x1f".join(_s(p) for p in parts)
    return "pk_" + hashlib.sha256(joined.encode()).hexdigest()[:24]


@dataclass(frozen=True)
class ProcessView:
    """One observation's PROCESS evidence, as the source stated it.

    Deliberately flat and dialect-free: `from_canonical()` and
    `from_observation()` translate the two shapes this platform holds, and
    nothing else in this module knows about either.
    """
    tenant_id: str = ""
    endpoint_id: str = ""
    process_guid: str = ""
    pid: str = ""
    start_time: str = ""
    image: str = ""
    command_line: str = ""
    original_file_name: str = ""
    parent_process_guid: str = ""
    parent_pid: str = ""
    parent_image: str = ""
    parent_command_line: str = ""
    kind: str = ""
    observed_at: str = ""
    evidence_ref: str = ""
    field_provenance: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class ResolvedIdentity:
    """The identity, its authority, and WHY — always together."""
    process_key: Optional[str]
    authority: str
    reason: str
    tenant_id: str = ""
    endpoint_id: str = ""
    process_guid: str = ""
    pid: str = ""
    start_time: str = ""
    identity_basis: tuple[str, ...] = ()

    @property
    def is_authoritative(self) -> bool:
        return self.authority in AUTHORITATIVE


@dataclass(frozen=True)
class ResolvedParent:
    parent_key: Optional[str]
    basis: str
    reason: str
    parent_process_guid: str = ""
    parent_pid: str = ""
    parent_image: str = ""


# ── dialect adapters ─────────────────────────────────────────────────

def from_canonical(canonical: dict[str, Any], *, tenant_id: str = "",
                   endpoint_id: str = "",
                   evidence_ref: str = "") -> ProcessView:
    """Canonical evidence (the authority) → `ProcessView`."""
    proc = canonical.get("process") or {}
    extra = canonical.get("additional_fields") or {}
    return ProcessView(
        tenant_id=_s(tenant_id or canonical.get("tenant_id")),
        endpoint_id=_s(endpoint_id or extra.get("endpoint_id")
                       or (canonical.get("host") or {}).get("host_id")),
        process_guid=_s(proc.get("process_guid")),
        pid=_s(proc.get("pid")),
        start_time=_s(proc.get("start_time")),
        image=_s(proc.get("executable_path") or proc.get("name")),
        command_line=_s(proc.get("command_line")),
        original_file_name=_s(proc.get("original_file_name")),
        parent_process_guid=_s(proc.get("parent_process_guid")),
        parent_pid=_s(proc.get("parent_pid") if proc.get("parent_pid")
                      is not None else proc.get("ppid")),
        parent_image=_s(proc.get("parent_executable_path")
                        or proc.get("parent_name")),
        parent_command_line=_s(proc.get("parent_command_line")),
        kind=_s(canonical.get("event_type")
                or extra.get("activity_type")),
        observed_at=_s(canonical.get("event_time")),
        evidence_ref=_s(evidence_ref or canonical.get("event_id")),
        field_provenance=dict(proc.get("field_provenance") or {}),
    )


def from_observation(doc: dict[str, Any]) -> ProcessView:
    """A `v2_shadow_observations` document (the read model) → `ProcessView`.

    Reads the fields B1 made the projection preserve. It does not reach
    into the raw payload for anything the projection dropped — if a field
    is missing here that is a B1 defect, and hiding it behind a second
    reader would be a parallel authority.
    """
    ev = doc.get("event") or doc
    raw = ev.get("raw") or {}
    proc = ev.get("process") or {}
    return ProcessView(
        tenant_id=_s(doc.get("tenant_id")),
        endpoint_id=_s(doc.get("connector_id") or doc.get("collector_id")
                       or ev.get("device_iid")),
        process_guid=_s(doc.get("process_guid") or proc.get("guid")
                        or raw.get("process_guid")),
        pid=_s(raw.get("pid") or proc.get("pid")),
        start_time=_s(raw.get("process_start_time") or proc.get("start_time")),
        image=_s(proc.get("image") or raw.get("image_path")),
        command_line=_s(raw.get("command_line")),
        original_file_name=_s(raw.get("original_file_name")),
        parent_process_guid=_s(doc.get("parent_process_guid")
                               or proc.get("parent_guid")
                               or raw.get("parent_process_guid")),
        parent_pid=_s(raw.get("ppid") or proc.get("ppid")),
        parent_image=_s(raw.get("parent_image_path")
                        or proc.get("parent_image")),
        parent_command_line=_s(raw.get("parent_command_line")),
        kind=_s(ev.get("kind")),
        observed_at=_s(ev.get("ts") or doc.get("captured_at")),
        evidence_ref=_s(doc.get("observation_id")
                        or doc.get("canonical_event_id")),
        field_provenance=dict(raw.get("field_provenance") or {}),
    )


# ── identity resolution ──────────────────────────────────────────────

def resolve_identity(view: ProcessView) -> ResolvedIdentity:
    """The process identity for ONE observation, with its authority."""
    if view.process_guid:
        # A ProcessGuid is unique for one process lifetime on its host.
        # It is scoped by TENANT (never widened across tenants) and is NOT
        # downgraded when the endpoint scope is unknown — the guid already
        # carries the machine component the source minted it from.
        return ResolvedIdentity(
            process_key=_key("guid", view.tenant_id, view.process_guid),
            authority=AUTHORITY_SOURCE_GUID,
            reason=("the source stated a native process identity that is "
                    "unique for this process's lifetime, so it survives "
                    "PID reuse and process restart"),
            tenant_id=view.tenant_id, endpoint_id=view.endpoint_id,
            process_guid=view.process_guid, pid=view.pid,
            start_time=view.start_time,
            identity_basis=("tenant_id", "process_guid"))
    if view.pid and view.start_time and view.endpoint_id:
        return ResolvedIdentity(
            process_key=_key("eps", view.tenant_id, view.endpoint_id,
                             view.pid, view.start_time),
            authority=AUTHORITY_ENDPOINT_PID_START,
            reason=("no native process identity was stated, but endpoint + "
                    "pid + process start time together identify one "
                    "lifetime and survive PID reuse"),
            tenant_id=view.tenant_id, endpoint_id=view.endpoint_id,
            pid=view.pid, start_time=view.start_time,
            identity_basis=("tenant_id", "endpoint_id", "pid", "start_time"))
    if view.pid:
        missing = [n for n, v in (("endpoint_id", view.endpoint_id),
                                  ("start_time", view.start_time)) if not v]
        return ResolvedIdentity(
            process_key=None,
            authority=AUTHORITY_PID_ONLY,
            reason=("a PID is reused by the OS and is not a process "
                    "identity; this observation carries no " +
                    " and no ".join(missing) + ", so it is CONTEXT and must "
                    "never be used for attribution"),
            tenant_id=view.tenant_id, endpoint_id=view.endpoint_id,
            pid=view.pid, start_time=view.start_time,
            identity_basis=("pid",))
    return ResolvedIdentity(
        process_key=None, authority=AUTHORITY_NOT_OBSERVED,
        reason=("this observation named no process: neither a native "
                "process identity nor a PID was stated. Absence of a "
                "process here is a collection fact, not an absence of "
                "activity"),
        tenant_id=view.tenant_id, endpoint_id=view.endpoint_id)


def resolve_parent(view: ProcessView) -> ResolvedParent:
    """The PARENT identity — accepted only where the SOURCE stated it."""
    if view.parent_process_guid:
        return ResolvedParent(
            parent_key=_key("guid", view.tenant_id, view.parent_process_guid),
            basis=PARENT_BY_SOURCE_GUID,
            reason=("the source stated the parent's native process "
                    "identity on this event, so the relationship is the "
                    "source's own assertion and resolves to one lifetime"),
            parent_process_guid=view.parent_process_guid,
            parent_pid=view.parent_pid, parent_image=view.parent_image)
    if view.parent_pid in ("0", "4") and view.parent_pid:
        return ResolvedParent(
            parent_key=None, basis=PARENT_KERNEL_BOUNDARY,
            reason=("the stated parent is the kernel boundary; this is a "
                    "real root, not a missing parent and not an invented "
                    "one"),
            parent_pid=view.parent_pid, parent_image=view.parent_image)
    if view.parent_pid or view.parent_image:
        # The SOURCE named the parent on this event. That is evidence. But
        # without the parent's lifetime identity it cannot be resolved to
        # ONE parent process, so it is carried as a source-stated,
        # NON-authoritative relationship and is never silently joined to
        # whatever else held that PID.
        return ResolvedParent(
            parent_key=None, basis=PARENT_BY_SOURCE_PID,
            reason=("the source named a parent pid/image on this event but "
                    "no parent process identity; a PID is reused, so this "
                    "parent is described and NOT resolved. It must never "
                    "be joined to another observation on PID alone"),
            parent_pid=view.parent_pid, parent_image=view.parent_image)
    return ResolvedParent(
        parent_key=None, basis=PARENT_NOT_OBSERVED,
        reason=("this event stated no parent. Nothing may be inferred "
                "from timestamp proximity, filename or row adjacency"))


# ── lifetime ─────────────────────────────────────────────────────────

def lifecycle(views: Iterable[ProcessView]) -> dict[str, Any]:
    """Lifetime facts for ONE process's observations.

    `evidence_span` is what we OBSERVED. It is not a lifetime, and the
    two are reported as different things: a process with no termination
    event is `PROCESS_LIFETIME_UNKNOWN`, whatever its last observation
    says.
    """
    rows = [v for v in views]
    times = sorted(v.observed_at for v in rows if v.observed_at)
    start = next((v for v in rows if v.kind in START_KINDS), None)
    term = next((v for v in rows if v.kind in TERMINATION_KINDS), None)
    if term is not None:
        lifetime_state = PROCESS_TERMINATION_OBSERVED
        lifetime_reason = ("a source-stated process termination event was "
                           "collected for this process")
    else:
        lifetime_state = PROCESS_LIFETIME_UNKNOWN
        lifetime_reason = ("no process termination event was collected for "
                           "this process. The last observation is the last "
                           "time we HEARD about it — it is not an exit and "
                           "it is not proof the process is still running")
    return {
        "start": {
            "state": (PROCESS_START_OBSERVED if start
                      else PROCESS_START_NOT_OBSERVED),
            "observed_at": start.observed_at if start else None,
            "evidence_ref": start.evidence_ref if start else None,
        },
        "termination": {
            "state": (PROCESS_TERMINATION_OBSERVED if term
                      else PROCESS_TERMINATION_NOT_OBSERVED),
            "observed_at": term.observed_at if term else None,
            "evidence_ref": term.evidence_ref if term else None,
        },
        "observed_evidence_span": {
            "first_observed_at": times[0] if times else None,
            "last_observed_at": times[-1] if times else None,
            "observation_count": len(rows),
            "note": ("the span of collected evidence, NOT the process "
                     "lifetime"),
        },
        "lifetime_state": lifetime_state,
        "lifetime_reason": lifetime_reason,
    }


# ── aggregation over many observations ───────────────────────────────

def build(views: Iterable[ProcessView]) -> dict[str, Any]:
    """Group observations into PROCESSES and state the relationships.

    Every derived relationship keeps its evidence references and its
    derivation basis. Observations whose identity is not authoritative are
    reported separately and are never merged into a process.
    """
    rows = list(views)
    processes: dict[str, dict[str, Any]] = {}
    unattributed: list[dict[str, Any]] = []
    for v in rows:
        ident = resolve_identity(v)
        if not ident.process_key:
            unattributed.append({
                "evidence_ref": v.evidence_ref, "authority": ident.authority,
                "reason": ident.reason, "pid": v.pid or None,
                "image": v.image or None, "kind": v.kind or None})
            continue
        entry = processes.setdefault(ident.process_key, {
            "process_key": ident.process_key,
            "identity_authority": ident.authority,
            "identity_reason": ident.reason,
            "identity_basis": list(ident.identity_basis),
            "tenant_id": ident.tenant_id, "endpoint_id": ident.endpoint_id,
            "process_guid": ident.process_guid or None,
            "pid": ident.pid or None, "start_time": ident.start_time or None,
            "image": v.image or None,
            "original_file_name": v.original_file_name or None,
            "command_line": v.command_line or None,
            "evidence_refs": [], "kinds": [], "_views": [],
        })
        entry["_views"].append(v)
        if v.evidence_ref:
            entry["evidence_refs"].append(v.evidence_ref)
        if v.kind and v.kind not in entry["kinds"]:
            entry["kinds"].append(v.kind)
        # Fields a later observation states and the first did not. A value
        # already present is never overwritten by a weaker observation.
        for attr in ("image", "command_line", "original_file_name"):
            if not entry.get(attr) and getattr(v, attr):
                entry[attr] = getattr(v, attr)

    edges: list[dict[str, Any]] = []
    for key, entry in processes.items():
        for v in entry["_views"]:
            parent = resolve_parent(v)
            if parent.basis == PARENT_NOT_OBSERVED:
                continue
            edges.append({
                "child_process_key": key,
                "parent_process_key": parent.parent_key,
                "basis": parent.basis,
                "reason": parent.reason,
                "resolved": bool(parent.parent_key),
                "parent_process_guid": parent.parent_process_guid or None,
                "parent_pid": parent.parent_pid or None,
                "parent_image": parent.parent_image or None,
                "evidence_refs": [v.evidence_ref] if v.evidence_ref else [],
            })
    for entry in processes.values():
        entry["lifecycle"] = lifecycle(entry.pop("_views"))

    return {
        "processes": list(processes.values()),
        "relationships": _dedupe_edges(edges),
        "unattributed_observations": unattributed,
        "pid_reuse": pid_reuse_report(rows),
        "counts": {
            "observations": len(rows),
            "processes": len(processes),
            "unattributed_observations": len(unattributed),
        },
    }


def _dedupe_edges(edges: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: dict[tuple, dict[str, Any]] = {}
    for e in edges:
        k = (e["child_process_key"], e["parent_process_key"], e["basis"],
             e["parent_pid"], e["parent_image"])
        prior = out.get(k)
        if prior:
            prior["evidence_refs"].extend(e["evidence_refs"])
        else:
            out[k] = dict(e)
    return list(out.values())


def pid_reuse_report(views: Iterable[ProcessView]) -> list[dict[str, Any]]:
    """Where one (endpoint, pid) carried MORE THAN ONE process.

    This is the measurement that proves PID-keyed identity would have
    collapsed distinct processes into one lifeline.
    """
    by_pid: dict[tuple[str, str, str], set[str]] = {}
    for v in views:
        ident = resolve_identity(v)
        if not ident.process_key or not v.pid:
            continue
        by_pid.setdefault((v.tenant_id, v.endpoint_id, v.pid),
                          set()).add(ident.process_key)
    return [{"tenant_id": t, "endpoint_id": e, "pid": p,
             "distinct_process_keys": sorted(keys),
             "count": len(keys),
             "note": ("this PID identified more than one process; a "
                      "PID-keyed model would have merged them")}
            for (t, e, p), keys in sorted(by_pid.items()) if len(keys) > 1]
