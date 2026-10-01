"""Project Timeline events + Lane wires → canonical ActivityInventory.

Owner rule #19: one canonical model drives every panel.

Deterministic: same inputs → same inventory (id, ordering, ancestry).
Non-inventive: entities emerge only from evidence (rule #3a).
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .model import (ActivityEntity, ActivityEvent, ActivityInventory,
                     KIND_PROCESS, KIND_FILE, KIND_NETWORK,
                     KIND_REGISTRY, KIND_IDENTITY, KIND_SYSTEM,
                     ENTITY_KINDS)


def _eid(prefix: str, key: str) -> str:
    m = hashlib.sha256(f"{prefix}::{key}".encode()).hexdigest()
    return f"{prefix}-{m[:16]}"


def _process_entity_key(name: str, pid: Optional[Any] = None) -> str:
    """Process entity id is deterministic on NAME ONLY.  PID is
    metadata surfaced in ``attributes.pids`` — a single logical
    process can span many PIDs across events/restarts and MUST
    consolidate under one entity for the analyst-facing view."""
    return name.lower()


def _network_entity_key(dest: str) -> str:
    return dest.lower().strip()


def _file_entity_key(path_or_name: str) -> str:
    return path_or_name.lower().strip()


def _registry_entity_key(k: str) -> str:
    return k.strip()


def _identity_entity_key(u: str) -> str:
    return u.strip()


def _first_last(ts: Optional[str], cur_first: Optional[str],
                  cur_last: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    if not ts:
        return cur_first, cur_last
    first = cur_first if cur_first and cur_first <= ts else ts
    last = cur_last if cur_last and cur_last >= ts else ts
    return first, last


def _process_from_event(ev: Dict[str, Any]) -> Tuple[Optional[ActivityEntity],
                                                        Optional[ActivityEntity]]:
    """Return (child_process_entity, parent_process_entity) — either may
    be None when not surfaced by evidence."""
    proc = ev.get("process") or (ev.get("canonical_fields") or {}
                                    ).get("canonical.process.name")
    parent = ev.get("parent_process") or (ev.get("canonical_fields") or {}
                                             ).get("canonical.process.parent")
    cf = ev.get("canonical_fields") or {}
    pid = cf.get("canonical.process.pid")
    parent_pid = cf.get("canonical.process.parent_pid")
    child_ent = None
    parent_ent = None
    if proc:
        eid = _eid("proc", _process_entity_key(str(proc), pid))
        # Read hashes / signer / path from either canonical_fields or a
        # co-supplied file_ref — the process's executable file IS its
        # file evidence, so surface it in the entity attributes.
        fref = ev.get("file_ref") or {}
        child_ent = ActivityEntity(
            entity_id=eid, kind=KIND_PROCESS,
            display_name=str(proc),
            attributes={
                "pid":            pid,
                "user":           ev.get("user") or cf.get("canonical.source.user"),
                "integrity":      cf.get("canonical.process.integrity"),
                "command_line":   ev.get("command_line"),
                "sha256":         (cf.get("canonical.file.hash.sha256")
                                     or fref.get("sha256")),
                "md5":            (cf.get("canonical.file.hash.md5")
                                     or fref.get("md5")),
                "sha1":           (cf.get("canonical.file.hash.sha1")
                                     or fref.get("sha1")),
                "path":           (cf.get("canonical.file.path")
                                     or cf.get("canonical.process.path")
                                     or fref.get("path")),
                "signer":         cf.get("canonical.file.signer")
                                     or cf.get("canonical.process.signer"),
                "signature_status": cf.get("canonical.file.signature_status"),
            },
        )
    if parent:
        peid = _eid("proc", _process_entity_key(str(parent), parent_pid))
        parent_ent = ActivityEntity(
            entity_id=peid, kind=KIND_PROCESS,
            display_name=str(parent),
            attributes={"pid": parent_pid},
        )
    return child_ent, parent_ent


def _file_entity_from_event(ev: Dict[str, Any]) -> Optional[ActivityEntity]:
    f = ev.get("file_ref") or ev.get("artifact_ref") or {}
    path = f.get("path") or f.get("file_name") or f.get("name")
    if not path:
        return None
    eid = _eid("file", _file_entity_key(str(path)))
    return ActivityEntity(
        entity_id=eid, kind=KIND_FILE,
        display_name=(f.get("name") or f.get("file_name") or str(path).split("\\")[-1].split("/")[-1]),
        attributes={
            "path":   f.get("path"),
            "sha256": f.get("sha256"),
            "md5":    f.get("md5"),
            "sha1":   f.get("sha1"),
            "size":   f.get("size"),
            "mime":   f.get("mime"),
            "artifact_type": f.get("type"),
            "display_hint":  f.get("display_name"),
        },
    )


def _network_entity_from_event(ev: Dict[str, Any]) -> Optional[ActivityEntity]:
    dest = ev.get("destination")
    if not dest:
        return None
    eid = _eid("net", _network_entity_key(str(dest)))
    host = dest.split("/")[2] if "://" in dest else dest.split(":")[0]
    return ActivityEntity(
        entity_id=eid, kind=KIND_NETWORK,
        display_name=host,
        attributes={
            "destination": dest,
            "host":        host,
            "port":        (ev.get("canonical_fields") or {}).get("canonical.destination.port"),
        },
    )


def _registry_entity_from_event(ev: Dict[str, Any]) -> Optional[ActivityEntity]:
    cf = ev.get("canonical_fields") or {}
    key = cf.get("canonical.registry.key")
    if not key:
        return None
    eid = _eid("reg", _registry_entity_key(str(key)))
    return ActivityEntity(
        entity_id=eid, kind=KIND_REGISTRY,
        display_name=str(key),
        attributes={
            "value_name": cf.get("canonical.registry.value_name"),
            "value_data": cf.get("canonical.registry.value_data"),
        },
    )


def _identity_entity_from_event(ev: Dict[str, Any]) -> Optional[ActivityEntity]:
    user = ev.get("user") or (ev.get("canonical_fields") or {}
                                 ).get("canonical.source.user")
    if not user:
        return None
    eid = _eid("id", _identity_entity_key(str(user)))
    return ActivityEntity(
        entity_id=eid, kind=KIND_IDENTITY,
        display_name=str(user),
        attributes={
            "domain": (ev.get("canonical_fields") or {}
                        ).get("canonical.identity.domain"),
        },
    )


def _system_entity_from_event(ev: Dict[str, Any]) -> Optional[ActivityEntity]:
    host = ev.get("host") or (ev.get("canonical_fields") or {}
                                 ).get("canonical.source.host")
    if not host:
        return None
    eid = _eid("sys", host.lower())
    return ActivityEntity(
        entity_id=eid, kind=KIND_SYSTEM,
        display_name=host,
        attributes={},
    )


def _pick_primary_kind(ev: Dict[str, Any]) -> str:
    """Every event belongs primarily to ONE entity kind for the
    trajectory canvas.  Order: process > file > network > registry >
    identity > system (deterministic)."""
    if ev.get("process") or (ev.get("canonical_fields") or {}
                                ).get("canonical.process.name"):
        return KIND_PROCESS
    if ev.get("file_ref") or ev.get("artifact_ref"):
        return KIND_FILE
    if ev.get("destination"):
        return KIND_NETWORK
    if (ev.get("canonical_fields") or {}).get("canonical.registry.key"):
        return KIND_REGISTRY
    if ev.get("user"):
        return KIND_IDENTITY
    if ev.get("host"):
        return KIND_SYSTEM
    return KIND_SYSTEM


def build_inventory(*,
                      case_id: Optional[str] = None,
                      tenant_id: Optional[str] = None,
                      timeline: Optional[Dict[str, Any]] = None
                      ) -> ActivityInventory:
    """Deterministic projection of a Timeline into ActivityInventory."""
    timeline = timeline or {}
    events_in = list(timeline.get("events") or [])
    untimed_in = list(timeline.get("untimed_events") or [])
    all_in = events_in + untimed_in

    # Accumulators — deterministic order via sorted-emit at the end.
    ents: Dict[str, Dict[str, ActivityEntity]] = {k: {} for k in ENTITY_KINDS}
    events_out: List[ActivityEvent] = []
    untimed_out: List[ActivityEvent] = []

    def _merge_ent(kind: str, ent: ActivityEntity, ts: Optional[str],
                    ev_id: str, parent_ent_id: Optional[str]) -> ActivityEntity:
        existing = ents[kind].get(ent.entity_id)
        if existing is None:
            first, last = _first_last(ts, None, None)
            merged = ActivityEntity(
                entity_id=ent.entity_id,
                kind=ent.kind,
                display_name=ent.display_name,
                attributes={k: v for k, v in ent.attributes.items()
                             if v is not None},
                event_ids=[ev_id] if ev_id else [],
                first_seen=first,
                last_seen=last,
                parent_entity_id=parent_ent_id,
                child_entity_ids=list(ent.child_entity_ids),
            )
        else:
            first, last = _first_last(ts, existing.first_seen,
                                        existing.last_seen)
            attrs = dict(existing.attributes)
            for k, v in ent.attributes.items():
                if v is not None and k not in attrs:
                    attrs[k] = v
            ev_ids = list(existing.event_ids)
            if ev_id and ev_id not in ev_ids:
                ev_ids.append(ev_id)
            merged = ActivityEntity(
                entity_id=ent.entity_id,
                kind=ent.kind,
                display_name=existing.display_name,
                attributes=attrs,
                event_ids=ev_ids,
                first_seen=first,
                last_seen=last,
                parent_entity_id=existing.parent_entity_id or parent_ent_id,
                child_entity_ids=existing.child_entity_ids,
            )
        ents[kind][ent.entity_id] = merged
        return merged

    for ev in all_in:
        if not isinstance(ev, dict):
            continue
        primary_kind = _pick_primary_kind(ev)
        ts = ev.get("timestamp")
        ev_id = ev.get("event_id") or ""

        # Materialise entities.
        child_proc, parent_proc = _process_from_event(ev)
        file_ent    = _file_entity_from_event(ev)
        net_ent     = _network_entity_from_event(ev)
        reg_ent     = _registry_entity_from_event(ev)
        id_ent      = _identity_entity_from_event(ev)
        sys_ent     = _system_entity_from_event(ev)

        parent_id_for_child = None
        if parent_proc is not None:
            _ = _merge_ent(KIND_PROCESS, parent_proc, ts, ev_id, None)
            parent_id_for_child = parent_proc.entity_id
        if child_proc is not None:
            m = _merge_ent(KIND_PROCESS, child_proc, ts, ev_id,
                            parent_id_for_child)
            # Update parent's child list.
            if parent_id_for_child:
                parent_entry = ents[KIND_PROCESS][parent_id_for_child]
                if m.entity_id not in parent_entry.child_entity_ids:
                    ents[KIND_PROCESS][parent_id_for_child] = ActivityEntity(
                        entity_id=parent_entry.entity_id,
                        kind=parent_entry.kind,
                        display_name=parent_entry.display_name,
                        attributes=parent_entry.attributes,
                        event_ids=parent_entry.event_ids,
                        first_seen=parent_entry.first_seen,
                        last_seen=parent_entry.last_seen,
                        parent_entity_id=parent_entry.parent_entity_id,
                        child_entity_ids=parent_entry.child_entity_ids + [m.entity_id],
                    )
        if file_ent:
            _merge_ent(KIND_FILE, file_ent, ts, ev_id, None)
        if net_ent:
            _merge_ent(KIND_NETWORK, net_ent, ts, ev_id, None)
        if reg_ent:
            _merge_ent(KIND_REGISTRY, reg_ent, ts, ev_id, None)
        if id_ent:
            _merge_ent(KIND_IDENTITY, id_ent, ts, ev_id, None)
        if sys_ent:
            _merge_ent(KIND_SYSTEM, sys_ent, ts, ev_id, None)

        # Emit the trajectory event tied to the PRIMARY entity.
        entity_id = ""
        if primary_kind == KIND_PROCESS and child_proc:
            entity_id = child_proc.entity_id
        elif primary_kind == KIND_FILE and file_ent:
            entity_id = file_ent.entity_id
        elif primary_kind == KIND_NETWORK and net_ent:
            entity_id = net_ent.entity_id
        elif primary_kind == KIND_REGISTRY and reg_ent:
            entity_id = reg_ent.entity_id
        elif primary_kind == KIND_IDENTITY and id_ent:
            entity_id = id_ent.entity_id
        elif primary_kind == KIND_SYSTEM and sys_ent:
            entity_id = sys_ent.entity_id

        summary = ev.get("display_summary") or ev.get("action") \
                     or ev.get("category") or "event"
        act_ev = ActivityEvent(
            event_id=ev_id,
            kind=primary_kind,
            entity_id=entity_id,
            timestamp=ts if ts else None,
            action=ev.get("action"),
            lane=ev.get("lane") or "log",
            display_summary=str(summary),
            canonical_fields=dict(ev.get("canonical_fields") or {}),
            provenance_chain=list(ev.get("provenance_chain") or []),
        )
        if ts:
            events_out.append(act_ev)
        else:
            untimed_out.append(act_ev)

    # Deterministic ordering.
    events_out.sort(key=lambda e: (e.timestamp or "", e.event_id))
    untimed_out.sort(key=lambda e: e.event_id)
    grouped = {k: sorted(ents[k].values(), key=lambda e: e.entity_id)
                for k in ENTITY_KINDS}

    span_start = events_out[0].timestamp if events_out else None
    span_end = events_out[-1].timestamp if events_out else None

    return ActivityInventory(
        case_id=case_id,
        tenant_id=tenant_id,
        entities=grouped,
        events=events_out,
        untimed_events=untimed_out,
        generated_at=datetime.now(timezone.utc).isoformat(),
        span_start=span_start,
        span_end=span_end,
    )


__all__ = ["build_inventory"]
