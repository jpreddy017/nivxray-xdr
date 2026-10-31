"""Stable process-instance identity, event identity and cross-store duplicate suppression."""
from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Iterable
from typing import Any, Optional

from .contracts import ID_GUID, ID_PID_ONLY, ID_START_TIME, parse_instant


def process_key(tenant_id: str, device_id: str, proc: dict[str, Any],
                boot_id: str | None = None) -> tuple[str | None, str]:
    """(key, identity_state). Key = tenant+device+pid+start time [+boot]; PID reuse safe.

    A source GUID (one lifetime per host) is accepted when start time is absent. PID alone is
    never authoritative: it is keyed but marked so lineage can only be UNRESOLVED from it.
    """
    pid, start = proc.get("pid"), parse_instant(proc.get("start_time"))
    boot = f":{boot_id}" if boot_id else ""
    if pid is not None and start is not None:
        return f"pi:{tenant_id}:{device_id}:{pid}:{start}{boot}", ID_START_TIME
    if proc.get("guid"):
        return f"pg:{tenant_id}:{device_id}:{str(proc['guid']).strip('{}').lower()}", ID_GUID
    if pid is not None:
        return f"pp:{tenant_id}:{device_id}:{pid}{boot}", ID_PID_ONLY
    return None, ID_PID_ONLY


def parent_spoof(ev: dict[str, Any]) -> dict[str, Any] | None:
    """Flag when the reported parent differs from creator evidence (e.g. PPID spoofing)."""
    par, cre = ev.get("parent") or {}, ev.get("creator") or {}
    if not cre or not par:
        return None
    for f in ("guid", "pid"):
        if cre.get(f) is not None and par.get(f) is not None:
            if str(cre[f]).strip("{}").lower() != str(par[f]).strip("{}").lower():
                return {"suspected": True, "reported_parent": {k: par.get(k) for k in ("pid", "guid", "image")},
                        "creator": {k: cre.get(k) for k in ("pid", "guid", "image")},
                        "basis": f"creator.{f} != parent.{f}"}
            return None
    return None


def fallback_event_id(tenant_id: str, device_id: str, ev: dict[str, Any]) -> str:
    """Content identity when no source identity exists (same real activity → same id)."""
    p, f, n = ev.get("process") or {}, ev.get("file") or {}, ev.get("network") or {}
    material = [tenant_id, device_id, ev.get("kind"), ev.get("observed_ms"), p.get("pid"), p.get("guid"),
                f.get("path"), n.get("dest_ip"), n.get("dest_port")]
    return "ce_" + hashlib.sha256(json.dumps(material, default=str).encode()).hexdigest()[:24]


#: Ranked identity keys for one activity. An activity may STATE several identities; a row is
#: matched on ANY of them and RENDERED under the highest-ranked one, so the id downstream
#: consumers already hold does not move.
#: 0 — the activity identity the writer stamped on the store (the id behavior evidence and
#:     deep links already use).
#: 1 — the canonical event id the AUTHENTICATED INGEST BOUNDARY assigned to the delivery, which
#:     BOTH stores carry (`xdr_canonical_evidence.event_id` ==
#:     `v2_shadow_observations.canonical_event_id`, one raw delivery -> one canonical id). This
#:     is the only identity the two stores provably share on real sensor evidence.
#: 2 — content identity, used only when the source states no identity at all.
RANK_ACTIVITY_IDENTITY = 0
RANK_CANONICAL_EVENT_ID = 1
RANK_CONTENT = 2


def identity_keys(canonical_event_id: Any, activity_identity: Any) -> list[tuple[int, str]]:
    """The identities one row STATES, as (rank, value), lowest rank first."""
    out: list[tuple[int, str]] = []
    for rank, v in ((RANK_ACTIVITY_IDENTITY, activity_identity),
                    (RANK_CANONICAL_EVENT_ID, canonical_event_id)):
        s = str(v).strip() if v is not None else ""
        if s:
            out.append((rank, s))
    return out


def _merge(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    out = dict(a)
    for k, v in b.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = {**v, **{kk: vv for kk, vv in out[k].items() if vv is not None}}
        elif out.get(k) in (None, "", [], {}):
            out[k] = v
    out["sources"] = sorted(set(a.get("sources") or []) | set(b.get("sources") or []))
    # ingest lateness: the EARLIEST store acceptance is the delivery time
    ins = [x for x in (a.get("ingested_ms"), b.get("ingested_ms")) if x is not None]
    out["ingested_ms"] = min(ins) if ins else None
    return out


def dedupe(events: Iterable[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    """Collapse the representations of ONE activity. Returns (events, suppressed).

    Two rows are the same activity only when they state the same identity (see
    `identity_keys`) inside the same tenant. The stores name the endpoint differently —
    canonical carries `ep_…`, the shadow observation carries `dev_…` for the same machine, which
    is why device agreement is NOT part of the key and why a content hash can never match across
    them. Nothing is matched on timestamp, PID or account: two genuine logons by the same
    account in the same second state two different identities and stay two rows.
    """
    # every map is TENANT-SCOPED: two tenants may legitimately hold the same identifier and
    # must never be merged into one row.
    # The group key carries the RANK as well as the value. Two rows that state the same text in
    # DIFFERENT namespaces are not evidenced to be the same activity, so they must land in
    # different groups; keying on the bare string let the later row silently overwrite the
    # earlier one, losing evidence and making the survivor depend on input order.
    groups: dict[tuple[str, tuple[int, str]], dict[str, Any]] = {}
    gkeys: dict[tuple[str, tuple[int, str]], set[tuple[int, str]]] = {}
    suppressed = 0
    for ev in events:
        tenant = ev["tenant_id"]
        keys = set(ev.get("identity_keys") or []) or {(RANK_CONTENT, ev["event_id"])}
        hits = sorted({g for g, ks in gkeys.items() if g[0] == tenant and ks & keys})
        if hits:
            for h in hits:
                keys |= gkeys.pop(h)
            merged = groups.pop(hits[0])
            for h in hits[1:]:
                merged = _merge(merged, groups.pop(h))
                suppressed += 1
            ev = _merge(merged, ev)
            suppressed += 1
        g = (tenant, min(keys))
        groups[g], gkeys[g] = ev, keys
    return _export(groups, gkeys), suppressed


#: Versioned identity encoding. Applied to EVERY exported identity, never conditionally, so the
#: exported value is a pure function of (rank, value) and does not depend on which other rows
#: share the page. The payload is base64url without padding, which cannot contain ':', so
#: "<version>:<rank>:<payload>" is unambiguous and no raw identity can forge an encoded one.
IDENTITY_ENCODING = "e3i1"


class AmbiguousIdentity(Exception):
    """A legacy identity resolved to more than one row. Never resolved by guessing."""


def encode_identity(key: tuple[int, str]) -> str:
    """Encode (rank, value) into the versioned identity space.

    Context-free by construction: adding or removing rows from the page cannot change the
    result, which is what makes a cursor taken on one page valid on another.
    """
    payload = base64.urlsafe_b64encode(str(key[1]).encode("utf-8")).decode("ascii").rstrip("=")
    return f"{IDENTITY_ENCODING}:{int(key[0])}:{payload}"


def decode_identity(encoded: str) -> Optional[tuple[int, str]]:
    """Inverse of `encode_identity`, or None if `encoded` is not of this version."""
    parts = str(encoded).split(":", 2)
    if len(parts) != 3 or parts[0] != IDENTITY_ENCODING or not parts[1].isdigit():
        return None
    pad = "=" * (-len(parts[2]) % 4)
    try:
        return int(parts[1]), base64.urlsafe_b64decode(parts[2] + pad).decode("utf-8")
    except Exception:
        return None


def resolve_identity(identity: str, events: list[dict[str, Any]], tenant_id: str
                     ) -> Optional[dict[str, Any]]:
    """Resolve an encoded id OR a legacy bare id to exactly one row, within one tenant.

    Legacy deep links carry the bare value that older builds exported, which is not unique on
    its own: the same text can exist in two namespaces. When a legacy id matches more than one
    row this raises rather than choosing, because no evidence states which was meant.
    """
    scoped = [e for e in events if e.get("tenant_id") == tenant_id]
    exact = [e for e in scoped if e.get("event_id") == identity
             or identity in (e.get("identity_aliases") or [])]
    if exact:
        return exact[0]
    legacy = [e for e in scoped if identity in (e.get("legacy_event_ids") or [])]
    if len(legacy) > 1:
        raise AmbiguousIdentity(
            f"legacy identity matches {len(legacy)} rows in tenant {tenant_id}; "
            "it must be disambiguated by the caller, not selected here")
    return legacy[0] if legacy else None


def _export(groups: dict[tuple[str, tuple[int, str]], dict[str, Any]],
            gkeys: dict[tuple[str, tuple[int, str]], set[tuple[int, str]]]
            ) -> list[dict[str, Any]]:
    """Emit one row per group under the versioned identity encoding.

    `event_id` is always encoded, so it is stable across subset and superset pages and can never
    collide with a raw identity that merely looks prefix-shaped. Every identity the group holds
    is also published as an alias, and the bare values are published as legacy ids, so a cursor
    or deep link minted before a further store representation raised the group's rank still
    resolves instead of 404-ing.
    """
    out = []
    for g, ev in groups.items():
        ev = dict(ev)
        keys = sorted(gkeys[g])
        ev["identity_keys"] = keys
        ev["event_id"] = encode_identity(min(keys))
        ev["identity_aliases"] = [encode_identity(k) for k in keys]
        ev["legacy_event_ids"] = sorted({str(v) for _r, v in keys})
        out.append(ev)
    return out
