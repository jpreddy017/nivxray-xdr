"""Device Identity Resolution (DIR) — read-only projection.

Owner-authorised P0 · 2026-09-05.

The audit
(``docs/uiux/NIVXFORGE_EDR_SANDBOX_CURRENT_STATE_AND_INDUSTRY_PARITY.md``)
established that ``workspace_cases.ssot.investigation_object.host`` is
empty in 484/484 cases, so the endpoint plane resolved **zero** devices
while the IRG shadow plane already carried a real device identity:

    v2_shadow_observations   639 observations / 36 cases
      event.device_iid       223 populated  → AUTHORITATIVE identity
      event.raw.computer     hostname string → INFERRED identity only

This module projects that existing substrate into the EDR endpoint
plane.  It creates no store, no engine and no synthetic device.  A
device exists here only because an observation exists.

Identity contract:
    device_iid present  → identity_confidence = "authoritative"
    hostname only       → identity_confidence = "inferred"
    neither             → not a device; the observation is unattributed

Note on the INFERRED branch: it is live code, not dead code.  It
currently yields zero rows because ``ssot.investigation_object.host`` is
empty in 484/484 persisted cases (see the audit), so every projected
device today comes from an authoritative ``device_iid``.  The branch
exists so that a hostname-only source can never be silently promoted to
an authoritative identity.

Tenant contract: ``v2_shadow_observations`` carries no ``tenant_id``.
Rather than invent one, the projection is exposed only to cross-tenant
SOC roles (see ``resolve_tenant_scope``).  Single-tenant principals get
an empty projection — stricter, never looser.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from deps import sync_collection

_obs = sync_collection("v2_shadow_observations")

# IRG observation kind → EDR canvas lane (the 5 lanes the canvas renders).
_KIND_LANE: Dict[str, str] = {
    "process_create":     "process",
    "file_create":        "file",
    "file_write":         "file",
    "file_delete":        "file",
    "registry_value_set": "registry",
    "network_connect":    "network",
    "network_listen":     "network",
    "service_install":    "system",
    "memory_alloc":       "system",
    "kernel_event":       "system",
    "cloud_iam_action":   "system",
}

AUTHORITATIVE = "authoritative"
INFERRED = "inferred"


def lane_for_kind(kind: str) -> str:
    return _KIND_LANE.get((kind or "").lower(), "system")


def _raw(ev: Dict[str, Any]) -> Dict[str, Any]:
    r = ev.get("raw")
    return r if isinstance(r, dict) else {}


def _hostname(ev: Dict[str, Any]) -> Optional[str]:
    r = _raw(ev)
    for key in ("computer", "hostname", "host"):
        v = r.get(key)
        if v:
            return str(v)
    return None


def _event_of(doc: Dict[str, Any]) -> Dict[str, Any]:
    ev = doc.get("event")
    return ev if isinstance(ev, dict) else {}


def _ts_of(doc: Dict[str, Any], ev: Dict[str, Any]) -> Optional[str]:
    return ev.get("ts") or doc.get("captured_at")


def _bump(row: Dict[str, Any], ts: Optional[str], lane: str,
          case_id: Optional[str], user: Optional[str],
          origin: Optional[str]) -> None:
    row["observation_count"] += 1
    row["lane_counts"][lane] = row["lane_counts"].get(lane, 0) + 1
    if ts:
        if not row["first_seen"] or ts < row["first_seen"]:
            row["first_seen"] = ts
        if not row["last_seen"] or ts > row["last_seen"]:
            row["last_seen"] = ts
    if case_id and case_id not in row["case_ids"]:
        row["case_ids"].append(case_id)
    if user and user not in row["users"]:
        row["users"].append(user)
    if origin and origin not in row["provenance"]:
        row["provenance"].append(origin)


def _new_row(ref: str, device_iid: Optional[str],
             hostname: Optional[str]) -> Dict[str, Any]:
    return {
        "device_ref":            ref,
        "device_iid":            device_iid,
        "hostname":              hostname,
        "identity_confidence":   AUTHORITATIVE if device_iid else INFERRED,
        "observation_count":     0,
        "lane_counts":           {},
        "first_seen":            None,
        "last_seen":             None,
        "case_ids":              [],
        "users":                 [],
        "provenance":            [],
        "source":                "v2_shadow_observations",
    }


def list_devices(cross_tenant: bool) -> List[Dict[str, Any]]:
    """Project every device identity observable in the IRG plane."""
    if not cross_tenant:
        return []
    rows: Dict[str, Dict[str, Any]] = {}
    for doc in _obs.find({}, {"_id": 0}):
        ev = _event_of(doc)
        device_iid = ev.get("device_iid") or None
        hostname = _hostname(ev)
        if not device_iid and not hostname:
            continue
        ref = device_iid or hostname
        row = rows.get(ref)
        if not row:
            row = _new_row(ref, device_iid, hostname)
            rows[ref] = row
        elif hostname and not row.get("hostname"):
            row["hostname"] = hostname
        _bump(row,
              _ts_of(doc, ev),
              lane_for_kind(ev.get("kind") or doc.get("kind") or ""),
              doc.get("case_id"),
              (_raw(ev).get("user") or None),
              ((ev.get("provenance") or {}) or {}).get("origin"))
    return sorted(rows.values(),
                  key=lambda r: r.get("last_seen") or "", reverse=True)


def resolve(device_ref: str, cross_tenant: bool) -> Optional[Dict[str, Any]]:
    """Resolve a URL device reference to a projected identity.

    Accepts an authoritative ``device_iid`` or a hostname (matched
    case-insensitively).  Returns ``None`` when nothing resolves — the
    caller must then render an explicit unresolved state rather than an
    empty canvas.
    """
    if not device_ref:
        return None
    needle = device_ref.strip().lower()
    for row in list_devices(cross_tenant):
        if (row.get("device_iid") or "").lower() == needle:
            return row
        if (row.get("hostname") or "").lower() == needle:
            return row
    return None


def observations(device_ref: str, cross_tenant: bool,
                 since_iso: Optional[str] = None,
                 identity: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Trajectory-shaped events for a resolved device.

    ``identity`` may be supplied by a caller that has already resolved
    the reference, so a request costs one collection pass instead of
    two.  Every field is copied from a persisted observation or omitted:
    no derived causality, no synthesis.
    """
    if identity is None:
        identity = resolve(device_ref, cross_tenant)
    if not identity:
        return []
    iid = (identity.get("device_iid") or "").lower()
    host = (identity.get("hostname") or "").lower()

    out: List[Dict[str, Any]] = []
    for doc in _obs.find({}, {"_id": 0}):
        ev = _event_of(doc)
        d_iid = (ev.get("device_iid") or "").lower()
        d_host = (_hostname(ev) or "").lower()
        if iid:
            if d_iid != iid:
                continue
        elif not host or d_host != host:
            continue

        ts = _ts_of(doc, ev)
        if since_iso and ts and str(ts) < since_iso:
            continue
        raw = _raw(ev)
        proc = ev.get("process") if isinstance(ev.get("process"), dict) else {}
        kind = ev.get("kind") or doc.get("kind") or "observation"
        out.append({
            "id":            f"{doc.get('case_id')}::{ev.get('iid') or doc.get('process_iid')}",
            "kind":          "observation",
            "observation_kind": kind,
            "lane":          lane_for_kind(kind),
            "timestamp":     ts,
            "title":         (proc.get("name") or raw.get("entity")
                              or raw.get("rule_label") or kind),
            "severity":      "info",
            "process":       proc.get("name") or raw.get("entity"),
            "process_iid":   doc.get("process_iid") or ev.get("process_iid"),
            "parent_iid":    proc.get("parent_iid"),
            "parent_name":   proc.get("parent_name") or raw.get("parent_image"),
            "path":          proc.get("image"),
            "file":          raw.get("target") or None,
            "command_line":  raw.get("command_line") or raw.get("text"),
            "user":          raw.get("user"),
            "device":        identity.get("hostname") or identity.get("device_iid"),
            "device_iid":    ev.get("device_iid"),
            "actor_iid":     ev.get("actor_iid"),
            "mitre":         ev.get("mitre") or [],
            "labels":        ev.get("labels") or [],
            "sha256":        raw.get("sha256"),
            "provider":      raw.get("provider"),
            "event_id":      raw.get("event_id"),
            "rule_label":    raw.get("rule_label"),
            "parent_image":  raw.get("parent_image"),
            "artefact_iids": ev.get("artefacts_iids") or doc.get("artefacts_iids") or [],
            "incident_id":   doc.get("case_id"),
            "adapter":       ev.get("adapter") or doc.get("adapter"),
            "evidence_ref": {
                "type":       "v2_shadow_observation",
                "event_iid":  ev.get("iid"),
                "case_id":    doc.get("case_id"),
                "sequence":   ev.get("sequence"),
            },
        })
    out.sort(key=lambda e: str(e.get("timestamp") or ""))
    return out


def find_observation(device_ref: str, event_iid: str,
                     cross_tenant: bool) -> Optional[Dict[str, Any]]:
    """Return the raw persisted observation for one ``event.iid`` on a
    resolved device.  ``None`` when the reference does not resolve —
    the caller renders an explicit unresolved state."""
    identity = resolve(device_ref, cross_tenant)
    if not identity or not event_iid:
        return None
    iid = (identity.get("device_iid") or "").lower()
    host = (identity.get("hostname") or "").lower()
    for doc in _obs.find({"event.iid": event_iid}, {"_id": 0}):
        ev = _event_of(doc)
        if iid:
            if (ev.get("device_iid") or "").lower() == iid:
                return doc
        elif host and (_hostname(ev) or "").lower() == host:
            return doc
    return None
