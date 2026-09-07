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


def _norm_scope(scope: Any) -> tuple[bool, List[str]]:
    """Accept the authorisation scope (dict) or the legacy bool."""
    if isinstance(scope, dict):
        return (bool(scope.get("all_tenants")),
                [str(t) for t in (scope.get("tenant_ids") or [])])
    return bool(scope), []


def _endpoint_owners() -> Dict[str, str]:
    """`endpoint_id -> tenant_id` from the durable enrolment records.

    This is the ownership authority. An observation's own `tenant_id` is
    only believed when it agrees with the endpoint record that the
    authenticated sensor enrolled under.
    """
    from deps import sync_collection
    return {d["endpoint_id"]: d.get("tenant_id")
            for d in sync_collection("edr_endpoints")
            .find({}, {"_id": 0, "endpoint_id": 1, "tenant_id": 1})
            if d.get("endpoint_id")}


def _attribute(row: Dict[str, Any], owners: Dict[str, str]) -> Dict[str, Any]:
    """Decide, and SAY, who owns a device — or that nobody does."""
    tenants = {t for t in row.pop("_tenant_ids", set()) if t}
    conns = {c for c in row.pop("_connector_ids", set()) if c}
    owner_tenants = {owners[c] for c in conns if c in owners}

    if not tenants:
        state, tenant = "UNATTRIBUTED_LEGACY_OBSERVATION", None
    elif len(tenants) > 1:
        state, tenant = "TENANT_CONFLICT_FAILED_CLOSED", None
    elif owner_tenants and owner_tenants != tenants:
        # The observation claims one customer, the enrolment record says
        # another. Neither gets it.
        state, tenant = "TENANT_MISMATCH_FAILED_CLOSED", None
    elif owner_tenants:
        state, tenant = "ATTRIBUTED_AUTHENTICATED_ENDPOINT", next(iter(tenants))
    else:
        state, tenant = "ATTRIBUTED_TENANT_ONLY", next(iter(tenants))

    row["tenant_id"] = tenant
    row["tenant_attribution"] = state
    row["attribution_basis"] = (
        "v2_shadow_observations.tenant_id cross-checked against "
        "edr_endpoints.tenant_id via the authenticated connector_id")
    row["owning_endpoint_ids"] = sorted(conns)
    return row


def list_devices(scope: Any) -> List[Dict[str, Any]]:
    """Project the device identities the PRINCIPAL is authorised to see.

    Ownership is decided here, on the server, from the enrolment record —
    never from a query parameter and never inferred from a hostname.
    A customer-scoped principal receives its own endpoints or nothing;
    it never falls back to cross-tenant devices. Legacy observations that
    carry no tenant at all are released to cross-tenant roles ONLY, and
    labelled, because an observation with no owner cannot be turned into
    customer-owned evidence by inference.

    The whole (small) collection is read so that a device with
    observations in two tenants is detected and failed closed rather than
    silently sliced by a query predicate.
    """
    all_tenants, tenant_ids = _norm_scope(scope)
    if not all_tenants and not tenant_ids:
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
            row["_tenant_ids"] = set()
            row["_connector_ids"] = set()
            rows[ref] = row
        elif hostname and not row.get("hostname"):
            row["hostname"] = hostname
        row["_tenant_ids"].add(doc.get("tenant_id"))
        row["_connector_ids"].add(doc.get("connector_id"))
        _bump(row,
              _ts_of(doc, ev),
              lane_for_kind(ev.get("kind") or doc.get("kind") or ""),
              doc.get("case_id"),
              (_raw(ev).get("user") or None),
              ((ev.get("provenance") or {}) or {}).get("origin"))

    owners = _endpoint_owners()
    out = [_attribute(r, owners) for r in rows.values()]
    if not all_tenants:
        allowed = set(tenant_ids)
        out = [r for r in out
               if r["tenant_attribution"].startswith("ATTRIBUTED")
               and r["tenant_id"] in allowed]
    return sorted(out, key=lambda r: r.get("last_seen") or "", reverse=True)


def _endpoint_id_aliases(needle: str) -> List[str]:
    """A platform-minted `endpoint_id` is the authoritative EDR identity,
    so it must be a usable trajectory pivot.

    The IRG observation plane keys on `device_iid` / hostname, so we
    translate through the enrolment record. This is a LOOKUP, not an
    inference: if the endpoint is not enrolled, nothing is returned and the
    caller renders the honest unresolved state.
    """
    if not needle.startswith("ep_"):
        return []
    row = sync_collection("edr_endpoints").find_one(
        {"endpoint_id": needle},
        {"hostname": 1, "device_iid": 1, "_id": 0}) or {}
    return [str(v).lower() for v in (row.get("device_iid"),
                                     row.get("hostname")) if v]


def identity_refs(identity: Optional[Dict[str, Any]],
                  supplied: Optional[str] = None,
                  tenant_ids: Optional[List[str]] = None) -> List[str]:
    """Every identifier that addresses ONE resolved endpoint.

    P0-W.F-1.  `resolve()` already translates a platform-minted
    `endpoint_id` down to the `device_iid`/hostname the observation plane
    keys on, but the reverse direction was never available, so a caller
    arriving with the `device_iid` could not address stores keyed on the
    `endpoint_id` (`edr_raw_events.endpoint_ref`,
    `v2_shadow_observations.collector_id`).  Surfaces therefore rendered
    an honest-looking empty state for an endpoint that genuinely has
    evidence.

    This is a LOOKUP through the enrolment record in BOTH directions,
    never an inference: an endpoint that is not enrolled contributes
    nothing, and no identifier is derived from a name, a pid or a
    timestamp.  The caller must still have resolved the reference under
    its own scope first — this function widens the identifiers, never
    the authorisation.
    """
    if not identity:
        return [supplied] if supplied else []
    refs: List[str] = []

    def _add(v: Any) -> None:
        if v and str(v) not in refs:
            refs.append(str(v))

    _add(supplied)
    _add(identity.get("device_iid"))
    _add(identity.get("hostname"))
    _add(identity.get("endpoint_id"))

    # device_iid / hostname → every enrolled endpoint_id (the reverse of
    # `_endpoint_id_aliases`).  A hostname may legitimately have been
    # enrolled more than once, so every match is carried.
    #
    # P0-2C: the enrolment registry IS tenant-partitioned, so the reverse
    # lookup is constrained to the tenants the resolved identity/caller
    # owns.  Without it, a hostname enrolled in two customers handed one
    # customer's surface the other customer's `endpoint_id`, and every
    # downstream query built from this alias set would then address the
    # other customer's records.  The constraint can only narrow.
    match = [{k: v} for k, v in (("device_iid", identity.get("device_iid")),
                                 ("hostname", identity.get("hostname"))) if v]
    if match:
        q: Dict[str, Any] = {"$or": match}
        if tenant_ids is not None:
            q["tenant_id"] = {"$in": [str(t) for t in tenant_ids]}
        for row in sync_collection("edr_endpoints").find(
                q, {"_id": 0, "endpoint_id": 1}):
            _add(row.get("endpoint_id"))
    return refs


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
    aliases = _endpoint_id_aliases(device_ref.strip())
    needles = {needle} | set(aliases)
    via_endpoint = bool(aliases)
    for row in list_devices(cross_tenant):
        if (row.get("device_iid") or "").lower() in needles:
            return {**row, "resolved_via": ("endpoint_id" if via_endpoint
                                            else "device_iid"),
                    "endpoint_id": (device_ref.strip() if via_endpoint
                                    else None)}
        if (row.get("hostname") or "").lower() in needles:
            return {**row, "resolved_via": ("endpoint_id" if via_endpoint
                                            else "hostname"),
                    "endpoint_id": (device_ref.strip() if via_endpoint
                                    else None)}
    return None


def _addresses(doc: Dict[str, Any], ev: Dict[str, Any],
               refs: set) -> bool:
    """Does this observation belong to the resolved endpoint?

    P0-2C: the observation plane keys an endpoint on `event.device_iid`,
    the hostname AND the authenticated `collector_id`/`connector_id`.
    Matching only two of the four is how one query site saw evidence
    that another query site reported as absent.
    """
    for v in (ev.get("device_iid"), doc.get("device_iid"), _hostname(ev),
              doc.get("collector_id"), doc.get("connector_id"),
              ev.get("computer")):
        if v and str(v).lower() in refs:
            return True
    return False


def observations(device_ref: str, cross_tenant: bool,
                 since_iso: Optional[str] = None,
                 identity: Optional[Dict[str, Any]] = None,
                 refs: Optional[List[str]] = None) -> List[Dict[str, Any]]:
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
    ref_set = {str(r).lower() for r in (refs or []) if r}
    ref_set |= {v for v in (iid, host) if v}

    out: List[Dict[str, Any]] = []
    for doc in _obs.find({}, {"_id": 0}):
        ev = _event_of(doc)
        if not _addresses(doc, ev, ref_set):
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
            "process":       proc.get("name") or None,
            # HONEST STATE: this field previously fell back to
            # `raw["entity"]`, which for a network-only observation is
            # the remote endpoint — so the Device Trajectory rendered an
            # IP address as a running process on the PROCESSES lane.
            # No process evidence means UNKNOWN, not a substitute.
            "process_state": "OBSERVED" if proc.get("name") else "UNKNOWN",
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
            "sha256":        None,   # deprecated: never a file digest here
            "input_digest":  raw.get("sha256"),
            "file_sha256":   next((f.get("sha256") for f in (
                                 (ev.get("artefacts") or {}).get("file") or [])
                                 if isinstance(f, dict) and f.get("sha256")), None),
            "file_paths":    [f.get("path") for f in (
                                 (ev.get("artefacts") or {}).get("file") or [])
                                 if isinstance(f, dict) and f.get("path")],
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
                     cross_tenant: bool,
                     refs: Optional[List[str]] = None) -> Optional[Dict[str, Any]]:
    """Return the raw persisted observation for one ``event.iid`` on a
    resolved device.  ``None`` when the reference does not resolve —
    the caller renders an explicit unresolved state."""
    identity = resolve(device_ref, cross_tenant)
    if not identity or not event_iid:
        return None
    ref_set = {str(r).lower() for r in (refs or []) if r}
    ref_set |= {v for v in ((identity.get("device_iid") or "").lower(),
                            (identity.get("hostname") or "").lower()) if v}
    for doc in _obs.find({"event.iid": event_iid}, {"_id": 0}):
        if _addresses(doc, _event_of(doc), ref_set):
            return doc
    return None
