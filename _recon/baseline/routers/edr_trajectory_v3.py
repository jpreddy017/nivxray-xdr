"""NivXForge EDR — the production Device Trajectory sub-routes the E3 V3 surface requires.

These three reads existed ONLY in the stripped E3 preview router (`e1_shape_preview.py`), which is
not mounted and reaches synthetic fixtures. V3 therefore had no production backend for its
navigator, its artefact panel or its ATT&CK strip. This module serves them from E1's authoritative
evidence, under E1's authority, with no fixture path of any kind.

EVERY ROUTE HERE
----------------
* authenticates the principal (`get_current_user`) and derives the customer SERVER-SIDE
  (`edr_tenant`) — a client-named tenant is an input to authorization, never a result of it;
* resolves the endpoint through the ONE resolver (`endpoint_query.resolve_endpoint`), so it can
  only ever address the validated alias set of an endpoint inside the authorized customer;
* orders and places evidence by the store's OWN stored observation time — `ingest_time` is never
  substituted, because backlog replay is real on this platform;
* reports an absence AS an absence. Zero observations in an hour is zero RETAINED observations,
  not a clean hour; no ATT&CK attribution is no attribution, not an absence of attack; no file
  facts is NOT_COLLECTED, never a fabricated signer, prevalence, reputation or hash.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException

from deps import get_current_user
from routers.edr_tenancy import edr_tenant
from services.edr import endpoint_query as eq
from services.edr.endpoint_query import ENDPOINT_KEYED_STORES, TENANT_PARTITIONED_STORES

from edr_trajectory import attack as attack_mod
from edr_trajectory.production_adapter import OBSERVATION_TIME_KEY, STORES, observation_us

router = APIRouter(prefix="/edr", tags=["edr"])

HOUR_MS = 3_600_000
DAY_MS = 24 * HOUR_MS


def _scope(user, tenant_id: str) -> Dict[str, Any]:
    from routers.edr import _tenant_scope
    return _tenant_scope(user, tenant_id)


async def _resolved(endpoint_id: str, user, tenant_id: str):
    import asyncio
    res = await asyncio.to_thread(eq.resolve_endpoint, endpoint_id, _scope(user, tenant_id))
    return res


def _day_bounds(day: str) -> tuple[int, int]:
    us = observation_us(f"{day}T00:00:00+00:00")
    if us is None:
        raise HTTPException(422, "day must be YYYY-MM-DD")
    return us // 1000, us // 1000 + DAY_MS


@router.get("/endpoints/{endpoint_id}/trajectory/hours")
async def trajectory_hours(endpoint_id: str, day: str,
                           user=Depends(get_current_user),
                           tenant_id: str = Depends(edr_tenant)) -> Dict[str, Any]:
    """Observations per UTC hour for one day, from REAL retained evidence.

    BOUNDED BY THE SAME FIELD THAT ORDERS THE EVIDENCE. The first implementation of this read
    matched the endpoint and then filtered the day in Python: on a 279,554-observation endpoint it
    fetched an unordered prefix of the history, never reached the requested day, and returned
    `0` for every hour of a day that holds 6,643 observations. A zero that means "I did not look"
    rendered identically to a zero that means "nothing was retained" — which is the exact class of
    defect this platform refuses to ship. The day is therefore now a RANGE on the store's own
    observation-time field, so the query is index-served and the answer cannot depend on how much
    history the endpoint has.

    The range is a lexicographic ISO prefix window deliberately widened by one day on each side,
    because the two stores write different offset representations (`+00:00` and `Z`) and three
    corrupt offset strings are known to exist. Exactness is then applied in Python by the same
    `observation_us` the ordering authority uses, so a row this platform cannot place in time is
    never counted into an hour it cannot prove.
    """
    from datetime import date, timedelta
    from deps import db as _db
    res = await _resolved(endpoint_id, user, tenant_id)
    if not res:
        return {"day": day, "hours": [0] * 24, "state": "ENDPOINT_NOT_RESOLVED",
                **eq.unresolved_envelope(endpoint_id)}
    tenant = str(res.identity.get("tenant_id") or tenant_id)
    d0, d1 = _day_bounds(day)
    try:
        anchor = date.fromisoformat(day)
    except ValueError as ex:
        raise HTTPException(422, "day must be YYYY-MM-DD") from ex
    lo, hi = (anchor - timedelta(days=1)).isoformat(), (anchor + timedelta(days=2)).isoformat()

    CAP = 200_000
    counts = [0] * 24
    per_store: Dict[str, int] = {}
    scanned: Dict[str, int] = {}
    truncated: Dict[str, bool] = {}
    unplaceable = 0
    for store in STORES:
        tkey = OBSERVATION_TIME_KEY[store]
        fields = ENDPOINT_KEYED_STORES.get(store) or []
        partition = TENANT_PARTITIONED_STORES.get(store)
        if partition and not tenant:
            per_store[store] = scanned[store] = 0
            truncated[store] = False
            continue                                  # fail closed: no customer, no evidence
        match: Dict[str, Any] = {"$or": [{f: {"$in": list(res.refs)}} for f in fields],
                                 tkey: {"$gte": lo, "$lt": hi}}
        if partition:
            match[partition] = tenant
        n = seen = 0
        async for doc in _db[store].find(match, {"_id": 0, tkey.split(".")[0]: 1}) \
                .sort(tkey, -1).limit(CAP):
            seen += 1
            cur: Any = doc
            for part in tkey.split("."):
                cur = cur.get(part) if isinstance(cur, dict) else None
            us = observation_us(cur)
            if us is None:
                unplaceable += 1
                continue
            ms = us // 1000
            if d0 <= ms < d1:
                counts[(ms - d0) // HOUR_MS] += 1
                n += 1
        per_store[store] = n
        scanned[store] = seen
        truncated[store] = seen >= CAP
    return {
        "day": day,
        "hours": counts,
        "state": "HOURS_READY",
        "basis": "OBSERVATIONS_PER_HOUR_IN_RETAINED_EVIDENCE",
        "observation_time_keys": {s: OBSERVATION_TIME_KEY[s] for s in STORES},
        "ordering_authority": "STORED_OBSERVATION_TIME",
        "ingest_time_used_as_observation_time": False,
        "time_filter": "LEXICOGRAPHIC_ISO_PREFIX_RANGE_ON_THE_STORED_TIME, WIDENED ONE DAY EACH "
                       "SIDE, THEN EXACT PLACEMENT BY observation_us",
        "per_store": per_store,
        "rows_examined": scanned,
        "truncated": truncated,
        "truncation_meaning": ("true means this day holds more rows than the read cap and the "
                              "counts are a LOWER BOUND. It never means the hours were empty."),
        "unplaceable_no_observation_time_count": unplaceable,
        "cross_store_identity_collapsed": False,
        "cross_store_meaning": ("identity collapsing across stores is a page-level operation in "
                               "the evidence adapter and is NOT applied to this aggregate, so an "
                               "observation recorded in both stores contributes once per store."),
        "tenant_id": tenant,
        "note": ("0 means no observation is RETAINED for that hour. It is not proof that the "
                 "sensor was offline and it is not proof that nothing happened."),
    }


@router.get("/endpoints/{endpoint_id}/trajectory/file-facts")
async def trajectory_file_facts(endpoint_id: str,
                                sha256: Optional[str] = None,
                                path: Optional[str] = None,
                                user=Depends(get_current_user),
                                tenant_id: str = Depends(edr_tenant)) -> Dict[str, Any]:
    """File facts E1 ACTUALLY HOLDS for a hash or path, inside this customer.

    Two facts only: when this customer's retained evidence first observed it, and on how many of
    this customer's endpoints it appears. Signer, reputation, prevalence-in-the-world, creator and
    disposition are NOT collected by this platform and are returned as NOT_COLLECTED with the
    reason. Nothing is inferred from the file name, the path or the extension.
    """
    from deps import db as _db
    if not sha256 and not path:
        return {"state": "NO_KEY"}
    res = await _resolved(endpoint_id, user, tenant_id)
    if not res:
        return {"state": "ENDPOINT_NOT_RESOLVED", **eq.unresolved_envelope(endpoint_id)}
    tenant = str(res.identity.get("tenant_id") or tenant_id)

    NC = {"state": "NOT_COLLECTED", "reason": "not collected by the NivXForge sensor"}
    first_ms: Optional[int] = None
    first_ref: Optional[str] = None
    devices: set[str] = set()
    for store in STORES:
        tkey = OBSERVATION_TIME_KEY[store]
        partition = TENANT_PARTITIONED_STORES.get(store)
        if partition and not tenant:
            continue
        keys = (["event.process.sha256", "event.file.sha256"] if store == "v2_shadow_observations"
                else ["process.hashes.sha256", "file.hashes.sha256"])
        paths = (["event.process.image", "event.file.path"] if store == "v2_shadow_observations"
                 else ["process.executable_path", "file.path"])
        ors = ([{k: sha256} for k in keys] if sha256 else []) + \
              ([{k: path} for k in paths] if path else [])
        match: Dict[str, Any] = {"$or": ors}
        if partition:
            match[partition] = tenant
        dev_fields = (["event.device_iid", "collector_id", "event.computer"]
                      if store == "v2_shadow_observations"
                      else ["provenance.collector_id", "host.host_id", "host.hostname"])
        async for doc in _db[store].find(match, {"_id": 0}).sort(tkey, 1).limit(5_000):
            cur: Any = doc
            for part in tkey.split("."):
                cur = cur.get(part) if isinstance(cur, dict) else None
            us = observation_us(cur)
            if us is not None and (first_ms is None or us // 1000 < first_ms):
                first_ms = us // 1000
                first_ref = doc.get("observation_id") or doc.get("event_id")
            for f in dev_fields:
                v: Any = doc
                for part in f.split("."):
                    v = v.get(part) if isinstance(v, dict) else None
                if v:
                    devices.add(str(v))
                    break
    if first_ms is None and not devices:
        return {"state": "NO_EVIDENCE_IN_THIS_CUSTOMER",
                "first_seen_on_device": NC, "prevalence_devices": 0,
                "signer": NC, "reputation": NC, "creator": NC,
                "basis": "no retained observation in this customer carries this hash or path",
                "tenant_id": tenant}
    from edr_trajectory.contracts import iso
    return {
        "state": "FACTS",
        "first_seen_on_device": iso(first_ms) if first_ms is not None else NC,
        "first_observation_id": first_ref or NC,
        "prevalence_devices": len(devices),
        "prevalence_scope": "ENDPOINTS_IN_THIS_CUSTOMER_WITH_RETAINED_EVIDENCE",
        "signer": NC,
        "reputation": NC,
        "creator": NC,
        "disposition": NC,
        "basis": "retained E1 evidence in this customer, placed by stored observation time",
        "tenant_id": tenant,
    }


@router.get("/endpoints/{endpoint_id}/trajectory/attack")
async def trajectory_attack(endpoint_id: str,
                            time_start: Optional[str] = None,
                            time_end: Optional[str] = None,
                            include_heuristic: bool = False,
                            user=Depends(get_current_user),
                            tenant_id: str = Depends(edr_tenant)) -> Dict[str, Any]:
    """The ATT&CK strip for this endpoint, from E1's ONE ATT&CK authority.

    Attribution is not minted here. It comes from E1 findings that carry `attck` metadata — i.e.
    from a rule that has the authority to make the claim — decorated against the vendored official
    STIX catalogue that the ATT&CK HeatMap already uses. When no finding claims this endpoint, the
    strip is returned with every tactic present and `observed: false`: an empty strip means NO
    OBSERVED TECHNIQUE, which is not a statement that no attack occurred.
    """
    import asyncio
    res = await _resolved(endpoint_id, user, tenant_id)
    if not res:
        return {"state": "ENDPOINT_NOT_RESOLVED", **eq.unresolved_envelope(endpoint_id),
                **attack_mod.device_summary([], None, None, ms_of=lambda r: None)}
    tenant = str(res.identity.get("tenant_id") or tenant_id)

    from edr_plane.fabric import store as finding_store
    items, _ = await asyncio.to_thread(
        finding_store.read, tenant,
        limit=500,
        endpoint_ref=str(res.identity.get("endpoint_id") or endpoint_id))

    rows = []
    for f in (items or []):
        attck = f.get("attck") or []
        if not attck:
            continue
        rows.append({
            "event_iid": None,
            "mitre": [str(x) for x in attck if x],
            "mitre_basis": f.get("attck_basis") or f.get("detection_source"),
            "findings": [{"rule_id": f.get("rule_id"), "rule_name": f.get("rule_name"),
                          "rule_version": f.get("rule_version"),
                          "engine": f.get("analyzer_id"), "confidence": f.get("confidence"),
                          "attck_basis": f.get("attck_basis"), "attck": attck,
                          "severity": f.get("severity")}],
            "observed_ms": (observation_us(f.get("observed_at")) or 0) // 1000
            if f.get("observed_at") else None,
        })

    t0 = observation_us(time_start) if time_start else None
    t1 = observation_us(time_end) if time_end else None
    out = attack_mod.device_summary(
        rows, t0 // 1000 if t0 is not None else None, t1 // 1000 if t1 is not None else None,
        ms_of=lambda r: r.get("observed_ms"), include_heuristic=include_heuristic)
    out["state"] = "ATTACK_READY"
    out["tenant_id"] = tenant
    out["attribution_authority"] = ("E1 findings carrying rule-declared ATT&CK metadata "
                                    "(edr_plane.fabric findings), decorated from the vendored "
                                    "official STIX catalogue")
    out["findings_considered"] = len(items or [])
    out["findings_with_attck"] = len(rows)
    out["meaning"] = ("an empty strip means NO OBSERVED TECHNIQUE in retained evidence. It is "
                      "not a statement that no attack occurred, and a technique badge is never a "
                      "verdict on its own.")
    out["mock_data_reachable"] = False
    return out
