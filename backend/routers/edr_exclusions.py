"""GATE 7 · Exclusion Sets — authoring, approval and PROVEN enforcement.

The surface that matters most here is `/enforcement-proof`: it runs the
REAL detection fabric over REAL persisted evidence twice — once with the
tenant's approved exclusions and once without — and reports the delta.
A MongoDB record that changes nothing cannot pass it.
"""
from __future__ import annotations

import json
from collections import Counter
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from deps import db as _db, get_current_user, sync_collection
from edr_plane.connector import catalog
from edr_plane.enrollment import store as enrollment_store
from edr_plane.exclusions import enforcement, store as exclusion_store
from edr_plane.exclusions.contracts import (AUTHORITY_CONTRACT, ApprovalState,
                                            ENDPOINT_ENGINES, ExclusionDraft,
                                            ExclusionEngine, ExclusionType,
                                            LifecycleState, MatchKind,
                                            SERVER_ENGINES, TruthState)
from edr_plane.fabric.analyzers.deterministic_rule import ANALYZER
from edr_plane.fabric.contracts import EvidenceUnit, Outcome
from edr_plane.policy import store as policy_store
from routers.edr_tenancy import edr_scope, edr_tenant

router = APIRouter(prefix="/edr/exclusions",
                   tags=["nivxforge-edr-exclusions"])

RAW_EVENTS = "edr_raw_events"
SERVER_ENGINE = ExclusionEngine.SERVER_DETERMINISTIC_RULE.value


def _who(user: dict) -> str:
    return (user or {}).get("email") or "unknown"


def _fail(e: exclusion_store.ExclusionError):
    raise HTTPException(status_code=e.status,
                        detail={"code": e.code, "reason": e.reason})


def _scoped(tenant_id: str, user: dict) -> str:
    edr_scope(tenant_id, user)
    return tenant_id


# ── taxonomy (so the console never hardcodes a vocabulary) ───────────
@router.get("/taxonomy")
async def taxonomy(user: dict = Depends(get_current_user)) -> Dict[str, Any]:
    return {
        "types": [t.value for t in ExclusionType],
        "match_kinds": [m.value for m in MatchKind],
        "engines": [{"engine": e.value,
                     "enforcement_point": ("SERVER_FABRIC"
                                           if e.value in SERVER_ENGINES
                                           else "ENDPOINT"),
                     "implemented": e.value in SERVER_ENGINES}
                    for e in ExclusionEngine],
        "truth_states": [s.value for s in TruthState],
        "lifecycle_states": [s.value for s in LifecycleState],
        "approval_states": [s.value for s in ApprovalState],
        "authority_contract": AUTHORITY_CONTRACT,
        "connector_capabilities": catalog.capabilities(
            "nvf-connector-windows-0.2.0-x64"),
        "endpoint_enforcement_contract": (
            "ENDPOINT_EXCLUSION_APPLIED is derived ONLY from an enforcement "
            "report the endpoint produced on its own authenticated session. "
            "A delivered configuration proves nothing about enforcement."),
    }


# ── sets ─────────────────────────────────────────────────────────────
class CreateSetBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=2, max_length=120)
    description: Optional[str] = Field(default=None, max_length=2000)
    os: str = Field(default="WINDOWS", pattern="^(WINDOWS|LINUX|MACOS|ANY)$")


@router.get("/sets")
async def list_sets(user: dict = Depends(get_current_user),
                    tenant_id: str = Depends(edr_tenant)) -> Dict[str, Any]:
    tenant = _scoped(tenant_id, user)
    rows = await exclusion_store.list_sets(_db, tenant_id=tenant)
    return {"tenant_id": tenant, "sets": rows, "count": len(rows)}


@router.post("/sets")
async def create_set(body: CreateSetBody,
                     user: dict = Depends(get_current_user),
                     tenant_id: str = Depends(edr_tenant)) -> Dict[str, Any]:
    tenant = _scoped(tenant_id, user)
    try:
        return await exclusion_store.create_set(
            _db, tenant_id=tenant, name=body.name,
            description=body.description, os_family=body.os, by=_who(user))
    except exclusion_store.ExclusionError as e:
        _fail(e)


# ── exclusions ───────────────────────────────────────────────────────
@router.get("")
async def list_exclusions(set_id: Optional[str] = None,
                          user: dict = Depends(get_current_user),
                          tenant_id: str = Depends(edr_tenant)
                          ) -> Dict[str, Any]:
    """Every exclusion with its lifecycle AND its per-enforcement-point
    truth state. An approved exclusion aimed at an endpoint engine is
    reported honestly as not supported or pending policy."""
    tenant = _scoped(tenant_id, user)
    rows = await exclusion_store.list_exclusions(_db, tenant_id=tenant,
                                                 set_id=set_id)
    endpoints = [e async for e in _db[enrollment_store.ENDPOINTS].find(
        {"tenant_id": tenant}, {"_id": 0})]
    states, caps = {}, {}
    for ep in endpoints:
        states[ep["endpoint_id"]] = await policy_store.endpoint_policy_state(
            _db, tenant_id=tenant, endpoint=ep)
        #: Capability is read from the release the endpoint is ACTUALLY
        #: running, not from the newest release in the catalog.
        caps[ep["endpoint_id"]] = catalog.capabilities_for_connector_version(
            ep.get("sensor_version"), ep.get("platform"))
    enforcement_map = await exclusion_store.endpoint_enforcement_map(
        _db, tenant_id=tenant)
    per_endpoint = {}
    for ep in endpoints:
        per_endpoint[ep["endpoint_id"]] = \
            await exclusion_store.endpoint_enforcement_map(
                _db, tenant_id=tenant, endpoint_id=ep["endpoint_id"])
    for r in rows:
        points = []
        for engine in (r.get("affected_engines") or []):
            if engine in SERVER_ENGINES:
                points.append({
                    "engine": engine, "enforcement_point": "SERVER_FABRIC",
                    "truth_state": (TruthState.SERVER_EXCLUSION_APPLIED.value
                                    if r["enforceable"] else
                                    "NOT_ENFORCED_" + r["lifecycle"]["state"]),
                    "basis": ("the detection fabric consults this exclusion "
                              "before the deterministic analyzer runs"
                              if r["enforceable"]
                              else r["lifecycle"]["basis"])})
            elif engine in ENDPOINT_ENGINES:
                per = [enforcement.endpoint_truth_state(
                    r, engine=engine,
                    connector_capabilities=caps.get(eid) or {},
                    endpoint_policy_state=st,
                    enforcement=(per_endpoint.get(eid) or {}).get(
                        r["exclusion_id"]))
                    for eid, st in states.items()]
                counts = Counter(p["truth_state"] for p in per)
                #: The estate state is the STRONGEST proven state: one
                #: endpoint that genuinely enforced it is enforcement.
                applied = TruthState.ENDPOINT_EXCLUSION_APPLIED.value
                estate = (applied if counts.get(applied) else
                          (per[0]["truth_state"] if per else
                           TruthState
                           .EXCLUSION_NOT_SUPPORTED_BY_ENGINE.value))
                folded = enforcement_map.get(r["exclusion_id"]) or {}
                points.append({
                    "engine": engine, "enforcement_point": "ENDPOINT",
                    "truth_state": estate,
                    "endpoint_distribution": dict(counts),
                    "endpoints_enforcing": counts.get(applied, 0),
                    "honoured_count": folded.get("honoured_count") or 0,
                    "last_enforced_at": folded.get("last_at"),
                    "evaluator_version": folded.get("evaluator_version"),
                    "basis": (next((p["basis"] for p in per
                                    if p["truth_state"] == estate), None)
                              or ("no endpoint is enrolled in this tenant"))})
        r["enforcement"] = points
    return {"tenant_id": tenant, "exclusions": rows, "count": len(rows),
            "authority_contract": AUTHORITY_CONTRACT}


@router.post("")
async def create_exclusion(body: ExclusionDraft,
                           user: dict = Depends(get_current_user),
                           tenant_id: str = Depends(edr_tenant)
                           ) -> Dict[str, Any]:
    tenant = _scoped(tenant_id, user)
    try:
        doc = await exclusion_store.create_exclusion(_db, tenant_id=tenant,
                                                     draft=body,
                                                     by=_who(user))
    except exclusion_store.ExclusionError as e:
        _fail(e)
    return {**doc, "note": ("PENDING_APPROVAL. No engine consults an "
                            "unapproved exclusion, so protection is "
                            "unchanged until a second operator approves it.")}


class ApproveBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: str = Field(pattern="^(APPROVED|REJECTED)$")
    note: Optional[str] = Field(default=None, max_length=2000)


@router.post("/{exclusion_id}/approval")
async def approve(exclusion_id: str, body: ApproveBody,
                  user: dict = Depends(get_current_user),
                  tenant_id: str = Depends(edr_tenant)) -> Dict[str, Any]:
    tenant = _scoped(tenant_id, user)
    try:
        return await exclusion_store.approve(
            _db, tenant_id=tenant, exclusion_id=exclusion_id, by=_who(user),
            decision=body.decision, note=body.note)
    except exclusion_store.ExclusionError as e:
        _fail(e)


class RevokeBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(min_length=5, max_length=2000)


@router.post("/{exclusion_id}/revoke")
async def revoke(exclusion_id: str, body: RevokeBody,
                 user: dict = Depends(get_current_user),
                 tenant_id: str = Depends(edr_tenant)) -> Dict[str, Any]:
    tenant = _scoped(tenant_id, user)
    try:
        return await exclusion_store.revoke(
            _db, tenant_id=tenant, exclusion_id=exclusion_id, by=_who(user),
            reason=body.reason)
    except exclusion_store.ExclusionError as e:
        _fail(e)


# ── the proof ────────────────────────────────────────────────────────
@router.get("/enforcement-proof")
async def enforcement_proof(sample: int = Query(300, ge=10, le=2000),
                            user: dict = Depends(get_current_user),
                            tenant_id: str = Depends(edr_tenant)
                            ) -> Dict[str, Any]:
    """Does this tenant's exclusion set ACTUALLY change the engine?

    READ-ONLY. Real `edr_raw_events` rows for this tenant are evaluated
    through the registered deterministic analyzer twice: once through the
    exclusion gate and once without it. The delta is the objective
    evidence that an exclusion affects an engine rather than a database.
    """
    tenant = _scoped(tenant_id, user)
    exclusions = await exclusion_store.enforceable_for_endpoint(
        _db, tenant_id=tenant)
    coll = sync_collection(RAW_EVENTS)
    rows = list(coll.find(
        {"tenant_id": tenant, "derivations": {"$exists": True, "$ne": []}},
        {"_id": 0, "tenant_id": 1, "endpoint_ref": 1, "payload": 1,
         "derivations": 1, "ingest_time": 1}).limit(sample))

    baseline: Counter = Counter()
    gated: Counter = Counter()
    bypassed: List[Dict[str, Any]] = []
    for r in rows:
        canonical = next((d.get("event_id") for d in r["derivations"]
                          if d.get("event_id")), None)
        if not canonical:
            baseline["NO_CANONICAL_REFERENCE_SKIPPED"] += 1
            gated["NO_CANONICAL_REFERENCE_SKIPPED"] += 1
            continue
        unit = EvidenceUnit(
            tenant_id=r.get("tenant_id") or tenant,
            evidence_ref=canonical, endpoint_ref=r.get("endpoint_ref"),
            observed_at=r.get("ingest_time"),
            activity=enforcement.payload_activity(r.get("payload") or ""),
            derivations=r.get("derivations") or [])
        base = ANALYZER.evaluate(unit)
        baseline[base.outcome] += 1
        result, decision = enforcement.gate(
            analyzer=ANALYZER, unit=unit, exclusions=exclusions,
            engine=SERVER_ENGINE)
        gated[result.outcome] += 1
        if decision.excluded:
            bypassed.append({
                **decision.to_dict(),
                "evidence_ref": canonical,
                "endpoint_ref": r.get("endpoint_ref"),
                "baseline_outcome": base.outcome,
                "gated_outcome": result.outcome,
                "baseline_findings": len(base.findings),
                #: TWO different facts, both preserved:
                #: what happened to the EVIDENCE, and WHERE the exclusion
                #: was enforced.
                "evidence_truth_state": (
                    TruthState.EXCLUDED.value if base.findings
                    else TruthState.NOT_EVALUATED_DUE_TO_EXCLUSION.value),
                "enforcement_truth_state": decision.truth_state,
                "truth_state": (
                    TruthState.EXCLUDED.value if base.findings
                    else TruthState.NOT_EVALUATED_DUE_TO_EXCLUSION.value),
            })
    findings_suppressed = sum(b["baseline_findings"] for b in bypassed)
    return {
        "tenant_id": tenant,
        "evidence_sampled": len(rows),
        "approved_exclusions_consulted": len(exclusions),
        "baseline_outcomes": dict(baseline),
        "gated_outcomes": dict(gated),
        "evidence_bypassed": len(bypassed),
        "findings_suppressed": findings_suppressed,
        "engine": SERVER_ENGINE,
        "enforcement_point": "SERVER_FABRIC",
        "changed_engine_behaviour": bool(bypassed),
        "examples": bypassed[:25],
        "method": ("the registered deterministic analyzer was executed over "
                   "real persisted evidence twice — with and without the "
                   "exclusion gate. Nothing was written."),
        "verdict": ("EXCLUSIONS AFFECT THE ENGINE" if bypassed else
                    "NO APPROVED EXCLUSION MATCHED THE SAMPLED EVIDENCE — "
                    "this is not a claim that exclusions do not work; it "
                    "means nothing in this sample was excluded"),
    }
