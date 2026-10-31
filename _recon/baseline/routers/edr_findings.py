"""P0-C · DURABLE EDR FINDINGS — the read plane.

Read-only. Four operations, all tenant-authorised through the same EDR
authority every other control-plane read uses.

The contract this surface exists to keep:

    an empty `findings` array is NOT a statement that anything was
    evaluated and found clean.

Every response therefore carries `evaluation_state`, derived from the
evaluation ledger written at the moment of evaluation — never inferred
from the absence of a finding document.

Provenance is stated, not implied: each finding names the source that
actually produced it. NivXForge has no local behavioural, prevention,
reputation or ML engine in this build, and the taxonomy says so.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from deps import get_current_user, sync_collection

from edr_plane.fabric import evaluation_state as ev_state, registry, store
from edr_plane.fabric.contracts import (DETECTION_SOURCE_DISCLOSURE,
                                        DetectionSource,
                                        IMPLEMENTED_DETECTION_SOURCES,
                                        Severity)
from routers.edr_tenancy import edr_scope, edr_tenant

router = APIRouter(prefix="/edr/findings", tags=["nivxforge-edr-findings"])

CANONICAL = "xdr_canonical_evidence"
RAW_EVENTS = "edr_raw_events"
OBSERVATIONS = "v2_shadow_observations"

PROVENANCE_CONTRACT = (
    "Every persisted finding states the source that actually produced it. "
    "A finding derived from the NivXRay XDR ingest detection pipeline is "
    "reported as XDR-produced and is never re-presented as a NivXForge "
    "local endpoint detection, an offline EDR verdict or an endpoint "
    "behavioural detection. NivXForge does not yet have a local "
    "behavioural detection engine."
)


def _scoped(tenant_id: str, user: dict) -> str:
    edr_scope(tenant_id, user)
    return tenant_id


def _disclosure() -> Dict[str, Any]:
    return {
        "empty_findings_meaning": (
            "an empty findings array means only that no finding matches "
            "this query. Read evaluation_state to learn whether the "
            "evidence was evaluated at all"),
        "truth_semantics": ["NO FINDING != BENIGN",
                            "NOT EVALUATED != NO FINDING",
                            "EVALUATION FAILED != NO FINDING",
                            "UNKNOWN != ABSENT"],
        "provenance_contract": PROVENANCE_CONTRACT,
        "local_behavioral_engine_present": False,
        "immutability": store.IMMUTABILITY_CONTRACT,
        "retrospection": ("historical re-evaluation and supersession are "
                          "NOT implemented; a finding is never rewritten "
                          "because detection logic changed later"),
    }


@router.get("/taxonomy")
async def taxonomy(user: dict = Depends(get_current_user)) -> Dict[str, Any]:
    """Product metadata · the vocabulary, so a console never hardcodes it."""
    return {
        "detection_sources": [
            {"detection_source": s.value,
             **DETECTION_SOURCE_DISCLOSURE[s.value]}
            for s in DetectionSource],
        "implemented_detection_sources": sorted(
            IMPLEMENTED_DETECTION_SOURCES),
        "severities": [s.value for s in Severity],
        "evaluation_states": [
            {"state": s.value, "meaning": ev_state.STATE_MEANING[s.value]}
            for s in ev_state.EvaluationState],
        "no_evaluation_recorded": ev_state.NO_EVALUATION_RECORDED,
        "evaluation_state_disclosure": ev_state.DISCLOSURE_CONTRACT,
        "analyzers": registry.declared_capabilities(),
        **_disclosure(),
    }


@router.get("/evaluation-state")
async def evaluation_state(endpoint_ref: Optional[str] = None,
                           endpoint_refs: Optional[str] = Query(default=None),
                           since: Optional[str] = None,
                           user: dict = Depends(get_current_user),
                           tenant_id: str = Depends(edr_tenant)
                           ) -> Dict[str, Any]:
    """What the platform has actually EVALUATED for this tenant.

    An endpoint with no recorded evaluation reads NOT_EVALUATED ·
    NO_EVALUATION_RECORDED. It is never reported as clean.
    """
    tenant = _scoped(tenant_id, user)
    refs = [r.strip() for r in (endpoint_refs or "").split(",") if r.strip()]
    if endpoint_ref:
        refs.append(endpoint_ref)
    return {
        "tenant_id": tenant,
        "summary": ev_state.summary(tenant, endpoint_ref=endpoint_ref,
                                    since=since),
        "endpoints": (ev_state.endpoint_states(tenant, refs) if refs
                      else []),
        "endpoints_note": ("per-endpoint state is reported only for the "
                           "endpoint_ref(s) asked for; this surface does "
                           "not claim a state for an endpoint it was not "
                           "asked about"),
        **_disclosure(),
    }


@router.get("")
async def list_findings(endpoint_ref: Optional[str] = None,
                        severity: Optional[str] = None,
                        rule_id: Optional[str] = None,
                        detection_source: Optional[str] = None,
                        since: Optional[str] = None,
                        until: Optional[str] = None,
                        limit: int = Query(100, ge=1, le=500),
                        cursor: Optional[str] = None,
                        user: dict = Depends(get_current_user),
                        tenant_id: str = Depends(edr_tenant)
                        ) -> Dict[str, Any]:
    tenant = _scoped(tenant_id, user)
    filters = dict(endpoint_ref=endpoint_ref, severity=severity,
                   rule_id=rule_id, detection_source=detection_source,
                   since=since, until=until)
    rows, next_cursor = store.read(tenant, limit=limit, cursor=cursor,
                                   **filters)
    return {
        "tenant_id": tenant,
        "findings": rows,
        "count": len(rows),
        "next_cursor": next_cursor,
        "counts": store.counts(tenant, **filters),
        "evaluation_state": ev_state.summary(tenant,
                                             endpoint_ref=endpoint_ref,
                                             since=since),
        **_disclosure(),
    }


def _resolve_evidence(tenant: str, refs: List[str]) -> List[Dict[str, Any]]:
    """Does every cited reference resolve to evidence that EXISTS?"""
    out: List[Dict[str, Any]] = []
    for ref in refs:
        canonical = sync_collection(CANONICAL).find_one(
            {"tenant_id": tenant, "event_id": ref},
            {"_id": 0, "event_id": 1, "event_time": 1, "source": 1})
        raw = sync_collection(RAW_EVENTS).find_one(
            {"tenant_id": tenant, "derivations.event_id": ref},
            {"_id": 0, "raw_id": 1, "endpoint_ref": 1, "ingest_time": 1})
        observation = sync_collection(OBSERVATIONS).find_one(
            {"tenant_id": tenant, "canonical_event_id": ref},
            {"_id": 0, "canonical_event_id": 1, "captured_at": 1,
             "kind": 1, "collector_id": 1})
        if canonical or raw or observation:
            out.append({"evidence_ref": ref, "state": "EVIDENCE_RESOLVED",
                        "canonical_evidence": canonical,
                        "raw_event": raw,
                        "observation": observation,
                        "resolved_in": [c for c, present in
                                        ((CANONICAL, bool(canonical)),
                                         (RAW_EVENTS, bool(raw)),
                                         (OBSERVATIONS, bool(observation)))
                                        if present]})
        else:
            out.append({"evidence_ref": ref,
                        "state": "EVIDENCE_REFERENCE_UNRESOLVED",
                        "reason": ("the cited reference does not resolve to "
                                   "evidence held for this tenant; the "
                                   "platform will NOT substitute a similar "
                                   "record")})
    return out


@router.get("/{finding_id}")
async def get_finding(finding_id: str,
                      user: dict = Depends(get_current_user),
                      tenant_id: str = Depends(edr_tenant)
                      ) -> Dict[str, Any]:
    tenant = _scoped(tenant_id, user)
    row = store.get(tenant, finding_id)
    if not row:
        raise HTTPException(status_code=404, detail={
            "code": "FINDING_NOT_FOUND",
            "reason": ("no finding with this id is held for the tenant this "
                       "request acts in")})
    ledger = ev_state.for_evidence(tenant, row.get("evidence_refs") or [])
    return {
        "tenant_id": tenant,
        "finding": row,
        "evidence": _resolve_evidence(tenant, row.get("evidence_refs") or []),
        "evaluation_state": [
            {"evidence_ref": ref,
             "state": (ledger[ref]["state"] if ref in ledger
                       else ev_state.EvaluationState.NOT_EVALUATED.value),
             "reason": (ledger[ref].get("reason") if ref in ledger
                        else ev_state.NO_EVALUATION_RECORDED)}
            for ref in (row.get("evidence_refs") or [])],
        **_disclosure(),
    }
