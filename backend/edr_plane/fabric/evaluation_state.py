"""P0-C · the EVALUATION STATE ledger.

Why this exists: an empty findings list is NOT a statement that an
endpoint or an event was evaluated and found clean. Without a recorded
evaluation state, "no findings" and "never looked" are the same API
response — which is exactly how a console starts implying safety it
cannot support.

So every evaluation of a piece of evidence records what actually
happened, and the read surface derives its disclosure from THIS ledger,
never from the emptiness of `edr_findings`.

    UNKNOWN != ABSENT != VERIFIED
    NO FINDING != BENIGN
    NOT EVALUATED != NO FINDING
    EVALUATION FAILED != NO FINDING

A state is only ever written from a real evaluation attempt. Nothing in
this module manufactures EVALUATED_NO_FINDING because a finding document
happens not to exist.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence

from deps import sync_collection

COLLECTION = "edr_finding_evaluations"


class EvaluationState(str, Enum):
    FINDINGS_PRESENT = "FINDINGS_PRESENT"
    EVALUATED_NO_FINDING = "EVALUATED_NO_FINDING"
    NOT_EVALUATED = "NOT_EVALUATED"
    EVALUATION_FAILED = "EVALUATION_FAILED"
    #: P0-B · an approved exclusion suppressed the verdict for this
    #: evidence. It is neither "no finding" nor "not evaluated by
    #: accident" — the platform was told not to judge it.
    EVALUATION_SUPPRESSED_BY_EXCLUSION = \
        "EVALUATION_SUPPRESSED_BY_EXCLUSION"


STATE_MEANING: Dict[str, str] = {
    EvaluationState.FINDINGS_PRESENT.value: (
        "the evidence was evaluated and at least one finding was produced"),
    EvaluationState.EVALUATED_NO_FINDING.value: (
        "the evidence WAS evaluated by the stated analyzer and that "
        "analyzer produced no finding. This is not a statement that the "
        "activity was benign, and it says nothing about engines that do "
        "not exist yet"),
    EvaluationState.NOT_EVALUATED.value: (
        "the evidence was NOT evaluated — the reason is recorded. This is "
        "not a finding of absence and must never be presented as clean"),
    EvaluationState.EVALUATION_FAILED.value: (
        "an evaluation was attempted and FAILED. The evidence is retained "
        "and replayable; the detection outcome for it is unknown"),
    EvaluationState.EVALUATION_SUPPRESSED_BY_EXCLUSION.value: (
        "an approved exclusion suppressed the verdict for this evidence "
        "(P0-B). The evidence itself is retained unless the exclusion was "
        "COLLECTION-scoped, in which case it never existed"),
}

NO_EVALUATION_RECORDED = "NO_EVALUATION_RECORDED"

DISCLOSURE_CONTRACT = (
    "An empty findings array is never sufficient to claim that an endpoint "
    "or an event was evaluated and found clean. Read evaluation_state: it "
    "is recorded per piece of evidence at the moment of evaluation. "
    "Evidence with no ledger row is NOT_EVALUATED · "
    f"{NO_EVALUATION_RECORDED} — the platform has no record of having "
    "looked at it."
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_indexes() -> None:
    coll = sync_collection(COLLECTION)
    coll.create_index([("tenant_id", 1), ("evidence_ref", 1),
                       ("analyzer_id", 1)], unique=True)
    coll.create_index([("tenant_id", 1), ("endpoint_ref", 1), ("state", 1)])
    coll.create_index([("tenant_id", 1), ("recorded_at", -1)])


def record(*, tenant_id: str, evidence_ref: str, analyzer_id: str,
           analyzer_version: str, state: EvaluationState,
           reason: Optional[str] = None, endpoint_ref: Optional[str] = None,
           detection_source: Optional[str] = None,
           finding_ids: Sequence[str] = (),
           observed_at: Optional[str] = None) -> Dict[str, Any]:
    """Record the state of ONE real evaluation attempt.

    The ledger holds the CURRENT evaluation state per (evidence,
    analyzer); the findings themselves stay immutable. A later evaluation
    updates the state and increments the attempt count, and the first
    attempt is never lost (`first_recorded_at`).
    """
    value = state.value if isinstance(state, EvaluationState) else str(state)
    if value in (EvaluationState.NOT_EVALUATED.value,
                 EvaluationState.EVALUATION_FAILED.value) and not reason:
        raise ValueError(f"{value} must state its reason")
    now = _now()
    doc = {"state": value, "reason": reason, "recorded_at": now,
           "analyzer_version": analyzer_version,
           "endpoint_ref": endpoint_ref,
           "detection_source": detection_source,
           "observed_at": observed_at,
           "finding_ids": list(finding_ids)}
    sync_collection(COLLECTION).update_one(
        {"tenant_id": tenant_id, "evidence_ref": evidence_ref,
         "analyzer_id": analyzer_id},
        {"$set": doc,
         "$setOnInsert": {"tenant_id": tenant_id,
                          "evidence_ref": evidence_ref,
                          "analyzer_id": analyzer_id,
                          "first_recorded_at": now},
         "$inc": {"evaluation_attempts": 1}},
        upsert=True)
    return {"evidence_ref": evidence_ref, "analyzer_id": analyzer_id,
            **doc}


def _match(tenant_id: str, endpoint_ref: Optional[str] = None,
           since: Optional[str] = None) -> Dict[str, Any]:
    q: Dict[str, Any] = {"tenant_id": tenant_id}
    if endpoint_ref:
        q["endpoint_ref"] = endpoint_ref
    if since:
        q["recorded_at"] = {"$gte": since}
    return q


def summary(tenant_id: str, *, endpoint_ref: Optional[str] = None,
            since: Optional[str] = None) -> Dict[str, Any]:
    coll = sync_collection(COLLECTION)
    q = _match(tenant_id, endpoint_ref, since)
    by_state = {r["_id"]: r["n"] for r in coll.aggregate(
        [{"$match": q}, {"$group": {"_id": "$state", "n": {"$sum": 1}}}])}
    total = sum(by_state.values())
    return {
        "evidence_with_a_recorded_evaluation": total,
        "by_state": by_state,
        "state_meaning": {s: STATE_MEANING[s] for s in by_state},
        "disclosure": DISCLOSURE_CONTRACT,
        "empty_result_meaning": (
            "no evaluation has been recorded for this scope: the state is "
            f"NOT_EVALUATED · {NO_EVALUATION_RECORDED}, NOT 'evaluated and "
            "clean'") if total == 0 else None,
    }


def for_evidence(tenant_id: str, evidence_refs: Sequence[str]
                 ) -> Dict[str, Dict[str, Any]]:
    rows = sync_collection(COLLECTION).find(
        {"tenant_id": tenant_id, "evidence_ref": {"$in": list(evidence_refs)}},
        {"_id": 0})
    return {r["evidence_ref"]: r for r in rows}


def endpoint_states(tenant_id: str, endpoint_refs: Sequence[str]
                    ) -> List[Dict[str, Any]]:
    """Per-endpoint evaluation state — an endpoint with no ledger row is
    reported as NOT_EVALUATED with the reason, never as clean."""
    coll = sync_collection(COLLECTION)
    rows = list(coll.aggregate([
        {"$match": {"tenant_id": tenant_id,
                    "endpoint_ref": {"$in": list(endpoint_refs)}}},
        {"$group": {"_id": {"e": "$endpoint_ref", "s": "$state"},
                    "n": {"$sum": 1}}}]))
    per: Dict[str, Dict[str, int]] = {}
    for r in rows:
        per.setdefault(r["_id"]["e"], {})[r["_id"]["s"]] = r["n"]
    out = []
    for ref in endpoint_refs:
        states = per.get(ref) or {}
        if not states:
            out.append({"endpoint_ref": ref,
                        "state": EvaluationState.NOT_EVALUATED.value,
                        "reason": NO_EVALUATION_RECORDED,
                        "meaning": STATE_MEANING[
                            EvaluationState.NOT_EVALUATED.value],
                        "by_state": {}})
            continue
        if states.get(EvaluationState.FINDINGS_PRESENT.value):
            state = EvaluationState.FINDINGS_PRESENT.value
        elif states.get(EvaluationState.EVALUATION_FAILED.value):
            state = EvaluationState.EVALUATION_FAILED.value
        elif states.get(EvaluationState.EVALUATED_NO_FINDING.value):
            state = EvaluationState.EVALUATED_NO_FINDING.value
        elif states.get(
                EvaluationState.EVALUATION_SUPPRESSED_BY_EXCLUSION.value):
            state = EvaluationState.EVALUATION_SUPPRESSED_BY_EXCLUSION.value
        else:
            state = EvaluationState.NOT_EVALUATED.value
        out.append({"endpoint_ref": ref, "state": state,
                    "reason": None, "meaning": STATE_MEANING[state],
                    "by_state": states})
    return out
