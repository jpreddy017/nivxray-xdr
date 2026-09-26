"""P0-C · the write path that makes an EDR finding durable.

Called from the authenticated telemetry canonicalisation path, right
after the platform has recorded what its detection plane did with the
event. Two things are written, both derived from real recorded facts:

1. the FINDINGS the detection produced, into `edr_findings` — durable,
   content-addressed, tenant-partitioned, immutable;
2. the EVALUATION STATE of that piece of evidence, into
   `edr_finding_evaluations` — so "no finding" can never be confused
   with "never evaluated" or "evaluation failed".

This module lives OUTSIDE `edr_plane.fabric` on purpose: the fabric may
not read or write the evidence stores, and the per-rule detection
citations it needs are read here and handed in as data.

No detection is invented. The producing source is the NivXRay XDR ingest
detection pipeline and every finding says so — NivXForge has no local
behavioural, prevention, reputation or ML engine in this build.
"""
from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

from deps import sync_collection

from edr_plane.exclusions import enforcement, store as exclusion_store
from edr_plane.exclusions.contracts import ExclusionEngine
from edr_plane.fabric import evaluation_state as ev_state, store as finding_store
from edr_plane.fabric.analyzers.deterministic_rule import ANALYZER
from edr_plane.fabric.contracts import EvidenceUnit, Outcome

SERVER_ENGINE = ExclusionEngine.SERVER_DETERMINISTIC_RULE.value
CITATIONS = "xdr_detection_matches"


def _citations(tenant_id: str, canonical_event_id: str,
               raw_ref: Optional[str] = None) -> List[Dict[str, Any]]:
    """The producing source's OWN per-rule records for this evidence.

    The XDR pipeline canonicalises the event under its OWN canonical id
    and records the citation against that id plus the ingest trace, which
    is the raw event id. The EDR plane's canonical id is a different
    identity for the same event, so the join is made on BOTH — never by
    resemblance, and never by assuming they are equal.
    """
    keys: List[Dict[str, Any]] = [{"canonical_event_id": canonical_event_id}]
    if raw_ref:
        keys += [{"trace_id": raw_ref}, {"raw_ref": raw_ref}]
    return list(sync_collection(CITATIONS).find(
        {"tenant_id": tenant_id, "$or": keys},
        {"_id": 0, "rule_id": 1, "rule_version": 1, "rule_name": 1,
         "severity": 1, "confidence": 1, "mitre_attack": 1,
         "canonical_event_id": 1}))


def _persist(unit: EvidenceUnit, exclusions: List[Dict[str, Any]]
             ) -> Dict[str, Any]:
    result, decision = enforcement.gate(
        analyzer=ANALYZER, unit=unit, exclusions=exclusions,
        engine=SERVER_ENGINE)
    common = dict(tenant_id=unit.tenant_id, evidence_ref=unit.evidence_ref,
                  analyzer_id=ANALYZER.id, analyzer_version=ANALYZER.version,
                  endpoint_ref=unit.endpoint_ref,
                  observed_at=unit.observed_at)
    if decision.excluded:
        ledger = ev_state.record(
            state=ev_state.EvaluationState
            .EVALUATION_SUPPRESSED_BY_EXCLUSION,
            reason=decision.basis, **common)
        return {"findings_persisted": 0, "outcome": result.outcome,
                "evaluation_state": ledger["state"],
                "exclusion_id": decision.exclusion_id}

    if result.outcome == Outcome.FINDINGS.value:
        written = finding_store.persist(result.findings)
        ledger = ev_state.record(
            state=ev_state.EvaluationState.FINDINGS_PRESENT,
            detection_source=result.findings[0].detection_source,
            finding_ids=written["finding_ids"], **common)
        return {"findings_persisted": len(written["finding_ids"]),
                "newly_inserted": written["inserted"],
                "already_present": written["already_present"],
                "finding_ids": written["finding_ids"],
                "outcome": result.outcome,
                "evaluation_state": ledger["state"]}

    state = {Outcome.EVALUATED_NO_FINDING.value:
             ev_state.EvaluationState.EVALUATED_NO_FINDING,
             Outcome.NOT_EVALUATED.value:
             ev_state.EvaluationState.NOT_EVALUATED}[result.outcome]
    ledger = ev_state.record(state=state,
                             reason=result.reason or (
                                 "the analyzer evaluated this evidence and "
                                 "produced no finding"),
                             **common)
    return {"findings_persisted": 0, "outcome": result.outcome,
            "evaluation_state": ledger["state"],
            "reason": ledger["reason"]}


async def record_endpoint_detection(db: Any, *, tenant_id: str,
                                    endpoint_ref: Optional[str],
                                    canonical_event_id: str,
                                    payload: str,
                                    observed_at: Optional[str],
                                    derivation: Dict[str, Any],
                                    raw_ref: Optional[str] = None
                                    ) -> Dict[str, Any]:
    """Make the outcome of ONE detection durable. Never raises.

    A failure here must not destroy the honest record that the evidence
    exists, so it is recorded as EVALUATION_FAILED for that evidence —
    which is a different fact from "no finding".
    """
    try:
        citations = await asyncio.to_thread(_citations, tenant_id,
                                            canonical_event_id, raw_ref)
        exclusions = await exclusion_store.enforceable_for_endpoint(
            db, tenant_id=tenant_id, endpoint_id=endpoint_ref)
        unit = EvidenceUnit(
            tenant_id=tenant_id, evidence_ref=canonical_event_id,
            endpoint_ref=endpoint_ref, observed_at=observed_at,
            activity=enforcement.payload_activity(payload),
            derivations=[derivation], detection_citations=citations)
        return await asyncio.to_thread(_persist, unit, exclusions)
    except Exception as e:                                     # noqa: BLE001
        why = ("the finding plane could not evaluate this evidence; the "
               "evidence itself EXISTS and is replayable — the detection "
               "outcome for it is unknown, not absent: " + str(e)[:200])
        try:
            await asyncio.to_thread(
                ev_state.record, tenant_id=tenant_id,
                evidence_ref=canonical_event_id, analyzer_id=ANALYZER.id,
                analyzer_version=ANALYZER.version,
                endpoint_ref=endpoint_ref, observed_at=observed_at,
                state=ev_state.EvaluationState.EVALUATION_FAILED,
                reason=why)
        except Exception:                                      # noqa: BLE001
            pass
        return {"findings_persisted": 0,
                "evaluation_state":
                    ev_state.EvaluationState.EVALUATION_FAILED.value,
                "reason": why}
