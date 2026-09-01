"""Round 31 · NivXRay XDR · Autonomous Investigator Orchestrator.

The Orchestrator is the closed loop:

    IUE understanding  →  planner  →  selector  →  capability
                                                         │
                                                         ▼
                                                     findings
                                                         │
                                     (recompute IUE)  ◀──┘

It runs autonomously, driven by evidence — never by a UI button.
Its state grammar is §26 (lifecycle) and its execution grammar is
§18 (Investigation Activity feed).

Persistence:
  * ``xdr_investigations``            — one row per (tenant, incident)
  * ``engine_executions``             — one row per real invocation
  * ``xdr_investigation_findings``    — findings emitted by capabilities
  * ``xdr_investigation_activity``    — activity feed entries (§18)
"""
from __future__ import annotations

import hashlib
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from services.iue.service import IUEService
from services.iue.artifacts import IUEUnderstanding
from services.investigator.models import (
    ActivityEntry, EngineExecution, Finding, InvestigationState,
    LifecycleState, PivotAction,
)
from services.investigator.lifecycle import can_transition
from services.investigator.planner import plan_pivots, select_capability


INVESTIGATIONS_COLLECTION = "xdr_investigations"
EXECUTIONS_COLLECTION     = "engine_executions"
FINDINGS_COLLECTION       = "xdr_investigation_findings"
ACTIVITY_COLLECTION       = "xdr_investigation_activity"
INCIDENTS_COLLECTION      = "workspace_cases"
CANONICAL_COLLECTION      = "xdr_canonical_evidence"


ENGINE_ID = "nivxray::investigator::v0"
ENGINE_VERSION = "0.1.0"

# Bounded loop: max pivot attempts per single tick to guarantee
# termination even under adversarial gap explosion.
MAX_PIVOTS_PER_TICK = 32


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _execution_id() -> str:
    return "exe_" + uuid.uuid4().hex[:20]


def _investigation_id(incident_id: str, tenant_id: str) -> str:
    seed = f"{tenant_id}|{incident_id}"
    return "inv_" + hashlib.sha256(seed.encode()).hexdigest()[:20]


# ── Orchestrator ────────────────────────────────────────────────────

class InvestigatorService:
    """Round 31 orchestrator.

    Entry point:  ``await InvestigatorService.tick(db, incident_id)``.
    """

    engine_id = ENGINE_ID
    engine_version = ENGINE_VERSION

    # ────────────────────────────────────────────────────────────
    @classmethod
    async def tick(cls, db, incident_id: str,
                       max_pivots: int = MAX_PIVOTS_PER_TICK,
                      ) -> InvestigationState:
        """Advance the incident's investigation by one tick.

        A tick is a bounded loop that:
          1. Loads the incident + latest IUE understanding.
          2. Plans pivots from the understanding's gaps.
          3. For each pivot, invokes the capability (or honestly
             skips + records reason).
          4. Records executions + findings.
          5. Recomputes IUE understanding if the evidence
             fingerprint changed (feedback loop).
          6. Converges when no more pivots are eligible.

        Ticks are idempotent — a second tick against unchanged
        evidence produces zero new pivots.
        """
        incident = await db[INCIDENTS_COLLECTION].find_one(
            {"id": incident_id}, {"_id": 0})
        if not incident:
            raise ValueError(f"incident_not_found: {incident_id}")

        tenant_id = incident.get("tenant_id") or "default"
        state = await cls._load_or_create_state(db, incident_id, tenant_id)

        # Ensure IUE understanding exists for the current evidence.
        understanding = await IUEService.latest_valid(db, incident_id)
        if understanding is None:
            understanding = await IUEService.understand_incident(
                db, incident_id, persist=True)

        # Idempotency: if the investigation already converged for this
        # exact evidence fingerprint, return immediately.  No new
        # transitions, no new executions, no fabricated activity.
        if state.state == "CONVERGED" \
                and state.iue_fingerprint == understanding.evidence_fingerprint:
            return state

        await cls._transition(db, state, "UNDERSTANDING_EVIDENCE",
                                  understanding=understanding,
                                  what="Consumed IUE understanding.",
                                  why="New / current governed evidence needs a plan.")

        # Load attempted pivots — the deterministic dedup key.
        attempted: Set[str] = await cls._attempted_pivot_ids(db, incident_id)

        pivots_this_tick = 0
        first_pivot_in_tick = True
        while pivots_this_tick < max_pivots:
            pivots = plan_pivots(understanding, attempted)
            if not pivots:
                break

            # Enter INVESTIGATING (or EXPANDING if not the first plan).
            target_state: LifecycleState = "INVESTIGATING" if first_pivot_in_tick \
                                                else "EXPANDING"
            if state.state != target_state:
                await cls._transition(db, state, target_state,
                                          understanding=understanding,
                                          what=f"Planned {len(pivots)} pivot(s).",
                                          why="IUE gaps have suggested capabilities.")
            first_pivot_in_tick = False

            pivot = pivots[0]  # Highest-priority, stable order.
            attempted.add(pivot.pivot_id)
            pivots_this_tick += 1

            # Log the plan step (§18 activity feed).
            await cls._append_activity(db, state, ActivityEntry(
                at=_now_iso(),
                kind="PIVOT_PLANNED",
                lifecycle_state=state.state,
                what=f"Planned pivot: {pivot.capability}",
                why=pivot.reason,
                evidence_refs=list(pivot.triggering_evidence),
                capability=pivot.capability,
                next_hint=pivot.expected_outcome,
            ))
            await cls._bump(db, state, planned=1)

            # Selector: is a real capability available?
            cap = select_capability(pivot)
            if cap is None:
                await cls._record_skip(
                    db, state, pivot,
                    reason=f"capability '{pivot.capability}' not registered",
                    status="SKIPPED_UNAVAILABLE")
                continue
            if cap.availability != "cap-full":
                await cls._record_skip(
                    db, state, pivot,
                    reason=cap.unavailable_reason
                              or f"capability '{cap.id}' is {cap.availability}",
                    status="SKIPPED_UNAVAILABLE",
                    engine_name=cap.engine)
                continue

            # Round 32 · evidence-sufficiency check — honestly skip
            # when the capability's declared inputs are missing.
            pipe_data = incident.get("xdr_pipeline") or {}
            canonical_id = pipe_data.get("canonical_event_id")
            canonical_for_check = None
            if canonical_id:
                canonical_for_check = await db[CANONICAL_COLLECTION].find_one(
                    {"event_id": canonical_id}, {"_id": 0})
            sufficiency, suf_reason = cap.check_evidence(
                incident, canonical_for_check)
            if sufficiency in ("INSUFFICIENT", "NOT_APPLICABLE"):
                await cls._record_skip(
                    db, state, pivot,
                    reason=f"evidence {sufficiency.lower()}: {suf_reason}",
                    status="SKIPPED_OUT_OF_SCOPE",
                    engine_name=cap.engine,
                    sufficiency=sufficiency)
                continue

            # Prevent duplicate execution (across ticks).
            already = await db[EXECUTIONS_COLLECTION].find_one(
                {"pivot_id": pivot.pivot_id,
                  "status":   {"$in": ["OK", "ERROR"]}},
                {"_id": 0, "execution_id": 1},
            )
            if already:
                await cls._record_skip(
                    db, state, pivot,
                    reason=(
                        f"pivot already executed as "
                        f"{already.get('execution_id')}"
                    ),
                    status="SKIPPED_DUPLICATE",
                    engine_name=cap.engine)
                continue

            # Real execution.
            exe = await cls._execute(db, state, pivot, cap, incident, understanding)
            # After execution: if new findings changed the evidence
            # fingerprint, refresh understanding for the next loop.
            new_understanding = await IUEService.latest_valid(db, incident_id)
            if new_understanding and new_understanding.evidence_fingerprint \
                    != understanding.evidence_fingerprint:
                understanding = new_understanding

        # Converge (deterministic termination).
        await cls._transition(db, state, "CONVERGING",
                                  understanding=understanding,
                                  what="No further eligible pivots.",
                                  why="All IUE gaps are exhausted or attempted.")
        await cls._transition(db, state, "CONVERGED",
                                  understanding=understanding,
                                  what="Investigation converged.",
                                  why=(
                                      f"{state.pivots_planned} planned, "
                                      f"{state.pivots_executed} executed, "
                                      f"{state.pivots_skipped} skipped."
                                  ))
        state.converged_at = _now_iso()
        state.convergence_reason = "no_more_eligible_pivots"
        state.updated_at = _now_iso()
        await cls._persist_state(db, state)
        return state

    # ── State CRUD ──────────────────────────────────────────────
    @classmethod
    async def _load_or_create_state(cls, db, incident_id: str,
                                             tenant_id: str) -> InvestigationState:
        existing = await db[INVESTIGATIONS_COLLECTION].find_one(
            {"incident_id": incident_id, "tenant_id": tenant_id},
            {"_id": 0},
        )
        if existing:
            state = InvestigationState(**existing)
            # If prior investigation converged and evidence changed,
            # reopen it.  Feedback-loop invariant (§14 rollout item 7).
            latest = await IUEService.latest_valid(db, incident_id)
            fp = latest.evidence_fingerprint if latest else None
            if state.state == "CONVERGED" and fp and fp != state.iue_fingerprint:
                await cls._transition(db, state, "REOPENED",
                                          what="New evidence detected.",
                                          why="IUE fingerprint changed post-convergence.")
            return state
        now = _now_iso()
        state = InvestigationState(
            investigation_id=_investigation_id(incident_id, tenant_id),
            tenant_id=tenant_id,
            incident_id=incident_id,
            state="WAITING_FOR_EVIDENCE",
            state_history=[{
                "state": "WAITING_FOR_EVIDENCE",
                "at": now,
                "reason": "Investigation registered on first tick.",
            }],
            started_at=now,
            updated_at=now,
            provenance={
                "engine_id":      ENGINE_ID,
                "engine_version": ENGINE_VERSION,
            },
        )
        await db[INVESTIGATIONS_COLLECTION].insert_one(state.model_dump(mode="python"))
        await cls._append_activity(db, state, ActivityEntry(
            at=now, kind="LIFECYCLE", lifecycle_state="WAITING_FOR_EVIDENCE",
            what="Investigation registered.",
            why="Incident materialised — Investigator will begin autonomously.",
        ))
        return state

    @classmethod
    async def _persist_state(cls, db, state: InvestigationState) -> None:
        await db[INVESTIGATIONS_COLLECTION].update_one(
            {"incident_id": state.incident_id,
              "tenant_id":   state.tenant_id},
            {"$set": state.model_dump(mode="python")},
            upsert=True,
        )

    @classmethod
    async def _transition(cls, db, state: InvestigationState,
                              target: LifecycleState,
                              what: str, why: str,
                              understanding: Optional[IUEUnderstanding] = None,
                             ) -> None:
        if state.state == target:
            return
        if not can_transition(state.state, target):
            # Illegal transition — record it and abort.
            state.state = "FAILED"
            state.state_history.append({
                "state": "FAILED", "at": _now_iso(),
                "reason": f"illegal transition {state.state}→{target}",
            })
            state.updated_at = _now_iso()
            await cls._persist_state(db, state)
            await cls._append_activity(db, state, ActivityEntry(
                at=_now_iso(), kind="LIFECYCLE",
                lifecycle_state="FAILED",
                what="Illegal state transition.",
                why=f"Refused {state.state}→{target}",
            ))
            return
        state.state = target
        state.state_history.append({
            "state": target, "at": _now_iso(),
            "reason": what,
        })
        state.updated_at = _now_iso()
        if understanding is not None:
            state.iue_fingerprint = understanding.evidence_fingerprint
            state.iue_version = understanding.version
        await cls._persist_state(db, state)
        await cls._append_activity(db, state, ActivityEntry(
            at=_now_iso(), kind="LIFECYCLE", lifecycle_state=target,
            what=what, why=why,
        ))

    @classmethod
    async def _bump(cls, db, state: InvestigationState, *,
                       planned: int = 0, executed: int = 0,
                       skipped: int = 0, findings: int = 0) -> None:
        state.pivots_planned += planned
        state.pivots_executed += executed
        state.pivots_skipped += skipped
        state.findings_count += findings
        state.updated_at = _now_iso()
        await cls._persist_state(db, state)

    # ── Executions ──────────────────────────────────────────────
    @classmethod
    async def _attempted_pivot_ids(cls, db, incident_id: str) -> Set[str]:
        attempted: Set[str] = set()
        async for d in db[EXECUTIONS_COLLECTION].find(
            {"incident_id": incident_id},
            {"_id": 0, "pivot_id": 1},
        ):
            pid = d.get("pivot_id")
            if pid:
                attempted.add(pid)
        return attempted

    @classmethod
    async def _record_skip(cls, db, state: InvestigationState,
                                pivot: PivotAction, *,
                                reason: str, status: str,
                                engine_name: Optional[str] = None,
                                sufficiency: Optional[str] = None) -> None:
        now = _now_iso()
        provenance = {"gap_key": pivot.gap_key,
                          "engine_id": ENGINE_ID,
                          "engine_version": ENGINE_VERSION}
        if sufficiency:
            provenance["evidence_sufficiency"] = sufficiency
        exe = EngineExecution(
            execution_id=_execution_id(),
            tenant_id=state.tenant_id,
            incident_id=state.incident_id,
            investigation_id=state.investigation_id,
            pivot_id=pivot.pivot_id,
            capability=pivot.capability,
            engine=engine_name or f"nivxray::investigator::{pivot.capability}",
            target_kind=pivot.target_kind,
            target_value=pivot.target_value,
            trigger="autonomous",
            reason=reason,
            started_at=now,
            completed_at=now,
            duration_ms=0,
            status=status,     # type: ignore[arg-type]
            evidence_created=0,
            evidence_ids=[],
            finding_ids=[],
            error=None,
            provenance=provenance,
        )
        await db[EXECUTIONS_COLLECTION].insert_one(exe.model_dump(mode="python"))
        await cls._append_activity(db, state, ActivityEntry(
            at=now, kind="SKIPPED", lifecycle_state=state.state,
            what=f"Skipped: {pivot.capability}",
            why=reason,
            capability=pivot.capability, engine=exe.engine,
            evidence_refs=list(pivot.triggering_evidence),
            result=status,
            execution_id=exe.execution_id,
            next_hint=None,
        ))
        await cls._bump(db, state, skipped=1)

    @classmethod
    async def _execute(cls, db, state: InvestigationState,
                           pivot: PivotAction, cap,
                           incident: Dict[str, Any],
                           understanding: IUEUnderstanding) -> EngineExecution:
        started = _now_iso()
        started_wall = time.perf_counter()
        # Load canonical for this incident + capture sufficiency.
        pipe = incident.get("xdr_pipeline") or {}
        canonical_id = pipe.get("canonical_event_id")
        canonical = None
        if canonical_id:
            canonical = await db[CANONICAL_COLLECTION].find_one(
                {"event_id": canonical_id}, {"_id": 0})
        sufficiency, suf_reason = cap.check_evidence(incident, canonical)
        exe = EngineExecution(
            execution_id=_execution_id(),
            tenant_id=state.tenant_id,
            incident_id=state.incident_id,
            investigation_id=state.investigation_id,
            pivot_id=pivot.pivot_id,
            capability=pivot.capability,
            engine=cap.engine,
            target_kind=pivot.target_kind,
            target_value=pivot.target_value,
            trigger="autonomous",
            reason=pivot.reason,
            started_at=started,
            status="RUNNING",
            provenance={"gap_key": pivot.gap_key,
                          "engine_id": ENGINE_ID,
                          "engine_version": ENGINE_VERSION,
                          "iue_content_hash": understanding.content_hash,
                          "evidence_sufficiency": sufficiency,
                          "sufficiency_reason":   suf_reason,
                          "capability_category":  cap.category,
                          "capability_version":   cap.version},
        )
        await db[EXECUTIONS_COLLECTION].insert_one(exe.model_dump(mode="python"))

        error: Optional[str] = None
        findings: List[Finding] = []
        evidence_ids: List[str] = []
        try:
            findings, evidence_ids = await cap.execute(
                db, pivot, incident, canonical)
        except Exception as ex:
            error = f"{type(ex).__name__}: {ex}"

        completed = _now_iso()
        duration_ms = int((time.perf_counter() - started_wall) * 1000)

        # Persist findings deterministically.
        for f in findings:
            f_dict = f.model_dump(mode="python")
            # Idempotent: findings are keyed by (incident, finding_id).
            await db[FINDINGS_COLLECTION].update_one(
                {"finding_id": f.finding_id,
                  "incident_id": state.incident_id},
                {"$set": f_dict},
                upsert=True,
            )
            await cls._append_activity(db, state, ActivityEntry(
                at=completed, kind="FINDING", lifecycle_state=state.state,
                what=f.summary,
                why=f.reasoning,
                evidence_refs=list(f.evidence_refs),
                capability=pivot.capability, engine=cap.engine,
                result=f"{f.state} · confidence {f.confidence}",
                execution_id=exe.execution_id,
                finding_id=f.finding_id,
            ))

        # Finalise execution row.
        status = "OK" if error is None else "ERROR"
        finding_ids = [f.finding_id for f in findings]
        await db[EXECUTIONS_COLLECTION].update_one(
            {"execution_id": exe.execution_id},
            {"$set": {
                "completed_at": completed,
                "duration_ms":  duration_ms,
                "status":       status,
                "evidence_created": len(evidence_ids),
                "evidence_ids":     sorted(set(evidence_ids)),
                "finding_ids":      finding_ids,
                "error":            error,
            }},
        )
        exe.completed_at = completed
        exe.duration_ms = duration_ms
        exe.status = status  # type: ignore[assignment]
        exe.evidence_created = len(evidence_ids)
        exe.evidence_ids = sorted(set(evidence_ids))
        exe.finding_ids = finding_ids
        exe.error = error

        await cls._append_activity(db, state, ActivityEntry(
            at=completed, kind="EXECUTION", lifecycle_state=state.state,
            what=f"Executed {pivot.capability}",
            why=pivot.reason,
            evidence_refs=list(pivot.triggering_evidence),
            capability=pivot.capability, engine=cap.engine,
            result=(
                f"{status} · {len(findings)} finding(s), "
                f"{len(exe.evidence_ids)} evidence ref(s)"
            ),
            execution_id=exe.execution_id,
            next_hint=None,
        ))
        await cls._bump(db, state, executed=1, findings=len(findings))
        return exe

    # ── Activity feed ────────────────────────────────────────────
    @classmethod
    async def _append_activity(cls, db, state: InvestigationState,
                                    entry: ActivityEntry) -> None:
        doc = entry.model_dump(mode="python")
        doc["incident_id"]      = state.incident_id
        doc["tenant_id"]        = state.tenant_id
        doc["investigation_id"] = state.investigation_id
        await db[ACTIVITY_COLLECTION].insert_one(doc)

    # ── Read APIs ────────────────────────────────────────────────
    @classmethod
    async def get_state(cls, db, incident_id: str
                             ) -> Optional[InvestigationState]:
        doc = await db[INVESTIGATIONS_COLLECTION].find_one(
            {"incident_id": incident_id}, {"_id": 0})
        return InvestigationState(**doc) if doc else None

    @classmethod
    async def get_activity(cls, db, incident_id: str,
                                limit: int = 200) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        async for d in db[ACTIVITY_COLLECTION].find(
            {"incident_id": incident_id}, {"_id": 0}
        ).sort("at", 1).limit(int(limit)):
            out.append(d)
        return out

    @classmethod
    async def get_executions(cls, db, incident_id: str,
                                    limit: int = 200) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        async for d in db[EXECUTIONS_COLLECTION].find(
            {"incident_id": incident_id}, {"_id": 0}
        ).sort("started_at", 1).limit(int(limit)):
            out.append(d)
        return out

    @classmethod
    async def get_findings(cls, db, incident_id: str,
                                 limit: int = 500) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        async for d in db[FINDINGS_COLLECTION].find(
            {"incident_id": incident_id}, {"_id": 0}
        ).sort("created_at", 1).limit(int(limit)):
            out.append(d)
        return out
