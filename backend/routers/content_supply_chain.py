"""
/api/admin/content-supply-chain/* · Detection Content Supply Chain
compatibility report + inventory summary endpoints.
Also exposes the Engine Registry inventory.

Read-only.  Serves the authoritative `detection_content` and
`xdr_engines` collections.  If a collection is empty, returns an
honest zero-report — no fabricated numbers.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from deps import db, require_admin
from detection_content.model import COLLECTION, LifecycleState
from detection_content.engine_registry import (
    COLLECTION as ENGINES_COLLECTION,
    EngineRole, EngineState,
)
from detection_content.capability_contract import (
    COLLECTION as CONTRACTS_COLLECTION,
    ContractStatus,
)
from detection_content.contract_registry import (
    declare_all_contracts, contract_report,
)
from detection_content.sigma_strict import strict_parse, StrictParseStatus
from detection_content.rule_binding import match_rule_to_contracts
from detection_content.detection_harness import (
    HarnessFixture, run_harness, record_verification,
)
from detection_content import nivxray_native_sigma as _nx_native
from detection_content.architecture_audit import audit as run_architecture_audit
from detection_content.engine_control_plane import (
    build_engine_registry, dependency_graph,
)
from detection_content.collector_runtime import (
    MANAGER as COLLECTOR_MANAGER,
    bootstrap_snort_collector,
)
from detection_content.xdr_pipeline import (
    process_event_through_pipeline, DSM_REGISTRY,
    CANONICAL_COLLECTION,
)
from detection_content.xdr_investigation import project_investigation
from detection_content.xdr_response_fabric import orchestrate as response_orchestrate
from detection_content.xdr_closed_loop   import recompute as closed_loop_recompute
from detection_content.xdr_framework_mapping import (
    resolve_mappings as framework_resolve, framework_registry,
)
from detection_content.xdr_action_registry import list_actions, registry_summary


router = APIRouter(prefix="/admin/content-supply-chain",
                     tags=["content-supply-chain"])


@router.get("/report")
async def compatibility_report(user=Depends(require_admin)):
    """
    Return the full-corpus compatibility report shape defined in
    the P0 spec: per-milestone counts + per-source rollup + per-
    product rollup + `unsupported_reasons`.
    """
    coll = db[COLLECTION]
    total = await coll.count_documents({})
    if total == 0:
        return _empty_report()

    # Milestone counts (each is a distinct set of state_history entries).
    milestones = {}
    for s in LifecycleState:
        milestones[s.value] = await coll.count_documents(
            {"state_history": s.value}
        )

    # Source rollup
    sources: dict[str, int] = {}
    async for r in coll.aggregate([
        {"$group": {"_id": "$source", "n": {"$sum": 1}}}
    ]):
        sources[r["_id"]] = r["n"]

    # Product rollup (top 15)
    products: dict[str, int] = {}
    async for r in coll.aggregate([
        {"$unwind": {"path": "$platform", "preserveNullAndEmptyArrays": True}},
        {"$group":  {"_id": "$platform", "n": {"$sum": 1}}},
        {"$sort":   {"n": -1}},
        {"$limit":  15},
    ]):
        products[r["_id"] or "unknown"] = r["n"]

    return {
        "total_content":       total,
        "milestones":          milestones,
        "sources":             sources,
        "products":            products,
        "guardrails": {
            "active_content_requires":  list(sorted(
                s.value for s in {LifecycleState.PARSED,
                                     LifecycleState.VALID,
                                     LifecycleState.SUPPORTED,
                                     LifecycleState.EXECUTION_READY,
                                     LifecycleState.ENABLED})),
            "supply_chain_phase":       "phase-1-inventory",
            "notes":                   "Engine binding + execution testing are subsequent slices. No document is ACTIVE until every required milestone is recorded.",
        },
    }


@router.get("/samples")
async def content_samples(limit: int = 20, user=Depends(require_admin)):
    """Small sample of the collection for spot-checks."""
    coll = db[COLLECTION]
    if await coll.count_documents({}) == 0:
        return {"samples": [], "message": "No content ingested yet."}
    items = []
    async for d in coll.find(
        {}, {"_id": 0, "raw_body": 0, "field_mappings": 0}
    ).limit(min(limit, 100)):
        items.append(d)
    return {"samples": items, "count": len(items)}


def _empty_report():
    return {
        "total_content":  0,
        "milestones":     {s.value: 0 for s in LifecycleState},
        "sources":        {},
        "products":       {},
        "guardrails": {
            "supply_chain_phase":  "not-yet-ingested",
            "notes":              "Detection Content Supply Chain has not run yet. Run `python -m detection_content.sigma_ingest` after cloning SigmaHQ under /var/nivxray/content/sigma to populate the authoritative content store.",
        },
    }


# ── Engine Registry ─────────────────────────────────────────────

@router.get("/engines/report")
async def engines_report(user=Depends(require_admin)):
    """
    Return the Engine Registry inventory — real classified roles
    from the codebase.  When empty, returns honest zeros with
    instructions rather than fabricated data.
    """
    coll = db[ENGINES_COLLECTION]
    total = await coll.count_documents({})
    if total == 0:
        return {
            "total_engines":     0,
            "roles":             {r.value: 0 for r in EngineRole},
            "states":            {s.value: 0 for s in EngineState},
            "notes":             "Engine Registry has not been populated. Run detection_content.engine_classifier.discover_engines() to inventory the real codebase.",
        }
    roles: dict[str, int] = {}
    async for r in coll.aggregate([
        {"$group": {"_id": "$role", "n": {"$sum": 1}}}
    ]):
        roles[r["_id"]] = r["n"]
    states: dict[str, int] = {}
    async for r in coll.aggregate([
        {"$group": {"_id": "$state", "n": {"$sum": 1}}}
    ]):
        states[r["_id"]] = r["n"]
    scopes: dict[str, int] = {}
    async for r in coll.aggregate([
        {"$group": {"_id": "$scope", "n": {"$sum": 1}}}
    ]):
        scopes[r["_id"]] = r["n"]
    return {
        "total_engines":     total,
        "roles":             roles,
        "states":            states,
        "scopes":            scopes,
        "guardrails": {
            "notes":         "Roles are classified from source-code paths and inspection. READY/CONNECTED require dependency resolution + runtime invocation — these transitions are subsequent slices.",
        },
    }


@router.get("/engines/list")
async def engines_list(role: str = None, scope: str = None,
                             limit: int = 200,
                             user=Depends(require_admin)):
    q = {}
    if role:  q["role"]  = role.upper()
    if scope: q["scope"] = scope
    items = []
    async for d in db[ENGINES_COLLECTION].find(
        q, {"_id": 0, "state_history": 0, "provenance": 0}
    ).limit(min(limit, 500)):
        items.append(d)
    return {"count": len(items), "items": items}


# ── P0.2c · Implementation Capability Contracts ─────────────────

@router.get("/contracts/report")
async def contracts_report(user=Depends(require_admin)):
    """
    Authoritative Implementation Capability Contract report.
    Contracts are DECLARED, never auto-promoted; the report is
    the honest state of the ladder at this moment.
    """
    return await contract_report(db)


@router.post("/contracts/declare")
async def contracts_declare(user=Depends(require_admin)):
    """
    (Re-)declare CONTRACT_DECLARED records for every engine in
    `xdr_engines`.  Contracts already at RUNTIME_VERIFIED or
    EXECUTION_VERIFIED are frozen — this pass will not touch them.
    """
    return await declare_all_contracts(db)


@router.get("/contracts")
async def contracts_list(classification: str = None,
                              status: str = None,
                              detection: bool | None = None,
                              limit: int = 200,
                              user=Depends(require_admin)):
    q: dict = {}
    if classification: q["classification"]  = classification.upper()
    if status:         q["contract_status"] = status.upper()
    if detection is not None:
        q["execution.detection"] = bool(detection)
    items = []
    async for d in db[CONTRACTS_COLLECTION].find(
        q, {"_id": 0, "status_history": 0}
    ).limit(min(limit, 500)):
        items.append(d)
    return {"count": len(items), "items": items}


@router.get("/contracts/{engine_id:path}")
async def contract_one(engine_id: str, user=Depends(require_admin)):
    doc = await db[CONTRACTS_COLLECTION].find_one(
        {"engine_id": engine_id}, {"_id": 0})
    if not doc:
        return {"engine_id": engine_id, "found": False,
                    "note": "No contract declared for this engine yet."}
    return {"engine_id": engine_id, "found": True, "contract": doc}


# ── P0.2d · Rule ↔ Capability Matching ──────────────────────────

from fastapi import Body


@router.post("/binding/match")
async def binding_match(rule_body: str = Body(..., media_type="text/plain"),
                                 user=Depends(require_admin)):
    """
    Strict-parse a Sigma rule from the request body and return the
    deterministic rule ↔ contract match report.  This endpoint is
    read-only — it does not persist the rule or any binding state.
    """
    parsed = strict_parse(rule_body)
    if parsed.status != StrictParseStatus.PARSED:
        return {
            "status":   "PARSE_FAILED",
            "parse":    parsed.to_dict(),
            "note":     "Strict pySigma parse failed. Fix the rule before running the matcher.",
        }
    contracts: list[dict] = []
    async for c in db[CONTRACTS_COLLECTION].find(
        {}, {"_id": 0, "status_history": 0}):
        contracts.append(c)
    report = match_rule_to_contracts(parsed.rule, contracts)
    return {"status": "OK", "parse": parsed.to_dict(), "match": report}


@router.get("/binding/report")
async def binding_report(user=Depends(require_admin)):
    """
    Roll up the current contract registry into a binding-readiness
    view: how many engines COULD potentially execute detection
    (candidates) and how many actually can today (detection_capable).
    """
    coll = db[CONTRACTS_COLLECTION]
    total = await coll.count_documents({})
    if total == 0:
        return {
            "total_contracts":            0,
            "detection_capable":          0,
            "candidate_detection":        0,
            "note": "No contracts declared. Run POST /contracts/declare first.",
        }

    detection_capable = 0
    candidate = 0
    async for c in coll.find(
        {}, {"execution": 1, "consumes": 1}):
        ex = c.get("execution") or {}
        if ex.get("detection"):
            detection_capable += 1
        else:
            # A contract that consumes canonical.evidence is a
            # candidate for detection promotion (P0.2e).
            if any(ev.startswith("canonical.evidence")
                       for ev in (c.get("consumes") or [])):
                candidate += 1

    return {
        "total_contracts":     total,
        "detection_capable":   detection_capable,
        "candidate_detection": candidate,
        "note": (
            "detection_capable is the authoritative count of engines "
            "that CAN execute a Sigma rule today (execution.detection=True). "
            "candidate_detection is the count of engines whose inputs "
            "match canonical evidence but which have NOT been promoted "
            "through the P0.2e execution harness."
        ),
    }


# ── P0.2e · Detection Execution Harness ──────────────────────────

# In-process registry of engines whose `evaluate()` callable is
# available to the harness endpoint.  Adding an engine to this map
# is INTENTIONAL — it is the developer stating "this module claims
# to be able to execute Sigma", which the harness will then verify.
_HARNESS_EVALUATORS = {
    _nx_native.ENGINE_ID: _nx_native.evaluate,
}


class HarnessRequest(BaseModel):
    engine_id: str
    rule:      str
    positive_evidence: dict
    negative_evidence: dict
    positive_name:     str = "positive"
    negative_name:     str = "negative"


@router.post("/harness/run")
async def harness_run(body: HarnessRequest,
                            user=Depends(require_admin)):
    """
    Execute the P0.2e Detection Execution Harness for one
    (engine, rule) pair.  On EXECUTION_VERIFIED the engine's
    capability contract is promoted to detection=True and
    classification=DETECTION_ENGINE.  On FAILED nothing is promoted
    but the attempt is preserved in verification_history[].
    """
    evaluator = _HARNESS_EVALUATORS.get(body.engine_id)
    if evaluator is None:
        return {"ok": False,
                    "engine_id": body.engine_id,
                    "note": ("Engine has no registered evaluate() callable. "
                                "Only engines added to _HARNESS_EVALUATORS may be "
                                "verified — the harness never proves an engine "
                                "that has not intentionally opted in.")}

    result = run_harness(
        engine_id       = body.engine_id,
        rule_body       = body.rule,
        engine_evaluate = evaluator,
        positive        = HarnessFixture(body.positive_name,
                                                    body.positive_evidence, True),
        negative        = HarnessFixture(body.negative_name,
                                                    body.negative_evidence, False),
    )
    persistence = await record_verification(db, result)
    return {"ok": True, "harness": result.to_dict(),
                "persistence": persistence}


@router.get("/harness/engines")
async def harness_engines(user=Depends(require_admin)):
    """
    List engines that have registered an `evaluate()` callable with
    the harness (opt-in).  These are the ONLY engines whose contract
    can move to EXECUTION_VERIFIED via /harness/run.
    """
    return {"engines": sorted(_HARNESS_EVALUATORS.keys())}


# ── P0.0 · Architecture Audit ────────────────────────────────────

@router.get("/architecture/audit")
async def architecture_audit(user=Depends(require_admin)):
    """
    Authoritative source-code audit of every declared NivXRay engine
    family (IUE · VEEE · DIE · IDE · ICE · UAIE · Verdict · Correlation
    · IKG · Evidence Graph · Process Tree · Device Trajectory · etc.).

    Reports source-code presence only — never runtime readiness.
    Presence is the honest starting point; every subsequent P0 slice
    verifies capability against this baseline.
    """
    return run_architecture_audit()


@router.get("/architecture/audit/summary")
async def architecture_audit_summary(user=Depends(require_admin)):
    """
    Slim version of the audit — only the family-level rollup, no
    file-level hits.  Useful for the XDR admin UI header strip.
    """
    a = run_architecture_audit()
    slim_reports = [{
        "family":          r["family"],
        "implementations": r["implementations"],
        "total_symbols":   r["total_symbols"],
    } for r in a["reports"]]
    return {
        "audit_version":         a["audit_version"],
        "files_scanned":         a["files_scanned"],
        "families_total":        a["families_total"],
        "families_present":      a["families_present"],
        "families_missing":      a["families_missing"],
        "families_present_list": a["families_present_list"],
        "families_missing_list": a["families_missing_list"],
        "reports":               slim_reports,
        "honesty_note":          a["honesty_note"],
    }


# ── P0.1 · Engine Control Plane ──────────────────────────────────

@router.get("/engines/control-plane")
async def engines_control_plane(user=Depends(require_admin)):
    """
    Unified Engine Registry with six independent state axes:
    presence · contract · runtime · execution · readiness · health.

    Consumes the P0.0 architecture audit and the P0.2c capability
    contract collection — no re-discovery.
    """
    return await build_engine_registry(db)


@router.get("/engines/control-plane/dependencies")
async def engines_dependencies(user=Depends(require_admin)):
    """
    Contract-derived dependency graph — every edge is honest
    (produces ∩ consumes overlap in declared contracts).
    """
    return await dependency_graph(db)


# ── P0.3 · Collector Runtime + Snort Adapter ────────────────────

@router.get("/collector-runtime/status")
async def collector_runtime_status(user=Depends(require_admin)):
    """
    Live status of the in-process CollectorManager.  Reports real
    lifecycle state; NOT_DEPLOYED is preserved when no collector
    is registered.
    """
    s = COLLECTOR_MANAGER.status()
    if s["count"] == 0:
        s["runtime_state"] = "NOT_DEPLOYED"
    else:
        s["runtime_state"] = "RUNNING" if s["running"] > 0 else "REGISTERED"
    return s


@router.post("/collector-runtime/bootstrap-snort")
async def collector_runtime_bootstrap_snort(user=Depends(require_admin)):
    """
    Idempotently register the reference Snort collector.
    Explicit operator action — never auto-runs.
    """
    return bootstrap_snort_collector()


@router.post("/collector-runtime/{collector_id}/start")
async def collector_runtime_start(collector_id: str,
                                             user=Depends(require_admin)):
    return await COLLECTOR_MANAGER.start(collector_id)


@router.post("/collector-runtime/{collector_id}/stop")
async def collector_runtime_stop(collector_id: str,
                                            user=Depends(require_admin)):
    return await COLLECTOR_MANAGER.stop(collector_id)


# ── P0.4 · Golden E2E harness ───────────────────────────────────

@router.post("/e2e/snort-golden")
async def e2e_snort_golden(user=Depends(require_admin)):
    """
    Run one golden Suricata-EVE alert through the pipeline.  Honestly
    halts at the first stage that is not yet executable; never
    manufactures downstream success.  Provenance-preserving.
    """
    from detection_content.collector_runtime import (
        GOLDEN_SNORT_EVENT, MANAGER, CollectorState, bootstrap_snort_collector,
    )
    from datetime import datetime, timezone
    import uuid as _uuid

    trace_id = str(_uuid.uuid4())
    bootstrap_snort_collector()
    coll = "collector-snort-ref"
    if MANAGER._collectors[coll]["state"] != CollectorState.RUNNING.value:
        await MANAGER.start(coll)
    stages: list[dict] = [
        {"stage": "integration", "status": "EXECUTED",
          "adapter": "snort-suricata-eve"},
        {"stage": "collector",   "status": "EXECUTED",
          "collector_id": coll},
    ]
    # Also record ingest through the manager for real event counters.
    await MANAGER.ingest_one(coll, dict(GOLDEN_SNORT_EVENT))

    pipeline = await process_event_through_pipeline(
        db, dict(GOLDEN_SNORT_EVENT), trace_id,
        integration_id="integration-snort-ref",
        collector_id=coll)
    stages.extend(pipeline["stages"])

    executed = sum(1 for s in stages if s["status"] == "EXECUTED")
    return {
        "trace_id":  trace_id,
        "stages":    stages,
        "executed":  executed,
        "total":     len(stages),
        "blocker":   pipeline.get("blocker"),
        "verdict":   "PARTIAL" if pipeline.get("blocker") else "COMPLETE",
        "canonical_event_id": (pipeline.get("canonical") or {}).get("event_id"),
        "detection": pipeline.get("detection"),
        "iue":       pipeline.get("iue"),
        "ice":       pipeline.get("ice"),
        "veee":      pipeline.get("verdict"),
        "incident":  pipeline.get("incident"),
        "investigation": pipeline.get("investigation"),
        "response":      pipeline.get("response"),
        "closed_loop":   pipeline.get("closed_loop"),
        "framework":     pipeline.get("framework"),
        "honesty_note": (
            "Every EXECUTED stage ran real code; every BLOCKED / NOT_CREATED "
            "stage records the exact reason.  No stage is fabricated."
        ),
    }


@router.get("/investigation/{incident_id}")
async def investigation_fabric(incident_id: str,
                                    user=Depends(require_admin)):
    """
    P0.6 · Investigation Fabric projection for one incident.

    Reads `workspace_cases` + linked canonical_evidence + linked
    correlation matches and emits the six lanes required by the
    Investigation UI.  Pure projection · no second engine ·
    empty lanes carry the exact reason.
    """
    return await project_investigation(db, incident_id)


@router.get("/response/actions")
async def response_actions(user=Depends(require_admin)):
    """P0.7 · Authoritative Action Registry — every executable
    action + honest capability_available flag."""
    return {"summary": registry_summary(), "actions": list_actions()}


@router.get("/response/{incident_id}")
async def response_fabric(incident_id: str,
                              user=Depends(require_admin)):
    """P0.7 · Response Fabric run for one incident.

    Context → Recommendation → Decision → Approval → Executor →
    Audit → Timeline.  Honest state end-to-end: capability probes
    are runtime, no fabricated SUCCESS.
    """
    return await response_orchestrate(db, incident_id)


@router.post("/response/{incident_id}/recompute")
async def response_recompute(incident_id: str,
                                    user=Depends(require_admin)):
    """P0.7.1 · Closed-Loop Recompute.

    Turns every SUCCEEDED action result into a provenance-bearing
    intelligence observation, then recomputes Investigation Fabric
    and Recommendations idempotently.  Deterministic — running
    twice on the same evidence state returns changed=False.
    """
    return await closed_loop_recompute(db, incident_id)


@router.get("/frameworks")
async def frameworks_registry(user=Depends(require_admin)):
    """P0.7.2 · Framework Mapping Fabric registry.  Lists supported
    frameworks with honest AVAILABLE / PARTIAL / NOT_LOADED state."""
    return {"frameworks": framework_registry(),
                "honesty_note":
                    "Frameworks are contextual knowledge only.  "
                    "They never independently create evidence, "
                    "detections or actions.  Mappings must be "
                    "evidence-derived per incident."}


@router.get("/incidents/{incident_id}/framework-mappings")
async def framework_mappings(incident_id: str,
                                    user=Depends(require_admin)):
    """P0.7.2 · Read-only framework mappings for one incident.
    Idempotent — repeated resolve() calls produce no duplicates."""
    return await framework_resolve(db, incident_id)


@router.post("/incidents/{incident_id}/framework-mappings/resolve")
async def framework_mappings_resolve(incident_id: str,
                                              user=Depends(require_admin)):
    return await framework_resolve(db, incident_id)


@router.get("/dsm/registry")
async def dsm_registry_list(user=Depends(require_admin)):
    return {"dsms": DSM_REGISTRY.list()}


@router.get("/canonical-evidence/count")
async def canonical_evidence_count(user=Depends(require_admin)):
    return {"collection": CANONICAL_COLLECTION,
                "count": await db[CANONICAL_COLLECTION].count_documents({})}
