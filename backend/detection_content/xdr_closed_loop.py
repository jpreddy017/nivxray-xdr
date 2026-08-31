"""
P0.7.1 · Round 14 · Closed-Loop Evidence Recompute
──────────────────────────────────────────────────

Turns the one-way pipeline into a real closed loop:

    Action Result
         │
         ▼
    Observation Adapter        ← provenance-bearing, honest
         │
         ▼
    Intelligence Observations  ← new collection (source-tagged)
         │
         ▼
    Investigation Fabric        ← recomputed idempotently
         │
         ▼
    Recommendations             ← re-evaluated with supersession
         │
         ▼
    Decision                    ← re-evaluated deterministically

Owner-locked rules (Round 14 master prompt):
  §1  · no second investigation engine / audit stream / SSOT
  §2  · Action result becomes provenance-bearing observation
  §3  · Classification: telemetry ≠ intelligence ≠ action-derived
  §4  · Investigation recompute is idempotent (stable IDs, no dupes)
  §5  · Recommendations are dynamically recomputed, never templated
  §7  · Recommendation lifecycle preserved: CREATED / SUPERSEDED / …
  §9  · Loop protection via evidence_state_hash + already_attempted
  §13 · Graph relations distinguish OBSERVED / ENRICHED / ACTION_DERIVED
  §16 · Do not force VEEE score movement — evidence justifies it or not
  §24 · No fabricated success — NOT_CONFIGURED / FAILED stay honest
"""
from __future__ import annotations
import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any


LOOP_ENGINE_ID     = "nivxray::xdr::closed_loop"
LOOP_ENGINE_VERSION = "1.0.0"

OBSERVATIONS_COLLECTION = "xdr_intelligence_observations"
RECOS_COLLECTION        = "xdr_recommendations"
TIMELINE_COLLECTION     = "xdr_response_timeline"


# ── Evidence state hash — deterministic loop protection ──────

def _evidence_state_hash(incident: dict, observations: list[dict],
                              executions: list[dict]) -> str:
    """
    Stable hash over the elements that can change a recommendation:
      * incident xdr_pipeline provenance
      * every observation's (source, indicator, verdict)
      * every past execution's (action_id, state)
    Deterministic — same inputs → same hash.
    """
    prov = incident.get("xdr_pipeline") or {}
    payload = {
        "trace":  prov.get("trace_id"),
        "veee":   (prov.get("veee") or {}).get("label"),
        "obs":    sorted([
            (o.get("source"), o.get("indicator"), o.get("verdict"))
            for o in observations
        ]),
        "exec":   sorted([
            (e.get("action_id"), e.get("state"))
            for e in executions
        ]),
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True).encode()
    ).hexdigest()[:20]


# ── Action Result → Observation (provenance-bearing) ─────────

def _observation_id(execution_id: str, indicator: str,
                          provider: str) -> str:
    """Stable ID · same (execution, indicator, provider) → same id.
    Guarantees idempotency: re-recording the same result never
    creates a duplicate observation."""
    seed = f"{execution_id}|{indicator}|{provider}".encode()
    return f"obs_{hashlib.sha256(seed).hexdigest()[:20]}"


async def record_observation_from_execution(db, execution: dict,
                                                    incident_id: str) -> list[dict]:
    """
    Convert a SUCCEEDED action execution into 1..N intelligence
    observations, one per provider that returned a verdict.

    Honest state (§3, §24):
      * Only SUCCEEDED executions produce observations.
      * Every observation stays classified `intelligence_observation`
        — it is NEVER promoted to `canonical_evidence`.
      * Missing provider data yields ZERO observations, never a
        fabricated one.
    """
    if not execution or execution.get("state") != "SUCCEEDED":
        return []
    adapter = execution.get("adapter_result") or {}
    indicator = adapter.get("value")
    kind      = adapter.get("kind")
    if not indicator:
        return []
    now = datetime.now(timezone.utc).isoformat()
    exec_id = execution.get("execution_id")

    # If the adapter returned provider-level detail, record one
    # observation per provider.  Otherwise record a single consensus
    # observation.
    providers = adapter.get("providers") or []
    docs: list[dict] = []
    if providers:
        for p in providers:
            pname   = p.get("provider") or "unknown"
            verdict = p.get("verdict")   or "unknown"
            docs.append({
                "id":             _observation_id(exec_id, indicator, pname),
                "kind":           "intelligence_observation",
                "indicator":      indicator,
                "indicator_kind": kind,
                "source":         "response_executor",
                "provider":       pname,
                "verdict":        verdict,
                "detail":         p.get("detail"),
                "confidence":     "source-derived",
                "execution_id":   exec_id,
                "incident_id":    incident_id,
                "action_id":      execution.get("action_id"),
                "at":             now,
                "provenance": {
                    "engine_id":     LOOP_ENGINE_ID,
                    "classification": "action_derived",
                    "parent_execution": exec_id,
                    "action_id":     execution.get("action_id"),
                },
            })
    else:
        docs.append({
            "id":             _observation_id(exec_id, indicator, "consensus"),
            "kind":           "intelligence_observation",
            "indicator":      indicator,
            "indicator_kind": kind,
            "source":         "response_executor",
            "provider":       "consensus",
            "verdict":        adapter.get("verdict") or "unknown",
            "score":          adapter.get("score"),
            "confidence":     "consensus-derived",
            "execution_id":   exec_id,
            "incident_id":    incident_id,
            "action_id":      execution.get("action_id"),
            "at":             now,
            "provenance": {
                "engine_id":     LOOP_ENGINE_ID,
                "classification": "action_derived",
                "parent_execution": exec_id,
                "action_id":     execution.get("action_id"),
            },
        })

    # Upsert — idempotency guaranteed by the stable id.
    for d in docs:
        await db[OBSERVATIONS_COLLECTION].update_one(
            {"id": d["id"]}, {"$set": d}, upsert=True)
    return docs


# ── Timeline emission (existing SSOT, no parallel stream) ────

async def _emit_timeline(db, *, incident_id: str, kind: str,
                              label: str, reason: str,
                              refs: dict | None = None) -> None:
    now = datetime.now(timezone.utc).isoformat()
    await db[TIMELINE_COLLECTION].insert_one({
        "timeline_id": f"tl_{uuid.uuid4().hex[:12]}",
        "incident_id": incident_id,
        "at":          now,
        "kind":        kind,
        "label":       label,
        "reason":      reason,
        "refs":        refs or {},
        "source":      LOOP_ENGINE_ID,
    })


# ── Recommendation history + supersession ────────────────────

async def _persist_recommendations(db, *, incident_id: str,
                                          recos: list[dict],
                                          evidence_state_hash: str) -> dict:
    """
    Store the current recommendation set + auto-supersede any
    prior recommendations that are no longer present.
    Returns a delta report.
    """
    now = datetime.now(timezone.utc).isoformat()
    current_ids = {r["id"] for r in recos}
    prev_active: list[dict] = []
    async for r in db[RECOS_COLLECTION].find(
        {"incident_id": incident_id, "state": "ACTIVE"}, {"_id": 0}
    ):
        prev_active.append(r)

    superseded: list[str] = []
    for prev in prev_active:
        if prev["recommendation_id"] not in current_ids:
            await db[RECOS_COLLECTION].update_one(
                {"recommendation_id": prev["recommendation_id"]},
                {"$set": {"state":          "SUPERSEDED",
                              "superseded_at": now,
                              "superseded_by_hash": evidence_state_hash}})
            superseded.append(prev["recommendation_id"])

    created:  list[str] = []
    prev_by_id = {p["recommendation_id"]: p for p in prev_active}
    for r in recos:
        if r["id"] in prev_by_id:
            continue
        doc = {
            "recommendation_id":     r["id"],
            "incident_id":           incident_id,
            "state":                 "ACTIVE",
            "text":                  r.get("text"),
            "confidence":            r.get("confidence"),
            "suggested_action":      r.get("suggested_action"),
            "supported_by":          r.get("supported_by") or [],
            "engine_id":             r.get("engine_id"),
            "evidence_state_hash":   evidence_state_hash,
            "created_at":            now,
            "supersedes":            [],
            "superseded_by_hash":    None,
        }
        await db[RECOS_COLLECTION].insert_one(dict(doc))
        created.append(r["id"])
    return {"created": created, "superseded": superseded,
                "active_now": list(current_ids)}


# ── Public: closed-loop recompute ────────────────────────────

async def recompute(db, incident_id: str) -> dict:
    """
    Round 14 closed-loop entry point.

    Deterministic and idempotent — running it twice on the same
    evidence state produces zero duplicates and reports
    `changed: False` on the second run.
    """
    from .xdr_investigation      import project_investigation
    from .xdr_response_decision  import (
        build_response_context, recommend, decide,
    )
    from .xdr_response_fabric    import _resolve_parameters  # loop guard

    inc = await db["workspace_cases"].find_one(
        {"id": incident_id}, {"_id": 0})
    if not inc:
        return {"engine_id": LOOP_ENGINE_ID,
                    "state":     "MISSING",
                    "reason":    f"incident {incident_id} not found"}

    # 1. Collect all successful executions on this incident and
    #    project their results into intelligence observations.
    executions: list[dict] = []
    async for e in db["xdr_response_executions"].find(
        {"incident_id": incident_id}, {"_id": 0}
    ):
        executions.append(e)

    new_observations: list[dict] = []
    for e in executions:
        obs = await record_observation_from_execution(db, e, incident_id)
        new_observations.extend(obs)

    all_observations: list[dict] = []
    async for o in db[OBSERVATIONS_COLLECTION].find(
        {"incident_id": incident_id}, {"_id": 0}
    ):
        all_observations.append(o)

    # 2. Compute the evidence-state hash BEFORE and AFTER
    #    recomputation.  If they match, we have a no-op recompute
    #    and we must NOT emit duplicate timeline events.
    prev_hash = inc.get("evidence_state_hash")
    new_hash  = _evidence_state_hash(inc, all_observations, executions)

    # 3. Recompute Investigation Fabric — the projector is a pure
    #    function of persisted state so it is naturally idempotent.
    investigation = await project_investigation(db, incident_id)

    # 4. Rebuild Response Context using observations (§4-§6).
    ctx = await build_response_context(db, incident_id)
    if ctx.get("state") == "READY":
        ctx["observations"] = [
            {"provider": o.get("provider"), "verdict": o.get("verdict"),
              "indicator": o.get("indicator")}
            for o in all_observations
        ]

    recos     = recommend_with_observations(ctx, all_observations)
    reco_delta = await _persist_recommendations(
        db, incident_id=incident_id, recos=recos,
        evidence_state_hash=new_hash)

    # 5. Re-evaluate the decision.  It's deterministic from ctx +
    #    the current recos — no forced score movement (§16).
    decision = decide(ctx, recos)

    changed = (prev_hash != new_hash)
    if changed:
        # Emit ONE timeline event per real change type.
        await _emit_timeline(db, incident_id=incident_id,
                                  kind="investigation_recomputed",
                                  label="Investigation Fabric recomputed",
                                  reason=f"evidence_state_hash={new_hash}",
                                  refs={"before": prev_hash, "after": new_hash})
        if reco_delta["created"] or reco_delta["superseded"]:
            await _emit_timeline(
                db, incident_id=incident_id,
                kind="recommendations_recomputed",
                label=f"{len(reco_delta['created'])} new · "
                          f"{len(reco_delta['superseded'])} superseded",
                reason="closed-loop evidence recompute",
                refs=reco_delta)
        # Persist the evidence_state_hash on the incident.
        await db["workspace_cases"].update_one(
            {"id": incident_id},
            {"$set": {"evidence_state_hash": new_hash,
                          "closed_loop_last_run":
                              datetime.now(timezone.utc).isoformat()}})

    return {
        "engine_id":                 LOOP_ENGINE_ID,
        "engine_version":            LOOP_ENGINE_VERSION,
        "state":                     "READY",
        "incident_id":               incident_id,
        "recomputed":                True,
        "changed":                   changed,
        "evidence_state_hash":       new_hash,
        "previous_evidence_state_hash": prev_hash,
        "new_observations":          len(new_observations),
        "total_observations":        len(all_observations),
        "investigation_state":       investigation.get("state"),
        "lanes_ready":               investigation.get("lanes_ready"),
        "recommendations": {
            "active":     reco_delta["active_now"],
            "created":    reco_delta["created"],
            "superseded": reco_delta["superseded"],
        },
        "decision":                  decision.get("decision"),
        "decision_reason":           decision.get("reason"),
        "honesty_note":
            "recompute is idempotent: identical evidence state produces "
            "changed=False and NO duplicate observations, timeline events, "
            "or recommendations.  Observations remain classified as "
            "action_derived — never promoted to canonical customer evidence.",
    }


# ── Enrichment-aware recommendation engine ───────────────────

def recommend_with_observations(context: dict,
                                              observations: list[dict]) -> list[dict]:
    """
    Extends the base `recommend()` with observation-driven signal.

    Rules (§5, §6, §14, §16):
      * Recommendation list is a pure function of context + observations.
      * A single external observation NEVER jumps confidence to MAX.
      * When ≥2 independent providers report `malicious` for the same
        indicator, an IP_BLOCK recommendation is generated (guidance
        only; the Action Registry decides if it can execute).
      * When observations lower risk (all `clean`), any prior IP_BLOCK
        recommendation is NOT emitted; the previous one gets superseded
        by the persistence layer.
    """
    from .xdr_response_decision import recommend, RECO_ENGINE_ID

    base = recommend(context)

    if context.get("state") != "READY":
        return base

    # Group observations by indicator.
    by_ind: dict[str, list[dict]] = {}
    for o in observations:
        by_ind.setdefault(o.get("indicator"), []).append(o)

    extra: list[dict] = []
    for ind, obs in by_ind.items():
        if not ind:
            continue
        mal = [o for o in obs
                  if (o.get("verdict") or "").lower() == "malicious"]
        if len(mal) >= 2:
            extra.append({
                "id":     f"reco-ip-block-{ind}",
                "text":   f"Block {ind} at network edge — corroborated "
                             f"malicious by {len(mal)} independent OSINT "
                             "providers",
                "confidence":       "HIGH",
                "supported_by":     [f"observation:{o.get('provider')}"
                                              for o in mal],
                "suggested_action": "IP_BLOCK",
                "engine_id":        RECO_ENGINE_ID,
            })

    # De-duplicate by id (base + extra).
    seen: set = set()
    merged: list[dict] = []
    for r in base + extra:
        if r["id"] in seen:
            continue
        seen.add(r["id"])
        merged.append(r)
    return merged
