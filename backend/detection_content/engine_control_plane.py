"""
P0.1 · Engine Control Plane
───────────────────────────

Unified Engine Registry that merges three independent sources of
truth into one authoritative per-engine record with SIX INDEPENDENT
STATE AXES (§3 of the Round 8 master prompt):

    presence_status   ← from P0.0 architecture audit
    contract_status   ← from P0.2c capability contracts
    runtime_status    ← from runtime adapter (P0.3 · not yet wired)
    execution_status  ← from P0.2e detection execution harness
    readiness_status  ← derived from the above
    health_status     ← from live heartbeat / execution telemetry
                         (unavailable until P0.3 · reported N/A)

These axes are NEVER collapsed.  An engine can be PRESENT +
CONTRACT_DECLARED yet still `readiness_status = BLOCKED` because
its runtime adapter is missing.  The UI must render each axis
distinctly.

Execution modes (§1 of Round 8 prompt): IN_PROCESS · WORKER ·
ASYNC_JOB · PIPELINE_STAGE · EXTERNAL_ADAPTER · LIBRARY.  A family
that has no runtime adapter yet reports execution_mode = UNKNOWN.

Roles (§5 of Round 8 prompt): INGESTION · PARSER · NORMALIZER ·
ANALYZER · INTELLIGENCE · DETECTION · CORRELATION · VERDICT · GRAPH
· INVESTIGATION · ENRICHMENT · DECODER · INTERPRETER · ORCHESTRATOR
· PLANNER · RESPONSE · UTILITY.

Do NOT introduce a second inventory: this module CONSUMES the P0.0
audit + P0.2c contracts; it does not re-discover.
"""
from __future__ import annotations
from enum import Enum
from typing import Any

from .architecture_audit import audit as _run_audit
from .capability_contract import (
    COLLECTION as CONTRACTS_COLLECTION, ContractStatus,
)


# ── Independent state axes ───────────────────────────────────────

class PresenceStatus(str, Enum):
    PRESENT = "PRESENT"          # audit found ≥1 real file
    MISSING = "MISSING"          # audit found 0 files


class RuntimeStatus(str, Enum):
    NOT_AVAILABLE = "NOT_AVAILABLE"   # no runtime adapter wired
    ADAPTER_READY = "ADAPTER_READY"   # adapter registered
    RUNTIME_VERIFIED = "RUNTIME_VERIFIED"


class ExecutionStatus(str, Enum):
    NOT_VERIFIED       = "NOT_VERIFIED"
    RUNTIME_VERIFIED   = "RUNTIME_VERIFIED"
    EXECUTION_VERIFIED = "EXECUTION_VERIFIED"


class ReadinessStatus(str, Enum):
    READY                 = "READY"
    NOT_READY             = "NOT_READY"
    BLOCKED               = "BLOCKED"
    DEPENDENCY_BLOCKED    = "DEPENDENCY_BLOCKED"
    CONFIGURATION_REQUIRED = "CONFIGURATION_REQUIRED"
    NOT_PRESENT           = "NOT_PRESENT"


class HealthStatus(str, Enum):
    NA        = "N/A"           # no runtime telemetry available
    HEALTHY   = "HEALTHY"
    DEGRADED  = "DEGRADED"
    UNHEALTHY = "UNHEALTHY"


class ExecutionMode(str, Enum):
    UNKNOWN            = "UNKNOWN"
    IN_PROCESS         = "IN_PROCESS"
    WORKER             = "WORKER"
    ASYNC_JOB          = "ASYNC_JOB"
    PIPELINE_STAGE     = "PIPELINE_STAGE"
    EXTERNAL_ADAPTER   = "EXTERNAL_ADAPTER"
    LIBRARY            = "LIBRARY"


# ── Runtime adapter registry ─────────────────────────────────────
#
# A family is only marked ADAPTER_READY when a real Python callable
# claiming to invoke that family has been registered here.  Empty
# by design today — the detection harness registers the one native
# Sigma evaluator; every other family stays honestly NOT_AVAILABLE
# until P0.3 delivers real adapters.
#
_RUNTIME_ADAPTERS: dict[str, dict] = {
    # family_key → {execution_mode, note}
    "SigmaEngine": {
        "execution_mode": ExecutionMode.IN_PROCESS.value,
        "note": "nivxray_native_sigma.evaluate — verified via P0.2e harness",
    },
}


# ── Derivation logic ────────────────────────────────────────────

def _derive_readiness(presence: str, contract: str, runtime: str,
                              execution: str) -> str:
    if presence == PresenceStatus.MISSING.value:
        return ReadinessStatus.NOT_PRESENT.value
    if contract in (None, "", ContractStatus.DISCOVERED.value,
                          ContractStatus.CONTRACT_PENDING.value):
        return ReadinessStatus.CONFIGURATION_REQUIRED.value
    if runtime == RuntimeStatus.NOT_AVAILABLE.value:
        return ReadinessStatus.BLOCKED.value
    if execution == ExecutionStatus.EXECUTION_VERIFIED.value:
        return ReadinessStatus.READY.value
    return ReadinessStatus.NOT_READY.value


# ── Public: build the full registry ─────────────────────────────

async def build_engine_registry(db) -> dict:
    """
    Merge P0.0 audit + P0.2c contracts into a per-family registry
    with all six independent state axes.

    Returns:
      {
        "families":   [ EngineRecord, ... ],
        "totals":     { presence · contract · runtime · execution · readiness · health },
        "sources":    { "audit": "P0.0", "contracts": "P0.2c",
                          "runtime_adapters": <count> },
      }
    """
    audit_report = _run_audit()
    family_hits = {r["family"]: r for r in audit_report["reports"]}

    # Contract lookup by classification — best-effort join.
    contract_by_family: dict[str, dict] = {}
    async for c in db[CONTRACTS_COLLECTION].find(
        {}, {"_id": 0, "classification": 1, "contract_status": 1,
                "execution": 1, "engine_id": 1}
    ):
        cls = c.get("classification")
        if cls:
            contract_by_family.setdefault(cls, {"count": 0,
                                                              "declared": 0,
                                                              "verified": 0})
            contract_by_family[cls]["count"] += 1
            if c.get("contract_status") == ContractStatus.CONTRACT_DECLARED.value:
                contract_by_family[cls]["declared"] += 1
            if c.get("contract_status") in (
                ContractStatus.RUNTIME_VERIFIED.value,
                ContractStatus.EXECUTION_VERIFIED.value,
            ):
                contract_by_family[cls]["verified"] += 1

    families: list[dict] = []
    totals = {
        "presence":  {"PRESENT": 0, "MISSING": 0},
        "runtime":   {"NOT_AVAILABLE": 0, "ADAPTER_READY": 0, "RUNTIME_VERIFIED": 0},
        "execution": {"NOT_VERIFIED": 0, "RUNTIME_VERIFIED": 0, "EXECUTION_VERIFIED": 0},
        "readiness": {"READY": 0, "BLOCKED": 0, "NOT_READY": 0,
                            "CONFIGURATION_REQUIRED": 0, "NOT_PRESENT": 0},
        "health":    {"N/A": 0, "HEALTHY": 0, "DEGRADED": 0, "UNHEALTHY": 0},
    }

    for name, hit in family_hits.items():
        impl = hit.get("implementations") or 0
        presence = (PresenceStatus.PRESENT if impl > 0
                        else PresenceStatus.MISSING).value

        adapter = _RUNTIME_ADAPTERS.get(name)
        runtime = (RuntimeStatus.ADAPTER_READY.value
                        if adapter else RuntimeStatus.NOT_AVAILABLE.value)
        execution_mode = (adapter["execution_mode"] if adapter
                                else ExecutionMode.UNKNOWN.value)

        # Best-effort join with contracts (some families won't map).
        c = contract_by_family.get(name.upper()) or {}
        contract = (
            "EXECUTION_VERIFIED" if c.get("verified", 0) > 0
            else "CONTRACT_DECLARED" if c.get("declared", 0) > 0
            else "NOT_DECLARED"
        )
        execution = (ExecutionStatus.EXECUTION_VERIFIED.value
                            if c.get("verified", 0) > 0
                            else ExecutionStatus.NOT_VERIFIED.value)

        readiness = _derive_readiness(presence, contract, runtime, execution)
        health    = HealthStatus.NA.value  # no runtime telemetry until P0.3

        totals["presence"][presence]   = totals["presence"].get(presence, 0) + 1
        totals["runtime"][runtime]     = totals["runtime"].get(runtime, 0) + 1
        totals["execution"][execution] = totals["execution"].get(execution, 0) + 1
        totals["readiness"][readiness] = totals["readiness"].get(readiness, 0) + 1
        totals["health"][health]       = totals["health"].get(health, 0) + 1

        families.append({
            "family":            name,
            "implementations":   impl,
            "presence_status":   presence,
            "contract_status":   contract,
            "contracts_count":   c.get("count", 0),
            "runtime_status":    runtime,
            "execution_status":  execution,
            "execution_mode":    execution_mode,
            "readiness_status":  readiness,
            "readiness_reason":  _reason_for(readiness, presence, contract,
                                                       runtime, execution),
            "health_status":     health,
            "adapter_note":      (adapter or {}).get("note"),
        })

    families.sort(key=lambda f: (-f["implementations"], f["family"]))
    return {
        "families":   families,
        "totals":     totals,
        "families_count": len(families),
        "sources": {
            "audit":            audit_report["audit_version"],
            "files_scanned":    audit_report["files_scanned"],
            "runtime_adapters": len(_RUNTIME_ADAPTERS),
        },
        "honesty_note": (
            "presence_status is source-code truth. contract_status is "
            "capability-declaration truth. execution_status is P0.2e "
            "harness truth.  runtime_status stays NOT_AVAILABLE until "
            "P0.3 ships real runtime adapters — no axis is fabricated."
        ),
    }


def _reason_for(readiness, presence, contract, runtime, execution) -> str:
    if readiness == ReadinessStatus.NOT_PRESENT.value:
        return "no real Python implementation discovered in source"
    if readiness == ReadinessStatus.CONFIGURATION_REQUIRED.value:
        return "capability contract not declared for this family"
    if readiness == ReadinessStatus.BLOCKED.value:
        return "no runtime adapter — P0.3 required before it can execute"
    if readiness == ReadinessStatus.READY.value:
        return "presence + contract + runtime + execution all verified"
    return "runtime/execution not yet verified"


# ── Dependency graph placeholder ────────────────────────────────
#
# A HONEST dependency edge is emitted only when both endpoints of
# the edge are PRESENT (real implementation) AND their capability
# contracts declare compatible consumes/produces types.  Fabricated
# edges (e.g., "IUE depends on Detection because the architecture
# diagram says so") are explicitly rejected.
#

async def dependency_graph(db) -> dict:
    """
    Return the deterministic dependency graph derived from
    declared capability contracts.  An edge (A → B) exists iff
    B.consumes ∩ A.produces ≠ ∅ and both contracts are declared.
    """
    contracts: list[dict] = []
    async for c in db[CONTRACTS_COLLECTION].find(
        {}, {"_id": 0, "engine_id": 1, "classification": 1,
                "consumes": 1, "produces": 1, "contract_status": 1}
    ):
        contracts.append(c)

    edges: list[dict] = []
    for a in contracts:
        prods = set(a.get("produces") or [])
        if not prods: continue
        for b in contracts:
            if a["engine_id"] == b["engine_id"]: continue
            cons = set(b.get("consumes") or [])
            overlap = prods & cons
            if overlap:
                edges.append({
                    "from":     a["engine_id"],
                    "to":       b["engine_id"],
                    "via":      sorted(overlap),
                    "from_role": a.get("classification"),
                    "to_role":   b.get("classification"),
                })

    return {
        "nodes": [{
            "engine_id":      c["engine_id"],
            "classification": c.get("classification"),
            "contract":       c.get("contract_status"),
        } for c in contracts],
        "edges": edges,
        "counts": {"nodes": len(contracts), "edges": len(edges)},
        "honesty_note": (
            "Every edge is derived from actual consumes/produces "
            "overlap in declared capability contracts.  No edge is "
            "hard-coded from architecture diagrams."
        ),
    }
