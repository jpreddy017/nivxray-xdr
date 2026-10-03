"""STEP 35 · the bounded one-time historical endpoint-identity correction.

A deterministic correction of 1,236 historical canonical rows — NOT a migration
framework. It adds three operations to the existing closed registry and nothing
else: no new route, no UI, no caller-supplied query, no generalization.

WHAT IT CORRECTS. STEP 34E measured 1,236 rows of `xdr_canonical_evidence` that
carry no `additional_fields.endpoint_id` but do carry a platform-minted
`provenance.collector_id` — the AUTHENTICATED ingest boundary supplied the
identity while a non-sensor DSM normalized the event. The value is already
authenticated; this copies it into the authoritative field so the §d read can be
narrowed to one identity key. Since STEP 34F/34G no newly ingested row can join
that population: it is closed, historical and shrinking.

THE SAFETY PROPERTIES, each covered by a test:
  * eligibility is `canonical_identity_contract.backfill_candidate` and nothing
    else — this module holds no predicate of its own;
  * the population is EXACTLY 1,236; any drift in either direction HOLDS the run
    and reports, and is never truncated or broadened;
  * every write is guarded on the authoritative field still being ABSENT, so an
    existing identity can never be overwritten, and a row changed under the run
    is skipped rather than forced;
  * each row's PRIOR state and a collateral digest are recorded permanently
    before its write, so recovery restores recorded state and never infers it;
  * collateral immutability is re-verified from those digests after the writes;
  * recovery is a bounded revert scoped to one proven run;
  * the production read plan is proved index-served, with no COLLSCAN and no
    blocking SORT.
"""
from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional

from edr_plane import canonical_identity_contract as idc
from edr_plane.canonical_index_contract import (CANONICAL_COLLECTION,
                                                TARGET_CANONICAL_INDEXES)

#: Permanent per-row audit artifact. No TTL, no cleanup: it is the record of a
#: modification to historical security evidence and the source of truth for
#: recovery.
LEDGER = "e3_migration_row_ledger"

#: The measured population (STEP 34E). An EXACT expectation, not a limit to
#: fill: see `REFUSED_DRIFT`.
EXPECTED_CANDIDATES = 1236

#: Distinct from `AUTHENTICATED_INGEST_BOUNDARY`, forever, so a corrected row is
#: never mistaken for one that arrived carrying its identity.
AUTHORITY_BACKFILL = "BACKFILL_DETERMINISTIC"
BASIS = "AUTHENTICATED_INGEST_BOUNDARY_SUPPLIED_PLATFORM_ID"
CONTRACT_VERSION = "G-26"

#: The two — and only two — document paths this correction may touch.
PATH_IDENTITY = "additional_fields.endpoint_id"
PATH_PROVENANCE = "provenance.endpoint_identity"
MUTABLE_PATHS = (PATH_IDENTITY, PATH_PROVENANCE)

OUTCOME_WRITTEN = "WRITTEN"
OUTCOME_SKIPPED_CHANGED = "SKIPPED_CHANGED_UNDER_RUN"
OUTCOME_SKIPPED_INELIGIBLE = "SKIPPED_NOT_ELIGIBLE"
OUTCOME_REVERTED = "REVERTED"
OUTCOME_REVERT_SKIPPED_CHANGED = "REVERT_SKIPPED_CHANGED_UNDER_RUN"
OUTCOME_REVERT_SKIPPED_DIVERGED = "REVERT_SKIPPED_COLLATERAL_DIVERGED"

HOLD_DRIFT = "CANDIDATE_POPULATION_DRIFT"
HOLD_NO_RUN = "NO_COMPLETED_BACKFILL_RUN_TO_REVERT"
HOLD_NO_SAMPLE = "NO_AUTHORITATIVE_ROW_TO_EXPLAIN"

#: Narrows the scan only. Eligibility is decided in Python by the contract.
CANDIDATE_SELECTOR: Dict[str, Any] = {
    PATH_IDENTITY: {"$exists": False},
    idc.AUTHENTICATED_BOUNDARY_FIELD: {"$regex": f"^{idc.PLATFORM_ID_PREFIX}"},
}

#: Fields kept verbatim in the prior projection. Same database, same tenant
#: boundary, so this adds no exposure; it is what makes recovery a restore.
_PRIOR_SUBDOCS = ("additional_fields", "provenance", "host")
_PRIOR_SCALARS = ("tenant_id", "event_time", "ingest_time")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _canonical(obj: Any) -> Any:
    if isinstance(obj, Mapping):
        return {str(k): _canonical(v) for k, v in sorted(obj.items(),
                                                         key=lambda kv: str(kv[0]))}
    if isinstance(obj, (list, tuple)):
        return [_canonical(v) for v in obj]
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    return str(obj)


def _digest(obj: Any) -> str:
    return hashlib.sha256(
        json.dumps(_canonical(obj), sort_keys=True,
                   separators=(",", ":")).encode()).hexdigest()


def _without_mutable_paths(doc: Mapping[str, Any]) -> Dict[str, Any]:
    out = deepcopy(dict(doc))
    af = out.get("additional_fields")
    if isinstance(af, Mapping):
        af = dict(af)
        af.pop("endpoint_id", None)
        out["additional_fields"] = af
    prov = out.get("provenance")
    if isinstance(prov, Mapping):
        prov = dict(prov)
        prov.pop("endpoint_identity", None)
        out["provenance"] = prov
    return out


def collateral_digest(doc: Mapping[str, Any]) -> str:
    """A digest of EVERYTHING except the two paths this correction may set.

    It must be byte-identical before and after the run. That proves nothing
    unrelated moved — including fields nobody enumerated, and event content we
    deliberately do not copy into the ledger.
    """
    return _digest(_without_mutable_paths(doc))


def prior_projection(doc: Mapping[str, Any]) -> Dict[str, Any]:
    prior: Dict[str, Any] = {"doc_id": str(doc.get("_id"))}
    for key in _PRIOR_SCALARS:
        if key in doc:
            prior[key] = doc[key]
    for key in _PRIOR_SUBDOCS:
        if isinstance(doc.get(key), Mapping):
            prior[key] = deepcopy(dict(doc[key]))
    prior["collateral_digest"] = collateral_digest(doc)
    prior["full_doc_digest"] = _digest(doc)
    return prior


def stamp(endpoint_id: str, run_id: str) -> Dict[str, Any]:
    return {"state": idc.STATE_RESOLVED, "authority": AUTHORITY_BACKFILL,
            "source": idc.AUTHENTICATED_BOUNDARY_FIELD, "basis": BASIS,
            "migration_run_id": run_id, "backfilled_at": _now_iso(),
            "contract_version": CONTRACT_VERSION}


# ── the correction ────────────────────────────────────────────────────────

async def op_backfill(db, *, mode: str, run_id: str = "") -> Dict[str, Any]:
    """Correct EXACTLY the declared population. `report` writes nothing at all."""
    coll = db[CANONICAL_COLLECTION]
    observed = await coll.count_documents(CANDIDATE_SELECTOR)
    gates = {
        "candidate_population_exact": observed == EXPECTED_CANDIDATES,
        "revert_operation_registered": True,
    }
    out: Dict[str, Any] = {
        "collection": CANONICAL_COLLECTION, "mode": mode,
        "expected_candidates": EXPECTED_CANDIDATES,
        "observed_candidates": observed,
        "drift": observed - EXPECTED_CANDIDATES,
        "gates": gates,
    }

    if not gates["candidate_population_exact"]:
        # HOLD. Not truncated to the expectation, not broadened to the
        # observation. Either direction means our picture of the evidence is
        # wrong, and that is a review, not a write.
        out.update({"hold": HOLD_DRIFT, "ok": False, "written": 0})
        if mode != "report":
            return out
        out["collateral_verification"] = await verify_collateral(db)
        return out

    if mode == "report":
        eligible = ineligible = 0
        async for doc in coll.find(CANDIDATE_SELECTOR).limit(
                EXPECTED_CANDIDATES):
            if idc.backfill_candidate(doc):
                eligible += 1
            else:
                ineligible += 1
        out.update({"contract_eligible": eligible,
                    "contract_ineligible": ineligible,
                    "would_write": eligible, "written": 0,
                    "ok": ineligible == 0 and eligible == EXPECTED_CANDIDATES})
        out["collateral_verification"] = await verify_collateral(db)
        return out

    written: List[str] = []
    await db[LEDGER].create_index([("migration_run_id", 1), ("doc_id", 1)])
    skipped: Dict[str, List[str]] = {OUTCOME_SKIPPED_CHANGED: [],
                                     OUTCOME_SKIPPED_INELIGIBLE: []}
    async for doc in coll.find(CANDIDATE_SELECTOR).limit(
            EXPECTED_CANDIDATES):
        candidate = idc.backfill_candidate(doc)
        doc_id = doc["_id"]
        if not candidate:
            skipped[OUTCOME_SKIPPED_INELIGIBLE].append(str(doc_id))
            await _ledger(db, run_id, doc, OUTCOME_SKIPPED_INELIGIBLE, None)
            continue
        endpoint_id = candidate["set"][idc.AUTHORITATIVE_FIELD]
        await _ledger(db, run_id, doc, "CAPTURED", endpoint_id)
        res = await coll.update_one(
            {"_id": doc_id,
             PATH_IDENTITY: {"$exists": False},
             idc.AUTHENTICATED_BOUNDARY_FIELD: endpoint_id},
            {"$set": {PATH_IDENTITY: endpoint_id,
                      PATH_PROVENANCE: stamp(endpoint_id, run_id)}})
        if res.matched_count == 1:
            written.append(str(doc_id))
            await _ledger_outcome(db, run_id, doc_id, OUTCOME_WRITTEN)
        else:
            skipped[OUTCOME_SKIPPED_CHANGED].append(str(doc_id))
            await _ledger_outcome(db, run_id, doc_id, OUTCOME_SKIPPED_CHANGED)

    residual = await coll.count_documents(CANDIDATE_SELECTOR)
    verification = await verify_collateral(db, run_id=run_id)
    out.update({
        "written": len(written),
        "skipped_changed_under_run": len(skipped[OUTCOME_SKIPPED_CHANGED]),
        "skipped_not_eligible": len(skipped[OUTCOME_SKIPPED_INELIGIBLE]),
        "residual_candidates": residual,
        "accounting_balanced": (len(written)
                                + len(skipped[OUTCOME_SKIPPED_CHANGED])
                                + len(skipped[OUTCOME_SKIPPED_INELIGIBLE])
                                ) == observed,
        "collateral_verification": verification,
        "ok": (len(written) == observed and residual == 0
               and verification["diverged"] == 0),
    })
    return out


async def _ledger(db, run_id: str, doc: Mapping[str, Any], outcome: str,
                  endpoint_id: Optional[str]) -> None:
    await db[LEDGER].update_one(
        {"migration_run_id": run_id, "doc_id": str(doc["_id"])},
        {"$set": {"operation": OP_BACKFILL, "collection": CANONICAL_COLLECTION,
                  "tenant_id": doc.get("tenant_id"),
                  "prior": prior_projection(doc),
                  "prior_endpoint_id": None,
                  "endpoint_id_set": endpoint_id,
                  "outcome": outcome, "at": _now_iso()}},
        upsert=True)


async def _ledger_outcome(db, run_id: str, doc_id: Any, outcome: str) -> None:
    await db[LEDGER].update_one(
        {"migration_run_id": run_id, "doc_id": str(doc_id)},
        {"$set": {"outcome": outcome, "at": _now_iso()}})


# ── collateral immutability ───────────────────────────────────────────────

async def verify_collateral(db, *, run_id: str = "") -> Dict[str, Any]:
    """Recompute the collateral digest for EVERY written row and compare it to
    the value recorded before the write. No sampling."""
    query: Dict[str, Any] = {"outcome": OUTCOME_WRITTEN,
                             "operation": OP_BACKFILL}
    if run_id:
        query["migration_run_id"] = run_id
    coll = db[CANONICAL_COLLECTION]
    checked = 0
    diverged: List[str] = []
    missing: List[str] = []
    async for row in db[LEDGER].find(query):
        doc = await coll.find_one({"_id": _as_id(row["doc_id"])})
        if doc is None:
            missing.append(row["doc_id"])
            continue
        checked += 1
        if collateral_digest(doc) != row["prior"]["collateral_digest"]:
            diverged.append(row["doc_id"])
    return {"checked": checked, "diverged": len(diverged),
            "diverged_doc_ids": diverged[:20], "missing": len(missing),
            "unchanged": checked - len(diverged)}


def _as_id(doc_id: str) -> Any:
    from bson import ObjectId
    try:
        return ObjectId(doc_id)
    except Exception:
        return doc_id


# ── bounded recovery ──────────────────────────────────────────────────────

async def op_revert(db, *, mode: str, run_id: str = "") -> Dict[str, Any]:
    """Undo ONE proven backfill run, restoring RECORDED prior state only.

    A row is reverted only when every one of these holds: the ledger says we
    wrote it, its provenance names THIS run with OUR authority, its current
    identity equals the value we set, and its collateral digest still matches
    what we recorded. Nothing is inferred; a boundary-stamped row can never
    qualify.
    """
    target = await _latest_backfill_run(db)
    out: Dict[str, Any] = {"collection": CANONICAL_COLLECTION, "mode": mode,
                           "target_run_id": target}
    if not target:
        out.update({"hold": HOLD_NO_RUN, "ok": False, "reverted": 0})
        return out

    coll = db[CANONICAL_COLLECTION]
    reverted: List[str] = []
    skipped = {OUTCOME_REVERT_SKIPPED_CHANGED: 0,
               OUTCOME_REVERT_SKIPPED_DIVERGED: 0}
    eligible = 0
    async for row in db[LEDGER].find({"migration_run_id": target,
                                      "operation": OP_BACKFILL,
                                      "outcome": OUTCOME_WRITTEN}):
        doc = await coll.find_one({"_id": _as_id(row["doc_id"])})
        if doc is None:
            skipped[OUTCOME_REVERT_SKIPPED_CHANGED] += 1
            continue
        prov = (doc.get("provenance") or {}).get("endpoint_identity") or {}
        current = (doc.get("additional_fields") or {}).get("endpoint_id")
        proven = (prov.get("authority") == AUTHORITY_BACKFILL
                  and prov.get("migration_run_id") == target
                  and current == row.get("endpoint_id_set"))
        if not proven:
            skipped[OUTCOME_REVERT_SKIPPED_CHANGED] += 1
            continue
        if collateral_digest(doc) != row["prior"]["collateral_digest"]:
            skipped[OUTCOME_REVERT_SKIPPED_DIVERGED] += 1
            continue
        eligible += 1
        if mode == "report":
            continue
        restore = _restore_update(row["prior"])
        res = await coll.update_one(
            {"_id": doc["_id"], PATH_IDENTITY: row["endpoint_id_set"],
             f"{PATH_PROVENANCE}.migration_run_id": target}, restore)
        if res.matched_count == 1:
            reverted.append(row["doc_id"])
            await _ledger_outcome(db, target, row["doc_id"], OUTCOME_REVERTED)
        else:
            skipped[OUTCOME_REVERT_SKIPPED_CHANGED] += 1

    out.update({"reversible": eligible, "reverted": len(reverted),
                "skipped_changed_under_run":
                    skipped[OUTCOME_REVERT_SKIPPED_CHANGED],
                "skipped_collateral_diverged":
                    skipped[OUTCOME_REVERT_SKIPPED_DIVERGED],
                "ok": (mode == "report") or len(reverted) == eligible})
    return out


def _restore_update(prior: Mapping[str, Any]) -> Dict[str, Any]:
    """Restore from the LEDGER. There is no branch here that reconstructs a
    value from the live document."""
    recorded_identity = (prior.get("additional_fields") or {}).get("endpoint_id")
    recorded_prov = (prior.get("provenance") or {}).get("endpoint_identity")
    sets: Dict[str, Any] = {}
    unsets: Dict[str, str] = {}
    if recorded_identity is None:
        unsets[PATH_IDENTITY] = ""
    else:
        sets[PATH_IDENTITY] = recorded_identity
    if recorded_prov is None:
        unsets[PATH_PROVENANCE] = ""
    else:
        sets[PATH_PROVENANCE] = recorded_prov
    update: Dict[str, Any] = {}
    if sets:
        update["$set"] = sets
    if unsets:
        update["$unset"] = unsets
    return update


async def _latest_backfill_run(db) -> Optional[str]:
    cur = db[LEDGER].find({"operation": OP_BACKFILL,
                           "outcome": OUTCOME_WRITTEN}).sort("at", -1).limit(1)
    async for row in cur:
        return row["migration_run_id"]
    return None


# ── the read plan must be index-served ────────────────────────────────────

async def op_explain(db, *, mode: str, run_id: str = "") -> Dict[str, Any]:
    """Prove the production §d read is served by the intended index: IXSCAN on
    the declared name, no COLLSCAN, no blocking SORT, and — because
    `indexBounds` preserves true key order where `list_indexes` does not (G-39)
    — an order-preserving attestation of the compound key."""
    coll = db[CANONICAL_COLLECTION]
    sample = await coll.find_one({PATH_IDENTITY: {"$exists": True}},
                                 {PATH_IDENTITY: 1, "tenant_id": 1})
    if not sample:
        return {"hold": HOLD_NO_SAMPLE, "ok": False}
    endpoint_id = (sample.get("additional_fields") or {}).get("endpoint_id")
    spec = TARGET_CANONICAL_INDEXES[0]
    plan = await _explain(db, filt={"tenant_id": sample.get("tenant_id"),
                                    PATH_IDENTITY: {"$in": [endpoint_id]}},
                          sort={"event_time": -1}, limit=200)
    stages = _stages(plan)
    bounds = _bounds(plan)
    checks = {
        "ixscan_present": "IXSCAN" in stages,
        "index_name_matches": _index_name(plan) == spec["name"],
        "no_collscan": "COLLSCAN" not in stages,
        "no_blocking_sort": "SORT" not in stages,
        "key_order_matches_contract":
            bounds == [k for k, _ in spec["key"]],
    }
    return {"collection": CANONICAL_COLLECTION, "mode": mode,
            "index_expected": spec["name"], "index_used": _index_name(plan),
            "stages": stages, "index_bounds_key_order": bounds,
            "contract_key_order": [k for k, _ in spec["key"]],
            "checks": checks, "ok": all(checks.values())}


async def _explain(db, *, filt: Dict[str, Any], sort: Dict[str, Any],
                   limit: int) -> Dict[str, Any]:
    return await db.command(
        {"explain": {"find": CANONICAL_COLLECTION, "filter": filt,
                     "sort": sort, "limit": limit},
         "verbosity": "executionStats"})


def _winning(plan: Mapping[str, Any]) -> Dict[str, Any]:
    qp = plan.get("queryPlanner") or {}
    return dict(qp.get("winningPlan") or {})


def _walk(node: Any):
    if isinstance(node, Mapping):
        yield node
        for key in ("inputStage", "queryPlan"):
            if isinstance(node.get(key), Mapping):
                yield from _walk(node[key])
        for key in ("inputStages", "shards"):
            for child in (node.get(key) or []):
                yield from _walk(child)


def _stages(plan: Mapping[str, Any]) -> List[str]:
    return [str(n.get("stage")) for n in _walk(_winning(plan))
            if n.get("stage")]


def _index_name(plan: Mapping[str, Any]) -> Optional[str]:
    for node in _walk(_winning(plan)):
        if node.get("stage") == "IXSCAN":
            return node.get("indexName")
    return None


def _bounds(plan: Mapping[str, Any]) -> List[str]:
    for node in _walk(_winning(plan)):
        if node.get("stage") == "IXSCAN":
            return list((node.get("indexBounds") or {}).keys())
    return []


OP_BACKFILL = "backfill_authoritative_endpoint_identity"
OP_REVERT = "revert_authoritative_endpoint_identity_backfill"
OP_EXPLAIN = "explain_canonical_identity_read_plan"

#: Registered into the existing closed registry. Nothing here is callable
#: except by name, and `op_explain` never writes.
OPERATIONS = {OP_BACKFILL: op_backfill,
              OP_REVERT: op_revert,
              OP_EXPLAIN: op_explain}
