"""G-41 · bounded historical backfill of `observation_us`. REPORT-ready; apply NOT authorized.

Same discipline as STEP 35, reusing the same closed registry: zero caller
parameters, admin-gated, single-writer lock, audited, `report` writes nothing.

ELIGIBILITY — all three required, no inference:
  1. `event_time` exists and is a non-empty string;
  2. `temporal_authority.to_epoch_us()` parses it deterministically;
  3. no existing `observation_us` (a conflicting value is never overwritten).

`event_time` is NEVER rewritten. The only paths this may set are
`observation_us` and the two declarations beside it.
"""
from __future__ import annotations

import copy
from datetime import datetime
from typing import Any, Dict, List, Optional

from edr_plane import temporal_authority as ta
from edr_plane.canonical_index_contract import CANONICAL_COLLECTION
from edr_plane.identity_backfill import (LEDGER, _as_id, _digest, _now_iso,
                                         digest_excluding)

OP_BACKFILL_OBSERVATION_US = "backfill_canonical_observation_us"

#: The provenance key this migration writes. Named once so the `$set` below and
#: the exclusion set beneath it cannot drift apart.
PROVENANCE_KEY = "observation_us_provenance"

#: The four — and only four — document paths this migration may set. Derived
#: from the writer contract, not restated by hand.
G41_MUTABLE_PATHS = (
    ta.OBSERVATION_US,
    f"additional_fields.{ta.STATE_KEY}",
    f"additional_fields.{ta.BASIS_KEY}",
    f"provenance.{PROVENANCE_KEY}",
)


def g41_collateral_digest(doc: Dict[str, Any]) -> str:
    """Collateral protection for THIS migration: everything except the four
    intended temporal paths.

    The shared STEP 35 digest excludes the identity paths instead, so using it
    here would have counted every intended `observation_us` addition as
    collateral divergence — and the verify would then be unable to tell an
    intended temporal change from an accidental one. `event_time`, tenant
    identity, endpoint identity, all other provenance and all other evidence
    stay protected.
    """
    return digest_excluding(doc, G41_MUTABLE_PATHS)


#: Narrows the scan only; eligibility is decided in Python by the contract.
CANDIDATE_SELECTOR: Dict[str, Any] = {
    ta.OBSERVATION_US: {"$exists": False},
    ta.SOURCE_FIELD: {"$exists": True, "$type": "string", "$ne": ""},
}

AUTHORITY = "BACKFILL_TEMPORAL_AUTHORITY"
HOLD_DRIFT = "CANDIDATE_POPULATION_DRIFT"

#: ONE immutable logical migration, across however many runs it takes. Runs are
#: disposable; the POPULATION is not. Stamped into every ledger row so a
#: continuation can prove what a previous run completed instead of being told.
POPULATION_ID = "g41_observation_us_historical"
OUTCOME_WRITTEN = "WRITTEN"
OUTCOME_SKIPPED_CHANGED = "SKIPPED_CHANGED_UNDER_RUN"
OUTCOME_SKIPPED_UNPARSEABLE = "SKIPPED_UNPARSEABLE_OBSERVATION_TIME"

#: Set ONLY by a reviewed commit, from a production REPORT census. Until then
#: `apply` cannot run: an unset expectation is not an expectation.
#:
#: Declared 2026-06 from a read-only production recount taken AFTER the G-41
#: writer went live, so the population is closed, not open: new evidence is
#: stamped at ingest and can no longer join this set. Measured twice, stable:
#: candidates 122,477 · representation space 43,521 + Z 78,956 + offset 0,
#: unaccounted 0, sum − candidates 0 · candidates already carrying a value 0.
#: Drift decision: this number is NEVER adjusted to make the gate pass. A lower
#: count means the population changed (retention) and a higher count means a
#: population believed closed has grown; both HOLD for owner investigation.
EXPECTED_CANDIDATES: Optional[int] = 122_477


def _written_query() -> Dict[str, Any]:
    return {"operation": OP_BACKFILL_OBSERVATION_US,
            "population_id": POPULATION_ID, "outcome": OUTCOME_WRITTEN}


async def _progress(db) -> Dict[str, Any]:
    """What a PREVIOUS run of this population provably completed.

    Read from the ledger and nowhere else. The expectation is never consulted
    here, so a continuation cannot be manufactured by editing a constant.
    """
    q = _written_query()
    written_before = await db[LEDGER].count_documents(q)
    if written_before == 0:
        return {"written_before": 0, "ledger_integrity": True,
                "ledger_detail": "no prior run for this population"}
    malformed = await db[LEDGER].count_documents({**q, "$or": [
        {f"prior.{ta.SOURCE_FIELD}": {"$exists": False}},
        {"prior.collateral_digest": {"$exists": False}},
        {"prior.full_doc_digest": {"$exists": False}},
        {"observation_us_set": {"$exists": False}}]})
    distinct = len(await db[LEDGER].distinct("doc_id", q))
    return {"written_before": written_before,
            "ledger_integrity": malformed == 0 and distinct == written_before,
            "ledger_detail": f"malformed={malformed} distinct={distinct}"}


async def op_backfill_observation_us(db, *, mode: str, run_id: str = "") -> Dict[str, Any]:
    coll = db[CANONICAL_COLLECTION]
    observed = await coll.count_documents(CANDIDATE_SELECTOR)
    prog = await _progress(db)
    written_before = prog["written_before"]
    eligible = unparseable = 0
    async for doc in coll.find(CANDIDATE_SELECTOR, {ta.SOURCE_FIELD: 1}).limit(
            observed if observed < 500_000 else 500_000):
        if ta.to_epoch_us(doc.get(ta.SOURCE_FIELD)) is None:
            unparseable += 1
        else:
            eligible += 1

    out: Dict[str, Any] = {
        "collection": CANONICAL_COLLECTION, "mode": mode,
        "expected_candidates": EXPECTED_CANDIDATES,
        "original_population": EXPECTED_CANDIDATES,
        "population_id": POPULATION_ID,
        "observed_candidates": observed,
        "written_before": written_before,
        "ledger_detail": prog["ledger_detail"],
        "contract_eligible": eligible,
        "contract_unparseable": unparseable,
        "gates": {
            "expectation_declared": EXPECTED_CANDIDATES is not None,
            "candidate_population_exact": (EXPECTED_CANDIDATES is not None
                                           and observed == EXPECTED_CANDIDATES),
            #: THE resume invariant. On a first run `written_before` is 0, so
            #: this is exactly the old exact-population gate. On a continuation
            #: it proves the same original population is still fully accounted
            #: for — a row that vanished, or a row that joined, breaks the sum.
            "population_accounted": (EXPECTED_CANDIDATES is not None
                                     and written_before + observed
                                     == EXPECTED_CANDIDATES),
            "all_candidates_parse": unparseable == 0,
            "ledger_integrity": prog["ledger_integrity"],
        },
    }
    #: `candidate_population_exact` is REPORTED for continuity but is not a
    #: precondition: a legitimate continuation has fewer candidates left. The
    #: accounting gate is what may never be false.
    required = {k: v for k, v in out["gates"].items()
                if k != "candidate_population_exact"}

    if mode == "report":
        out.update({"written": 0, "would_write": eligible,
                    "ok": all(required.values())})
        return out

    if not all(required.values()):
        out.update({"hold": HOLD_DRIFT, "ok": False, "written": 0})
        return out

    written: List[str] = []
    skipped = {OUTCOME_SKIPPED_CHANGED: 0, OUTCOME_SKIPPED_UNPARSEABLE: 0}
    await db[LEDGER].create_index([("migration_run_id", 1), ("doc_id", 1)])
    async for doc in coll.find(CANDIDATE_SELECTOR).limit(observed):
        us = ta.to_epoch_us(doc.get(ta.SOURCE_FIELD))
        if us is None:
            skipped[OUTCOME_SKIPPED_UNPARSEABLE] += 1
            continue
        await db[LEDGER].update_one(
            {"migration_run_id": run_id, "doc_id": str(doc["_id"])},
            {"$set": {"operation": OP_BACKFILL_OBSERVATION_US,
                      "population_id": POPULATION_ID,
                      "collection": CANONICAL_COLLECTION,
                      "tenant_id": doc.get("tenant_id"),
                      "prior": {"doc_id": str(doc["_id"]),
                                ta.SOURCE_FIELD: doc.get(ta.SOURCE_FIELD),
                                "collateral_digest": g41_collateral_digest(doc),
                                "full_doc_digest": _digest(doc)},
                      "observation_us_set": us, "prior_observation_us": None,
                      "outcome": "CAPTURED", "at": _now_iso()}}, upsert=True)
        res = await coll.update_one(
            {"_id": doc["_id"], ta.OBSERVATION_US: {"$exists": False},
             ta.SOURCE_FIELD: doc.get(ta.SOURCE_FIELD)},
            {"$set": {ta.OBSERVATION_US: us,
                      f"additional_fields.{ta.STATE_KEY}": ta.STATE_DERIVED,
                      f"additional_fields.{ta.BASIS_KEY}": ta.BASIS,
                      f"provenance.{PROVENANCE_KEY}": {
                          "authority": AUTHORITY, "migration_run_id": run_id,
                          "source": ta.SOURCE_FIELD,
                          "contract_version": ta.CONTRACT_VERSION,
                          "backfilled_at": _now_iso()}}})
        if res.matched_count == 1:
            written.append(str(doc["_id"]))
            await db[LEDGER].update_one(
                {"migration_run_id": run_id, "doc_id": str(doc["_id"])},
                {"$set": {"outcome": OUTCOME_WRITTEN, "at": _now_iso()}})
        else:
            skipped[OUTCOME_SKIPPED_CHANGED] += 1

    residual = await coll.count_documents(CANDIDATE_SELECTOR)
    population_written = written_before + len(written)
    out.update({"written": len(written), "written_this_run": len(written),
                "population_written_total": population_written,
                "residual_candidates": residual,
                "skipped_changed_under_run": skipped[OUTCOME_SKIPPED_CHANGED],
                "skipped_unparseable": skipped[OUTCOME_SKIPPED_UNPARSEABLE],
                "ok": (population_written == EXPECTED_CANDIDATES
                       and residual == 0)})
    return out


async def op_verify_observation_us(db, *, mode: str, run_id: str = "") -> Dict[str, Any]:
    """Read-only: does the stored comparable value still agree with the stored
    evidence, and did anything else move?"""
    coll = db[CANONICAL_COLLECTION]
    checked = disagreeing = collateral_diverged = 0
    async for row in db[LEDGER].find(_written_query()):
        doc = await coll.find_one({"_id": _as_id(row["doc_id"])})
        if doc is None:
            continue
        checked += 1
        if doc.get(ta.OBSERVATION_US) != ta.to_epoch_us(doc.get(ta.SOURCE_FIELD)):
            disagreeing += 1
        if g41_collateral_digest(doc) != row["prior"]["collateral_digest"]:
            collateral_diverged += 1
    return {"collection": CANONICAL_COLLECTION, "mode": mode, "checked": checked,
            "disagreeing": disagreeing, "collateral_diverged": collateral_diverged,
            "ok": disagreeing == 0 and collateral_diverged == 0}


OP_VERIFY_OBSERVATION_US = "verify_canonical_observation_us"

#: Observable progress for THIS operation: the newest row the backfill wrote.
#: A worker that is writing rows is alive, however long it has been running —
#: which is the signal elapsed age could not provide.
async def last_backfill_progress(db):
    row = await db[LEDGER].find_one(
        {"operation": OP_BACKFILL_OBSERVATION_US,
         "population_id": POPULATION_ID},
        sort=[("at", -1)])
    if not row:
        return None
    try:
        return datetime.fromisoformat(str(row.get("at")).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


LIVENESS = {OP_BACKFILL_OBSERVATION_US: last_backfill_progress}

OPERATIONS = {OP_BACKFILL_OBSERVATION_US: op_backfill_observation_us,
              OP_VERIFY_OBSERVATION_US: op_verify_observation_us}


def selector() -> Dict[str, Any]:
    return copy.deepcopy(CANDIDATE_SELECTOR)
