"""STEP 35 · the bounded historical identity correction, proven locally.

Every test runs against the PREVIEW database and a THROWAWAY collection created
and dropped by the fixture. Nothing here reads or writes production, executes
Behavior, or touches a sensor, KUSHU or DESKTOP.

The correction's own constants are redirected at the module level
(`CANONICAL_COLLECTION`, `EXPECTED_CANDIDATES`), which is exactly how the real
run resolves them — so the code under test is the shipped code, not a variant.
"""
from __future__ import annotations

import copy
import os
import sys
import uuid

import pytest
import pytest_asyncio
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import MongoClient

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from edr_plane import canonical_identity_contract as idc
from edr_plane import identity_backfill as ib
from edr_plane import migration_control as mc
from edr_plane.canonical_index_contract import \
    TARGET_CANONICAL_INDEXES

POP = 5  # the declared population, scaled down; the RULE is what is under test
TENANT = "t_step35"


def _eligible(n: int) -> dict:
    """The one eligible shape: no authoritative field, platform-minted
    authenticated boundary id."""
    return {"tenant_id": TENANT, "event_time": f"2026-06-0{n % 9 + 1}T00:00:00Z",
            "ingest_time": "2026-06-10T00:00:00Z",
            "host": {"hostname": f"h{n}", "host_id": f"h{n}"},
            "provenance": {"collector_id": f"ep_src{n}", "source": "dsm"},
            "additional_fields": {"rule": f"r{n}"},
            "event": {"command_line": f"cmd {n}"}}


@pytest_asyncio.fixture
async def ctx(monkeypatch):
    name = f"step35_canon_{uuid.uuid4().hex[:10]}"
    db = AsyncIOMotorClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]
    monkeypatch.setattr(ib, "CANONICAL_COLLECTION", name)
    monkeypatch.setattr(ib, "EXPECTED_CANDIDATES", POP)
    monkeypatch.setattr(ib, "LEDGER", f"step35_ledger_{uuid.uuid4().hex[:8]}")
    yield db, name
    await db[name].drop()
    await db[ib.LEDGER].drop()


async def _seed(db, name, n=POP):
    if n:
        await db[name].insert_many([_eligible(i) for i in range(n)])


def _run_id() -> str:
    return "mig_" + uuid.uuid4().hex[:16]


async def _docs(db, name):
    return {str(d["_id"]): d async for d in db[name].find({})}


# ── eligibility is the contract's, not ours ──────────────────────────────

def test_the_correction_holds_no_eligibility_predicate_of_its_own():
    """The rule lives in the identity contract. A second copy here is how the
    two drift apart, so there must not be one."""
    with open(ib.__file__) as fh:
        src = fh.read()
    assert "idc.backfill_candidate(" in src
    body = src.split("async def op_backfill")[1].split("async def op_revert")[0]
    for invented in ("startswith(", "host_id", "hostname", '"ep_"'):
        assert invented not in body, f"invented predicate {invented!r}"


@pytest.mark.asyncio
async def test_report_mode_writes_absolutely_nothing(ctx):
    db, name = ctx
    await _seed(db, name)
    before = await _docs(db, name)
    out = await ib.op_backfill(db, mode="report", run_id=_run_id())
    assert out["observed_candidates"] == POP
    assert out["would_write"] == POP and out["written"] == 0
    assert out["ok"] is True
    assert await _docs(db, name) == before
    assert await db[ib.LEDGER].count_documents({}) == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("mutate,label", [
    (lambda d: d["additional_fields"].update(endpoint_id="ep_already"),
     "authoritative already present"),
    (lambda d: d["additional_fields"].update(endpoint_id="not-minted"),
     "authoritative present but not platform-minted"),
    (lambda d: d["provenance"].pop("collector_id"), "name only"),
    (lambda d: (d.pop("host"), d["provenance"].pop("collector_id")),
     "no host object at all"),
    (lambda d: d["provenance"].update(collector_id="DESKTOP-ABC"),
     "boundary id is a hostname, not platform-minted"),
])
async def test_an_ineligible_row_is_never_written(ctx, mutate, label):
    db, name = ctx
    doc = _eligible(0)
    mutate(doc)
    await db[name].insert_one(doc)
    out = await ib.op_backfill(db, mode="apply", run_id=_run_id())
    assert out["written"] == 0, label
    stored = await db[name].find_one({})
    assert (stored.get("additional_fields") or {}).get("endpoint_id") == \
        (doc.get("additional_fields") or {}).get("endpoint_id"), label
    assert "endpoint_identity" not in (stored.get("provenance") or {}), label


# ── the population is EXACT: drift HOLDS, it is never absorbed ───────────

@pytest.mark.asyncio
@pytest.mark.parametrize("n", [POP + 1, POP - 1, 0])
async def test_any_population_drift_holds_and_writes_nothing(ctx, n):
    db, name = ctx
    await _seed(db, name, n)
    before = await _docs(db, name)
    out = await ib.op_backfill(db, mode="apply", run_id=_run_id())
    assert out["hold"] == ib.HOLD_DRIFT
    assert out["ok"] is False and out["written"] == 0
    assert out["observed_candidates"] == n and out["drift"] == n - POP
    assert await _docs(db, name) == before, "a drifting population was touched"


@pytest.mark.asyncio
async def test_an_oversized_population_is_not_truncated_to_the_expectation(ctx):
    """The ceiling is a refusal threshold. Processing the first POP rows of a
    larger population would be a silent partial migration."""
    db, name = ctx
    await _seed(db, name, POP + 3)
    out = await ib.op_backfill(db, mode="apply", run_id=_run_id())
    assert out["written"] == 0
    assert await db[name].count_documents(
        {ib.PATH_IDENTITY: {"$exists": True}}) == 0


def test_no_request_field_or_env_var_can_relax_the_population_ceiling():
    from routers.edr_migration_control import MigrationRequest
    assert MigrationRequest.model_config["extra"] == "forbid"
    assert set(MigrationRequest.model_fields) == {"mode"}
    with open(ib.__file__) as fh:
        src = fh.read()
    assert "environ" not in src and "getenv" not in src


# ── the write ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_apply_corrects_exactly_the_population_and_stamps_provenance(ctx):
    db, name = ctx
    await _seed(db, name)
    run = _run_id()
    out = await ib.op_backfill(db, mode="apply", run_id=run)
    assert out["written"] == POP and out["residual_candidates"] == 0
    assert out["accounting_balanced"] is True and out["ok"] is True
    async for doc in db[name].find({}):
        boundary = doc["provenance"]["collector_id"]
        assert doc["additional_fields"]["endpoint_id"] == boundary
        stamp = doc["provenance"]["endpoint_identity"]
        assert stamp["authority"] == ib.AUTHORITY_BACKFILL
        assert stamp["authority"] != idc.BOUNDARY_AUTHORITY, \
            "a corrected row must never look boundary-stamped"
        assert stamp["source"] == idc.AUTHENTICATED_BOUNDARY_FIELD
        assert stamp["basis"] == ib.BASIS
        assert stamp["migration_run_id"] == run
        assert stamp["state"] == idc.STATE_RESOLVED
        assert stamp["backfilled_at"].endswith("Z")


@pytest.mark.asyncio
async def test_the_write_touches_exactly_two_paths_and_nothing_else(ctx):
    db, name = ctx
    await _seed(db, name)
    before = await _docs(db, name)
    await ib.op_backfill(db, mode="apply", run_id=_run_id())
    after = await _docs(db, name)
    assert set(before) == set(after)
    for doc_id, old in before.items():
        new = copy.deepcopy(after[doc_id])
        new["additional_fields"].pop("endpoint_id")
        new["provenance"].pop("endpoint_identity")
        assert new == old, "a collateral field changed"
        assert ib.collateral_digest(after[doc_id]) == \
            ib.collateral_digest(old)


@pytest.mark.asyncio
async def test_collateral_immutability_is_verified_for_every_written_row(ctx):
    db, name = ctx
    await _seed(db, name)
    run = _run_id()
    out = await ib.op_backfill(db, mode="apply", run_id=run)
    v = out["collateral_verification"]
    assert v["checked"] == POP and v["unchanged"] == POP
    assert v["diverged"] == 0 and v["missing"] == 0


@pytest.mark.asyncio
async def test_divergence_is_detected_rather_than_assumed_away(ctx):
    """The digest is only worth having if a real change trips it."""
    db, name = ctx
    await _seed(db, name)
    run = _run_id()
    await ib.op_backfill(db, mode="apply", run_id=run)
    victim = await db[name].find_one({})
    await db[name].update_one({"_id": victim["_id"]},
                              {"$set": {"host.hostname": "tampered"}})
    v = await ib.verify_collateral(db, run_id=run)
    assert v["diverged"] == 1 and str(victim["_id"]) in v["diverged_doc_ids"]


@pytest.mark.asyncio
async def test_an_existing_authoritative_identity_is_never_overwritten(ctx, monkeypatch):
    """A row that gains an identity between the eligibility decision and the
    write is SKIPPED, not forced. The guard lives in the update filter itself,
    so it holds under a real race rather than by good timing."""
    db, name = ctx
    await _seed(db, name)
    sync = MongoClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]
    real = idc.backfill_candidate
    raced = {}

    def sneak_a_live_identity_in(row):
        if not raced:
            raced["id"] = row["_id"]
            sync[name].update_one(
                {"_id": row["_id"]},
                {"$set": {ib.PATH_IDENTITY: "ep_live_winner"}})
        return real(row)

    monkeypatch.setattr(ib.idc, "backfill_candidate", sneak_a_live_identity_in)
    out = await ib.op_backfill(db, mode="apply", run_id=_run_id())

    assert out["skipped_changed_under_run"] == 1
    assert out["written"] == POP - 1
    assert out["ok"] is False, "a skip must never report a clean pass"
    kept = await db[name].find_one({"_id": raced["id"]})
    assert kept["additional_fields"]["endpoint_id"] == "ep_live_winner"
    assert "endpoint_identity" not in kept["provenance"]


@pytest.mark.asyncio
async def test_a_second_apply_holds_because_the_population_is_now_empty(ctx):
    db, name = ctx
    await _seed(db, name)
    await ib.op_backfill(db, mode="apply", run_id=_run_id())
    again = await ib.op_backfill(db, mode="apply", run_id=_run_id())
    assert again["observed_candidates"] == 0
    assert again["hold"] == ib.HOLD_DRIFT and again["written"] == 0


# ── the permanent ledger ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_the_ledger_is_permanent_and_records_prior_state_per_row(ctx):
    db, name = ctx
    await _seed(db, name)
    run = _run_id()
    await ib.op_backfill(db, mode="apply", run_id=run)
    rows = [r async for r in db[ib.LEDGER].find({"migration_run_id": run})]
    assert len(rows) == POP
    for r in rows:
        assert r["outcome"] == ib.OUTCOME_WRITTEN
        assert r["prior_endpoint_id"] is None
        assert "endpoint_id" not in (r["prior"].get("additional_fields") or {})
        assert "endpoint_identity" not in (r["prior"].get("provenance") or {})
        assert r["prior"]["collateral_digest"] and r["prior"]["full_doc_digest"]
    names = [i["name"] async for i in db[ib.LEDGER].list_indexes()]
    assert "migration_run_id_1_doc_id_1" in names
    async for i in db[ib.LEDGER].list_indexes():
        assert "expireAfterSeconds" not in i, "the audit ledger must not expire"


# ── bounded recovery ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_revert_restores_every_document_byte_for_byte(ctx):
    db, name = ctx
    await _seed(db, name)
    before = await _docs(db, name)
    run = _run_id()
    await ib.op_backfill(db, mode="apply", run_id=run)
    out = await ib.op_revert(db, mode="apply", run_id=_run_id())
    assert out["target_run_id"] == run
    assert out["reverted"] == POP and out["ok"] is True
    assert await _docs(db, name) == before


@pytest.mark.asyncio
async def test_revert_report_mode_names_the_reversible_rows_and_writes_nothing(ctx):
    db, name = ctx
    await _seed(db, name)
    run = _run_id()
    await ib.op_backfill(db, mode="apply", run_id=run)
    after_apply = await _docs(db, name)
    out = await ib.op_revert(db, mode="report", run_id=_run_id())
    assert out["reversible"] == POP and out["reverted"] == 0
    assert await _docs(db, name) == after_apply


@pytest.mark.asyncio
async def test_revert_restores_from_the_ledger_only_and_never_infers(ctx):
    """Delete the record of a row and the revert must leave that row alone.
    Reconstructing its prior state from the live document would be a guess."""
    db, name = ctx
    await _seed(db, name)
    run = _run_id()
    await ib.op_backfill(db, mode="apply", run_id=run)
    orphan = await db[name].find_one({})
    await db[ib.LEDGER].delete_one({"migration_run_id": run,
                                    "doc_id": str(orphan["_id"])})
    out = await ib.op_revert(db, mode="apply", run_id=_run_id())
    assert out["reverted"] == POP - 1
    still = await db[name].find_one({"_id": orphan["_id"]})
    assert still["additional_fields"]["endpoint_id"] == \
        still["provenance"]["collector_id"], "an unrecorded row was inferred"


@pytest.mark.asyncio
async def test_revert_cannot_touch_a_boundary_stamped_row(ctx):
    db, name = ctx
    await _seed(db, name)
    run = _run_id()
    await ib.op_backfill(db, mode="apply", run_id=run)
    protected = await db[name].find_one({})
    await db[name].update_one(
        {"_id": protected["_id"]},
        {"$set": {f"{ib.PATH_PROVENANCE}.authority": idc.BOUNDARY_AUTHORITY}})
    out = await ib.op_revert(db, mode="apply", run_id=_run_id())
    assert out["reverted"] == POP - 1
    assert out["skipped_changed_under_run"] == 1
    kept = await db[name].find_one({"_id": protected["_id"]})
    assert kept["additional_fields"]["endpoint_id"]


@pytest.mark.asyncio
async def test_revert_skips_a_row_whose_collateral_diverged_since_the_write(ctx):
    db, name = ctx
    await _seed(db, name)
    run = _run_id()
    await ib.op_backfill(db, mode="apply", run_id=run)
    moved = await db[name].find_one({})
    await db[name].update_one({"_id": moved["_id"]},
                              {"$set": {"event.command_line": "changed later"}})
    out = await ib.op_revert(db, mode="apply", run_id=_run_id())
    assert out["skipped_collateral_diverged"] == 1
    assert out["reverted"] == POP - 1


@pytest.mark.asyncio
async def test_revert_holds_when_there_is_no_run_to_revert(ctx):
    db, _ = ctx
    out = await ib.op_revert(db, mode="apply", run_id=_run_id())
    assert out["hold"] == ib.HOLD_NO_RUN and out["reverted"] == 0


# ── the read plan must be index-served ───────────────────────────────────

@pytest.mark.asyncio
async def test_the_endpoint_time_read_is_index_served_with_no_scan_or_sort(ctx):
    db, name = ctx
    await _seed(db, name)
    await ib.op_backfill(db, mode="apply", run_id=_run_id())
    for spec in TARGET_CANONICAL_INDEXES:
        await db[name].create_index([(k, v) for k, v in spec["key"]],
                                    name=spec["name"])
    out = await ib.op_explain(db, mode="report", run_id="")
    assert out["checks"]["ixscan_present"] is True
    assert out["checks"]["no_collscan"] is True
    assert out["checks"]["no_blocking_sort"] is True, out["stages"]
    assert out["index_used"] == TARGET_CANONICAL_INDEXES[0]["name"]
    assert out["index_bounds_key_order"] == out["contract_key_order"] == \
        ["tenant_id", idc.AUTHORITATIVE_FIELD, "event_time"]
    assert out["ok"] is True


@pytest.mark.asyncio
async def test_the_explain_verification_fails_when_the_index_is_absent(ctx):
    """Proof that the check is load-bearing: without the index the same read
    must be reported as NOT index-served."""
    db, name = ctx
    await _seed(db, name)
    await ib.op_backfill(db, mode="apply", run_id=_run_id())
    out = await ib.op_explain(db, mode="report", run_id="")
    assert out["ok"] is False
    assert out["checks"]["index_name_matches"] is False


@pytest.mark.asyncio
async def test_the_explain_operation_never_writes(ctx):
    db, name = ctx
    await _seed(db, name)
    before = await _docs(db, name)
    await ib.op_explain(db, mode="report", run_id="")
    assert await _docs(db, name) == before
    assert await db[ib.LEDGER].count_documents({}) == 0


# ── the registry stays closed ────────────────────────────────────────────

def test_the_three_operations_are_registered_and_the_registry_stays_closed():
    assert mc.OP_BACKFILL_IDENTITY in mc.allowed_operations()
    assert mc.OP_REVERT_IDENTITY_BACKFILL in mc.allowed_operations()
    assert mc.OP_EXPLAIN_IDENTITY_READ_PLAN in mc.allowed_operations()
    assert "drop_everything" not in mc.OPERATIONS
