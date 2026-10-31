"""G-41 · post-APPLY collateral verification, fixed and proven.

THE DEFECT THIS SUITE EXISTS FOR. The historical `observation_us` backfill
recorded and re-checked its collateral digest with STEP 35's
`collateral_digest()`, whose exclusion set is the two IDENTITY paths. The four
paths G-41 intends to set were therefore INSIDE the protected surface, so
`verify_canonical_observation_us` would have reported collateral divergence for
every one of the 122,477 intentionally migrated rows — and lost all ability to
tell an intended temporal change from an accidental modification of something
else.

The fix is scoped to the verification boundary: the exclusion set is named by
the caller, so G-41 forgives exactly its own four temporal paths and STEP 35
keeps forgiving exactly its own two. Nothing is excluded by default.

Preview database, throwaway collections, dropped per test. No production read or
write, no index, no deploy, no Behavior run, no sensor, no KUSHU, no DESKTOP.
"""
from __future__ import annotations

import os
import sys
import uuid
from copy import deepcopy

import pytest
import pytest_asyncio
from motor.motor_asyncio import AsyncIOMotorClient

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from edr_plane import identity_backfill as ib  # noqa: E402
from edr_plane import observation_us_migration as m  # noqa: E402
from edr_plane import temporal_authority as ta  # noqa: E402

TENANT = "ten_g41_collateral"
EP = "ep_g41_collateral"


def evidence(eid="e1"):
    """A candidate row: real evidence, no comparable value yet."""
    return {"tenant_id": TENANT, "event_time": "2026-09-27 23:55:38.144",
            "event_id": eid, "ingest_time": "2026-09-30T00:00:00+00:00",
            "additional_fields": {"endpoint_id": EP, "activity_type": "process",
                                  "rule": "r1"},
            "host": {"hostname": "h1", "host_id": "h1"},
            "provenance": {"collector_id": EP, "trace_id": "t1",
                           "endpoint_identity": {"state": "RESOLVED"}},
            "process": {"pid": 1, "executable_path": "/x"},
            "event": {"command_line": "cmd 1"}}


def with_intended_g41(doc, us=1_759_017_338_144_000):
    """Exactly what the migration's `$set` does, and nothing more."""
    out = deepcopy(doc)
    out[ta.OBSERVATION_US] = us
    out["additional_fields"][ta.STATE_KEY] = ta.STATE_DERIVED
    out["additional_fields"][ta.BASIS_KEY] = ta.BASIS
    out["provenance"][m.PROVENANCE_KEY] = {"authority": m.AUTHORITY,
                                           "migration_run_id": "r1"}
    return out


# ── the four excluded paths are DERIVED, never restated ──────────────────

def test_the_excluded_paths_are_exactly_the_four_the_writer_contract_names():
    assert m.G41_MUTABLE_PATHS == (
        "observation_us",
        "additional_fields.observation_us_state",
        "additional_fields.observation_us_basis",
        "provenance.observation_us_provenance",
    )
    # and they are built from the contract, so they cannot drift from the writer
    assert m.G41_MUTABLE_PATHS == (
        ta.OBSERVATION_US,
        f"additional_fields.{ta.STATE_KEY}",
        f"additional_fields.{ta.BASIS_KEY}",
        f"provenance.{m.PROVENANCE_KEY}",
    )
    assert len(set(m.G41_MUTABLE_PATHS)) == 4
    assert ta.SOURCE_FIELD not in m.G41_MUTABLE_PATHS, \
        "event_time must never be forgiven"


# ── the intended change is forgiven ──────────────────────────────────────

def test_the_intended_temporal_change_alone_leaves_the_digest_equal():
    before = evidence()
    assert m.g41_collateral_digest(with_intended_g41(before)) == \
        m.g41_collateral_digest(before)


def test_a_different_derived_microsecond_value_is_still_forgiven():
    """The digest must not smuggle in a value check; agreement of
    `observation_us` with `event_time` is the OTHER half of the verify."""
    before = evidence()
    assert m.g41_collateral_digest(with_intended_g41(before, us=1)) == \
        m.g41_collateral_digest(before)


# ── everything else remains detectable ───────────────────────────────────

@pytest.mark.parametrize("label,mutate", [
    ("event_time", lambda d: d.update({"event_time": "2026-09-27T00:06:30Z"})),
    ("event_time_removed", lambda d: d.pop("event_time")),
    ("tenant", lambda d: d.update({"tenant_id": "other_tenant"})),
    ("endpoint_id", lambda d: d["additional_fields"].update({"endpoint_id": "ep_x"})),
    ("endpoint_id_removed", lambda d: d["additional_fields"].pop("endpoint_id")),
    ("hostname", lambda d: d["host"].update({"hostname": "h2"})),
    ("provenance_collector", lambda d: d["provenance"].update({"collector_id": "c2"})),
    ("provenance_identity", lambda d: d["provenance"].update(
        {"endpoint_identity": {"state": "UNATTESTED"}})),
    ("provenance_identity_removed", lambda d: d["provenance"].pop("endpoint_identity")),
    ("ingest_time", lambda d: d.update({"ingest_time": "2026-10-01T00:00:00Z"})),
    ("raw_evidence", lambda d: d["event"].update({"command_line": "cmd 2"})),
    ("process", lambda d: d["process"].update({"pid": 999})),
    ("unrelated_new_field", lambda d: d.update({"verdict": "malicious"})),
    ("unrelated_in_additional", lambda d: d["additional_fields"].update({"rule": "r2"})),
])
def test_any_non_temporal_modification_is_detected(label, mutate):
    before = evidence()
    after = with_intended_g41(before)
    mutate(after)
    assert m.g41_collateral_digest(after) != m.g41_collateral_digest(before), \
        f"{label} must be detected as collateral divergence"


def test_the_identity_paths_are_protected_by_the_g41_digest():
    """The defect's mirror image: G-41 must NOT inherit STEP 35's exclusions."""
    before = evidence()
    after = with_intended_g41(before)
    after["additional_fields"]["endpoint_id"] = "ep_changed"
    after["provenance"]["endpoint_identity"] = {"state": "CHANGED"}
    assert m.g41_collateral_digest(after) != m.g41_collateral_digest(before)


# ── STEP 35's verifier is not weakened and does not change ───────────────

def _legacy_step35_digest(doc):
    """STEP 35's exclusion written out independently of the refactor."""
    out = deepcopy(dict(doc))
    for key, sub in (("additional_fields", "endpoint_id"),
                     ("provenance", "endpoint_identity")):
        if isinstance(out.get(key), dict):
            parent = dict(out[key])
            parent.pop(sub, None)
            out[key] = parent
    return ib._digest(out)


def test_step35_digest_values_are_byte_identical_to_the_previous_semantics():
    for doc in (evidence(), with_intended_g41(evidence()), {"tenant_id": "t"},
                {"additional_fields": "not-a-mapping", "provenance": None}):
        assert ib.collateral_digest(doc) == _legacy_step35_digest(doc)


def test_step35_still_forgives_only_identity_and_still_sees_temporal_change():
    before = evidence()
    identity_only = deepcopy(before)
    identity_only["additional_fields"]["endpoint_id"] = "ep_new"
    identity_only["provenance"]["endpoint_identity"] = {"state": "RESOLVED2"}
    assert ib.collateral_digest(identity_only) == ib.collateral_digest(before)
    assert ib.collateral_digest(with_intended_g41(before)) != \
        ib.collateral_digest(before), \
        "STEP 35 must keep treating a temporal addition as collateral change"
    assert ib.MUTABLE_PATHS == (ib.PATH_IDENTITY, ib.PATH_PROVENANCE)


def test_naming_no_exclusion_protects_everything():
    before = evidence()
    assert ib.digest_excluding(before, ()) == ib._digest(before)
    assert ib.digest_excluding(with_intended_g41(before), ()) != \
        ib.digest_excluding(before, ())


def test_a_deeper_path_is_refused_rather_than_silently_ignored():
    with pytest.raises(ValueError):
        ib.digest_excluding(evidence(), ("a.b.c",))


# ── end to end: apply, then verify reports no divergence ─────────────────

@pytest_asyncio.fixture
async def scoped(monkeypatch):
    name = f"g41_col_{uuid.uuid4().hex[:10]}"
    ledger = f"g41_col_ledger_{uuid.uuid4().hex[:8]}"
    database = AsyncIOMotorClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]
    monkeypatch.setattr(m, "CANONICAL_COLLECTION", name)
    monkeypatch.setattr(m, "LEDGER", ledger)
    yield database, database[name]
    await database[name].drop()
    await database[ledger].drop()


@pytest.mark.asyncio
async def test_apply_touches_only_the_four_paths_and_verify_sees_no_divergence(
        scoped, monkeypatch):
    database, coll = scoped
    await coll.insert_many([evidence(f"e{i}") for i in range(4)])
    monkeypatch.setattr(m, "EXPECTED_CANDIDATES", 4)
    before = {str(d["_id"]): d async for d in coll.find({})}

    out = await m.op_backfill_observation_us(database, mode="apply", run_id="r1")
    assert out["written"] == 4 and out["residual_candidates"] == 0 and out["ok"]

    after = {str(d["_id"]): d async for d in coll.find({})}
    for doc_id, old in before.items():
        new = after[doc_id]
        assert new["event_time"] == old["event_time"]
        assert new["tenant_id"] == old["tenant_id"]
        assert new["additional_fields"]["endpoint_id"] == \
            old["additional_fields"]["endpoint_id"]
        assert new["provenance"]["endpoint_identity"] == \
            old["provenance"]["endpoint_identity"]
        assert new["event"] == old["event"] and new["host"] == old["host"]
        # the mutation surface, measured rather than asserted by inspection
        changed = {k for k in set(old) | set(new) if old.get(k) != new.get(k)}
        changed |= {f"additional_fields.{k}"
                    for k in set(old["additional_fields"]) | set(new["additional_fields"])
                    if old["additional_fields"].get(k) != new["additional_fields"].get(k)}
        changed |= {f"provenance.{k}"
                    for k in set(old["provenance"]) | set(new["provenance"])
                    if old["provenance"].get(k) != new["provenance"].get(k)}
        changed.discard("additional_fields")
        changed.discard("provenance")
        assert changed == set(m.G41_MUTABLE_PATHS)

    v = await m.op_verify_observation_us(database, mode="report", run_id="r1")
    assert v["checked"] == 4
    assert v["disagreeing"] == 0
    assert v["collateral_diverged"] == 0, \
        "the intended temporal change must not be reported as collateral change"
    assert v["ok"] is True


@pytest.mark.asyncio
async def test_verify_still_catches_a_real_collateral_change_after_apply(
        scoped, monkeypatch):
    database, coll = scoped
    await coll.insert_many([evidence(f"e{i}") for i in range(3)])
    monkeypatch.setattr(m, "EXPECTED_CANDIDATES", 3)
    await m.op_backfill_observation_us(database, mode="apply", run_id="r2")

    victim = await coll.find_one({"event_id": "e1"})
    await coll.update_one({"_id": victim["_id"]},
                          {"$set": {"additional_fields.endpoint_id": "ep_tampered"}})
    v = await m.op_verify_observation_us(database, mode="report", run_id="r2")
    assert v["checked"] == 3
    assert v["collateral_diverged"] == 1
    assert v["ok"] is False


@pytest.mark.asyncio
async def test_verify_still_catches_a_value_that_stops_agreeing_with_event_time(
        scoped, monkeypatch):
    database, coll = scoped
    await coll.insert_many([evidence(f"e{i}") for i in range(2)])
    monkeypatch.setattr(m, "EXPECTED_CANDIDATES", 2)
    await m.op_backfill_observation_us(database, mode="apply", run_id="r3")

    victim = await coll.find_one({"event_id": "e0"})
    await coll.update_one({"_id": victim["_id"]},
                          {"$set": {ta.OBSERVATION_US: 1}})
    v = await m.op_verify_observation_us(database, mode="report", run_id="r3")
    assert v["disagreeing"] == 1
    assert v["collateral_diverged"] == 0, "only the forgiven path moved"
    assert v["ok"] is False
