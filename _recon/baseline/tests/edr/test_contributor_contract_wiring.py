"""CONTRIBUTOR CONTRACT WIRING · the server resolves, the client renders.

Proves the required flow against a real store:

    detection / IOC mechanism -> compromise_event
      -> contributing_event_refs[] -> canonical OBSERVATION identities
      -> trajectory projection -> frontend

and the four refusals: an unresolvable reference stays unresolved (never
nearest-event substitution), a cross-tenant / cross-device reference
fails closed, a contract violation in the store is rejected on READ, and
an authority that named no contributors yields no contributor emphasis.
"""
from __future__ import annotations

import asyncio  # noqa: F401
import os
import uuid

import pytest
import pytest_asyncio
from dotenv import load_dotenv

load_dotenv("/app/backend/.env", override=True)
from motor.motor_asyncio import AsyncIOMotorClient        # noqa: E402

from edr_plane import compromise_store as cs              # noqa: E402
from edr_plane import trajectory_window as tw             # noqa: E402
from edr_plane.compromise_contract import (               # noqa: E402
    AUTHORITY_DETECTION_FABRIC,
    AUTHORITY_IOC_CORRELATION,
    CompromiseContractError,
    from_detection_derivation,
    unproven_contributors,
)

RUN = uuid.uuid4().hex[:10]
TENANT = f"ten_fixture_{RUN}"
OTHER_TENANT = f"ten_other_{RUN}"
DEVICE = f"dev_fixture_{RUN}"
OTHER_DEVICE = f"dev_other_{RUN}"
HOST = f"FIXTURE-{RUN.upper()}"
TS = "2026-09-22T16:20:09.743000+00:00"

#: TWO observations with byte-identical content and ONE that differs. The
#: identical pair is the whole point: only the referenced one may ever be
#: emphasised.
OBS_A = f"obs_fixture_a_{RUN}"
OBS_TWIN = f"obs_fixture_twin_{RUN}"
OBS_OTHER = f"obs_fixture_other_{RUN}"
CONTENT_IID = f"evt_shared_{RUN}"


def _observation(observation_id, *, content_iid, image, lane_kind="registry_value_set"):
    return {
        "adapter": "sysmon-normalizer", "cem_version": "v1", "case_id": None,
        "tenant_id": TENANT, "captured_at": TS, "kind": lane_kind,
        "observation_id": observation_id,
        "observation_identity_state": "UNIQUE_BY_SOURCE_RECORD_IDENTITY",
        "observation_identity_key": f"{TENANT}|{DEVICE}|{observation_id}",
        "ingest_job_id": f"fixture_{RUN}",
        "event": {
            "iid": content_iid, "ts": TS, "kind": lane_kind,
            "adapter": "sysmon-normalizer", "adapter_version": "1.0",
            "sequence": 0, "device_iid": DEVICE, "computer": HOST,
            "process": {"iid": f"proc_{RUN}", "name": "svchost.exe",
                        "image": image},
            "raw": {"computer": HOST, "image_path": image,
                    "registry_key": "HKLM\\Software\\Nivx\\Run",
                    "source_identity": {"provider": "Microsoft-Windows-Sysmon",
                                        "channel": "Sysmon/Operational",
                                        "event_id": 13, "computer": HOST}},
            "provenance": {"origin": "collector-live",
                           "normalizer": "sysmon-normalizer"},
        },
    }


@pytest_asyncio.fixture
async def db():
    client = AsyncIOMotorClient(os.environ["MONGO_URL"])
    database = client[os.environ["DB_NAME"]]

    async def clean():
        await database[tw.COLLECTION].delete_many({"tenant_id": TENANT})
        await database[cs.COLLECTION].delete_many(
            {"tenant_id": {"$in": [TENANT, OTHER_TENANT]}})

    await clean()
    await database[tw.COLLECTION].insert_many([
        _observation(OBS_A, content_iid=CONTENT_IID,
                     image="C:\\Windows\\system32\\svchost.exe"),
        _observation(OBS_TWIN, content_iid=CONTENT_IID,
                     image="C:\\Windows\\system32\\svchost.exe"),
        _observation(OBS_OTHER, content_iid=f"evt_other_{RUN}",
                     image="C:\\Windows\\explorer.exe",
                     lane_kind="process_create"),
    ])
    yield database
    await clean()
    client.close()


def _derivation(evidence_ids):
    return {"outcome": "DETECTION_MATCHED",
            "derived_at": TS,
            "detection_content_version": f"fixture_sigma@{RUN}",
            "event_id": f"cev_{RUN}",
            "evidence_ids": list(evidence_ids),
            "reason": "rules: win_susp_registry_run_key"}


async def _resolve(db, *, tenant=TENANT, device=DEVICE, ids=None):
    return await cs.resolve_for_device(
        db, tenant_id=tenant, device_iid=device,
        observation_ids=ids if ids is not None
        else [OBS_A, OBS_TWIN, OBS_OTHER])


# ── A · a valid reference selects the EXACT observation ─────────────
@pytest.mark.asyncio
async def test_a_valid_contributor_ref_selects_exactly_that_observation(db):
    await db[cs.COLLECTION].delete_many({"tenant_id": TENANT})
    compromise = from_detection_derivation(_derivation([]),
                                           observation_iid=OBS_A)
    await cs.persist(db, compromise, tenant_id=TENANT, device_iid=DEVICE,
                     raised_by="fixture")
    out = await _resolve(db)
    assert out["state"] == "AUTHORITATIVE_COMPROMISES_RESOLVED"
    assert len(out["compromise_events"]) == 1
    ev = out["compromise_events"][0]
    assert ev["resolved_observation_ids"] == [OBS_A]
    assert ev["contributor_emphasis"] == "RENDER_CONTRIBUTORS"
    assert list(out["contributor_of"]) == [OBS_A]


@pytest.mark.asyncio
async def test_only_the_referenced_twin_becomes_a_contributor(db):
    """OBS_A and OBS_TWIN are content-identical and share `event.iid`.
    Emphasis must follow the observation identity, not the content."""
    await db[cs.COLLECTION].delete_many({"tenant_id": TENANT})
    await cs.persist(db, from_detection_derivation(_derivation([]),
                                                   observation_iid=OBS_TWIN),
                     tenant_id=TENANT, device_iid=DEVICE,
                     raised_by="fixture")
    out = await _resolve(db)
    assert list(out["contributor_of"]) == [OBS_TWIN]
    assert OBS_A not in out["contributor_of"]


@pytest.mark.asyncio
async def test_multiple_named_contributors_all_resolve(db):
    await db[cs.COLLECTION].delete_many({"tenant_id": TENANT})
    await cs.persist(db, from_detection_derivation(
        _derivation([OBS_TWIN, OBS_OTHER]), observation_iid=OBS_A),
        tenant_id=TENANT, device_iid=DEVICE, raised_by="fixture")
    out = await _resolve(db)
    ev = out["compromise_events"][0]
    assert sorted(ev["resolved_observation_ids"]) == sorted(
        [OBS_A, OBS_TWIN, OBS_OTHER])
    assert ev["unresolved_event_refs"] == []


# ── B · UNRESOLVED_REF_TEST — never nearest-event substitution ──────
@pytest.mark.asyncio
async def test_an_unresolvable_reference_is_reported_not_substituted(db):
    await db[cs.COLLECTION].delete_many({"tenant_id": TENANT})
    missing = f"obs_deleted_{RUN}"
    await cs.persist(db, from_detection_derivation(
        _derivation([missing]), observation_iid=OBS_A),
        tenant_id=TENANT, device_iid=DEVICE, raised_by="fixture")
    out = await _resolve(db)
    ev = out["compromise_events"][0]
    assert ev["resolved_observation_ids"] == [OBS_A]
    assert len(ev["unresolved_event_refs"]) == 1
    unresolved = ev["unresolved_event_refs"][0]
    assert unresolved["observation_id"] == missing
    assert unresolved["resolution_state"] == \
        cs.REF_UNRESOLVED_NOT_IN_PROJECTION
    # the missing reference did NOT land on any nearby observation
    assert set(out["contributor_of"]) == {OBS_A}


@pytest.mark.asyncio
async def test_every_reference_unresolvable_yields_no_emphasis(db):
    await db[cs.COLLECTION].delete_many({"tenant_id": TENANT})
    await cs.persist(db, from_detection_derivation(
        _derivation([]), observation_iid=f"obs_gone_{RUN}"),
        tenant_id=TENANT, device_iid=DEVICE, raised_by="fixture")
    out = await _resolve(db)
    ev = out["compromise_events"][0]
    assert ev["resolved_observation_ids"] == []
    assert ev["contributor_emphasis"] == "RENDER_NO_CONTRIBUTORS"
    assert out["contributor_of"] == {}


# ── C · CROSS_TENANT_REF_TEST — fail closed ─────────────────────────
@pytest.mark.asyncio
async def test_a_compromise_raised_for_another_tenant_is_never_read(db):
    await db[cs.COLLECTION].delete_many(
        {"tenant_id": {"$in": [TENANT, OTHER_TENANT]}})
    await cs.persist(db, from_detection_derivation(_derivation([]),
                                                   observation_iid=OBS_A),
                     tenant_id=OTHER_TENANT, device_iid=DEVICE,
                     raised_by="fixture")
    out = await _resolve(db)
    assert out["compromise_events"] == []
    assert out["contributor_of"] == {}
    assert out["state"] == "NO_AUTHORITATIVE_COMPROMISE_OBSERVED"


@pytest.mark.asyncio
async def test_a_compromise_raised_for_another_device_is_never_read(db):
    await db[cs.COLLECTION].delete_many({"tenant_id": TENANT})
    await cs.persist(db, from_detection_derivation(_derivation([]),
                                                   observation_iid=OBS_A),
                     tenant_id=TENANT, device_iid=OTHER_DEVICE,
                     raised_by="fixture")
    out = await _resolve(db)
    assert out["compromise_events"] == []


@pytest.mark.asyncio
async def test_no_device_scope_resolves_to_nothing(db):
    out = await cs.resolve_for_device(db, tenant_id=None, device_iid=None,
                                      observation_ids=[OBS_A])
    assert out == {"compromise_events": [], "contributor_of": {},
                   "rejected": [], "state": "NO_DEVICE_SCOPE"}


# ── D · a stored row is re-validated through the contract on READ ───
@pytest.mark.asyncio
async def test_a_row_written_outside_the_contract_is_rejected_on_read(db):
    await db[cs.COLLECTION].delete_many({"tenant_id": TENANT})
    await db[cs.COLLECTION].insert_one({
        "tenant_id": TENANT, "device_iid": DEVICE,
        "compromise_event_id": f"cmp_smuggled_{RUN}",
        "indicator_id": "ind_1", "authority": AUTHORITY_DETECTION_FABRIC,
        "derivation_basis": "DETECTION_FABRIC_DERIVATION_ON_RAW_EVENT",
        "description": "written straight to Mongo",
        "contributors_state": "CONTRIBUTORS_PROVEN_BY_AUTHORITY",
        # inferred from proximity — the contract must refuse it
        "contributing_event_refs": [
            {"observation_id": OBS_A, "contribution_basis": "SAME_PID",
             "stated_by": AUTHORITY_DETECTION_FABRIC}]})
    out = await _resolve(db)
    assert out["compromise_events"] == []
    assert out["contributor_of"] == {}
    assert out["rejected"][0]["state"] == cs.STORE_REJECTED_INVALID
    assert out["rejected"][0]["code"] == "CONTRIBUTOR_BASIS_FORBIDDEN"


@pytest.mark.asyncio
async def test_only_a_validated_object_can_be_persisted(db):
    with pytest.raises(CompromiseContractError) as e:
        await cs.persist(db, {"compromise_event_id": "cmp_x"},
                         tenant_id=TENANT, device_iid=DEVICE,
                         raised_by="fixture")
    assert e.value.code == "COMPROMISE_TYPE_INVALID"


# ── E · an authority that named nobody emphasises nobody ────────────
@pytest.mark.asyncio
async def test_unproven_contributors_survive_the_round_trip(db):
    await db[cs.COLLECTION].delete_many({"tenant_id": TENANT})
    await cs.persist(db, unproven_contributors(
        compromise_event_id=f"cmp_unproven_{RUN}", indicator_id="ind_1",
        authority=AUTHORITY_IOC_CORRELATION,
        derivation_basis="ENGINE_STATED_MEMBERSHIP",
        description="raised, but the engine named no members",
        observed_at=TS), tenant_id=TENANT, device_iid=DEVICE,
        raised_by="fixture")
    out = await _resolve(db)
    ev = out["compromise_events"][0]
    assert ev["contributors_state"] == "CONTRIBUTORS_NOT_PROVEN_BY_AUTHORITY"
    assert ev["contributing_event_refs"] == []
    assert ev["contributor_emphasis"] == "RENDER_NO_CONTRIBUTORS"
    assert out["contributor_of"] == {}


# ── F · through the trajectory read the frontend actually calls ─────
@pytest.mark.asyncio
async def test_the_trajectory_payload_carries_the_resolved_contract(db):
    await db[cs.COLLECTION].delete_many({"tenant_id": TENANT})
    missing = f"obs_deleted_{RUN}"
    await cs.persist(db, from_detection_derivation(
        _derivation([missing]), observation_iid=OBS_TWIN),
        tenant_id=TENANT, device_iid=DEVICE, raised_by="fixture")
    out = await tw.query_window(
        db, identity={"tenant_id": TENANT, "device_iid": DEVICE,
                      "hostname": HOST},
        refs=[DEVICE], limit=50)
    assert out["compromise_contract"]["reference_identity"] == "observation_id"
    assert out["compromise_contract"]["resolved_server_side"] is True
    assert out["compromise_contract"]["frontend_may_infer_contributors"] \
        is False
    assert len(out["compromise_events"]) == 1
    ev = out["compromise_events"][0]
    assert ev["resolved_observation_ids"] == [OBS_TWIN]
    assert ev["unresolved_event_refs"][0]["observation_id"] == missing

    rows = {r["observation_id"]: r for r in out["events"]}
    assert set(rows) == {OBS_A, OBS_TWIN, OBS_OTHER}
    assert rows[OBS_TWIN]["contributor_of"] == [ev["compromise_event_id"]]
    assert rows[OBS_TWIN]["contributor_state"] == "PROVEN_BY_AUTHORITY"
    # the content-identical twin is NOT emphasised
    assert "contributor_of" not in rows[OBS_A]
    assert "contributor_of" not in rows[OBS_OTHER]
    # and the rows carry the identity the contract references
    assert rows[OBS_A]["observation_identity_state"] == \
        "UNIQUE_BY_SOURCE_RECORD_IDENTITY"
    assert rows[OBS_A]["event_iid"] != rows[OBS_TWIN]["event_iid"]


@pytest.mark.asyncio
async def test_no_compromise_means_no_compromise_not_a_clean_claim(db):
    await db[cs.COLLECTION].delete_many({"tenant_id": TENANT})
    out = await tw.query_window(
        db, identity={"tenant_id": TENANT, "device_iid": DEVICE,
                      "hostname": HOST},
        refs=[DEVICE], limit=50)
    assert out["compromise_events"] == []
    assert out["compromise_contract"]["state"] == \
        "NO_AUTHORITATIVE_COMPROMISE_OBSERVED"
    for row in out["events"]:
        assert "contributor_of" not in row
        assert row["disposition"] != "CLEAN"


# ── G · OWNER-REQUIRED REGRESSION · the collision defect ────────────
@pytest.mark.asyncio
async def test_content_identical_twins_never_share_the_blue_emphasis(db):
    """Two observations with IDENTICAL content and therefore the SAME
    `event.iid`, but different `observation_id`. Only the one the
    authority named may receive contributor emphasis — this is the direct
    regression test for the corpus defect where 2,250 of 3,299 distinct
    Windows records shared one content hash.
    """
    await db[cs.COLLECTION].delete_many({"tenant_id": TENANT})
    rows = {r["observation_id"]: r for r in
            await db[tw.COLLECTION].find(
                {"tenant_id": TENANT,
                 "observation_id": {"$in": [OBS_A, OBS_TWIN]}}).to_list(10)}
    # the twins really are content-identical
    assert rows[OBS_A]["event"]["iid"] == rows[OBS_TWIN]["event"]["iid"]
    assert OBS_A != OBS_TWIN

    for named, other in ((OBS_A, OBS_TWIN), (OBS_TWIN, OBS_A)):
        await db[cs.COLLECTION].delete_many({"tenant_id": TENANT})
        await cs.persist(db, from_detection_derivation(
            _derivation([]), observation_iid=named),
            tenant_id=TENANT, device_iid=DEVICE, raised_by="fixture")
        out = await tw.query_window(
            db, identity={"tenant_id": TENANT, "device_iid": DEVICE,
                          "hostname": HOST},
            refs=[DEVICE], limit=50)
        projected = {r["observation_id"]: r for r in out["events"]}
        # EXACTLY one row carries the emphasis, and it is the named one
        emphasised = [oid for oid, r in projected.items()
                      if r.get("contributor_of")]
        assert emphasised == [named], (
            f"authority named {named}; emphasis landed on {emphasised}")
        assert projected[named]["contributor_state"] == "PROVEN_BY_AUTHORITY"
        assert "contributor_of" not in projected[other]
