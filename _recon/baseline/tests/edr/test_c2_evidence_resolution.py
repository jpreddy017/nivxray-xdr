"""R3/R4 · detection → canonical observation resolution, and its PROOF.

The acceptance rule the owner set: newly generated detections must
resolve by the PRIMARY canonical identifier, and a fallback that keeps
working must never hide a regression in the primary. So every resolution
reports the reference it used.

Historical detections carrying the legacy `_pl` reference must still
resolve. Nothing is rewritten, nothing is matched heuristically, and a
detection whose raw event is absent stays unresolved and says why.
"""
from __future__ import annotations

import asyncio
import os
import sys
import uuid

from motor.motor_asyncio import AsyncIOMotorClient

sys.path.insert(0, "/app/backend")

from edr_plane import canonical_bridge as cb                    # noqa: E402
from edr_plane import evidence_resolution as er                 # noqa: E402

TENANT = "ten_c2_primary"
OTHER = "ten_c2_other"
RAW_NEW = "raw_aaaaaaaaaaaaaaaaaaaaaaa1"
RAW_LEGACY = "raw_bbbbbbbbbbbbbbbbbbbbbbb2"
RAW_ABSENT = "raw_cccccccccccccccccccccc3"


def with_db(fn):
    """One disposable database per test, seeded identically."""
    def wrapper():
        asyncio.run(_scoped(fn))
    wrapper.__name__ = fn.__name__
    wrapper.__doc__ = fn.__doc__
    return wrapper


async def _scoped(fn):
    client = AsyncIOMotorClient(os.environ["MONGO_URL"])
    name = f"c2_resolution_{uuid.uuid4().hex[:10]}"
    handle = client[name]
    # NEW DATA · the evidence authority's own identifier.
    await handle["v2_shadow_observations"].insert_one({
        "tenant_id": TENANT,
        "canonical_event_id": cb.canonical_event_id(RAW_NEW, 0),
        "event": {"kind": "process_create",
                  "process": {"iid": "proc_new"},
                  "provenance": {"ingest_job_id": RAW_NEW}}})
    # HISTORICAL · an observation stored under the legacy pipeline form.
    await handle["v2_shadow_observations"].insert_one({
        "tenant_id": TENANT,
        "canonical_event_id": f"cev_{RAW_LEGACY}_pl",
        "event": {"kind": "process_create",
                  "process": {"iid": "proc_legacy"},
                  "provenance": {"ingest_job_id": RAW_LEGACY}}})
    # ANOTHER TENANT holds an identically-named observation.
    await handle["v2_shadow_observations"].insert_one({
        "tenant_id": OTHER,
        "canonical_event_id": cb.canonical_event_id(RAW_NEW, 0),
        "event": {"kind": "process_create",
                  "process": {"iid": "proc_foreign"},
                  "provenance": {"ingest_job_id": RAW_NEW}}})
    try:
        await fn(handle)
    finally:
        await client.drop_database(name)
        client.close()


# ── A · NEW DATA resolves by the PRIMARY reference ─────────────────

@with_db
async def test_new_detection_resolves_by_the_primary_canonical_identifier(db):
    out = await er.resolve(db, tenant_id=TENANT,
                           canonical_event_id=cb.canonical_event_id(
                               RAW_NEW, 0),
                           raw_event_id=RAW_NEW)
    assert out["resolved_via"] == er.PRIMARY
    assert out["is_fallback"] is False
    assert out["canonical_event_id_form"] == er.FORM_AUTHORITY
    assert out["observation"]["event"]["process"]["iid"] == "proc_new"


@with_db
async def test_the_primary_attempt_is_always_first(db):
    out = await er.resolve(db, tenant_id=TENANT,
                           canonical_event_id=cb.canonical_event_id(
                               RAW_NEW, 0),
                           raw_event_id=RAW_NEW)
    assert out["attempts"][0]["reference"] == er.PRIMARY
    assert out["attempts"][0]["found"] is True
    # Nothing after a hit is attempted, so a fallback cannot silently
    # answer for the primary.
    assert len(out["attempts"]) == 1


# ── B · LEGACY evidence still resolves, and declares the fallback ──

@with_db
async def test_legacy_pl_reference_resolves_by_the_legacy_form(db):
    out = await er.resolve(db, tenant_id=TENANT,
                           canonical_event_id=cb.canonical_event_id(
                               RAW_LEGACY, 0),
                           raw_event_id=RAW_LEGACY)
    assert out["resolved_via"] == er.LEGACY
    assert out["is_fallback"] is True
    assert out["observation"]["event"]["process"]["iid"] == "proc_legacy"


@with_db
async def test_a_detection_carrying_the_legacy_reference_is_classified(db):
    legacy_ref = f"cev_{RAW_LEGACY}_pl"
    out = await er.resolve(db, tenant_id=TENANT,
                           canonical_event_id=legacy_ref,
                           raw_event_id=RAW_LEGACY)
    assert out["canonical_event_id_form"] == er.FORM_LEGACY
    assert out["resolved_via"] == er.PRIMARY  # it IS the stored reference
    assert out["observation"]["event"]["process"]["iid"] == "proc_legacy"


@with_db
async def test_raw_event_id_remains_the_last_authoritative_fallback(db):
    # No canonical reference at all — only the raw event id the canonical
    # evidence carries in its own provenance.
    out = await er.resolve(db, tenant_id=TENANT, canonical_event_id=None,
                           raw_event_id=RAW_NEW)
    assert out["resolved_via"] == er.RAW
    assert out["is_fallback"] is True
    assert out["canonical_event_id_form"] == er.FORM_ABSENT


@with_db
async def test_resolution_order_is_primary_then_legacy_then_raw(db):
    assert er.ORDER == (er.PRIMARY, er.LEGACY, er.RAW)


# ── C · honest non-resolution ──────────────────────────────────────

@with_db
async def test_a_detection_whose_evidence_is_absent_stays_unresolved(db):
    out = await er.resolve(db, tenant_id=TENANT,
                           canonical_event_id=cb.canonical_event_id(
                               RAW_ABSENT, 0),
                           raw_event_id=RAW_ABSENT)
    assert out["observation"] is None
    assert out["resolved_via"] is None
    assert out["unresolved_reason"] == er.UNRESOLVED_NOT_FOUND
    # Nothing was bound to a near miss.
    assert all(a.get("found") in (False, None) for a in out["attempts"])


@with_db
async def test_a_detection_with_no_reference_at_all_says_so(db):
    out = await er.resolve(db, tenant_id=TENANT, canonical_event_id=None,
                           raw_event_id=None)
    assert out["unresolved_reason"] == er.UNRESOLVED_NO_REFERENCE
    assert all(a["attempted"] is False for a in out["attempts"])


# ── D · tenancy ────────────────────────────────────────────────────

@with_db
async def test_an_identifier_never_resolves_across_tenants(db):
    out = await er.resolve(db, tenant_id="ten_c2_unrelated",
                           canonical_event_id=cb.canonical_event_id(
                               RAW_NEW, 0),
                           raw_event_id=RAW_NEW)
    assert out["observation"] is None
    assert out["resolved_via"] is None
    # The refusal discloses nothing about the other tenant's evidence.
    assert "proc_foreign" not in str(out)
    assert "proc_new" not in str(out)


@with_db
async def test_resolution_stays_inside_the_requested_tenant(db):
    out = await er.resolve(db, tenant_id=OTHER,
                           canonical_event_id=cb.canonical_event_id(
                               RAW_NEW, 0),
                           raw_event_id=RAW_NEW)
    assert out["observation"]["event"]["process"]["iid"] == "proc_foreign"


# ── E · classification is string inspection, never a heuristic join ─

def test_reference_forms_are_classified_without_touching_the_database():
    assert er.reference_form("cev_abc_0") == er.FORM_AUTHORITY
    assert er.reference_form("cev_raw_abc_pl") == er.FORM_LEGACY
    assert er.reference_form("") == er.FORM_ABSENT
    assert er.reference_form("sysmon-1-deadbeef") == er.FORM_UNRECOGNISED


def test_the_legacy_read_form_is_derived_only_from_a_raw_event_id():
    assert er.legacy_reference("raw_x") == "cev_raw_x_pl"
    assert er.legacy_reference(None) is None
