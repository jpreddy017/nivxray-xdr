"""Wave 0 · the immutability claim, proven against real Mongo.

Asserting "append-only" in a docstring is worthless. These tests prove it:
a byte-identical re-delivery does not create a second record and does not
modify the first; a re-reasoning pass APPENDS a derivation and leaves the
earlier one intact; and the original payload bytes are still there
afterwards.

The parser-failure case is the one that matters most. Directive §5 says a
parser fix must be applicable retroactively — so the test fails a parse,
retains the bytes, selects the event as a replay candidate, re-reasons it
successfully at generation 1, and then asserts that BOTH derivations
survive. If the second overwrote the first, we would have lost the record
of what we believed and when, and the audit trail would be a lie.
"""
from __future__ import annotations

import os
import uuid

import pytest
from motor.motor_asyncio import AsyncIOMotorClient

from edr_plane.raw_events import (COLLECTION, Derivation, RawEndpointEvent,
                                  add_derivation, append, ensure_indexes, get,
                                  next_generation, replay_candidates, stats)

CEF = ("CEF:0|NivXForge|Sensor|1.0|100|process start|8|"
       "dproc=powershell.exe dpid=4242")


class _Scope:
    """Real Mongo, isolated tenant, always cleaned up. No async fixture —
    this suite follows the existing tests/edr convention of building the
    client inside the test."""

    async def __aenter__(self):
        self.client = AsyncIOMotorClient(os.environ["MONGO_URL"])
        self.db = self.client[os.environ["DB_NAME"]]
        await ensure_indexes(self.db)
        self.tenant = f"wave0-test-{uuid.uuid4().hex[:8]}"
        return self.db, self.tenant

    async def __aexit__(self, *exc):
        await self.db[COLLECTION].delete_many(
            {"tenant_id": {"$regex": f"^{self.tenant}"}})
        self.client.close()
        return False


@pytest.mark.asyncio
async def test_append_is_idempotent_and_never_overwrites():
  async with _Scope() as (database, tenant):
      ev = RawEndpointEvent.build(tenant_id=tenant, source="sensor-01",
                                  payload=CEF, source_kind="sensor")
      first = await append(database, ev)
      assert first["stored"] is True and first["duplicate"] is False

      # Byte-identical re-delivery, e.g. a collector retry after a timeout.
      again = RawEndpointEvent.build(tenant_id=tenant, source="sensor-01",
                                     payload=CEF, source_kind="sensor")
      second = await append(database, again)
      assert second["stored"] is False
      assert second["duplicate"] is True
      assert second["raw_id"] == first["raw_id"]
      assert "immutable" in second["reason"]

      assert await database[COLLECTION].count_documents(
          {"tenant_id": tenant}) == 1
      doc = await get(database, tenant_id=tenant, raw_id=first["raw_id"])
      assert doc["payload"] == CEF          # bytes untouched
      assert doc["duplicate_count"] == 1    # but the retry IS recorded


@pytest.mark.asyncio
async def test_one_byte_difference_is_a_different_event():
  async with _Scope() as (database, tenant):
      await append(database, RawEndpointEvent.build(
          tenant_id=tenant, source="s", payload=CEF))
      await append(database, RawEndpointEvent.build(
          tenant_id=tenant, source="s", payload=CEF + " "))
      assert await database[COLLECTION].count_documents(
          {"tenant_id": tenant}) == 2


@pytest.mark.asyncio
async def test_parser_failure_is_retained_and_replayable():
  async with _Scope() as (database, tenant):
      bad = "CEF:0|NivXForge|Sensor|1.0|100|broken|8|cs1=unterminated"
      ev = RawEndpointEvent.build(tenant_id=tenant, source="sensor-01",
                                  payload=bad)
      await append(database, ev)

      # Generation 0 · the parser of the day fails. The event still exists.
      await add_derivation(database, tenant_id=tenant, raw_id=ev.raw_id,
                           derivation=Derivation(
                               derived_at=RawEndpointEvent.now(),
                               parser_name="cef-leef", parser_version="1.0.0",
                               parser_state="FAILED",
                               parser_notes=["unterminated extension value"],
                               outcome="NO_CANONICAL_EVIDENCE",
                               reason="parser could not read the payload; the "
                                      "raw bytes are retained for replay"))

      candidates = await replay_candidates(database, tenant_id=tenant,
                                           parser_state="FAILED")
      assert [c["raw_id"] for c in candidates] == [ev.raw_id]

      # Generation 1 · the parser is fixed and we re-reason the SAME bytes.
      gen = await next_generation(database, tenant_id=tenant, raw_id=ev.raw_id)
      assert gen == 1
      await add_derivation(database, tenant_id=tenant, raw_id=ev.raw_id,
                           derivation=Derivation(
                               replay_generation=gen,
                               derived_at=RawEndpointEvent.now(),
                               parser_name="cef-leef", parser_version="1.1.0",
                               parser_state="OK", event_id="evt_replayed",
                               outcome="CANONICAL_EVIDENCE_CREATED"))

      doc = await get(database, tenant_id=tenant, raw_id=ev.raw_id)
      assert doc["payload"] == bad                       # bytes still verbatim
      assert len(doc["derivations"]) == 2                # history preserved
      assert doc["derivations"][0]["parser_state"] == "FAILED"
      assert doc["derivations"][0]["replay_generation"] == 0
      assert doc["derivations"][1]["parser_state"] == "OK"
      assert doc["derivations"][1]["replay_generation"] == 1


@pytest.mark.asyncio
async def test_rejected_payload_is_retained_but_never_trusted():
  async with _Scope() as (database, tenant):
      ev = RawEndpointEvent.build(
          tenant_id=tenant, source="unknown-agent", payload=CEF,
          received_from_ip="203.0.113.9", trust_state="REJECTED")
      await append(database, ev)
      doc = await get(database, tenant_id=tenant, raw_id=ev.raw_id)
      assert doc["trust_state"] == "REJECTED"
      assert doc["payload"] == CEF
      assert doc["received_from_ip"] == "203.0.113.9"
      assert doc["derivations"] == []      # never reasoned over

      s = await stats(database, tenant_id=tenant)
      assert s["rejected_untrusted"] == 1
      assert s["never_derived"] == 1
      assert s["append_only"] is True


@pytest.mark.asyncio
async def test_tenants_cannot_see_each_others_raw_events():
  async with _Scope() as (database, tenant):
      other = f"{tenant}-other"
      try:
          await append(database, RawEndpointEvent.build(
              tenant_id=tenant, source="s", payload=CEF))
          await append(database, RawEndpointEvent.build(
              tenant_id=other, source="s", payload=CEF))
          assert (await stats(database, tenant_id=tenant))[
              "total_raw_events"] == 1
          assert (await stats(database, tenant_id=other))[
              "total_raw_events"] == 1
      finally:
          await database[COLLECTION].delete_many({"tenant_id": other})
