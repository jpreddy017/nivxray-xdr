"""Focused event-detail regression. Mongo test uses only its own UUID database."""
import importlib.util
import os
import pathlib
import unittest
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException
from pymongo.errors import ExecutionTimeout, AutoReconnect

ROOT = pathlib.Path(__file__).resolve().parents[2]


def module(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


class DetailLookupTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.route = module("event_detail_candidate", "routers/edr_events.py")
        self.raw = SimpleNamespace(find_one=AsyncMock())
        self.endpoints = SimpleNamespace(find_one=AsyncMock(return_value=None))
        self.db = {"edr_raw_events": self.raw, "edr_endpoints": self.endpoints}
        self.scope = patch.object(self.route, "edr_scope")
        self.scope.start()
        self.db_patch = patch.object(self.route, "_db", self.db)
        self.db_patch.start()
        self.addCleanup(self.scope.stop)
        self.addCleanup(self.db_patch.stop)

    async def test_exact_tenant_lookup_retains_payload_and_derivations(self):
        self.raw.find_one.return_value = {"raw_id": "raw_test", "tenant_id": "A",
            "payload": "verbatim", "derivations": [{"outcome": "DETECTION_NOT_EVALUATED"}]}
        result = await self.route.get_event("raw_test", user={}, tenant_id="A")
        args, kwargs = self.raw.find_one.call_args
        self.assertEqual(args[0], {"tenant_id": "A", "raw_id": "raw_test"})
        self.assertEqual(kwargs["max_time_ms"], 5000)
        self.assertEqual(result["event"]["payload"], "verbatim")
        self.assertEqual(len(result["event"]["derivations"]), 1)

    async def test_missing_is_404_not_timeout(self):
        self.raw.find_one.return_value = None
        with self.assertRaises(HTTPException) as ctx:
            await self.route.get_event("raw_other_tenant", user={}, tenant_id="A")
        self.assertEqual(ctx.exception.status_code, 404)

    async def test_database_timeout_is_explicit_503(self):
        self.raw.find_one.side_effect = ExecutionTimeout("private database message")
        with self.assertRaises(HTTPException) as ctx:
            await self.route.get_event("raw_test", user={}, tenant_id="A")
        self.assertEqual(ctx.exception.status_code, 503)
        self.assertEqual(ctx.exception.detail["code"], "EVENT_LOOKUP_UNAVAILABLE")
        self.assertNotIn("private", str(ctx.exception.detail))

    async def test_transport_error_is_explicit_503(self):
        self.raw.find_one.side_effect = AutoReconnect("unavailable")
        with self.assertRaises(HTTPException) as ctx:
            await self.route.get_event("raw_test", user={}, tenant_id="A")
        self.assertEqual(ctx.exception.status_code, 503)

    async def test_optional_hostname_failure_does_not_hide_evidence(self):
        self.raw.find_one.return_value = {"raw_id": "raw_test", "payload": "bytes",
                                         "endpoint_ref": "ep_A"}
        self.endpoints.find_one.side_effect = ExecutionTimeout("timeout")
        result = await self.route.get_event("raw_test", user={}, tenant_id="A")
        self.assertEqual(result["event"]["payload"], "bytes")
        self.assertIsNone(result["event"]["hostname"])
        self.assertEqual(self.endpoints.find_one.call_args.args[0],
                         {"tenant_id": "A", "endpoint_id": "ep_A"})

    async def test_scope_refusal_precedes_any_database_read(self):
        with patch.object(self.route, "edr_scope", side_effect=HTTPException(403)):
            with self.assertRaises(HTTPException):
                await self.route.get_event("raw_test", user={}, tenant_id="B")
        self.raw.find_one.assert_not_awaited()


@unittest.skipUnless(os.environ.get("NIVX_EVENTS_MONGO_INTEGRATION") == "1",
                     "explicit local Mongo fixture opt-in")
class IndexPlanTests(unittest.IsolatedAsyncioTestCase):
    async def test_index_is_idempotent_and_exact_lookup_examines_one_key(self):
        from motor.motor_asyncio import AsyncIOMotorClient
        client = AsyncIOMotorClient("mongodb://127.0.0.1:27017", serverSelectionTimeoutMS=2000)
        name = "nivx_event_detail_ci_" + uuid.uuid4().hex
        db = client[name]
        try:
            raw = module("event_detail_raw_candidate", "edr_plane/raw_events.py")
            docs = [{"tenant_id": "A", "raw_id": f"raw_{i:06d}",
                     "ingest_time": f"2026-11-01T{i:06d}", "dedup_key": str(i)}
                    for i in range(50000)]
            await db.edr_raw_events.insert_many(docs)
            await db.edr_raw_events.create_index(
                [("tenant_id", 1), ("ingest_time", -1), ("raw_id", -1)], name="events_keyset")
            query = {"tenant_id": "A", "raw_id": "raw_049999"}
            before = await db.command("explain", {"find": "edr_raw_events", "filter": query,
                "limit": 1, "hint": "events_keyset"}, verbosity="executionStats")
            await raw.ensure_indexes(db)
            await raw.ensure_indexes(db)
            after = await db.command("explain", {"find": "edr_raw_events", "filter": query,
                "limit": 1}, verbosity="executionStats")
            self.assertGreater(before["executionStats"]["totalKeysExamined"], 1000)
            self.assertEqual(after["executionStats"]["nReturned"], 1)
            self.assertLessEqual(after["executionStats"]["totalKeysExamined"], 1)
            self.assertLessEqual(after["executionStats"]["totalDocsExamined"], 1)
            print("EVENT_LOOKUP_PLAN", {"before": before["executionStats"]["totalKeysExamined"],
                "after": after["executionStats"]["totalKeysExamined"]})
        finally:
            await client.drop_database(name)
            client.close()
