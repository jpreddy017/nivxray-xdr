"""Isolated regression tests: execute the real module with only deps.db injected.

Run: python -m unittest discover -s tools -p test_artifact_write_ack.py -v
ARTIFACT_SOURCE optionally selects the frozen baseline for reproduction.
"""
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock
from pymongo.errors import DuplicateKeyError, OperationFailure


def load_store(collection):
    root = next(p for p in Path(__file__).resolve().parents if (p / "backend").is_dir())
    path = Path(os.environ.get("ARTIFACT_SOURCE", str(root /
        "backend/v2/decoded_artifacts/__init__.py")))
    source = path.read_text()
    # Do not import the shared server, env or database at test startup.
    assert source.count("from deps import db") == 1
    namespace = {"db": {"v2_decoded_payloads": collection}}
    exec(compile(source.replace("from deps import db", ""), str(path), "exec"), namespace)
    return namespace


class ArtifactWriteAcknowledgement(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.coll = SimpleNamespace(find_one=AsyncMock(return_value=None),
            insert_one=AsyncMock(return_value=SimpleNamespace(acknowledged=True)),
            update_one=AsyncMock(return_value=SimpleNamespace(acknowledged=True, matched_count=1)))
        self.module = load_store(self.coll)
        self.args = dict(command_binary="powershell", command_line="Write-Output test",
                         report_dict={"output": "test"}, job_id="fixture")

    async def invoke(self):
        return await self.module["upsert_artifact"](**self.args)

    async def test_successful_insert_preserves_contract(self):
        digest, new = await self.invoke()
        self.assertTrue(new)
        self.assertEqual(digest, self.module["sha256_of"](self.args["command_line"]))
        self.assertEqual(self.coll.insert_one.call_args.args[0]["report"], self.args["report_dict"])
        self.coll.update_one.assert_not_awaited()

    async def test_genuine_duplicate_updates_existing_record(self):
        self.coll.insert_one.side_effect = DuplicateKeyError("duplicate")
        self.assertFalse((await self.invoke())[1])
        self.coll.update_one.assert_awaited_once()

    async def test_validation_error_propagates_without_fallback(self):
        self.coll.insert_one.side_effect = OperationFailure("validator rejected", code=121)
        with self.assertRaises(OperationFailure): await self.invoke()
        self.coll.update_one.assert_not_awaited()

    async def test_unknown_insert_failure_is_not_duplicate(self):
        self.coll.insert_one.side_effect = RuntimeError("unknown write outcome")
        with self.assertRaisesRegex(RuntimeError, "unknown write outcome"): await self.invoke()
        self.coll.update_one.assert_not_awaited()

    async def test_unacknowledged_insert_refused(self):
        self.coll.insert_one.return_value = SimpleNamespace(acknowledged=False)
        with self.assertRaises(RuntimeError): await self.invoke()

    async def test_duplicate_with_missing_record_refused(self):
        self.coll.insert_one.side_effect = DuplicateKeyError("duplicate")
        self.coll.update_one.return_value = SimpleNamespace(acknowledged=True, matched_count=0)
        with self.assertRaises(RuntimeError): await self.invoke()

    async def test_cache_hit_deleted_before_update_refused(self):
        self.coll.find_one.return_value = {"_id": "fixture"}
        self.coll.update_one.return_value = SimpleNamespace(acknowledged=True, matched_count=0)
        with self.assertRaises(RuntimeError): await self.invoke()

    async def test_unacknowledged_cache_update_refused(self):
        self.coll.find_one.return_value = {"_id": "fixture"}
        self.coll.update_one.return_value = SimpleNamespace(acknowledged=False)
        with self.assertRaises(RuntimeError): await self.invoke()

    async def test_existing_report_is_not_overwritten(self):
        self.coll.find_one.return_value = {"_id": "fixture"}
        self.assertFalse((await self.invoke())[1])
        update = self.coll.update_one.call_args.args[1]
        self.assertNotIn("report", update.get("$set", {}))
        self.coll.insert_one.assert_not_awaited()
