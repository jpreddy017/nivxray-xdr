"""Opt-in real Mongo read integration, using a newly created disposable DB.

NIVX_FILES_MONGO_INTEGRATION=1 python -m unittest ...
Never reads a production URI or the application's configured database.
"""
import importlib.util
import os
import pathlib
import sys
import unittest
import uuid
from unittest.mock import patch


@unittest.skipUnless(os.environ.get("NIVX_FILES_MONGO_INTEGRATION") == "1",
                     "requires explicit local Mongo integration opt-in")
class MongoFileEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from pymongo import MongoClient
        from services.edr import endpoint_file_evidence, endpoint_query
        cls.files, cls.eq = endpoint_file_evidence, endpoint_query
        cls.client = MongoClient("mongodb://127.0.0.1:27017", serverSelectionTimeoutMS=2000)
        cls.client.admin.command("ping")
        cls.db_name = "nivx_files_slice1_ci_" + uuid.uuid4().hex
        cls.collection = cls.client[cls.db_name][cls.files.STORE]

    @classmethod
    def tearDownClass(cls):
        cls.client.drop_database(cls.db_name)  # this test created it; no existing DB
        cls.client.close()

    def setUp(self):
        from bson import ObjectId
        self.collection.delete_many({})  # only this test's fresh database
        self.q = self.files.validate_query("ep_a", 1788220800000, 1790812800000, limit=1)
        self.res = self.eq.EndpointResolution("ep_a", {"tenant_id": "ten_a", "endpoint_id": "ep_a"}, ["ep_a", "shared-host"])
        self.ids = [ObjectId() for _ in range(4)]
        self.collection.insert_many([{
            "_id": oid, "tenant_id": tenant, "collector_id": endpoint,
            "event": {"device_iid": endpoint, "kind": "file_create", "ts": "2026-09-02T10:00:00Z",
                      "raw": {"file": {"path": "C:\\tmp\\payload.dll", "hashes": {}}}},
        } for oid, tenant, endpoint in zip(self.ids,
            ["ten_a", "ten_a", "ten_b", "ten_a"], ["ep_a", "ep_a", "shared-host", "ep_b"])])

    def test_real_cursor_filters_customer_and_endpoint_aliases(self):
        page = self.files.read_page(self.collection, self.res, self.q, "ten_a")
        self.assertEqual(page["observations"][0]["record_id"], str(self.ids[1]))
        self.assertEqual(page["observations"][0]["endpoint_id"], "ep_a")
        self.assertTrue(page["next_cursor"])

    def test_real_objectid_continuation_has_no_duplicate_or_gap(self):
        first = self.files.read_page(self.collection, self.res, self.q, "ten_a")
        second = self.files.read_page(self.collection, self.res, self.q, "ten_a", first["next_cursor"])
        self.assertEqual([first["observations"][0]["record_id"], second["observations"][0]["record_id"]],
                         [str(self.ids[1]), str(self.ids[0])])
        self.assertTrue(second["complete"])

    def test_context_mismatch_is_refused(self):
        first = self.files.read_page(self.collection, self.res, self.q, "ten_a")
        with self.assertRaises(self.files.InvalidFileQuery):
            self.files.read_page(self.collection, self.res, self.q, "ten_b", first["next_cursor"])

    def test_resolution_customer_mismatch_is_refused(self):
        with self.assertRaises(self.files.InvalidFileQuery):
            self.files.read_page(self.collection, self.res, self.q, "ten_b")

    def test_newer_insert_is_not_repeated_in_continuation(self):
        from bson import ObjectId
        first = self.files.read_page(self.collection, self.res, self.q, "ten_a")
        item = self.collection.find_one({"_id": self.ids[0]})
        item["_id"] = ObjectId(); self.collection.insert_one(item)
        second = self.files.read_page(self.collection, self.res, self.q, "ten_a", first["next_cursor"])
        self.assertEqual(second["observations"][0]["record_id"], str(self.ids[0]))

    def test_route_with_real_read_and_mocked_identity_boundary(self):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        root = pathlib.Path(__file__).resolve().parents[2]
        spec = importlib.util.spec_from_file_location("ft_candidate_router", root / "routers/edr.py")
        route = importlib.util.module_from_spec(spec); spec.loader.exec_module(route)
        app = FastAPI(); app.include_router(route.router)
        app.dependency_overrides[route.get_current_user] = lambda: {"email": "test@example.invalid"}
        app.dependency_overrides[route.edr_tenant] = lambda: "ten_a"
        params = dict(self.q)
        with patch.object(route.eq, "resolve_endpoint", return_value=self.res), \
             patch.object(route, "_tenant_scope", return_value={"tenant_ids": ["ten_a"]}), \
             patch.object(route, "sync_collection", return_value=self.collection):
            response = TestClient(app).get("/edr/endpoint-file-observations", params=params)
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(len(response.json()["observations"]), 1)
            response = TestClient(app).get("/edr/endpoint-file-observations", params={**params, "limit": 201})
            self.assertEqual(response.status_code, 422)


if __name__ == "__main__":
    unittest.main()
