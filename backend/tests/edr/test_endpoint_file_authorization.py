"""Real in-process JWT→tenant registry→endpoint→file read chain.

Only database location and JWT signing secret are test-local replacements.
No auth, tenant or identity function is mocked; no HTTP dependency overrides.
Requires explicit opt-in and a local Mongo instance. Never opens app DB config.
"""
import importlib.util
import os
import pathlib
import sys
import unittest
import uuid
from contextlib import asynccontextmanager
from unittest.mock import patch


@unittest.skipUnless(os.environ.get("NIVX_FILES_MONGO_INTEGRATION") == "1",
                     "requires explicit isolated local Mongo integration")
class FileAuthorizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from pymongo import MongoClient
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from motor.motor_asyncio import AsyncIOMotorClient
        import deps

        cls.mongo = MongoClient("mongodb://127.0.0.1:27017", serverSelectionTimeoutMS=2000)
        cls.mongo.admin.command("ping")
        cls.name = "nivx_files_auth_ci_" + uuid.uuid4().hex
        cls.database = cls.mongo[cls.name]
        cls.stack = []
        cls.deps = deps
        cls.proxy_state = {}
        for module in list(sys.modules.values()):
            for value in list(vars(module).values()) if module else []:
                if isinstance(value, deps._SyncCollectionProxy):
                    cls.proxy_state[id(value)] = (value, object.__getattribute__(value, "_real"))

        cls.sync_patch = patch.object(deps, "get_sync_db", return_value=cls.database)
        cls.secret_patch = patch.object(deps, "JWT_SECRET", "isolated-files-auth-test-secret-not-a-deployment-credential")
        cls.sync_patch.start(); cls.secret_patch.start()
        root = pathlib.Path(__file__).resolve().parents[2]
        spec = importlib.util.spec_from_file_location("files_auth_candidate_router", root / "routers/edr.py")
        cls.route = importlib.util.module_from_spec(spec); spec.loader.exec_module(cls.route)
        # Reset legacy lazy handles to the explicitly selected test database.
        for module in list(sys.modules.values()):
            for value in list(vars(module).values()) if module else []:
                if isinstance(value, deps._SyncCollectionProxy):
                    cls.proxy_state.setdefault(id(value), (value, object.__getattribute__(value, "_real")))
                    object.__setattr__(value, "_real", None)

        @asynccontextmanager
        async def lifespan(app):
            motor = AsyncIOMotorClient("mongodb://127.0.0.1:27017", serverSelectionTimeoutMS=2000)
            previous = object.__getattribute__(deps.db, "_real")
            deps.db._bind(motor[cls.name])
            try:
                yield
            finally:
                deps.db._bind(previous); motor.close()

        cls.app = FastAPI(lifespan=lifespan)
        cls.app.include_router(cls.route.router, prefix="/api")
        cls.test_client = TestClient(cls.app)

    @classmethod
    def tearDownClass(cls):
        cls.secret_patch.stop(); cls.sync_patch.stop()
        for value, previous in cls.proxy_state.values():
            object.__setattr__(value, "_real", previous)
        cls.mongo.drop_database(cls.name)  # created solely by this test class
        cls.mongo.close()

    def setUp(self):
        for name in self.database.list_collection_names():
            self.database[name].delete_many({})
        self.database.organizations.insert_one({"id": "org_files", "state": "ACTIVE"})
        self.database.tenants.insert_many([
            {"id": t, "organization_id": "org_files", "state": "ACTIVE"}
            for t in ("ten_files_a", "ten_files_b")])
        self.database.users.insert_many([
            {"email": "files-a@example.invalid", "role": "l1_analyst", "authority_scope": "CUSTOMER", "tenant_ids": ["ten_files_a"]},
            {"email": "files-b@example.invalid", "role": "l1_analyst", "authority_scope": "CUSTOMER", "tenant_ids": ["ten_files_b"]},
            {"email": "files-platform@example.invalid", "role": "platform_admin", "authority_scope": "PLATFORM"}])
        self.database.edr_endpoints.insert_many([
            {"endpoint_id": "ep_files_a", "tenant_id": "ten_files_a", "device_iid": "dev_files_a", "hostname": "FILES-A"},
            {"endpoint_id": "ep_files_b", "tenant_id": "ten_files_b", "device_iid": "dev_files_b", "hostname": "FILES-B"}])
        self.database.v2_shadow_observations.insert_many([
            {"tenant_id": f"ten_files_{suffix}", "collector_id": f"ep_files_{suffix}",
             "connector_id": f"ep_files_{suffix}", "observation_id": f"obs_files_{suffix}",
             "event": {"device_iid": f"dev_files_{suffix}", "kind": "file_create",
                       "ts": "2026-09-02T10:00:00Z", "raw": {"computer": f"FILES-{suffix.upper()}",
                       "file": {"path": f"C:\\tmp\\{suffix}.dll", "hashes": {}}}}}
            for suffix in ("a", "b")])
        self.params = {"endpoint_id": "ep_files_a", "time_start": 1788220800000,
                       "time_end": 1790812800000}

    def request(self, email="files-a@example.invalid", tenant=None, params=None, token=None):
        headers = {}
        if email:
            headers["Authorization"] = "Bearer " + (token or self.deps.create_token(email))
        if tenant:
            headers["X-Tenant-Id"] = tenant
        with self.test_client as client:
            return client.get("/api/edr/endpoint-file-observations", params=params or self.params, headers=headers)

    def test_no_authentication_is_refused(self):
        self.assertIn(self.request(email=None).status_code, (401, 403))

    def test_invalid_jwt_is_refused(self):
        self.assertEqual(self.request(token="invalid.jwt.value").status_code, 401)

    def test_password_change_gate_is_enforced(self):
        self.database.users.update_one({"email": "files-a@example.invalid"}, {"$set": {"must_change_password": True}})
        self.assertEqual(self.request().status_code, 428)

    def test_real_single_customer_auto_binding_returns_only_own_evidence(self):
        result = self.request()
        self.assertEqual(result.status_code, 200, result.text)
        self.assertEqual([r["evidence_ref"] for r in result.json()["observations"]], ["obs_files_a"])
        self.assertEqual(self.app.dependency_overrides, {})

    def test_other_customer_header_is_refused(self):
        self.assertEqual(self.request(tenant="ten_files_b").status_code, 403)

    def test_other_customer_endpoint_does_not_leak_evidence(self):
        result = self.request(params={**self.params, "endpoint_id": "ep_files_b"})
        self.assertEqual(result.status_code, 200, result.text)
        self.assertEqual(result.json()["state"], "ENDPOINT_NOT_RESOLVED")
        self.assertEqual(result.json()["observations"], [])

    def test_archived_customer_is_refused(self):
        self.database.tenants.update_one({"id": "ten_files_a"}, {"$set": {"state": "ARCHIVED"}})
        self.assertEqual(self.request().status_code, 403)

    def test_platform_user_must_choose_customer(self):
        self.assertEqual(self.request(email="files-platform@example.invalid").status_code, 403)

    def test_platform_user_is_narrowed_to_selected_customer(self):
        result = self.request(email="files-platform@example.invalid", tenant="ten_files_b",
                              params={**self.params, "endpoint_id": "ep_files_b"})
        self.assertEqual(result.status_code, 200, result.text)
        self.assertEqual([r["evidence_ref"] for r in result.json()["observations"]], ["obs_files_b"])

    def test_route_has_explicit_tenant_classification_and_dependency(self):
        from routers.edr_tenancy import ROUTE_CLASSIFICATION, TENANT_SCOPED, edr_tenant
        key = ("GET", "/api/edr/endpoint-file-observations")
        self.assertEqual(ROUTE_CLASSIFICATION.get(key), TENANT_SCOPED)
        operation = next(r for r in self.app.routes if getattr(r, "path", "") == key[1])
        self.assertIn(edr_tenant, [d.call for d in operation.dependant.dependencies])


if __name__ == "__main__":
    unittest.main()
