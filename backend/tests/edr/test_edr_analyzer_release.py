"""Exercises the real worker through the release router without production data."""
import base64
import sys
import types
import unittest
from unittest.mock import patch

from fastapi import FastAPI, Header, HTTPException
from fastapi.testclient import TestClient


async def user(authorization: str | None = Header(None)):
    if authorization != "Bearer fixture":
        raise HTTPException(401)
    return {"email": "fixture@example.test"}


async def tenant(x_tenant_id: str | None = Header(None)):
    if x_tenant_id != "fixture":
        raise HTTPException(403)
    return x_tenant_id


class ReleaseAnalyzer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from importlib import import_module

        dependencies = types.ModuleType("deps")
        dependencies.get_current_user = user
        tenancy = types.ModuleType("routers.edr_tenancy")
        tenancy.edr_tenant = tenant
        tenancy.edr_scope = lambda tenant_id, user: None
        with patch.dict(sys.modules, {"deps": dependencies, "routers.edr_tenancy": tenancy}):
            routes = import_module("routers.edr_analyzer")
        app = FastAPI()
        app.include_router(routes.router, prefix="/api/edr/forensics")
        cls.client = TestClient(app)
        cls.url = "/api/edr/forensics/command-analysis"
        cls.headers = {"Authorization": "Bearer fixture", "X-Tenant-Id": "fixture"}

    def test_recovers_full_script_and_extracts_indicator(self):
        script = "Test-NetConnection -ComputerName 192.0.2.42 -Port 443"
        encoded = base64.b64encode(script.encode("utf-16-le")).decode()
        command = "powershell.exe -NoProfile -EncodedCommand " + encoded
        response = self.client.post(self.url, headers=self.headers, json={
            "mode": "command", "command_line": command,
        })
        self.assertEqual(response.status_code, 200, response.text[:500])
        evidence = response.json()
        self.assertEqual(evidence["submission"]["command_line"], command)
        self.assertFalse(evidence["report"]["executed"])
        recovered = evidence["report"]["recovered_layers"]
        self.assertTrue(any(i["value"] == "192.0.2.42" for i in recovered["indicators"]))
        self.assertTrue(any(
            base64.b64decode(layer["output_base64"]).decode("utf-8", "replace") == script
            for layer in recovered["layers"]
        ))
        self.assertEqual(response.headers["Cache-Control"], "no-store")

    def test_session_and_tenant_guards_run_before_analysis(self):
        body = {"mode": "command", "command_line": "Write-Output test"}
        self.assertEqual(self.client.post(self.url, json=body).status_code, 401)
        wrong = {**self.headers, "X-Tenant-Id": "other"}
        self.assertEqual(self.client.post(self.url, headers=wrong, json=body).status_code, 403)

    def test_reserved_addresses_are_ineligible_for_live_lookup(self):
        response = self.client.post("/api/edr/forensics/ioc-reputation", headers=self.headers,
                                    json={"kind": "ip", "value": "192.0.2.42"})
        self.assertEqual(response.status_code, 422)
