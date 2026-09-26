"""P0-C · the durable-findings READ plane, against the LIVE preview edge.

Read-only. Nothing is created, nothing is deleted. These assert the
contract an EDR console will depend on: tenant authority on every read,
provenance stated on every finding, and an evaluation state that makes
"nothing found" distinguishable from "never looked".
"""
from __future__ import annotations

import os

import pytest
import requests
from dotenv import load_dotenv

load_dotenv("/app/backend/.env")

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL",
                          "http://localhost:8001").rstrip("/")
ADMIN_EMAIL = "admin@nivxray.com"
ADMIN_PASSWORD = "uulVDp5cCSB3Hva99s7UUAwK"
SCOPED_EMAIL = "analyst@nivx-live.com"
SCOPED_PASSWORD = "NivxLive!Analyst2026"
TENANT = "default"
OTHER_TENANT = "nivx-live"
UNKNOWN_TENANT = "ten_definitely_not_registered_0000"


def _login(email: str, password: str) -> str:
    r = requests.post(f"{BASE_URL}/api/auth/login",
                      json={"email": email, "password": password}, timeout=20)
    assert r.status_code == 200, f"login {email}: {r.status_code} {r.text}"
    return r.json()["access_token"]


@pytest.fixture(scope="module")
def admin() -> dict:
    return {"Authorization": f"Bearer {_login(ADMIN_EMAIL, ADMIN_PASSWORD)}"}


@pytest.fixture(scope="module")
def scoped() -> dict:
    token = _login(SCOPED_EMAIL, SCOPED_PASSWORD)
    return {"Authorization": f"Bearer {token}"}


def _get(path: str, headers: dict, tenant: str | None = TENANT):
    h = dict(headers)
    if tenant:
        h["X-Tenant-Id"] = tenant
    return requests.get(f"{BASE_URL}{path}", headers=h, timeout=40)


def _code(r) -> str:
    try:
        detail = r.json().get("detail")
    except (ValueError, AttributeError):
        return ""
    return str(detail.get("code") or "") if isinstance(detail, dict) else ""


# ── the taxonomy tells the truth about what exists ──────────────────────
def test_the_taxonomy_declares_only_the_engines_that_exist(admin):
    r = _get("/api/edr/findings/taxonomy", admin, tenant=None)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["implemented_detection_sources"] == [
        "XDR_PLATFORM_DETERMINISTIC_DETECTION"]
    assert body["local_behavioral_engine_present"] is False
    unimplemented = [s for s in body["detection_sources"]
                     if not s["implemented"]]
    assert unimplemented, "the absent engines must still be disclosed"
    for s in unimplemented:
        assert s["produced_by"] is None and s["nivxforge_role"]
    states = {s["state"] for s in body["evaluation_states"]}
    assert {"FINDINGS_PRESENT", "EVALUATED_NO_FINDING", "NOT_EVALUATED",
            "EVALUATION_FAILED"} <= states
    # exactly one analyzer exists, and it declares its own blind spots
    assert len(body["analyzers"]) == 1
    assert body["analyzers"][0]["cannot"]


# ── tenant authority on every read ──────────────────────────────────────
@pytest.mark.parametrize("path", ["/api/edr/findings",
                                  "/api/edr/findings/evaluation-state",
                                  "/api/edr/findings/fnd_probe"])
def test_a_findings_read_requires_an_explicit_registered_tenant(path, admin):
    absent = _get(path, admin, tenant=None)
    assert absent.status_code == 403 and _code(absent) == "TENANT_REQUIRED"
    unknown = _get(path, admin, tenant=UNKNOWN_TENANT)
    assert unknown.status_code == 403 and _code(unknown) == "TENANT_NOT_FOUND"


def test_a_principal_cannot_read_findings_of_a_tenant_it_does_not_hold(
        scoped):
    r = _get("/api/edr/findings", scoped, tenant=TENANT)
    assert r.status_code == 403, r.text
    assert _code(r) == "TENANT_NOT_AUTHORIZED_FOR_PRINCIPAL", r.text
    own = _get("/api/edr/findings", scoped, tenant=OTHER_TENANT)
    assert own.status_code == 200, own.text
    assert own.json()["tenant_id"] == OTHER_TENANT


# ── the disclosure contract ─────────────────────────────────────────────
def test_every_findings_response_discloses_the_evaluation_state(admin):
    r = _get("/api/edr/findings?limit=5", admin)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["tenant_id"] == TENANT
    assert "evaluation_state" in body
    assert body["local_behavioral_engine_present"] is False
    assert "NO FINDING != BENIGN" in body["truth_semantics"]
    assert "NOT EVALUATED != NO FINDING" in body["truth_semantics"]
    assert "never rewritten" in body["retrospection"]
    assert "does not yet have a local behavioural detection engine" in \
        body["provenance_contract"]


def test_a_tenant_with_no_findings_is_not_reported_as_clean(scoped):
    """The empty case is the dangerous one: it must still say whether
    anything was evaluated at all."""
    r = _get("/api/edr/findings", scoped, tenant=OTHER_TENANT)
    body = r.json()
    state = body["evaluation_state"]
    if not body["findings"]:
        assert "evidence_with_a_recorded_evaluation" in state
        if state["evidence_with_a_recorded_evaluation"] == 0:
            assert "NOT 'evaluated and clean'" in state["empty_result_meaning"]


def test_an_endpoint_nobody_evaluated_reads_not_evaluated(admin):
    r = _get("/api/edr/findings/evaluation-state?endpoint_refs="
             "ep_never_enrolled_probe", admin)
    assert r.status_code == 200, r.text
    row = r.json()["endpoints"][0]
    assert row["state"] == "NOT_EVALUATED"
    assert row["reason"] == "NO_EVALUATION_RECORDED"


# ── real findings on the live edge: provenance and evidence ─────────────
def test_a_live_finding_states_its_real_producing_source(admin):
    r = _get("/api/edr/findings?limit=5", admin)
    findings = r.json()["findings"]
    if not findings:
        pytest.skip("no finding has been produced on this edge yet — "
                    "there is nothing to make a claim about")
    for f in findings:
        assert f["detection_source"] == "XDR_PLATFORM_DETERMINISTIC_DETECTION"
        assert "NivXRay XDR ingest detection pipeline" in \
            f["detection_source_detail"]
        assert f["inference_location"] == "BACKEND"
        assert f["evidence_refs"], "a finding must cite evidence"
        assert f["severity_basis"] and f["confidence_basis"] and \
            f["attck_basis"]
        assert f["first_seen"] and f["created_at"] and \
            f["recurrence_count"] >= 1


def test_a_live_finding_resolves_to_the_evidence_responsible_for_it(admin):
    findings = _get("/api/edr/findings?limit=1", admin).json()["findings"]
    if not findings:
        pytest.skip("no finding has been produced on this edge yet")
    fid = findings[0]["finding_id"]
    r = _get(f"/api/edr/findings/{fid}", admin)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["finding"]["finding_id"] == fid
    assert body["evidence"], "the finding cites evidence but resolved none"
    for e in body["evidence"]:
        assert e["state"] == "EVIDENCE_RESOLVED", e
        assert e["resolved_in"], e
    assert body["evaluation_state"][0]["state"] == "FINDINGS_PRESENT"


def test_a_finding_is_never_readable_from_another_tenant(admin):
    findings = _get("/api/edr/findings?limit=1", admin).json()["findings"]
    if not findings:
        pytest.skip("no finding has been produced on this edge yet")
    fid = findings[0]["finding_id"]
    r = _get(f"/api/edr/findings/{fid}", admin, tenant=OTHER_TENANT)
    assert r.status_code == 404, r.text
    assert _code(r) == "FINDING_NOT_FOUND"
    # and the refusal discloses nothing about the finding it refused
    assert fid not in r.text
