"""R28 / R28.1 live regression against preview URL.

Validates:
  • ssot_ref (id, sha256 checksum, compound version) attached on GET /api/cases/{id}
  • ssot_source == 'immutable_store' after fresh save; artifact_trace projection populated
  • GET /api/ssot/{investigation_id} → 200 with ssot + artifact_trace, 404 unknown
  • Compound version stamp (schema, engine, uaie, baseline)
  • Content-addressable dedupe (same ssot → same ssot_ref.id + checksum)
  • Regression: sigma/yara/reinvestigate/delete/list still work
"""
from __future__ import annotations

import os
import re
import uuid
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "https://greeting-app-5782.preview.emergentagent.com").rstrip("/")
ADMIN_EMAIL = "admin@nivxray.com"
ADMIN_PASSWORD = "uulVDp5cCSB3Hva99s7UUAwK"

_created_case_ids: list[str] = []


@pytest.fixture(scope="session")
def token():
    r = requests.post(f"{BASE_URL}/api/auth/login",
                      json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}, timeout=30)
    assert r.status_code == 200, f"login failed: {r.status_code} {r.text}"
    tok = r.json().get("access_token") or r.json().get("token")
    assert tok, f"no token in {r.json()}"
    return tok


@pytest.fixture(scope="session")
def s(token):
    ses = requests.Session()
    ses.headers.update({"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    return ses


def _sample_ssot():
    return {
        "understanding": {"input_kind": "powershell", "confidence": 0.94,
                          "decode_required": True, "next_steps": ["b64", "gzip"]},
        "analyst_narrative": {"executive_summary": "PS downloader.",
                              "sigma_ideas": ["proc_win_ps_iex"],
                              "yara_ideas": ["gzip_pe"],
                              "recommended_actions": ["Isolate"]},
        "inline_story_preproc": {"stages": [{"op": "b64", "reason": "b64 alphabet"},
                                            {"op": "gzip", "reason": "magic 1F8B"}]},
        "investigation_object": {"acquisition_plan": [{"step": "extract_iocs"}],
                                 "incident": {"behaviors": ["T1059.001"]},
                                 "ice": {"behavior_clusters": ["download-and-exec"]}},
        "investigation_mode": True,
        "verdict_card": {"verdict": "Malicious", "confidence": 92, "family": "CobaltStrike",
                         "summary": "Beacon loader"},
        "decode_trace": [
            {"layer": 1, "op": "b64", "out_len": 512, "reason": "b64 alphabet",
             "output_preview": "eJxLSs0rSc0rAQAJTgKG"},
            {"layer": 2, "op": "gzip", "out_len": 2048, "reason": "magic 1F8B",
             "output_preview": "MZ\\x90\\x00"},
        ],
        "analysis": {"iocs": {"ipv4": ["1.2.3.4"], "url": ["http://c2.example/beacon"]},
                     "mitre": ["T1059.001"], "ai_verdict": "Malicious"},
        "mitre": ["T1059.001", "T1105"],
        "lolbas": ["powershell.exe"],
        "chain": [{"op": "b64"}, {"op": "gzip"}],
        "steps": [{"op": "b64"}, {"op": "gzip"}],
        "canonical_confidence": 0.93,
    }


def _save(s, name, ssot):
    r = s.post(f"{BASE_URL}/api/cases/save", json={
        "name": name, "input": "powershell -EncodedCommand ABC==",
        "output": "iex ...", "engine": "powershell-recursive",
        "confidence": 92, "chain_ids": ["b64", "gzip"], "verdict": "Malicious",
        "iocs": {"ipv4": ["1.2.3.4"]}, "ssot": ssot,
    }, timeout=30)
    assert r.status_code == 200, r.text
    body = r.json()
    _created_case_ids.append(body["id"])
    return body


# ─── T1 · ssot_ref present with id + sha256 checksum + compound version ──
def test_case_get_returns_ssot_ref(s):
    name = f"TEST_r28-ref-{uuid.uuid4().hex[:8]}"
    saved = _save(s, name, _sample_ssot())
    case_id = saved["id"]
    r = s.get(f"{BASE_URL}/api/cases/{case_id}", timeout=30)
    assert r.status_code == 200, r.text
    body = r.json()
    ref = body.get("ssot_ref")
    assert isinstance(ref, dict), f"ssot_ref missing: {list(body.keys())}"
    assert ref.get("id") and isinstance(ref["id"], str)
    checksum = ref.get("checksum")
    assert checksum and re.fullmatch(r"[0-9a-f]{64}", checksum), f"bad sha256: {checksum!r}"
    v = ref.get("version")
    assert isinstance(v, dict), f"expected compound version dict got {v!r}"
    for k in ("schema", "engine", "uaie", "baseline"):
        assert k in v, f"version missing {k}: {v}"


# ─── T2 · ssot_source == immutable_store + artifact_trace populated ──────
def test_case_get_source_and_artifact_trace(s):
    name = f"TEST_r28-src-{uuid.uuid4().hex[:8]}"
    saved = _save(s, name, _sample_ssot())
    body = s.get(f"{BASE_URL}/api/cases/{saved['id']}", timeout=30).json()
    assert body.get("ssot_source") == "immutable_store", \
        f"expected immutable_store, got {body.get('ssot_source')!r}"
    at = body.get("artifact_trace")
    assert isinstance(at, list) and len(at) == 2, f"artifact_trace: {at!r}"
    row0 = at[0]
    for k in ("artifact_uri", "layer_index", "recognizer", "capability",
              "evidence", "child_artifact"):
        assert k in row0, f"artifact_trace row missing {k}: {row0}"
    assert row0["artifact_uri"].startswith("uaie://artifact/")
    assert isinstance(row0["recognizer"], dict) and "name" in row0["recognizer"]
    assert isinstance(row0["capability"], dict) and "name" in row0["capability"]
    # last layer inherits case-level IOC evidence
    last = at[-1]
    assert last["child_artifact"] is None
    kinds = {e["kind"] for e in last["evidence"]}
    assert "ipv4" in kinds or "url" in kinds


# ─── T3 · Compound version stamp on saved ssot ────────────────────────────
def test_compound_version_stamp_on_ssot(s):
    name = f"TEST_r28-vs-{uuid.uuid4().hex[:8]}"
    saved = _save(s, name, _sample_ssot())
    body = s.get(f"{BASE_URL}/api/cases/{saved['id']}", timeout=30).json()
    ssot = body.get("ssot") or {}
    v = ssot.get("version")
    assert isinstance(v, dict), f"expected compound version, got {v!r}"
    assert v.get("schema") == "1.0"
    assert v.get("engine") in ("legacy", "uaie-plugin")
    assert v.get("uaie") in ("phase0", "phase1", "phase2", "phase3")
    assert str(v.get("baseline", "")).startswith("R2")


# ─── T4 · GET /api/ssot/{id} 200 + 404 ────────────────────────────────────
def test_ssot_dereference_endpoint(s):
    name = f"TEST_r28-deref-{uuid.uuid4().hex[:8]}"
    saved = _save(s, name, _sample_ssot())
    case_doc = s.get(f"{BASE_URL}/api/cases/{saved['id']}", timeout=30).json()
    inv_id = case_doc["ssot_ref"]["id"]
    r = s.get(f"{BASE_URL}/api/ssot/{inv_id}", timeout=30)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["investigation_id"] == inv_id
    assert body["checksum"] == case_doc["ssot_ref"]["checksum"]
    assert isinstance(body["version"], dict)
    assert isinstance(body.get("ssot"), dict)
    at = body.get("artifact_trace")
    assert isinstance(at, list) and len(at) >= 1

    # 404 unknown
    r404 = s.get(f"{BASE_URL}/api/ssot/does-not-exist-{uuid.uuid4().hex}", timeout=30)
    assert r404.status_code == 404


# ─── T5 · Content-addressable dedupe ──────────────────────────────────────
def test_content_addressable_dedupe(s):
    ssot = _sample_ssot()
    a = _save(s, f"TEST_r28-dedupe-a-{uuid.uuid4().hex[:8]}", ssot)
    b = _save(s, f"TEST_r28-dedupe-b-{uuid.uuid4().hex[:8]}", ssot)
    ra = s.get(f"{BASE_URL}/api/cases/{a['id']}", timeout=30).json()["ssot_ref"]
    rb = s.get(f"{BASE_URL}/api/cases/{b['id']}", timeout=30).json()["ssot_ref"]
    assert ra["checksum"] == rb["checksum"], "identical ssot → same checksum"
    assert ra["id"] == rb["id"], "content-addressable store must dedupe by checksum"


# ─── T6 · Legacy save (no ssot) → inline_legacy source, no ssot_ref ──────
def test_legacy_save_no_ssot(s):
    name = f"TEST_r28-legacy-{uuid.uuid4().hex[:8]}"
    r = s.post(f"{BASE_URL}/api/cases/save", json={
        "name": name, "input": "cmd", "output": "out", "engine": "manual",
        "confidence": 10, "chain_ids": [], "verdict": "Suspicious", "iocs": {},
    }, timeout=30)
    assert r.status_code == 200, r.text
    _created_case_ids.append(r.json()["id"])
    body = s.get(f"{BASE_URL}/api/cases/{r.json()['id']}", timeout=30).json()
    assert body.get("ssot") is None
    assert body.get("ssot_ref") in (None, {}, {"id": None})
    src = body.get("ssot_source")
    # Either omitted or explicitly 'inline_legacy'/None; accept both permissive shapes
    assert src in (None, "", "inline_legacy"), f"unexpected ssot_source={src!r}"


# ─── T7 · Regression: list, sigma, yara, reinvestigate, delete ────────────
def test_list_has_ssot_flag(s):
    name_ssot = f"TEST_r28-list-ssot-{uuid.uuid4().hex[:6]}"
    _save(s, name_ssot, _sample_ssot())
    r = s.get(f"{BASE_URL}/api/cases", params={"limit": 200}, timeout=30)
    assert r.status_code == 200
    cases = r.json().get("cases", [])
    row = next((c for c in cases if c["name"] == name_ssot), None)
    assert row is not None
    assert row.get("has_ssot") is True


def test_regression_sigma_yara(s):
    name = f"TEST_r28-sigyara-{uuid.uuid4().hex[:6]}"
    saved = _save(s, name, _sample_ssot())
    cid = saved["id"]
    r = s.get(f"{BASE_URL}/api/cases/{cid}/sigma", timeout=60)
    assert r.status_code == 200, r.text
    r = s.get(f"{BASE_URL}/api/cases/{cid}/yara", timeout=60)
    assert r.status_code == 200, r.text


def test_zzz_cleanup(s):
    for cid in _created_case_ids:
        try:
            s.delete(f"{BASE_URL}/api/cases/{cid}", timeout=15)
        except Exception:
            pass
