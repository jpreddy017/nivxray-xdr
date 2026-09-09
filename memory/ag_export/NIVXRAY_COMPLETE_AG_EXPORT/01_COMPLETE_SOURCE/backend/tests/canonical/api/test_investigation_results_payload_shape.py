"""Phase 5.W permanent fix · P0.a — payload-shape contract (2026-08-11).

Locks the WIRE response shape of `POST /api/die/investigation-results`
so that any future contributor who accidentally drops a heavy internal
field (`preprocessor / commands / artifacts / explanations / acquired_document
/ behaviour / ice / incident`) back onto the wire triggers a red build.

The freeze that hit the analyst on SEP.csv (505 KB response, 5-minute
browser hang) was fundamentally caused by these fields leaking to the
UI.  The `_slim_investigation_response()` function in
`services/die/canonical_bridge.py` strips them today — this test
ensures nobody can silently undo that.

Governance:
  • Runs against the FastAPI TestClient — no external network.
  • Sample1 case row is not touched.
  • Uses two representative inputs:
      1.  Vendor URL (narrative MITRE path)
      2.  Tabular EDR CSV (csv_edr_analyzer path)
"""
from __future__ import annotations
import json
import os
import sys
from pathlib import Path

# Add backend to sys.path so `import server` works.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import pytest
from fastapi.testclient import TestClient

# Import the FastAPI app.
from server import app  # noqa: E402


# ── Allow-list — the ONLY keys that may appear on `object.*` ──────
# Add a new key here only after weighing (i) whether the Workspace UI
# renders it, (ii) whether it fits within the 250 KB response budget,
# (iii) whether it carries any of the heavy internal state that
# previously caused the Wait/Exit freeze.
ALLOWED_OBJECT_KEYS = {
    # Core canonical output
    "narrative",             # analyst-facing summary + progression + mitre_matrix + …
    "mitre",                 # flat list of {id, name, tactic, kill_chain, evidence, …}
    "iocs",                  # {domain, hostname, sha256, url, ip, filename, path, user}
    "lolbas",                # [{binary, legit, abuse, detection, mitre}]
    "chain",                 # {steps, root, source, total}
    "csv_edr",               # compact CSV/EDR summary (added Phase 5.W)
    # P0e-Unslim (2026-02-09) · nested-slimmed structured-evidence
    # container carrying commands / mitre_techniques / body_artifacts /
    # yara_rules / sigma_rules / threat_actors / malware_families /
    # cves / timeline / hash_context / totals / source /
    # investigation_summary / acquisition_failure. Heavy sub-fields
    # (raw doc text, per-stage decoded output, etc.) are dropped by
    # `_slim_report_extraction()` in services/die/canonical_bridge.py.
    # Rendered by the Workspace UI in WorkspacePage.jsx,
    # StructuredEvidenceTab.jsx, ExtractedArtifactsPanel.jsx,
    # AcquisitionPlanPanel.jsx, InvestigationSessionGateway.jsx,
    # InvestigationSessionPage.jsx. Wire size stays within the
    # 250 KB budget (verified by test_response_size_under_budget).
    "report_extraction",
    # Metadata / bookkeeping
    "input",                 # truncated echo of the analysed input (≤ 64 KB)
    "input_kind",
    "input_hash",
    "input_preview",
    "confidence",
    "metadata",
    "verdict",
    "artifact_type",
    "acquisition_summary",
    "acquisition_ocr_records",
    "incident_tactics",      # compact tactic list (P5.W slim replacement for `incident`)
    # Diagnostics — must remain small
    "engines_selected_lite",
    "raw_input_class",
    "raw_input_preview",
    "annotations",           # very compact tag list
    "confidence_reason",
    "phase",                 # canonical bridge phase tag
    "reached_shellcode",
    "verdict_reason",
    "story_summary",         # small string
    "detection_hits_count",  # scalar
    "health",                # small pipeline health flags
    "ida",                   # compact IDA lifecycle bookkeeping
}

# ── Forbidden keys — must NEVER appear on wire (they killed the tab) ──
# NOTE (P0e-Unslim · 2026-02-09): `report_extraction` was previously
# on this list. It is now on the ALLOWED list (nested-slimmed) because
# the Workspace UI renders its structured sub-fields. See the comment
# in ALLOWED_OBJECT_KEYS and `_slim_report_extraction()` in
# services/die/canonical_bridge.py for the size-bounded contract.
FORBIDDEN_OBJECT_KEYS = {
    "preprocessor",
    "commands",
    "artifacts",
    "explanations",
    "explanation_coverage",
    "acquired_document",
    "document_profile",
    "artifact_summary",
    "profiling",
    "engines_selected",
    "engines_skipped",
    "understanding",
    "plan",
    "acquisition_plan",
    "dkp",
    "intent",
    "behaviour",
    "ice",
    "incident",   # replaced by compact `incident_tactics`
}

MAX_RESPONSE_BYTES = 250 * 1024   # 250 KB hard cap on the wire


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def _fixture_csv() -> str:
    """Return a representative tabular EDR CSV (small SEP subset)."""
    return (
        "date,src_host,user,file_name,file_hash,parent_file_name,parent_file_hash,file_path,action,category\n"
        "2026-08-03T13:24:57+00:00,DMZ01.axium.local,jsmith,browserhost.exe,"
        "12f07d1352844bc7f12d3ad598dd73c19d86c5bdbe230e9c0acdebf4e182e2ad,,,"
        "C:\\Program Files\\Edge\\browserhost.exe,detect,Exploit Prevention\n"
        "2026-08-03T13:25:11+00:00,DMZ01.axium.local,jsmith,winlogon.exe,"
        "abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabca,,,"
        "C:\\Windows\\System32\\winlogon.exe,block,System Process Protection\n"
        "2026-08-03T13:25:44+00:00,DMZ01.axium.local,jsmith,ChromeSetup.exe,,,,,"
        "success,File Fetch Completed\n"
        "2026-08-03T13:26:15+00:00,DMZ02.axium.local,rjones,,,,,,,"
        "success,Signature Set Update Success\n"
        "2026-08-03T13:26:44+00:00,DMZ02.axium.local,rjones,foo.exe,,,,,detect,"
        "Suspicious Endpoint Findings without Tactics\n"
    )


def _fixture_prose() -> str:
    """Vendor narrative that the canonical MITRE narrative rules should hit."""
    return (
        "During the incident the actor deployed a remote access trojan and "
        "used PowerShell to execute an encoded command. The malware attempted "
        "to disable Windows Defender and moved laterally over SMB."
    )


def _post(client, text: str) -> dict:
    """Post to /api/die/investigation-results and return parsed JSON."""
    r = client.post("/api/die/investigation-results", json={"input": text})
    assert r.status_code == 200, f"http={r.status_code} body={r.text[:400]}"
    return r.json()


# ─────────────────────────────────────────────────────────────────
# P0.a.1 — Response body must not exceed 250 KB on either input.
# ─────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("label,text", [
    ("csv_edr", _fixture_csv()),
    ("prose",   _fixture_prose()),
    ("empty",   ""),
])
def test_response_size_under_budget(client, label, text):
    resp = _post(client, text)
    body_len = len(json.dumps(resp))
    assert body_len <= MAX_RESPONSE_BYTES, (
        f"[{label}] wire response {body_len:,} bytes exceeds the {MAX_RESPONSE_BYTES:,} "
        f"byte budget. See _slim_investigation_response() in "
        f"services/die/canonical_bridge.py — a new heavy field probably leaked to the wire."
    )


# ─────────────────────────────────────────────────────────────────
# P0.a.2 — Response `object` must only contain allow-listed keys.
# ─────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("label,text", [
    ("csv_edr", _fixture_csv()),
    ("prose",   _fixture_prose()),
    ("empty",   ""),
])
def test_object_keys_are_allow_listed(client, label, text):
    resp = _post(client, text)
    obj  = resp.get("object") or {}
    unexpected = sorted(k for k in obj.keys() if k not in ALLOWED_OBJECT_KEYS)
    assert not unexpected, (
        f"[{label}] response.object contains keys outside the allow-list: {unexpected}. "
        f"Either (a) they belong on the wire → add them to ALLOWED_OBJECT_KEYS in this "
        f"test AFTER confirming they fit the 250 KB budget and are actually rendered by "
        f"the Workspace UI, or (b) they are internal state that leaked → strip them in "
        f"services/die/canonical_bridge.py::_slim_investigation_response()."
    )


# ─────────────────────────────────────────────────────────────────
# P0.a.3 — Explicitly forbidden keys must not appear.
# ─────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("label,text", [
    ("csv_edr", _fixture_csv()),
    ("prose",   _fixture_prose()),
    ("empty",   ""),
])
def test_forbidden_heavy_fields_absent(client, label, text):
    resp = _post(client, text)
    obj  = resp.get("object") or {}
    leaked = sorted(k for k in obj.keys() if k in FORBIDDEN_OBJECT_KEYS)
    assert not leaked, (
        f"[{label}] response.object contains FORBIDDEN heavy fields {leaked}. "
        f"These caused the SEP.csv 5-minute browser freeze on 2026-08-10. "
        f"Restore _slim_investigation_response() in services/die/canonical_bridge.py."
    )


# ─────────────────────────────────────────────────────────────────
# P0.a.4 — CSV input must produce non-empty MITRE (regression guard).
# ─────────────────────────────────────────────────────────────────
def test_csv_input_produces_mitre(client):
    resp = _post(client, _fixture_csv())
    obj  = resp.get("object") or {}
    mitre = obj.get("mitre") or []
    assert len(mitre) >= 3, (
        f"tabular EDR CSV should produce ≥ 3 MITRE techniques via csv_edr_analyzer; "
        f"got {len(mitre)}. Check services/die/csv_edr_analyzer.py::analyse_csv_edr()."
    )
    ids = {t.get("id") for t in mitre if isinstance(t, dict)}
    # SEP-style categories map to T1203 / T1055 / T1204.002 / T1543.003 / T1055.012 etc.
    assert ids & {"T1203", "T1055", "T1204.002", "T1543.003", "T1055.012"}, (
        f"expected at least one SEP-mapped technique id, got {ids}"
    )


# ─────────────────────────────────────────────────────────────────
# P0.a.5 — Narrative must have populated executive_summary (regression).
# ─────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("label,text", [
    ("csv_edr", _fixture_csv()),
    ("prose",   _fixture_prose()),
])
def test_executive_summary_populated(client, label, text):
    resp = _post(client, text)
    n = ((resp.get("object") or {}).get("narrative") or {})
    es = (n.get("executive_summary") or "").strip()
    assert es, (
        f"[{label}] narrative.executive_summary is empty — the canned-legacy "
        f"detection in canonical_narrative_enrichment._is_canned probably regressed."
    )
    # Must be the enriched shape, not the legacy canned one.
    assert "analyst-observable stages" not in es, (
        f"[{label}] executive_summary is the legacy canned string. The "
        f"canonical enrichment did not fire — check _is_canned() and the "
        f"csv_edr_analyzer wire-up in routers/die.py::die_narrate."
    )
