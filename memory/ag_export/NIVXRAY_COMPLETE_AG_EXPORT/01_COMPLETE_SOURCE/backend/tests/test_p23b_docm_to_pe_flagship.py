"""P2.3b — `.docm → PowerShell → PE` flagship end-to-end test.

Master architecture reference: /app/memory/ARCHITECTURE.md v1.1 (FROZEN).

This is the "product proof" test: a single `.docm` upload traverses
every core architectural layer:

    File Upload
        ↓
    Artifact Router (magic detects OOXML)
        ↓
    Office Analyzer  (extracts embedded PowerShell command)
        ↓
    Recursive Child Artifact Pipeline (declares PS child)
        ↓
    RTE / IEDDE     (utf-16 → base64 → gzip → PE bytes)
        ↓
    Artifact Router (recognises MZ)
        ↓
    PE Analyzer     (findings + hashes)
        ↓
    (CEM emitted downstream)

Design contract:
  • The recovered PE MUST have the same sha256 as the workspace
    flagship's canonical PE (Multi-Origin Equivalence).
  • The full chain MUST fire without any hardcoded exceptions or
    special-case bypasses in the pipeline modules.
  • The `.docm` MUST be regeneratable byte-for-byte from
    `_build_docm_ps_to_pe.py`.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from services.artifact_intelligence import dispatch
from services.recursive_child_pipeline import process as rcp_process

SAMPLES = (Path(__file__).resolve().parent / "golden_corpus" / "samples")
DOCM_PATH = SAMPLES / "docm_ps_to_pe_chain.docm"
WORKSPACE_PS_PATH = SAMPLES / "workspace_ps_to_pe_chain.txt"


def _load_docm() -> bytes:
    if not DOCM_PATH.exists():
        pytest.skip(f"synthetic .docm missing: {DOCM_PATH}")
    return DOCM_PATH.read_bytes()


# ────────────────────────────────────────────────────────────────────
# Layer 1 · Artifact Router recognises OOXML
# ────────────────────────────────────────────────────────────────────
def test_router_identifies_docm_as_office():
    routed = dispatch(_load_docm()).to_dict()
    assert routed["artifact_type"] == "office", (
        f"router misidentified .docm: got {routed['artifact_type']!r}")


# ────────────────────────────────────────────────────────────────────
# Layer 2 · Office Analyzer surfaces the embedded PowerShell command
# ────────────────────────────────────────────────────────────────────
def test_office_analyzer_extracts_powershell_command():
    routed = dispatch(_load_docm()).to_dict()
    macros = routed["analysis"]["macros"]
    scripts = macros.get("extracted_scripts") or []
    ps_scripts = [s for s in scripts if s["language"] == "powershell"]
    assert ps_scripts, (
        f"Office Analyzer failed to extract PowerShell command · scripts={scripts}")
    # The extracted command must contain the wrapper we ship.
    cmd = ps_scripts[0]["command"]
    assert "-EncodedCommand" in cmd, (
        f"extracted PS command missing -EncodedCommand: {cmd[:120]}")


def test_office_finding_flags_script_invocation():
    routed = dispatch(_load_docm()).to_dict()
    codes = {f["code"] for f in routed["analysis"]["findings"]}
    assert "macro_script_invocation" in codes, (
        f"expected macro_script_invocation finding; got codes={codes}")


# ────────────────────────────────────────────────────────────────────
# Layer 3 · Recursive Child Artifact Pipeline recovers the canonical PE
# ────────────────────────────────────────────────────────────────────
def test_recursive_pipeline_recovers_pe_from_office():
    routed = dispatch(_load_docm()).to_dict()
    children = rcp_process(routed)
    ps_children = [c for c in children if c["type"] == "powershell"]
    assert ps_children, f"no powershell child produced; children={children}"

    ps = ps_children[0]
    assert ps["rte"] and ps["rte"]["terminal_state"] == "binary_artifact_recovered", (
        f"RTE failed to recover PE from macro-embedded wrapper · "
        f"terminal_state={ps['rte']['terminal_state'] if ps['rte'] else None}")

    ra = ps.get("routed_analysis") or {}
    assert ra.get("artifact_type") == "pe", (
        f"recursive child failed to route to PE analyzer · "
        f"artifact_type={ra.get('artifact_type')!r}")

    findings = (ra.get("analysis") or {}).get("findings") or []
    assert findings, "PE analyzer produced zero findings — analyzer did not run"


# ────────────────────────────────────────────────────────────────────
# Layer 4 · Multi-Origin Equivalence — same PE across `.docm` vs
# workspace PowerShell paste vs direct PE upload.
# ────────────────────────────────────────────────────────────────────
def test_docm_pe_matches_workspace_flagship_pe_sha256():
    from services.recipe_planner import plan_and_execute
    import base64, gzip

    docm_routed = dispatch(_load_docm()).to_dict()
    docm_children = rcp_process(docm_routed)
    ps_child = next(c for c in docm_children if c["type"] == "powershell")
    docm_pe_sha = ((ps_child["routed_analysis"] or {}
                    ).get("hashes") or {}).get("sha256")

    # Workspace flagship recovery
    ws_plan = plan_and_execute(WORKSPACE_PS_PATH.read_text())
    ws_pe_sha = ((ws_plan.binary_artifact.routed_analysis or {}
                  ).get("hashes") or {}).get("sha256")

    # Direct file upload of the extracted PE bytes
    m = re.search(r"FromBase64String\(['\"]([A-Za-z0-9+/=]+)['\"]\)",
                  base64.b64decode(re.search(
                      r"-EncodedCommand\s+([A-Za-z0-9+/=]+)",
                      WORKSPACE_PS_PATH.read_text()).group(1)
                  ).decode("utf-16le"))
    pe_bytes = gzip.decompress(base64.b64decode(m.group(1)))
    upload_sha = dispatch(pe_bytes).to_dict()["hashes"]["sha256"]

    assert docm_pe_sha == ws_pe_sha == upload_sha, (
        f"multi-origin PE divergence · P0 architectural regression\n"
        f"  docm      = {docm_pe_sha}\n"
        f"  workspace = {ws_pe_sha}\n"
        f"  upload    = {upload_sha}\n"
        f"All three origins must produce the same canonical PE bytes.")


# ────────────────────────────────────────────────────────────────────
# Determinism — the synthetic .docm is byte-stable across regenerations
# ────────────────────────────────────────────────────────────────────
def test_synthetic_docm_regenerates_byte_stable(tmp_path):
    import subprocess, sys
    builder = SAMPLES / "_build_docm_ps_to_pe.py"
    if not builder.exists():
        pytest.skip(f"builder missing: {builder}")

    out = tmp_path / "regen.docm"
    # Run the builder importing it (not via CLI) so we can pass a path.
    import importlib.util
    spec = importlib.util.spec_from_file_location("docm_builder", builder)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.build(out_path=out)

    original = DOCM_PATH.read_bytes()
    regen = out.read_bytes()
    assert original == regen, (
        f"synthetic .docm is not byte-stable · original_len={len(original)} "
        f"regen_len={len(regen)}")
