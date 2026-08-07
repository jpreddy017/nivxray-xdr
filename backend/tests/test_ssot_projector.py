"""UAIE · SSOT Projector CI Gate.

Proves:
  1. ``ssot_projector.project(result)`` produces a bundle carrying the
     canonical SSOT keys the Workspace expects.
  2. The Verdict Card in the bundle is the one produced by the
     EXISTING production ``evidence_extractor.build_verdict_card`` —
     no reimplementation drift.
  3. The projected SSOT round-trips through ``services.ssot_store``
     (checksum stable, artifact_trace projection identical).
  4. Pure projection · same OrchestratorResult → same SSOT.
  5. UAIE-provenance is surfaced via ``source_engine == 'uaie'``.

This is Priority 1 (wire evidence_extractor) + Priority 2 (route UAIE
output into SSOT) landing together — the actual switchover from
"UAIE is a framework" to "UAIE produces the SSOT".

Run:  cd /app/backend && python -m pytest tests/test_ssot_projector.py -v
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, "/app/backend")
os.environ.setdefault("MONGO_URL", "mongodb://localhost:27017")
os.environ.setdefault("DB_NAME", "test_database")

from services.uaie.orchestrator    import Orchestrator
from services.uaie                 import plugins as _plugins_pkg
from services.uaie.ssot_projector  import project as _project
from services.ssot_store           import (
    store_ssot, load_ssot, project_artifact_trace, compute_checksum,
)
import evidence_extractor as _ee


def _make_msf_meterpreter_bytes() -> bytes:
    prologue = b"\xFC\xE8\x89\x00\x00\x00\x60\x89\xE5\x31\xD2"
    body = (
        b"wininet.dll\x00ws2_32.dll\x00WSAStartup\x00socket\x00connect\x00"
        b"MSIE 8.0\x00InternetOpenA\x00"
        b"http://c2.example.com/beacon.php\x00"
        b"149.28.81.19\x00"
    )
    import hashlib
    tail = b"".join(hashlib.sha256(str(i).encode()).digest()[:16] for i in range(64))
    return prologue + body + tail


def _run_orch():
    return Orchestrator(recognizers=_plugins_pkg.all_recognizers()).run(
        _make_msf_meterpreter_bytes(), root_type="shellcode_bytes",
    )


# ═════════════════════════════════════════════════════════════════════════
# T1 · Projector produces the canonical SSOT keys.
# ═════════════════════════════════════════════════════════════════════════
def test_projector_produces_canonical_ssot_shape():
    result = _run_orch()
    ssot = _project(result, root_input="paste input", root_output="")
    for k in [
        "verdict_card", "analysis", "mitre", "lolbas", "chain",
        "steps", "decode_trace", "reached_shellcode", "corrupted_container",
        "semantic", "iedde", "iedde_terminal_state",
        "canonical_confidence", "canonical_confidence_reason",
        "understanding", "analyst_narrative", "inline_story_preproc",
        "investigation_object", "investigation_mode", "predicted_tree",
        "source_engine", "uaie_stats",
    ]:
        assert k in ssot, f"SSOT missing canonical key {k!r}"


def test_projector_marks_source_engine_as_uaie():
    ssot = _project(_run_orch(), root_input="paste", root_output="")
    assert ssot["source_engine"] == "uaie"
    stats = ssot["uaie_stats"]
    assert stats["artifacts"] >= 1
    assert stats["ledger"] >= 1
    # timing (non-deterministic) MUST NOT enter the canonical SSOT
    assert "total_ms" not in stats, "SSOT must be free of non-deterministic timing"


# ═════════════════════════════════════════════════════════════════════════
# T2 · Verdict Card is the exact output of build_verdict_card.
# ═════════════════════════════════════════════════════════════════════════
def test_projector_verdict_card_matches_evidence_extractor():
    """R26 · no reimplementation.  The Verdict Card in the SSOT MUST be
    the exact dict produced by ``evidence_extractor.build_verdict_card``
    when given the same aggregated findings."""
    result = _run_orch()
    ssot   = _project(result, root_input="paste", root_output="ok")

    # Rebuild findings the same way the projector did, then invoke
    # build_verdict_card directly and compare.
    from services.uaie.ssot_projector import (
        _collect_iocs, _collect_mitre, _collect_lolbas, _collect_family,
        _build_chain,
    )
    findings = {
        "iocs":             _collect_iocs(result),
        "mitre_techniques": _collect_mitre(result),
        "lolbas":           _collect_lolbas(result),
    }
    fam = _collect_family(result)
    if fam:
        findings["family"] = fam
    direct_card = _ee.build_verdict_card(
        input_text="paste", output_text="ok",
        chain=_build_chain(result),
        corrupted_container=None,
        findings=findings,
    )
    assert ssot["verdict_card"] == direct_card, (
        "verdict_card drift between projector output and direct "
        "build_verdict_card call — R26 breach"
    )


# ═════════════════════════════════════════════════════════════════════════
# T3 · Projected SSOT round-trips through the immutable store cleanly.
# ═════════════════════════════════════════════════════════════════════════
def test_projected_ssot_round_trips_through_store():
    ssot = _project(_run_orch(), root_input="paste", root_output="")
    ref = store_ssot(ssot, user_email="uaie-projector@test", case_name="unit")
    assert ref["id"]
    assert ref["checksum"] == compute_checksum(ssot), \
        "immutable store checksum drift"
    resolved = load_ssot(ref["id"])
    # Compare business fields (persisted_at / checksum injected by store).
    for k in ("verdict_card", "mitre", "lolbas", "reached_shellcode",
              "source_engine"):
        assert resolved.get(k) == ssot.get(k), f"round-trip drift on {k!r}"
    # Artifact Trace projection on the resolved SSOT is deterministic.
    at1 = project_artifact_trace(ssot)
    at2 = project_artifact_trace(resolved)
    assert at1 == at2


# ═════════════════════════════════════════════════════════════════════════
# T4 · Pure projection — same input, same SSOT.
# ═════════════════════════════════════════════════════════════════════════
def test_projector_is_pure():
    a = _project(_run_orch(), root_input="paste", root_output="")
    b = _project(_run_orch(), root_input="paste", root_output="")
    # persisted_at is added by the store, not the projector — projector
    # output must be identical.
    assert compute_checksum(a) == compute_checksum(b)


# ═════════════════════════════════════════════════════════════════════════
# T5 · Projector honours R28 (Restore is Rendering) — no /die/* calls.
# ═════════════════════════════════════════════════════════════════════════
def test_projector_is_restore_safe_ast():
    """AST-inspect the projector module — it must not import any
    decoder / classifier / LLM / troubleshooter."""
    import ast
    import services.uaie.ssot_projector as mod
    src = open(mod.__file__, "r", encoding="utf-8").read()
    tree = ast.parse(src)
    imported: set = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            m = node.module or ""
            for a in node.names:
                imported.add(f"{m}.{a.name}")
        elif isinstance(node, ast.Import):
            for a in node.names:
                imported.add(a.name)
    forbidden = ["die.analyze", "narrate", "understand",
                 "recursive_decoder", "llm_", "openai", "anthropic",
                 "gemini", "troubleshoot"]
    for name in imported:
        for f in forbidden:
            assert f not in name, (
                f"projector imports forbidden business-logic module "
                f"{name!r} (matches {f!r}) — R28 breach"
            )
