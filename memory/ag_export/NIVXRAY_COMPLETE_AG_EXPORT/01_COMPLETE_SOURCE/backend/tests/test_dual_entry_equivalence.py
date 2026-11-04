"""Dual-Entry Architectural Equivalence Test — Phase 4 · P2.2.

Master architecture reference: `/app/memory/ARCHITECTURE.md` §1, §3, §5.

Owner directive (2026-02-15):
    Verify that both supported entry paths (File Upload / Workspace
    Input) converge into the SAME deterministic pipeline. Divergence
    is a P0 architectural regression.

This suite validates the **contract properties** that make dual-entry
equivalence possible — it does NOT require a realistic exploit chain
(which will come with the P2.3 demonstration once we source a sample
from nivxmachines.com). The properties tested here are the *guardrails*:

    §1  Universal Deterministic Processing Law
        · The RTE is a pure function of its input — identical input
          MUST yield identical (canonical_output, terminal_state,
          chain, techniques). No hidden state.
    §3  Dual Entry Paths
        · Both paths eventually funnel through the SAME `dispatch()`
          (Artifact Router). Given identical bytes, `dispatch()` MUST
          yield identical routed_analysis.
    §5  Explicit CEM Emission Boundary
        · `emit_cem()` is a pure function. Same case doc → same CEM.
        · The CEM schema shape is stable across all input provenances.
    §6  Investigation Engine Consumption
        · `build_evidence_signature()` MUST be provenance-agnostic:
          two cases with the same recovered PE hash produce the same
          fingerprint whether they came from File Upload or Workspace
          Input.

If any of these contracts break, cross-artifact correlation silently
mis-clusters identical payloads that entered via different paths — the
worst kind of platform bug.
"""
from __future__ import annotations

import hashlib
import struct

import pytest

from services.recipe_planner import plan_and_execute
from services.artifact_intelligence import dispatch
from services.cem import emit_cem
from services.correlation_engine import (
    build_evidence_signature,
    compute_correlation,
    score_to_confidence,
)


# ---------------------------------------------------------------------
# Deterministic PE stub — the same bytes used across both scenarios.
# ---------------------------------------------------------------------
def _minimal_pe_bytes() -> bytes:
    dos = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x80)
    dos = dos.ljust(0x80, b"\x00")
    pe_header = b"PE\x00\x00"
    coff = struct.pack("<HHIIIHH",
                       0x014c, 1, 0, 0, 0, 0xe0, 0x0102)
    opt = b"\x0b\x01" + b"\x00" * (0xe0 - 2)
    section = b".text\x00\x00\x00" + struct.pack(
        "<IIIIIIHHI", 0x100, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
    return (dos + pe_header + coff + opt + section).ljust(0x400, b"\x90")


# =====================================================================
# §1 · Universal Deterministic Processing Law
# =====================================================================
def test_rte_is_deterministic_for_identical_input():
    """Same input → same (canonical_output, terminal_state, techniques).
    No hidden state, no wall-clock leakage, no randomness."""
    # Use a payload that the RTE actually decodes (a wrapper the recipe
    # planner can classify), so both runs execute the full pipeline.
    text = "powershell -EncodedCommand aGVsbG8="
    a = plan_and_execute(text)
    b = plan_and_execute(text)
    assert a.canonical_output == b.canonical_output
    assert a.terminal_state == b.terminal_state
    assert list(a.final_techniques or []) == list(b.final_techniques or [])
    # Second-order determinism guarantee — stop_reason and iterations
    # must match too.
    assert a.stop_reason == b.stop_reason
    assert a.iterations_executed == b.iterations_executed


# =====================================================================
# §3 · Artifact Router — provenance-agnostic dispatch
# =====================================================================
def test_dispatch_is_pure_function_of_bytes():
    """Given identical bytes, the Artifact Router MUST yield identical
    routed_analysis regardless of how those bytes were obtained."""
    pe = _minimal_pe_bytes()
    a = dispatch(pe).to_dict()
    b = dispatch(pe).to_dict()
    assert a["artifact_type"] == b["artifact_type"] == "pe"
    # Hashes match (deterministic hashing over identical bytes)
    assert a.get("hashes") == b.get("hashes")


def test_dispatch_pe_hash_matches_manual_hash():
    """The Artifact Router publishes hashes computed over the same
    canonical bytes an analyst would hash locally. This proves the
    §3 → §5 boundary preserves byte-identity."""
    pe = _minimal_pe_bytes()
    d = dispatch(pe).to_dict()
    expected = hashlib.sha256(pe).hexdigest()
    assert (d.get("hashes") or {}).get("sha256") == expected


# =====================================================================
# §5 · CEM Emission Boundary — deterministic, shape-stable
# =====================================================================
def test_cem_is_pure_function_of_case_doc():
    """emit_cem MUST be deterministic. Same case → same CEM. No LLM,
    no clock, no randomness."""
    case = {
        "id": "c-1", "user_email": "t@t",
        "input": "powershell -c echo hi",
        "output": "canonical",
        "iedde_terminal_state": "canonical",
        "canonical_confidence": 100,
        "iocs": {"urls": ["http://ex.com"], "sha256": ["a"*64]},
        "mitre": [{"id": "T1059", "technique": "PS"}],
        "verdict": {"verdict": "Suspicious"},
        "verdict_card": {"risk_score": 40},
        "chain": ["b64d", "utf8"],
    }
    a = emit_cem(case)
    b = emit_cem(case)
    assert a == b


def test_cem_shape_is_stable_across_input_provenances():
    """The CEM schema must have the same top-level keys for both
    file_upload and workspace_input provenances — downstream consumers
    depend on this stability."""
    workspace_case = {
        "id": "w-1", "input": "aGVsbG8=", "output": "hello",
        "iedde_terminal_state": "canonical", "canonical_confidence": 100,
        "iocs": {}, "mitre": [], "chain": [],
    }
    file_upload_case = {
        "id": "f-1", "input": "MZ\x00\x00...", "output": "",
        "iedde_terminal_state": "binary_artifact_recovered",
        "canonical_confidence": 100,
        "iocs": {}, "mitre": [], "chain": [],
        "iedde": {"binary_artifact": {"routed_analysis": {
            "artifact_type": "pe",
            "hashes": {"sha256": "a"*64},
        }}},
    }
    cem_w = emit_cem(workspace_case)
    cem_f = emit_cem(file_upload_case)
    assert cem_w["cem_version"] == cem_f["cem_version"]
    assert set(cem_w.keys()) == set(cem_f.keys())
    # Both converged
    assert cem_w["convergence"]["reached"] is True
    assert cem_f["convergence"]["reached"] is True
    # Provenance is correctly detected
    assert cem_w["input_provenance"] == "workspace_input"
    assert cem_f["input_provenance"] == "file_upload"


def test_cem_events_carry_provenance_from_source_layer():
    """Every event in the CEM MUST carry a `provenance` field back to
    the layer that produced it (§8 traceability). No orphaned events."""
    case = {
        "id": "c-1", "output": "x",
        "iedde_terminal_state": "canonical", "canonical_confidence": 100,
        "iedde": {"binary_artifact": {"routed_analysis": {
            "artifact_type": "pe",
            "analysis": {"findings": [
                {"severity": "high", "code": "packed", "title": "UPX",
                 "detail": ""},
            ]},
        }}},
    }
    cem = emit_cem(case)
    assert all("provenance" in ev for ev in cem["events"])
    assert any(ev["provenance"].startswith("analyzer:") for ev in cem["events"])
    assert any(ev["provenance"] == "rte" for ev in cem["events"])


# =====================================================================
# §6 · Investigation Engine — provenance-agnostic evidence signature
# =====================================================================
def test_signature_is_identical_across_entry_paths_for_same_pe():
    """Two case docs carrying the same recovered PE hash MUST produce
    identical evidence signatures regardless of entry path.

    This is the *core* dual-entry equivalence property — if it breaks,
    identical payloads that entered via File Upload vs Workspace Input
    will silently fail to correlate.
    """
    pe = _minimal_pe_bytes()
    sha256 = hashlib.sha256(pe).hexdigest()

    def _case(cid, entry_path_marker):
        return {
            "id": cid, "user_email": "t@t",
            "input": entry_path_marker,       # differs per path — must NOT
                                              # leak into the signature
            "iocs": {"sha256": [sha256]},
            "iedde": {"binary_artifact": {"routed_analysis": {
                "artifact_type": "pe",
                "hashes": {"sha256": sha256},
            }}},
            "verdict": {"verdict": "Suspicious"},
            "verdict_card": {"risk_score": 50},
            "chain": ["b64d", "gzip_decompress"],
            "mitre": [{"id": "T1059"}, {"id": "T1140"}, {"id": "T1027"}],
        }

    sig_a = build_evidence_signature(_case("A", "<uploaded docm>"))
    sig_b = build_evidence_signature(_case("B", "powershell -EncodedCommand..."))

    # The signature MUST NOT depend on input provenance.
    assert sig_a["sha256"] == sig_b["sha256"]
    assert sig_a["artifact_type"] == sig_b["artifact_type"] == "pe"
    assert sig_a["techniques"] == sig_b["techniques"]
    assert sig_a["chain"] == sig_b["chain"]


def test_correlation_score_reaches_high_for_dual_entry_same_payload():
    """Two cases from different entry paths carrying identical PE +
    MITRE overlap MUST correlate at HIGH confidence.

    Deterministic threshold: SHA-256 (60) + shared MITRE (18 for 3
    techniques) + artifact_type overlap (5) + shared recipe (8) = 91 →
    HIGH band (>= 80). Under this threshold means the auto-scan would
    silently miss the correlation → architectural regression.
    """
    pe = _minimal_pe_bytes()
    sha256 = hashlib.sha256(pe).hexdigest()

    def _case(cid):
        return {
            "id": cid, "user_email": "t@t",
            "iocs": {"sha256": [sha256]},
            "iedde": {"binary_artifact": {"routed_analysis":
                                          {"artifact_type": "pe"}}},
            "verdict": {"verdict": "Suspicious"},
            "chain": ["b64d", "gzip_decompress", "pe_recover"],
            "mitre": [{"id": "T1059"}, {"id": "T1140"}, {"id": "T1027"}],
        }

    score, shared = compute_correlation(
        build_evidence_signature(_case("A")),
        build_evidence_signature(_case("B")),
    )
    assert score >= 80, (
        f"dual-entry equivalence broken: identical PE via different paths "
        f"scored {score} (confidence={score_to_confidence(score)}); expected "
        f">= 80 (high)")
    assert score_to_confidence(score) == "high"
    assert sha256 in (shared.get("sha256") or [])


# =====================================================================
# Regression guard — the correlation signature MUST ignore input text
# =====================================================================
def test_signature_ignores_raw_input_text():
    """Two cases with wildly different raw input text but IDENTICAL
    recovered artifacts + IOCs + MITRE must still correlate.

    If the signature accidentally includes raw input text, two paths
    to the same PE would score 0 and never correlate.
    """
    pe = _minimal_pe_bytes()
    sha256 = hashlib.sha256(pe).hexdigest()
    base_iocs = {"sha256": [sha256], "urls": ["http://ex.com"]}
    base_mitre = [{"id": "T1059"}, {"id": "T1140"}]
    a = {
        "id": "A", "user_email": "t@t",
        "input": "A" * 1000,                            # long junk
        "iocs": base_iocs, "mitre": base_mitre,
        "iedde": {"binary_artifact": {"routed_analysis":
                                       {"artifact_type": "pe"}}},
        "verdict": {"verdict": "Suspicious"},
        "chain": ["b64d"],
    }
    b = {**a, "id": "B", "input": "B" * 50}             # short junk
    sig_a = build_evidence_signature(a)
    sig_b = build_evidence_signature(b)
    # Explicit: `input` isn't in the signature at all.
    assert "input" not in sig_a
    # And the correlation still works.
    score, _ = compute_correlation(sig_a, sig_b)
    assert score >= 60, "input text bleed detected in signature"
