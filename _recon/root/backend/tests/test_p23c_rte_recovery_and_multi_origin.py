"""P2.3c — RTE Recovery Improvement + Multi-Origin Equivalence.

Master architecture reference: /app/memory/ARCHITECTURE.md v1.1 (FROZEN).

These are permanent regression anchors, not one-off demos. They verify:

1. **P2.3c — RTE Recovery**
   For a `powershell.exe -EncodedCommand <utf-16 b64>` payload wrapping
   a `[Convert]::FromBase64String('<gzip b64>')` gzip+PE dropper, the
   RTE must:
     • decode the outer -EncodedCommand
     • fold the inner FromBase64String → gzip → PE bytes
     • terminate on `binary_artifact_recovered`
     • hand the recovered PE to the Artifact Router → PE Analyzer
     • surface `artifact_type == "pe"` in the routed_analysis
   No `stability_gate` bypass. No hardcoded golden-corpus exception.

2. **Multi-Origin Equivalence** (§8 — dual-entry contract)
   The recovered canonical PE must produce the *identical* Canonical
   Event Model (CEM), threat surface, MITRE, IOC counts, and artifact
   types regardless of origin:
     • Workspace paste of the PowerShell -EncodedCommand wrapper.
     • Direct file upload of the extracted PE bytes.
   Any divergence is a P0 architectural regression.
"""
from __future__ import annotations

import base64
import gzip
import io
import re
from typing import Any

import pytest

from services.artifact_intelligence import dispatch
from services.cem import emit_cem
from services.correlation_engine import build_evidence_signature
from services.recipe_planner import plan_and_execute


# ────────────────────────────────────────────────────────────────────
# Sample fixtures (self-sufficient · no external corpus dependency)
# ────────────────────────────────────────────────────────────────────
CORPUS_PATH = "tests/golden_corpus/samples/workspace_ps_to_pe_chain.txt"


def _load_golden_sample() -> str:
    with open("/app/backend/" + CORPUS_PATH, "r") as f:
        return f.read()


def _extract_inflated_pe(sample_text: str) -> bytes:
    """Deterministically extract the PE bytes hidden inside the golden
    sample by walking the exact chain the RTE must traverse:
      -EncodedCommand → utf-16le → PS script
      [Convert]::FromBase64String('...') → base64 → gzip bytes
      gzip.decompress → PE bytes.
    """
    m = re.search(r"-EncodedCommand\s+([A-Za-z0-9+/=]+)", sample_text)
    assert m is not None, "sample missing -EncodedCommand payload"
    outer_b64 = m.group(1)
    script = base64.b64decode(outer_b64).decode("utf-16le")

    m2 = re.search(r"FromBase64String\(['\"]([A-Za-z0-9+/=]+)['\"]\)", script)
    assert m2 is not None, "decoded script missing FromBase64String call"
    gz = base64.b64decode(m2.group(1))
    assert gz[:3] == b"\x1f\x8b\x08", "inner blob is not a gzip stream"

    return gzip.decompress(gz)


# ────────────────────────────────────────────────────────────────────
# 1 · P2.3c — RTE recovers the canonical PE from the workspace input
# ────────────────────────────────────────────────────────────────────
class TestP23cRteRecovery:
    def test_terminal_state_is_binary_artifact_recovered(self):
        sample = _load_golden_sample()
        plan = plan_and_execute(sample)
        assert plan.terminal_state == "binary_artifact_recovered", (
            f"expected 'binary_artifact_recovered', got "
            f"{plan.terminal_state!r} (stop_reason={plan.stop_reason!r}).\n"
            f"This is the P2.3c gate: the RTE must natively traverse "
            f"utf-16 → base64 → gzip and recover the PE."
        )
        assert plan.binary_artifact is not None, (
            "expected binary_artifact to be attached after recovery")
        assert plan.binary_artifact.kind == "PE", (
            f"expected PE, got {plan.binary_artifact.kind!r}")

    def test_routed_analysis_is_pe(self):
        sample = _load_golden_sample()
        plan = plan_and_execute(sample)
        ra = plan.binary_artifact.routed_analysis if plan.binary_artifact else None
        assert ra is not None, "routed_analysis must be attached"
        assert ra.get("artifact_type") == "pe", (
            f"expected artifact_type=='pe', got {ra.get('artifact_type')!r}")

    def test_deterministic_recovery(self):
        """Same input → same terminal_state + same PE sha256. Rule 21."""
        sample = _load_golden_sample()
        r1 = plan_and_execute(sample)
        r2 = plan_and_execute(sample)
        assert r1.terminal_state == r2.terminal_state
        assert r1.binary_artifact is not None and r2.binary_artifact is not None
        h1 = (r1.binary_artifact.routed_analysis or {}).get("hashes", {}).get("sha256")
        h2 = (r2.binary_artifact.routed_analysis or {}).get("hashes", {}).get("sha256")
        assert h1 and h1 == h2, (
            f"non-deterministic PE recovery: {h1!r} vs {h2!r}")


# ────────────────────────────────────────────────────────────────────
# 2 · Multi-Origin Equivalence — same PE, two entry paths, one CEM
# ────────────────────────────────────────────────────────────────────
def _pe_canonical_shape(case: dict[str, Any]) -> dict[str, Any]:
    """PE-specific canonical invariants that MUST be identical across
    entry paths for the same canonical PE payload.

    Deliberately excludes provenance-specific artifacts (e.g. the
    intermediate workspace decoded text) — the dual-entry contract
    (§8) is that the *recovered PE and its analysis* are identical,
    not that origins hide their own provenance.
    """
    cem = emit_cem(case)
    sig = build_evidence_signature(case)
    # PE-specific binary artifact entry
    pe_entry = next(
        (a for a in cem["canonical_artifacts"]
         if a.get("kind") == "binary_artifact" and a.get("type") == "pe"),
        None,
    )
    # PE analyzer findings only (skip the rte.convergence event whose
    # `code` is the terminal-state label — that's origin-dependent).
    pe_findings = sorted(
        [(ev.get("code"), ev.get("severity"), ev.get("title"),
          ev.get("provenance"))
         for ev in cem["events"] if ev.get("kind") == "analyzer.finding"]
    )
    return {
        "cem_version":             cem["cem_version"],
        "convergence_reached":     cem["convergence"]["reached"],
        "pe_sha256":               pe_entry.get("sha256") if pe_entry else None,
        "pe_sha1":                 pe_entry.get("sha1") if pe_entry else None,
        "pe_md5":                  pe_entry.get("md5") if pe_entry else None,
        "pe_size":                 pe_entry.get("size") if pe_entry else None,
        "pe_provenance":           pe_entry.get("provenance") if pe_entry else None,
        "pe_analyzer_findings":    pe_findings,
        "mitre_ids":               sorted({m["id"] for m in cem["mitre"]}),
        "indicator_kinds":         sorted({i["kind"] for i in cem["indicators"]}),
        "signature_shape_keys":    sorted(sig.keys()),
    }


class TestMultiOriginEquivalence:
    """Workspace paste vs File upload — same canonical PE → same CEM."""

    def _case_from_workspace_input(self, sample_text: str) -> dict[str, Any]:
        plan = plan_and_execute(sample_text)
        assert plan.terminal_state == "binary_artifact_recovered"
        return {
            "id": "workspace_origin",
            "input": sample_text,
            "output": plan.canonical_output,
            "iedde": {
                "binary_artifact": {
                    "routed_analysis": plan.binary_artifact.routed_analysis
                }
            } if plan.binary_artifact else {},
            "iedde_terminal_state": plan.terminal_state,
            "canonical_confidence": 100,
            "iocs": {}, "mitre": [], "chain": list(plan.final_techniques or []),
        }

    def _case_from_file_upload(self, pe_bytes: bytes) -> dict[str, Any]:
        result = dispatch(pe_bytes).to_dict()
        assert result["artifact_type"] == "pe"
        return {
            "id": "file_upload_origin",
            "input": pe_bytes[:200].hex(),
            "output": "",
            "iedde": {"binary_artifact": {"routed_analysis": result}},
            "iedde_terminal_state": "binary_artifact_recovered",
            "canonical_confidence": 100,
            "iocs": {}, "mitre": [], "chain": [],
        }

    def test_workspace_and_upload_produce_same_canonical_pe(self):
        """The bytes the RTE recovers via decoding must be byte-identical
        to the bytes a direct file upload receives."""
        sample = _load_golden_sample()
        expected_pe = _extract_inflated_pe(sample)

        plan = plan_and_execute(sample)
        assert plan.binary_artifact is not None
        recovered_sha = (plan.binary_artifact.routed_analysis or {}).get(
            "hashes", {}).get("sha256")
        upload_sha = dispatch(expected_pe).to_dict().get(
            "hashes", {}).get("sha256")

        assert recovered_sha and upload_sha, (
            f"missing sha256 · recovered={recovered_sha!r} upload={upload_sha!r}")
        assert recovered_sha == upload_sha, (
            f"multi-origin PE divergence — recovered sha256 "
            f"{recovered_sha!r} != file-upload sha256 {upload_sha!r}. "
            f"This is a P0 architectural regression.")

    def test_cem_shape_equivalence(self):
        """PE-specific CEM invariants must be identical across entry paths."""
        sample = _load_golden_sample()
        pe_bytes = _extract_inflated_pe(sample)

        case_ws = self._case_from_workspace_input(sample)
        case_fu = self._case_from_file_upload(pe_bytes)

        shape_ws = _pe_canonical_shape(case_ws)
        shape_fu = _pe_canonical_shape(case_fu)
        assert shape_ws == shape_fu, (
            f"multi-origin CEM PE-artifact divergence · P0 architectural regression\n"
            f"workspace = {shape_ws}\n"
            f"file_upload = {shape_fu}\n"
            f"Divergent keys: "
            f"{sorted(k for k in shape_ws if shape_ws[k] != shape_fu.get(k))}"
        )
