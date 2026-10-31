"""Attack Fingerprint (Attack DNA) — unit tests.

Contract from owner (2026-02-16):
  1. Read-only — never modifies case, CEM, verdict, evidence.
  2. Deterministic — same input → same fingerprint hash.
  3. Convergence-gated — pre-convergence returns `hash=None`.
  4. Versioned schema — `fingerprint_version` field always present.
  5. Ignores volatile fields (timestamps, case_id, user_email, notes).
  6. Component digests exposed for Compare Cases consumption.
"""
from __future__ import annotations

import copy
import re
from pathlib import Path

import pytest

from services.artifact_intelligence import dispatch
from services.attack_fingerprint import (
    FINGERPRINT_VERSION,
    emit_fingerprint,
)
from services.cem import emit_cem
from services.recipe_planner import plan_and_execute
from services.recursive_child_pipeline import (
    process as rcp_process,
    flatten_for_correlation,
)

SAMPLES = Path(__file__).resolve().parent / "golden_corpus" / "samples"


def _workspace_case() -> dict:
    text = (SAMPLES / "workspace_ps_to_pe_chain.txt").read_text()
    plan = plan_and_execute(text)
    case = {
        "id": "ws-case",
        "input": text,
        "output": plan.canonical_output,
        "iedde": {"binary_artifact": {
            "routed_analysis": plan.binary_artifact.routed_analysis
        }},
        "iedde_terminal_state": plan.terminal_state,
        "canonical_confidence": 100,
        "iocs": {}, "mitre": [], "chain": list(plan.final_techniques or []),
    }
    case["cem"] = emit_cem(case)
    return case


def _docm_case() -> dict:
    data = (SAMPLES / "docm_ps_to_pe_chain.docm").read_bytes()
    routed = dispatch(data).to_dict()
    kids = rcp_process(routed)
    case = {
        "id": "docm-case",
        "input": data[:200].hex(),
        "output": "",
        "iedde": {
            "binary_artifact": {"routed_analysis": routed},
            "recursive_children": flatten_for_correlation(kids),
        },
        "iedde_terminal_state": "binary_artifact_recovered",
        "canonical_confidence": 100,
        "iocs": {}, "mitre": [], "chain": [],
    }
    case["cem"] = emit_cem(case)
    return case


# ────────────────────────────────────────────────────────────────────
# 1 · Read-only contract
# ────────────────────────────────────────────────────────────────────
class TestReadOnly:
    def test_fingerprint_does_not_mutate_case(self):
        case = _workspace_case()
        before = copy.deepcopy(case)
        emit_fingerprint(case)
        assert case == before, (
            "emit_fingerprint mutated the case dict — read-only contract broken")

    def test_fingerprint_does_not_mutate_cem(self):
        case = _workspace_case()
        cem_before = copy.deepcopy(case["cem"])
        emit_fingerprint(case)
        assert case["cem"] == cem_before, (
            "emit_fingerprint mutated the CEM — §5 boundary broken")


# ────────────────────────────────────────────────────────────────────
# 2 · Determinism
# ────────────────────────────────────────────────────────────────────
class TestDeterminism:
    def test_same_case_produces_same_hash(self):
        case = _workspace_case()
        fp1 = emit_fingerprint(case)
        fp2 = emit_fingerprint(case)
        assert fp1["hash"] == fp2["hash"]
        assert fp1 == fp2

    def test_component_digests_stable(self):
        case = _workspace_case()
        d1 = emit_fingerprint(case)["component_digests"]
        d2 = emit_fingerprint(case)["component_digests"]
        assert d1 == d2

    def test_fingerprint_stable_across_case_dict_ordering(self):
        """Reordering keys in the input case dict must not change the
        fingerprint — canonical serialization sorts keys."""
        case = _workspace_case()
        fp1 = emit_fingerprint(case)
        # Rebuild case with keys in reverse order.
        reordered = {k: case[k] for k in reversed(list(case.keys()))}
        fp2 = emit_fingerprint(reordered)
        assert fp1["hash"] == fp2["hash"]


# ────────────────────────────────────────────────────────────────────
# 3 · Convergence gating
# ────────────────────────────────────────────────────────────────────
class TestConvergenceGate:
    def test_no_hash_when_convergence_not_reached(self):
        case = {
            "id": "x",
            "iedde": {}, "iedde_terminal_state": "stability_gate",
            "canonical_confidence": 0, "iocs": {}, "mitre": [], "chain": [],
        }
        case["cem"] = emit_cem(case)
        fp = emit_fingerprint(case)
        assert fp["hash"] is None
        assert fp["reason"] == "convergence_not_reached"
        assert fp["fingerprint_version"] == FINGERPRINT_VERSION

    def test_stub_when_case_is_not_dict(self):
        assert emit_fingerprint(None)["hash"] is None
        assert emit_fingerprint("garbage")["hash"] is None


# ────────────────────────────────────────────────────────────────────
# 4 · Schema versioning
# ────────────────────────────────────────────────────────────────────
class TestSchemaVersion:
    def test_version_field_always_present(self):
        case = _workspace_case()
        assert emit_fingerprint(case)["fingerprint_version"] == FINGERPRINT_VERSION

    def test_version_present_even_on_stub(self):
        stub = emit_fingerprint({})
        assert stub["fingerprint_version"] == FINGERPRINT_VERSION


# ────────────────────────────────────────────────────────────────────
# 5 · Volatile-field isolation
# ────────────────────────────────────────────────────────────────────
class TestIgnoresVolatileFields:
    def test_case_id_change_does_not_change_hash(self):
        case = _workspace_case()
        h1 = emit_fingerprint(case)["hash"]
        case2 = {**case, "id": "different-case-id", "_id": "abc123"}
        h2 = emit_fingerprint(case2)["hash"]
        assert h1 == h2, "case_id / _id leaked into the fingerprint"

    def test_user_email_change_does_not_change_hash(self):
        case = _workspace_case()
        h1 = emit_fingerprint(case)["hash"]
        case2 = {**case, "user_email": "someone@else.com"}
        h2 = emit_fingerprint(case2)["hash"]
        assert h1 == h2, "user_email leaked into the fingerprint"

    def test_timestamp_change_does_not_change_hash(self):
        case = _workspace_case()
        h1 = emit_fingerprint(case)["hash"]
        case2 = {**case, "ts": "2099-01-01T00:00:00Z",
                 "created_at": "2000-01-01T00:00:00Z"}
        h2 = emit_fingerprint(case2)["hash"]
        assert h1 == h2, "timestamps leaked into the fingerprint"

    def test_analyst_note_change_does_not_change_hash(self):
        case = _workspace_case()
        h1 = emit_fingerprint(case)["hash"]
        case2 = {**case, "note": "analyst comment #42",
                 "analyst_note": "different"}
        h2 = emit_fingerprint(case2)["hash"]
        assert h1 == h2, "analyst notes leaked into the fingerprint"


# ────────────────────────────────────────────────────────────────────
# 6 · Component digests + similarity vector shape
# ────────────────────────────────────────────────────────────────────
class TestExposedContract:
    def test_output_shape(self):
        case = _workspace_case()
        fp = emit_fingerprint(case)
        for key in ("fingerprint_version", "hash", "components",
                    "component_digests", "similarity_vector",
                    "recipe", "interpreter_chain",
                    "artifact_graph_digest", "mitre_digest",
                    "behavior_digest"):
            assert key in fp, f"missing key {key!r} in fingerprint output"

    def test_component_digests_shape(self):
        case = _workspace_case()
        digests = emit_fingerprint(case)["component_digests"]
        for name in ("recipe", "interpreter_chain", "transformation_trace",
                     "artifact_graph", "mitre", "iocs", "behavior",
                     "parent_child_edges"):
            key = f"{name}_digest"
            assert key in digests, f"missing digest {key!r}"
            assert re.fullmatch(r"[0-9a-f]{64}", digests[key]), (
                f"digest {key} is not a sha256 hex: {digests[key]!r}")


# ────────────────────────────────────────────────────────────────────
# 7 · Multi-origin fingerprint equivalence for identical investigations
# ────────────────────────────────────────────────────────────────────
class TestMultiOriginFingerprint:
    """Semantic contract: fingerprints identify *investigations*, not
    just payloads. Same-payload / different-origin fingerprints differ
    (as they should — the .docm investigation has additional artifacts
    that the workspace investigation doesn't), but similarity_vectors
    overlap heavily.

    Running the same case twice must yield identical fingerprints;
    that is what the Golden Corpus guard actually needs to enforce.
    """

    def test_same_case_run_twice_identical_fingerprint(self):
        case = _workspace_case()
        fp1 = emit_fingerprint(case)
        fp2 = emit_fingerprint(case)
        assert fp1["hash"] == fp2["hash"]

    def test_workspace_and_docm_share_pe_via_similarity_vector(self):
        """The .docm and workspace flagship investigations share the
        recovered PE sha256. The similarity_vector.canonical_hashes
        overlap must contain that PE sha256, enabling Compare Cases
        to identify them as related campaigns even though their
        full fingerprints differ."""
        ws = emit_fingerprint(_workspace_case())
        docm = emit_fingerprint(_docm_case())
        pe_sha256 = "aa5cca50fb3b54634533ed4c306f3b77343c4f9bd09d1b81ed2aa15d428ebb18"
        assert pe_sha256 in ws["similarity_vector"]["canonical_hashes"], (
            f"workspace fingerprint missing shared PE sha256\n"
            f"canonical_hashes={ws['similarity_vector']['canonical_hashes']}")
        assert pe_sha256 in docm["similarity_vector"]["canonical_hashes"], (
            f".docm fingerprint missing shared PE sha256\n"
            f"canonical_hashes={docm['similarity_vector']['canonical_hashes']}")
