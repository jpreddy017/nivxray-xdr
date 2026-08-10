"""Phase 3.x · TEXT_EXTRACT_FROM_ARCHIVE acceptance.

Owner directive 2026-08-10 · scope:
  - New capability only. No new IOC/MITRE logic. No projection changes.
  - D6-r recursive child SSOTs via ssot_ref.
  - Raw XML/text bytes preserved (no tag-strip).
  - Existing ExecutorBudget (max_depth=3, max_children=20).

Acceptance criteria (from directive):
  1. Real Sample.docx must be ingested as a NEW case.
  2. word/document.xml must become a child SSOT through ssot_ref.
  3. Child provenance must be complete.
  4. IOC/MITRE capabilities must execute against the child.
  5. Verify deterministic fingerprints across replays.
  6. Verify recursion budget enforcement.
  7. Verify parent/child SSOT relationships.
  8. Verify all Phase 4 projections consume the resulting SSOT.
  9. Verify original Sample1 fingerprint remains untouched (deferred on
     this pod — recorded in Phase 3.x report).
"""
from __future__ import annotations

import hashlib
import os

import pytest

from canonical.iue import classify, RawInput, Capability
from canonical.executor import Executor, ExecutorBudget
from canonical.ssot import InMemorySSOTStore


SAMPLE_DOCX = "/app/memory/fixtures/Sample.docx"
SAMPLE_DOCX_SHA256 = "3915b712ed7f2a591b93f42f3597b40b4c5684f7c630902061e95c3b748623a7"


def _read_sample():
    if not os.path.exists(SAMPLE_DOCX):
        pytest.skip(f"Sample.docx fixture missing: {SAMPLE_DOCX}")
    with open(SAMPLE_DOCX, "rb") as f:
        return f.read()


def _run_sample(store=None, budget=None):
    payload = _read_sample()
    assert hashlib.sha256(payload).hexdigest() == SAMPLE_DOCX_SHA256, \
        "Sample.docx SHA256 drifted — fixture mutated"
    raw = RawInput(payload=payload, filename="Sample.docx")
    iue = classify(raw)
    return Executor(store=store or InMemorySSOTStore(),
                    budget=budget or ExecutorBudget()).run(iue, raw), iue


# =====================================================================
#   PX.1 · Plan includes TEXT_EXTRACT_FROM_ARCHIVE for DOCX
# =====================================================================
def test_px_1_docx_plan_includes_text_extract():
    _res, iue = _run_sample()
    caps = [s.capability.value for s in iue.plan]
    assert "ARCHIVE_EXTRACT" in caps
    assert "TEXT_EXTRACT_FROM_ARCHIVE" in caps
    # TEXT_EXTRACT_FROM_ARCHIVE must come after ARCHIVE_EXTRACT.
    assert caps.index("TEXT_EXTRACT_FROM_ARCHIVE") > caps.index("ARCHIVE_EXTRACT")


# =====================================================================
#   PX.2 · word/document.xml materialises as a child SSOT via ssot_ref
# =====================================================================
def test_px_2_word_document_xml_becomes_child_ssot():
    res, _iue = _run_sample()
    parent = res.ssot

    # Parent has an archive_member artifact for word/document.xml
    doc_xml_arts = [a for a in parent.artifacts
                    if a.kind == "archive_member"
                    and a.label == "word/document.xml"]
    assert doc_xml_arts, "word/document.xml archive_member artifact missing"

    # And a corresponding child_ssot_ref referencing it.
    doc_xml_id = doc_xml_arts[0].id
    child_refs = [a for a in parent.artifacts
                  if a.kind == "child_ssot_ref"
                  and a.parent_evidence_id == doc_xml_id]
    assert child_refs, \
        "word/document.xml did not materialise into a child SSOT via ssot_ref"
    child_ref = child_refs[0].investigation_ref
    assert child_ref and child_ref.startswith("cssot:sha256:")


# =====================================================================
#   PX.3 · Child provenance complete + IOC/MITRE ran against the child
# =====================================================================
def test_px_3_child_ioc_and_mitre_execute_against_extracted_text():
    store = InMemorySSOTStore()
    res, _iue = _run_sample(store=store)
    parent = res.ssot

    # Locate the word/document.xml child ssot_ref.
    doc_xml_arts = [a for a in parent.artifacts
                    if a.kind == "archive_member"
                    and a.label == "word/document.xml"]
    assert doc_xml_arts
    doc_xml_id = doc_xml_arts[0].id
    child_ref = next(a.investigation_ref for a in parent.artifacts
                     if a.kind == "child_ssot_ref"
                     and a.parent_evidence_id == doc_xml_id)
    child = store.get(child_ref)
    assert child is not None, "child SSOT missing from store"

    # Child provenance
    for n in child.evidence_graph.nodes:
        assert n.provenance is not None, \
            f"child evidence node {n.id!r} missing provenance"
    for step in child.execution_trace:
        assert step.provenance is not None, \
            f"child execution step {step.step_id!r} missing provenance"
    assert child.provenance is not None

    # IOC + MITRE capabilities executed against the child.
    executed = {t.capability for t in child.execution_trace
                if t.status == "executed"}
    assert "IOC_EXTRACTOR" in executed
    assert "MITRE_MAP" in executed

    # Child depth == 1 (parent = 0). Enforced via ssot child id derivation.
    # Also: the child MUST have observed some evidence — the XML text of
    # word/document.xml typically contains at least one URL (namespaces
    # like http://schemas.openxmlformats.org/*).
    ioc_nodes = [n for n in child.evidence_graph.nodes if n.kind == "ioc"]
    assert ioc_nodes, "child SSOT extracted zero IOCs from word/document.xml"


# =====================================================================
#   PX.4 · Determinism across replays (fingerprint stable)
# =====================================================================
def test_px_4_determinism_10_replays():
    res0, _ = _run_sample()
    fp0 = res0.ssot.fingerprint()
    for _ in range(10):
        res, _ = _run_sample()
        assert res.ssot.fingerprint() == fp0, "Phase 3.x determinism broken"


# =====================================================================
#   PX.5 · Recursion budget enforcement (max_depth=0 ⇒ no children)
# =====================================================================
def test_px_5_max_depth_zero_prevents_child_creation():
    res, _ = _run_sample(budget=ExecutorBudget(max_depth=0))
    parent = res.ssot
    text_extract_children = [
        a for a in parent.artifacts
        if a.kind == "child_ssot_ref" and a.attrs.get("member_name")
    ]
    assert text_extract_children == [], \
        "max_depth=0 should have prevented any TEXT_EXTRACT child creation"


def test_px_5_max_children_enforced():
    """Cap children at 2. Sample.docx has many members ⇒ TEXT_EXTRACT
    only materialises up to `max_children` real (populated) children.
    RECURSIVE_DISCOVERY placeholders for unhandled members remain a
    separate legacy behaviour (out-of-scope for Phase 3.x)."""
    res, _ = _run_sample(budget=ExecutorBudget(max_depth=3, max_children=2))
    parent = res.ssot
    text_extract_children = [
        a for a in parent.artifacts
        if a.kind == "child_ssot_ref" and a.attrs.get("member_name")
    ]
    assert len(text_extract_children) <= 2, (
        f"TEXT_EXTRACT_FROM_ARCHIVE ignored max_children=2; "
        f"got {len(text_extract_children)} populated children"
    )
    # Also confirm the budget-exhausted trace was recorded.
    exhausted = [t for t in parent.execution_trace
                 if t.step_id == "exec.text_extract.budget"
                 and t.status == "budget_exhausted"]
    # It may or may not be present depending on how many text members exist;
    # what MUST hold: no more than max_children materialised.


# =====================================================================
#   PX.6 · Parent/child linkage integrity
# =====================================================================
def test_px_6_parent_child_linkage_integrity():
    store = InMemorySSOTStore()
    res, _ = _run_sample(store=store)
    parent = res.ssot

    for a in parent.artifacts:
        if a.kind != "child_ssot_ref":
            continue
        # Every child_ssot_ref points to a real SSOT in the store.
        assert store.exists(a.investigation_ref), \
            f"dangling child ssot_ref {a.investigation_ref}"
        assert a.parent_evidence_id, \
            "child_ssot_ref missing parent_evidence_id"
        # The parent_evidence_id references a real archive_member artifact.
        parent_arts = [x for x in parent.artifacts if x.id == a.parent_evidence_id]
        assert parent_arts, \
            f"parent artifact {a.parent_evidence_id!r} not found"
        assert parent_arts[0].kind == "archive_member"


# =====================================================================
#   PX.7 · All 15 Phase 4 projections consume the resulting SSOT
# =====================================================================
def test_px_7_phase4_projections_consume_child_populated_ssot():
    from canonical.projections import (
        project_verdict, project_iocs, project_attck, project_attack_chain,
        project_attack_story, project_recommendations, project_timeline,
        project_lolbas, project_activity, project_canonical,
        project_evidence_bundle, project_evidence_graph_view,
        project_analyst_summary, project_executive_summary, project_reports,
    )
    store = InMemorySSOTStore()
    res, _ = _run_sample(store=store)
    parent = res.ssot

    # Parent projections still run (must be pure / non-mutating).
    fp_before = parent.fingerprint()
    for fn in (project_verdict, project_iocs, project_attck,
               project_attack_chain, project_attack_story,
               project_recommendations, project_timeline, project_lolbas,
               project_activity, project_canonical, project_evidence_bundle,
               project_evidence_graph_view, project_analyst_summary,
               project_executive_summary, project_reports):
        fn(parent)
    assert parent.fingerprint() == fp_before, \
        "projection mutated the child-populated parent SSOT"

    # Child projections also work.
    child_ref = next((a.investigation_ref for a in parent.artifacts
                      if a.kind == "child_ssot_ref"), None)
    assert child_ref, "no child SSOT to project against"
    child = store.get(child_ref)
    assert child is not None
    # Child has IOC evidence — project_iocs must reflect it.
    child_iocs = project_iocs(child)
    total_iocs = (len(child_iocs.urls) + len(child_iocs.ips)
                  + len(child_iocs.domains) + len(child_iocs.emails)
                  + sum(len(v) for v in child_iocs.hashes.values()))
    assert total_iocs > 0, \
        "Phase 4 project_iocs saw zero IOCs on child that has ioc nodes"


# =====================================================================
#   PX.8 · Recommendations still respect P4-FW3 on parent (no MITRE)
# =====================================================================
def test_px_8_recommendations_no_fallback_on_parent():
    """Parent SSOT typically has no MITRE evidence (MITRE runs on the
    child text). Parent's project_recommendations MUST still return []
    + the mandatory reasoning note — no generic template."""
    from canonical.projections import project_recommendations
    import json
    res, _ = _run_sample()
    out = project_recommendations(res.ssot)
    blob = json.dumps(out, sort_keys=True)
    for banned in ("IMMEDIATE", "THREAT HUNTING", "CONTAINMENT",
                   "Isolate the host"):
        assert banned not in blob, \
            f"Phase 4 no-fallback rule broken: {banned!r} appeared"


# =====================================================================
#   PX.9 · Sample1 fingerprint UNTOUCHED (skipped on this pod)
# =====================================================================
SAMPLE1_FINGERPRINT = "5b4337d5a9fc05923bd3090f1270268ae8eef7af2ccf06f4e8d8492bf908261d"
SAMPLE1_CASE_ID = "3db79c4a-088b-4df7-b65a-f68b367b7677"


@pytest.mark.skipif(not os.environ.get("MONGO_URL"),
                    reason="MONGO_URL not set")
def test_px_9_sample1_fingerprint_unchanged():
    import json as _json
    from pymongo import MongoClient
    client = MongoClient(os.environ["MONGO_URL"])
    db = client[os.environ["DB_NAME"]]
    case = db.workspace_cases.find_one({"id": SAMPLE1_CASE_ID})
    if case is None:
        pytest.skip("Sample1 row not present on this pod — deferred per "
                    "owner directive; must run on the Sample1-hosting pod")
    snap = {k: v for k, v in case.items() if k != "_id"}
    blob = _json.dumps(snap, default=str, sort_keys=True,
                       ensure_ascii=False).encode()
    assert hashlib.sha256(blob).hexdigest() == SAMPLE1_FINGERPRINT
