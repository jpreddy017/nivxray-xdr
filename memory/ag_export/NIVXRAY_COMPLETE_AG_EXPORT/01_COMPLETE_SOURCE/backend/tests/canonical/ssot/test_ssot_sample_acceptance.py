"""A2.1 + A2.2 + A2.3 · Sample.docx acceptance + store roundtrip
+ Sample1 fingerprint unchanged."""
import hashlib
import json
import os

import pytest

from canonical.iue import classify, RawInput
from canonical.ssot import (
    AuthoritativeSSOT, InMemorySSOTStore, Provenance, Source,
    GraphNode,
)


SAMPLE1_FINGERPRINT = "5b4337d5a9fc05923bd3090f1270268ae8eef7af2ccf06f4e8d8492bf908261d"


PROV_INGRESS = Provenance(engine="canonical.entry_adapter", version="phase2",
                          at="phase2")


def _load_sample_docx() -> bytes:
    for path in ("/app/backend/tests/live/ideas_updated.docx",
                 "/app/backend/docs/exports/nivxray-user-guide.docx"):
        if os.path.exists(path):
            with open(path, "rb") as f:
                return f.read()
    return b"PK\x03\x04" + b"\x14\x00\x06\x00" + b"\x00" * 4000


# ─────────────────────────────────────────────────────────────────────────
#   A2.1 · Sample.docx canonical SSOT construction
# ─────────────────────────────────────────────────────────────────────────
def _build_sample_docx_ssot() -> AuthoritativeSSOT:
    """Minimal but complete canonical SSOT for a NEW Sample.docx ingestion.

    Reuses Phase 1's canonical IUE to produce iue_decision. This is
    exactly the shape the Phase 3 Executor will emit — but Phase 2 does
    not require the Executor. This test just proves the authoritative
    tier CAN represent Sample.docx.
    """
    docx_bytes = _load_sample_docx()
    iue = classify(RawInput(payload=docx_bytes, filename="Sample.docx"))

    ssot = AuthoritativeSSOT(
        id="new-sample-docx-case",
        created_at="2026-08-10T00:00:00+00:00",
        updated_at="2026-08-10T00:00:00+00:00",
        source=Source(
            surface="workspace",
            endpoint="/api/documents/{id}/re-investigate",
            correlation_id="phase2-a21",
            channel="document_reinvestigate",
        ),
        input_raw=docx_bytes,
        input_profile=iue.to_dict()["input_profile"],
        input_health=iue.to_dict()["input_health"],
        iue_decision=iue.to_dict(),
        plan=iue.to_dict()["plan"],
        provenance=Provenance(
            engine="canonical.ssot.builder", version="phase2", at="phase2"
        ),
    )
    # Minimal graph node for the input itself — represents "raw input".
    ssot.append("evidence_graph.nodes",
                GraphNode(id="input.root", kind="input",
                          label="Sample.docx",
                          attrs={"size_bytes": len(docx_bytes),
                                 "filename": "Sample.docx"}),
                PROV_INGRESS)
    return ssot


def test_a2_1_sample_docx_ssot_constructs_and_fingerprints():
    ssot = _build_sample_docx_ssot()
    assert ssot.schema_version.startswith("2.")
    fp = ssot.fingerprint()
    assert len(fp) == 64
    # iue_decision populated (proves cross-Phase-1 integration)
    assert ssot.iue_decision.get("input_profile", {}).get("primary_type")
    assert ssot.plan and len(ssot.plan) > 0
    # Projections must remain EMPTY per Phase 2 §5.
    ssot.assert_projections_empty()


def test_a2_1_sample_docx_ssot_carries_provenance():
    ssot = _build_sample_docx_ssot()
    assert ssot.provenance is not None
    assert ssot.provenance.engine
    # Every appended graph node carries provenance too
    assert all(n.provenance is not None for n in ssot.evidence_graph.nodes)


def test_a2_1_sample_docx_ssot_is_deterministic():
    """Same input + same builder ⇒ identical fingerprint."""
    fp0 = _build_sample_docx_ssot().fingerprint()
    for _ in range(20):
        assert _build_sample_docx_ssot().fingerprint() == fp0


# ─────────────────────────────────────────────────────────────────────────
#   A2.2 · Store roundtrip
# ─────────────────────────────────────────────────────────────────────────
def test_a2_2_store_roundtrip_byte_identical():
    ssot = _build_sample_docx_ssot()
    ssot.freeze()

    store = InMemorySSOTStore()
    ref = store.put(ssot)
    reloaded = store.get(ref)

    assert reloaded is not None
    assert reloaded.fingerprint() == ssot.fingerprint()
    assert reloaded.to_canonical_json() == ssot.to_canonical_json()


def test_a2_2_recursive_child_artefact_roundtrip():
    """Prove the FULL D6-r contract on a Sample.docx-like case: parent
    SSOT plus a child SSOT for an extracted artefact."""
    from canonical.ssot import Artifact
    store = InMemorySSOTStore()

    child = AuthoritativeSSOT(id="child-artifact",
                              created_at="2026-08-10T00:00:00Z",
                              updated_at="2026-08-10T00:00:00Z")
    child.append("evidence_graph.nodes",
                 GraphNode(id="cn.decoded",
                           kind="decoded",
                           label="decoded fragment"),
                 PROV_INGRESS)
    child_ref = store.put(child)

    parent = _build_sample_docx_ssot()
    parent.append("artifacts",
                  Artifact(id="art.001",
                           kind="docx.embedded_command_chain",
                           label="embedded command_chain from Sample.docx",
                           investigation_ref=child_ref),
                  PROV_INGRESS)
    parent_ref = store.put(parent)

    reloaded_parent = store.get(parent_ref)
    assert reloaded_parent.artifacts[0].investigation_ref == child_ref
    reloaded_child = store.get(reloaded_parent.artifacts[0].investigation_ref)
    assert reloaded_child.fingerprint() == child.fingerprint()


# ─────────────────────────────────────────────────────────────────────────
#   A2.3 · Sample1 fingerprint UNCHANGED
# ─────────────────────────────────────────────────────────────────────────
@pytest.mark.skipif(not os.environ.get("MONGO_URL"),
                    reason="MONGO_URL not set")
def test_a2_3_sample1_fingerprint_unchanged():
    """R-G1..R-G6, IX-1. Sample1 golden case must remain byte-identical."""
    from pymongo import MongoClient
    client = MongoClient(os.environ["MONGO_URL"])
    db = client[os.environ["DB_NAME"]]
    case = db.workspace_cases.find_one(
        {"id": "3db79c4a-088b-4df7-b65a-f68b367b7677"}
    )
    assert case is not None, \
        "Sample1 case not found in workspace_cases — R-G1 VIOLATION"
    snap = {k: v for k, v in case.items() if k != "_id"}
    blob = json.dumps(snap, default=str, sort_keys=True,
                      ensure_ascii=False).encode()
    fp = hashlib.sha256(blob).hexdigest()
    assert fp == SAMPLE1_FINGERPRINT, \
        f"Sample1 DRIFTED: {fp} != {SAMPLE1_FINGERPRINT} — HALT"


@pytest.mark.skipif(not os.environ.get("MONGO_URL"),
                    reason="MONGO_URL not set")
def test_a2_3_new_docx_case_does_not_touch_workspace_cases():
    """Phase 2 store writes to canonical_ssot_store, never to
    workspace_cases."""
    from pymongo import MongoClient
    from canonical.ssot import SSOTStore
    client = MongoClient(os.environ["MONGO_URL"])
    db = client[os.environ["DB_NAME"]]

    before_wc = db.workspace_cases.count_documents({})
    before_legacy_ssot = db.investigation_ssot.count_documents({})

    ssot = _build_sample_docx_ssot()
    store = SSOTStore()
    ref = store.put(ssot)
    assert ref.startswith("cssot:sha256:")

    after_wc = db.workspace_cases.count_documents({})
    after_legacy_ssot = db.investigation_ssot.count_documents({})

    # Phase 2 store must NOT touch workspace_cases or investigation_ssot.
    assert after_wc == before_wc, \
        f"workspace_cases changed: {before_wc} -> {after_wc}"
    assert after_legacy_ssot == before_legacy_ssot, \
        f"investigation_ssot changed: {before_legacy_ssot} -> {after_legacy_ssot}"

    # Prove the write landed in the new collection.
    assert db["canonical_ssot_store"].count_documents({}) >= 1
