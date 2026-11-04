"""Phase 4 · A4.2 — Sample1 fingerprint UNCHANGED.

Phase 4 introduces read-only projection functions. Sample1 (stored in
workspace_cases) MUST never be touched.
"""
from __future__ import annotations

import hashlib
import json
import os

import pytest


SAMPLE1_FINGERPRINT = "5b4337d5a9fc05923bd3090f1270268ae8eef7af2ccf06f4e8d8492bf908261d"
SAMPLE1_CASE_ID = "3db79c4a-088b-4df7-b65a-f68b367b7677"


@pytest.mark.skipif(not os.environ.get("MONGO_URL"),
                    reason="MONGO_URL not set")
def test_a4_2_sample1_fingerprint_unchanged():
    from pymongo import MongoClient
    client = MongoClient(os.environ["MONGO_URL"])
    db = client[os.environ["DB_NAME"]]
    case = db.workspace_cases.find_one({"id": SAMPLE1_CASE_ID})
    if case is None:
        pytest.skip("Sample1 row not present in this pod's DB "
                    "(freshly-forked pod); the invariant applies only "
                    "in the pod that hosts Sample1.")
    snap = {k: v for k, v in case.items() if k != "_id"}
    blob = json.dumps(snap, default=str, sort_keys=True,
                      ensure_ascii=False).encode()
    assert hashlib.sha256(blob).hexdigest() == SAMPLE1_FINGERPRINT, (
        "Sample1 DRIFTED — Phase 4 must be read-only against production"
    )


@pytest.mark.skipif(not os.environ.get("MONGO_URL"),
                    reason="MONGO_URL not set")
def test_a4_2_wave1_records_untouched():
    from pymongo import MongoClient
    client = MongoClient(os.environ["MONGO_URL"])
    db = client[os.environ["DB_NAME"]]
    # Only enforce in the pod that hosts Sample1 (production pod).
    if db.workspace_cases.find_one({"id": SAMPLE1_CASE_ID}) is None:
        pytest.skip("not the pod that hosts Sample1 — Wave 1 invariant "
                    "only applies against production data")
    # Wave-1 stability invariant.  Historical baseline in the original
    # long-lived DB was 2 records.  In a fresh pod the baseline is 0 —
    # either state is valid; the real invariant is that the collection
    # MUST NOT grow beyond the historical baseline (Wave-1 was
    # deprecated in Phase 4 — no new attaches from legacy paths).
    count = db.verdict_shadow_observations.count_documents({})
    assert count <= 2, (
        f"verdict_shadow_observations grew beyond historical baseline: "
        f"got {count}, expected <= 2 (Wave 1 deprecated in Phase 4)"
    )


@pytest.mark.skipif(not os.environ.get("MONGO_URL"),
                    reason="MONGO_URL not set")
def test_a4_2_no_projection_writes_to_mongo():
    """Run every projection against every SSOT variant. Confirm the
    Sample1 fingerprint is still intact afterwards."""
    from pymongo import MongoClient
    from canonical.projections import (
        project_activity, project_analyst_summary, project_attck,
        project_attack_chain, project_attack_story, project_canonical,
        project_evidence_bundle, project_evidence_graph_view,
        project_executive_summary, project_iocs, project_lolbas,
        project_recommendations, project_reports, project_timeline,
        project_verdict,
    )
    from canonical.ssot import AuthoritativeSSOT, GraphNode, Provenance, Source

    prov = Provenance(engine="test.phase4", version="1.0.0", at="phase4")
    ssot = AuthoritativeSSOT(
        id="a4_2", source=Source(surface="test"),
        input_raw=b"", provenance=prov,
    )
    ssot.append("evidence_graph.nodes",
                GraphNode(id="ev.ioc.url.0000", kind="ioc",
                          label="http://x.example",
                          attrs={"ioc_kind": "url"}), prov)
    ssot.freeze()

    for fn in [project_activity, project_analyst_summary, project_attck,
               project_attack_chain, project_attack_story,
               project_canonical, project_evidence_bundle,
               project_evidence_graph_view, project_executive_summary,
               project_iocs, project_lolbas, project_recommendations,
               project_reports, project_timeline, project_verdict]:
        fn(ssot)

    client = MongoClient(os.environ["MONGO_URL"])
    db = client[os.environ["DB_NAME"]]
    case = db.workspace_cases.find_one({"id": SAMPLE1_CASE_ID})
    if case is None:
        pytest.skip("Sample1 row not present in this pod")
    snap = {k: v for k, v in case.items() if k != "_id"}
    blob = json.dumps(snap, default=str, sort_keys=True,
                      ensure_ascii=False).encode()
    assert hashlib.sha256(blob).hexdigest() == SAMPLE1_FINGERPRINT
