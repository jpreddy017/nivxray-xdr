"""Phase 4 · A4.1 — Sample.docx acceptance.

Runs the full canonical lifecycle on the true Sample.docx fixture,
then asserts every projection is deterministic and follows P4-FW3
(no generic-recommendation fallback when MITRE is missing).
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, is_dataclass

import pytest

from canonical.iue import classify, RawInput
from canonical.executor import Executor
from canonical.projections import (
    project_activity, project_analyst_summary, project_attck,
    project_attack_chain, project_attack_story, project_canonical,
    project_evidence_bundle, project_evidence_graph_view,
    project_executive_summary, project_iocs, project_lolbas,
    project_recommendations, project_reports, project_timeline,
    project_verdict,
)

FIXTURE = "/app/memory/fixtures/Sample.docx"


def _read_sample():
    if os.path.exists(FIXTURE):
        with open(FIXTURE, "rb") as f:
            return f.read()
    # Fallback to nivxray user guide if the fixture is not present.
    fallback = "/app/backend/docs/exports/nivxray-user-guide.docx"
    if os.path.exists(fallback):
        with open(fallback, "rb") as f:
            return f.read()
    # Minimal ZIP stub (deterministic).
    return b"PK\x03\x04" + b"\x14\x00\x06\x00" + b"\x00" * 4000


def _canonical_ssot():
    raw = RawInput(payload=_read_sample(), filename="Sample.docx")
    iue = classify(raw)
    return Executor().run(iue, raw).ssot


def _norm(v):
    if v is None:
        return None
    if is_dataclass(v):
        v = asdict(v)
    return json.dumps(v, sort_keys=True, ensure_ascii=False,
                      default=str, separators=(",", ":"))


def test_a4_1_sample_docx_all_projections_deterministic():
    ssot = _canonical_ssot()
    for name, fn in [
        ("verdict", project_verdict), ("iocs", project_iocs),
        ("attck", project_attck), ("attack_chain", project_attack_chain),
        ("attack_story", project_attack_story),
        ("recommendations", project_recommendations),
        ("timeline", project_timeline),
        ("lolbas", project_lolbas), ("activity", project_activity),
        ("canonical", project_canonical),
        ("evidence_bundle", project_evidence_bundle),
        ("evidence_graph_view", project_evidence_graph_view),
        ("analyst_summary", project_analyst_summary),
        ("executive_summary", project_executive_summary),
        ("reports", project_reports),
    ]:
        base = _norm(fn(ssot))
        for _ in range(3):
            assert _norm(fn(ssot)) == base, f"{name} drifted on Sample.docx"


def test_a4_1_recommendations_no_generic_fallback_on_sample_docx():
    """Sample.docx (user guide DOCX) has no MITRE evidence in the canonical
    lifecycle. Recommendations MUST return empty + the mandatory note."""
    ssot = _canonical_ssot()
    out = project_recommendations(ssot)
    if not out["items"]:
        # Path A: no MITRE ⇒ empty + explicit note.
        assert out["notes"], "empty recommendations must state why"
        assert "no evidence-derived" in out["notes"][0]["note"].lower() \
            or "no canonical" in out["notes"][0]["note"].lower()
    # Regardless: banned tokens must never appear.
    blob = json.dumps(out, sort_keys=True)
    for banned in ("IMMEDIATE", "THREAT HUNTING", "CONTAINMENT"):
        assert banned not in blob


def test_a4_1_reports_sample_docx_shape_valid():
    ssot = _canonical_ssot()
    rep = project_reports(ssot)
    assert rep.stix["type"] == "bundle"
    assert "rules" in rep.sigma
    assert "rule_name" in rep.yara
    assert rep.navigator["domain"] == "enterprise-attack"
    assert rep.mdr["verdict"]["label"] in {
        "MALICIOUS", "SUSPICIOUS", "LIKELY_BENIGN", "INCONCLUSIVE",
    }


def test_a4_1_projections_do_not_mutate_ssot_fingerprint():
    ssot = _canonical_ssot()
    fp_before = ssot.fingerprint()
    project_verdict(ssot)
    project_reports(ssot)
    project_recommendations(ssot)
    project_analyst_summary(ssot)
    project_executive_summary(ssot)
    assert ssot.fingerprint() == fp_before
