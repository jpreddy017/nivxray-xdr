"""P0-B · EXCLUSION ENFORCEMENT SCOPE — deterministic proof.

The defect this closes: the only endpoint exclusion engine was
`endpoint.collection`, so an ordinary analyst tuning exclusion silently
destroyed the underlying telemetry. Tuning out a false positive and
deleting the evidence are two different decisions, and only one of them
was possible.

Proven here, separately:

  1. a DETECTION-scoped exclusion  → event occurs, telemetry retained,
     evidence retained, matching detection suppressed;
  2. an explicit COLLECTION-scoped exclusion → matching collection
     intentionally suppressed at the endpoint;
  3. a legacy (scope-less) exclusion keeps COLLECTION semantics, so no
     live exclusion changes behaviour without an explicit migration;
  4. a PREVENTION-scoped exclusion is REFUSED and reported as refused.
"""
from __future__ import annotations

import importlib.util
import json

import pytest

from edr_plane.exclusions.contracts import (DETECTION_SUPPRESSING_SCOPES,
                                            EnforcementScope,
                                            ExclusionDraft,
                                            enforcement_scope_of)
from edr_plane.exclusions import enforcement as enf

CANONICAL = "/app/agents/_shared/nivxforge_exclusions.py"


def _evaluator():
    spec = importlib.util.spec_from_file_location("nvx_excl_p0b", CANONICAL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


nvx = _evaluator()

PROCESS_EVENT = {"activity": "PROCESS", "operation": "PROCESS_OBSERVED",
                 "pid": 4242, "image": "agent", "image_path": "/opt/vendor/agent",
                 "command_line": "/opt/vendor/agent --run",
                 "sha256": "a" * 64, "user": "root"}
OTHER_EVENT = {"activity": "PROCESS", "operation": "PROCESS_OBSERVED",
               "pid": 4243, "image": "sshd", "image_path": "/usr/sbin/sshd"}
POLICY = {"policy_id": "pol_x", "version": 3, "config_digest": "cfg_x"}


def _exclusion(scope=None, engines=("endpoint.collection",)):
    e = {"exclusion_id": "exc_path", "type": "PATH", "match": "EXACT",
         "value": "/opt/vendor/agent", "affected_engines": list(engines),
         "reason": "vendor agent, tuned out by the SOC"}
    if scope is not None:
        e["enforcement_scope"] = scope
    return e


def _partition(exclusion, tmp_path):
    journal = nvx.Journal(str(tmp_path / "j.json"))
    keep, suppressed = nvx.partition(
        [dict(PROCESS_EVENT), dict(OTHER_EVENT)], [exclusion], journal, POLICY)
    return keep, suppressed, journal


# ── 1 · DETECTION scope: the evidence survives the exclusion ───────────

def test_detection_scope_retains_telemetry_and_evidence(tmp_path):
    keep, suppressed, journal = _partition(
        _exclusion(EnforcementScope.DETECTION.value), tmp_path)
    assert suppressed == 0, "a DETECTION exclusion must not drop telemetry"
    assert len(keep) == 2, "both events must still be delivered"
    delivered = [e for e in keep if e["pid"] == 4242][0]
    mark = delivered["endpoint_exclusion_matches"][0]
    assert mark["exclusion_id"] == "exc_path"
    assert mark["enforcement_scope"] == "DETECTION"
    assert mark["matched_attribute"] == "path"
    entry = journal.entries["exc_path"]
    assert entry["acceptance"] == "HONOURED"
    assert entry["enforcement_scope"] == "DETECTION"
    assert entry["detection_suppression_requested_count"] == 1
    assert entry.get("collection_suppressed_count", 0) == 0
    assert entry["evidence_retained"] is True
    # and the raw observed value is still never re-uploaded
    assert "/opt/vendor/agent" not in json.dumps(journal.report())


def test_detection_scope_suppresses_the_verdict_server_side():
    """The verdict is suppressed by the engine that OWNS verdicts."""
    decision = enf.decide(
        exclusions=[_exclusion(EnforcementScope.DETECTION.value,
                               engines=("server.deterministic.rule",))],
        engine="server.deterministic.rule",
        candidate={"path": "/opt/vendor/agent", "process": "agent",
                   "command_line": None, "file_hash": None,
                   "network_address": None})
    assert decision.excluded is True
    assert decision.enforcement_scope == "DETECTION"
    assert decision.evidence_retained is True
    assert decision.truth_state == "SERVER_EXCLUSION_APPLIED"
    assert "evidence is retained" in decision.basis


# ── 2 · COLLECTION scope: an explicit, disclosed visibility loss ───────

def test_explicit_collection_scope_suppresses_collection(tmp_path):
    keep, suppressed, journal = _partition(
        _exclusion(EnforcementScope.COLLECTION.value), tmp_path)
    assert suppressed == 1
    assert keep == [OTHER_EVENT], "the matching event must never be delivered"
    entry = journal.entries["exc_path"]
    assert entry["enforcement_scope"] == "COLLECTION"
    assert entry["collection_suppressed_count"] == 1
    assert entry.get("detection_suppression_requested_count", 0) == 0
    assert entry["evidence_retained"] is False


def test_collection_scope_also_suppresses_the_verdict():
    decision = enf.decide(
        exclusions=[_exclusion(EnforcementScope.COLLECTION.value,
                               engines=("server.deterministic.rule",))],
        engine="server.deterministic.rule",
        candidate={"path": "/opt/vendor/agent", "process": None,
                   "command_line": None, "file_hash": None,
                   "network_address": None})
    assert decision.excluded is True
    assert decision.evidence_retained is False


# ── 3 · migration: a live exclusion does not change behaviour ──────────

def test_a_legacy_scopeless_exclusion_keeps_collection_semantics(tmp_path):
    keep, suppressed, journal = _partition(_exclusion(None), tmp_path)
    assert suppressed == 1 and keep == [OTHER_EVENT]
    assert journal.entries["exc_path"]["enforcement_scope"] == "COLLECTION"
    scope, basis = enforcement_scope_of(_exclusion(None))
    assert scope == "COLLECTION"
    assert basis == "LEGACY_PRE_P0B_COLLECTION_PRESERVED"


def test_a_new_exclusion_defaults_to_detection():
    draft = ExclusionDraft(
        set_id="set_x", type="PATH", value="/opt/vendor/agent",
        reason="tuned out by the SOC after review",
        affected_engines=["endpoint.collection"])
    assert draft.enforcement_scope == "DETECTION"


# ── 4 · PREVENTION is refused, never silently accepted ─────────────────

def test_prevention_scope_is_refused_and_reported(tmp_path):
    keep, suppressed, journal = _partition(
        _exclusion(EnforcementScope.PREVENTION.value), tmp_path)
    assert suppressed == 0 and len(keep) == 2
    assert journal.entries["exc_path"]["acceptance"] == \
        "REFUSED_UNSUPPORTED_SCOPE"


def test_a_prevention_only_exclusion_never_becomes_detection_blindness():
    decision = enf.decide(
        exclusions=[_exclusion(EnforcementScope.PREVENTION.value,
                               engines=("server.deterministic.rule",))],
        engine="server.deterministic.rule",
        candidate={"path": "/opt/vendor/agent", "process": None,
                   "command_line": None, "file_hash": None,
                   "network_address": None})
    assert decision.excluded is False
    assert "PREVENTION" not in DETECTION_SUPPRESSING_SCOPES


# ── the shipped evaluator copies must not drift ────────────────────────

@pytest.mark.parametrize("shipped", [
    "/app/agents/nivxforge-linux/nivxforge_exclusions.py",
    "/app/agents/nivxforge-windows/nivxforge_exclusions.py"])
def test_every_shipped_evaluator_carries_the_scope_rules(shipped):
    assert open(shipped, "rb").read() == open(CANONICAL, "rb").read()


def test_the_policy_delivery_projection_carries_the_scope():
    """A connector that is not told the scope can only guess."""
    import inspect
    from routers import edr_policies
    src = inspect.getsource(edr_policies)
    assert '"enforcement_scope": enforcement_scope_of(e)[0]' in src
    assert '"affected_engines": list(' in src
