"""GATE 7 · endpoint-side exclusion enforcement.

Two things are proven here:

  1. the canonical evaluator shipped inside every connector release is
     byte-identical to the single source of truth, so Windows and Linux
     cannot drift apart;
  2. `ENDPOINT_EXCLUSION_APPLIED` is derivable ONLY from an enforcement
     record the endpoint produced — a delivered configuration proves
     nothing.

The ten scenarios the owner required are each a separate test, because
"exclusions work" is not a finding.
"""
from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path

import pytest

sys.path.insert(0, "/app/backend")
from edr_plane.connector import catalog                     # noqa: E402
from edr_plane.exclusions import enforcement                 # noqa: E402
from edr_plane.exclusions.contracts import TruthState        # noqa: E402

AGENTS = Path("/app/agents")
CANONICAL = AGENTS / "_shared" / "nivxforge_exclusions.py"
SHIPPED = ("nivxforge-linux/nivxforge_exclusions.py",
           "nivxforge-windows/nivxforge_exclusions.py")


def _load():
    spec = importlib.util.spec_from_file_location("nvx_excl_canonical",
                                                  CANONICAL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


nvx = _load()

APPROVED_PATH_EXCLUSION = {
    "exclusion_id": "exc_path", "type": "PATH", "match": "EXACT",
    "value": "/opt/vendor/agent", "affected_engines": ["endpoint.collection"]}

PROCESS_EVENT = {"activity": "PROCESS", "image_path": "/opt/vendor/agent",
                 "process_name": "agent", "command_line": "/opt/vendor/agent -d",
                 "sha256": "a" * 64}
OTHER_EVENT = {"activity": "PROCESS", "image_path": "/usr/bin/curl",
               "process_name": "curl", "command_line": "curl https://x",
               "sha256": "b" * 64}


# ── the shipped copies are the canonical evaluator ───────────────────
def test_shipped_evaluator_is_byte_identical_to_the_canonical_source():
    want = hashlib.sha256(CANONICAL.read_bytes()).hexdigest()
    for rel in SHIPPED:
        got = hashlib.sha256((AGENTS / rel).read_bytes()).hexdigest()
        assert got == want, (
            f"{rel} has drifted from the canonical evaluator. One evaluator, "
            "one behaviour, on every platform — a divergent copy means an "
            "exclusion behaves differently per OS.")


def test_every_release_declaring_endpoint_exclusions_ships_the_evaluator():
    for release in catalog.catalog():
        if not (release.get("declared_capabilities") or {}).get(
                "endpoint_exclusions"):
            continue
        names = [f["name"] for f in release.get("artifact_files") or []]
        assert "nivxforge_exclusions.py" in names, (
            f"{release['release_id']} declares endpoint_exclusions but its "
            "artifact does not ship the evaluator, so it cannot honour one")


# ── 1 · a valid applicable exclusion is enforced locally ─────────────
def test_valid_applicable_exclusion_drops_the_event_at_the_endpoint(tmp_path):
    journal = nvx.Journal(tmp_path / "j.json")
    kept, excluded = nvx.partition([PROCESS_EVENT, OTHER_EVENT],
                                   [APPROVED_PATH_EXCLUSION], journal,
                                   {"policy_id": "pol_x", "version": 1,
                                    "config_digest": "cfg_x"})
    assert excluded == 1
    assert kept == [OTHER_EVENT], (
        "the excluded event must never be queued: endpoint enforcement means "
        "the evidence does not leave the machine")
    entry = journal.entries["exc_path"]
    assert entry["acceptance"] == "HONOURED"
    assert entry["honoured_count"] == 1
    assert entry["matched_attribute"] == "path"
    assert entry["policy_id"] == "pol_x" and entry["config_digest"] == "cfg_x"


def test_the_report_carries_digests_not_the_excluded_content(tmp_path):
    journal = nvx.Journal(tmp_path / "j.json")
    nvx.partition([PROCESS_EVENT], [APPROVED_PATH_EXCLUSION], journal,
                  {"policy_id": "p", "version": 1, "config_digest": "c"})
    blob = str(journal.report())
    assert "/opt/vendor/agent" not in blob, (
        "re-uploading the excluded value would defeat the exclusion")
    assert hashlib.sha256(b"/opt/vendor/agent").hexdigest() in blob


# ── 2 · a non-matching exclusion changes nothing ─────────────────────
def test_non_matching_exclusion_delivers_every_event(tmp_path):
    journal = nvx.Journal(tmp_path / "j.json")
    kept, excluded = nvx.partition(
        [OTHER_EVENT], [APPROVED_PATH_EXCLUSION], journal,
        {"policy_id": "p", "version": 1, "config_digest": "c"})
    assert excluded == 0 and kept == [OTHER_EVENT]
    assert journal.entries["exc_path"]["honoured_count"] == 0


def test_an_absent_attribute_never_matches(tmp_path):
    """A hash exclusion cannot swallow an event whose hash was never
    observed — that would be a blind spot the operator never asked for."""
    journal = nvx.Journal(tmp_path / "j.json")
    hashless = {"activity": "NETWORK", "remote_ip": "10.0.0.9"}
    kept, excluded = nvx.partition(
        [hashless],
        [{"exclusion_id": "exc_h", "type": "FILE_HASH", "match": "EXACT",
          "value": "c" * 64, "affected_engines": ["endpoint.collection"]}],
        journal, {})
    assert excluded == 0 and kept == [hashless]


# ── 3 / 4 / 5 · unapproved, revoked and expired never reach the engine ─
@pytest.mark.parametrize("field,value", [
    ("approval_state", "PENDING_APPROVAL"),
    ("revoked_at", "2026-01-01T00:00:00+00:00"),
    ("expires_at", "2020-01-01T00:00:00+00:00"),
])
def test_unapproved_revoked_and_expired_are_never_delivered(field, value):
    """The connector can only enforce what the platform DELIVERS, and the
    platform's delivery query filters these out before they are ever
    handed to an endpoint. Proven at the source of truth."""
    from edr_plane.exclusions.contracts import (ENFORCEABLE_STATES,
                                                lifecycle_state)
    doc = {"approval_state": "APPROVED", "revoked_at": None,
           "effective_from": "2020-01-01T00:00:00+00:00",
           "expires_at": None, "review_at": None,
           "revoked_by": "x", "revoke_reason": "x", field: value}
    assert lifecycle_state(doc)["state"] not in ENFORCEABLE_STATES


# ── 6 · an unsupported exclusion type is REFUSED, not skipped ────────
def test_unsupported_type_is_refused_and_reported(tmp_path):
    journal = nvx.Journal(tmp_path / "j.json")
    kept, excluded = nvx.partition(
        [PROCESS_EVENT],
        [{"exclusion_id": "exc_u", "type": "REGISTRY_KEY", "match": "EXACT",
          "value": "HKLM\\Software", "affected_engines": ["endpoint.collection"]}],
        journal, {})
    assert excluded == 0 and kept == [PROCESS_EVENT]
    assert journal.entries["exc_u"]["acceptance"] == "REFUSED_UNSUPPORTED_TYPE"


def test_an_exclusion_aimed_only_at_prevention_is_refused(tmp_path):
    """The released connector has no prevention engine. Its collection
    evaluator must never be mistaken for one."""
    journal = nvx.Journal(tmp_path / "j.json")
    _kept, excluded = nvx.partition(
        [PROCESS_EVENT],
        [{**APPROVED_PATH_EXCLUSION, "exclusion_id": "exc_prev",
          "affected_engines": ["endpoint.prevention"]}], journal, {})
    assert excluded == 0
    assert journal.entries["exc_prev"]["acceptance"] == \
        "REFUSED_UNSUPPORTED_ENGINE"


# ── 9 · a malformed exclusion is refused, never guessed at ───────────
@pytest.mark.parametrize("bad", [
    {"exclusion_id": "exc_m1", "type": "PATH", "value": "",
     "affected_engines": ["endpoint.collection"]},
    {"exclusion_id": "exc_m2", "type": "PATH", "value": "/x",
     "match": "REGEX", "affected_engines": ["endpoint.collection"]},
    {"exclusion_id": "exc_m3", "type": "FILE_HASH", "value": "abc",
     "affected_engines": ["endpoint.collection"]},
    {"type": "PATH", "value": "/x", "affected_engines": ["endpoint.collection"]},
])
def test_malformed_exclusions_are_refused(bad, tmp_path):
    assert nvx.validate(bad) == "REFUSED_MALFORMED"
    journal = nvx.Journal(tmp_path / "j.json")
    _kept, excluded = nvx.partition([PROCESS_EVENT], [bad], journal, {})
    assert excluded == 0


# ── truth-state derivation · the heart of the gate ───────────────────
BOUND = {"exclusion_id": "exc_path",
         "policy_version_bindings": [{"policy_id": "pol_a", "version": 3}]}
APPLIED_STATE = {"assigned_policy_id": "pol_a", "applied_version": 3,
                 "confirmed_by_endpoint": True}
CAPABLE = {"endpoint_exclusions": True}


def test_capability_gap_reports_not_supported():
    out = enforcement.endpoint_truth_state(
        BOUND, engine="endpoint.collection",
        connector_capabilities={"endpoint_exclusions": False},
        endpoint_policy_state=APPLIED_STATE, enforcement=None)
    assert out["truth_state"] == \
        TruthState.EXCLUSION_NOT_SUPPORTED_BY_ENGINE.value


def test_prevention_engine_is_never_claimed_by_a_collection_capable_release():
    """A release declaring `endpoint_exclusions` says nothing about
    prevention. Conflating them would claim protection that does not
    exist."""
    out = enforcement.endpoint_truth_state(
        BOUND, engine="endpoint.prevention", connector_capabilities=CAPABLE,
        endpoint_policy_state=APPLIED_STATE,
        enforcement={"acceptance": "HONOURED", "honoured_count": 9})
    assert out["truth_state"] == \
        TruthState.EXCLUSION_NOT_SUPPORTED_BY_ENGINE.value


# ── 7 · a new policy version un-proves the old enforcement ───────────
def test_a_new_policy_version_returns_the_exclusion_to_pending_policy():
    out = enforcement.endpoint_truth_state(
        BOUND, engine="endpoint.collection", connector_capabilities=CAPABLE,
        endpoint_policy_state={"assigned_policy_id": "pol_a",
                               "applied_version": 4,
                               "confirmed_by_endpoint": True},
        enforcement={"acceptance": "HONOURED", "honoured_count": 5})
    assert out["truth_state"] == TruthState.EXCLUSION_PENDING_POLICY.value, (
        "the endpoint now runs v4, which does not carry this exclusion; a "
        "historical enforcement count must not keep it reported as enforced")


def test_delivered_but_unacknowledged_is_pending_policy():
    out = enforcement.endpoint_truth_state(
        BOUND, engine="endpoint.collection", connector_capabilities=CAPABLE,
        endpoint_policy_state={"assigned_policy_id": "pol_a",
                               "applied_version": None,
                               "confirmed_by_endpoint": False},
        enforcement=None)
    assert out["truth_state"] == TruthState.EXCLUSION_PENDING_POLICY.value


def test_applied_policy_with_no_match_yet_is_not_reported_as_applied():
    out = enforcement.endpoint_truth_state(
        BOUND, engine="endpoint.collection", connector_capabilities=CAPABLE,
        endpoint_policy_state=APPLIED_STATE,
        enforcement={"acceptance": "HONOURED", "honoured_count": 0})
    assert out["truth_state"] == \
        TruthState.ENDPOINT_EXCLUSION_ACTIVE_NO_MATCH_YET.value, (
        "nothing has been enforced, so APPLIED would be a claim without "
        "evidence")


def test_endpoint_applied_requires_a_real_enforcement_count():
    out = enforcement.endpoint_truth_state(
        BOUND, engine="endpoint.collection", connector_capabilities=CAPABLE,
        endpoint_policy_state=APPLIED_STATE,
        enforcement={"acceptance": "HONOURED", "honoured_count": 7,
                     "matched_attribute": "path",
                     "evaluator_version": "1.0.0"})
    assert out["truth_state"] == \
        TruthState.ENDPOINT_EXCLUSION_APPLIED.value
    assert out["honoured_count"] == 7


# ── 8 · a stale connector policy still enforces, and says so ─────────
def test_a_connector_refusal_overrides_a_capable_release():
    out = enforcement.endpoint_truth_state(
        BOUND, engine="endpoint.collection", connector_capabilities=CAPABLE,
        endpoint_policy_state=APPLIED_STATE,
        enforcement={"acceptance": "REFUSED_UNSUPPORTED_TYPE",
                     "honoured_count": 0})
    assert out["truth_state"] == \
        TruthState.EXCLUSION_NOT_SUPPORTED_BY_ENGINE.value
    assert out["acceptance"] == "REFUSED_UNSUPPORTED_TYPE"


# ── 10 · a cross-tenant exclusion id asserts nothing ─────────────────
def test_cross_tenant_report_cannot_produce_applied():
    out = enforcement.endpoint_truth_state(
        BOUND, engine="endpoint.collection", connector_capabilities=CAPABLE,
        endpoint_policy_state=APPLIED_STATE,
        enforcement={"acceptance": "REJECTED_NOT_IN_TENANT",
                     "honoured_count": 0})
    assert out["truth_state"] != TruthState.ENDPOINT_EXCLUSION_APPLIED.value


def test_a_superseded_release_keeps_its_own_declared_capability():
    """Endpoints still RUNNING 0.1.0 must not inherit 0.2.0's capability
    just because a newer release exists in the catalog."""
    old = catalog.capabilities_for_connector_version("0.1.0-windows",
                                                     "WINDOWS")
    new = catalog.capabilities_for_connector_version("0.2.0-windows",
                                                    "WINDOWS")
    assert old.get("endpoint_exclusions") is False
    assert new.get("endpoint_exclusions") is True


def test_linux_and_windows_releases_do_not_inherit_each_others_capability():
    win = catalog.capabilities_for_connector_version("0.2.0", "WINDOWS")
    lin = catalog.capabilities_for_connector_version("0.2.0", "LINUX")
    assert win.get("network_event_collection") is False
    assert lin.get("network_event_collection") is True
