"""L2 service determinism · every service is a pure function."""
from __future__ import annotations

import pytest

from l2_investigation.services import iter_services
from l2_investigation.services.base import all_service_names

from _fixtures import empty_bundle, synthetic_bundle


EXPECTED_SERVICES = {
    "attack_story",
    "capability_explorer",
    "detection_rules",
    "executive_summary",
    "hunting_queries",
    "ioc_intelligence",
    "threat_assessment",
    "workspace_bundle",
}


def test_all_expected_services_registered():
    assert set(all_service_names()) == EXPECTED_SERVICES


@pytest.mark.parametrize("service", list(iter_services()), ids=lambda s: s.name)
def test_service_output_is_hash_stable(service):
    bundle = synthetic_bundle("case-det-01")
    out1 = service.run(bundle)
    out2 = service.run(bundle)
    assert out1.fingerprint == out2.fingerprint
    assert out1.to_json() == out2.to_json()


@pytest.mark.parametrize("service", list(iter_services()), ids=lambda s: s.name)
def test_service_output_shape_is_uniform(service):
    bundle = synthetic_bundle()
    out = service.run(bundle)
    d = out.to_dict()
    assert set(d) == {"service", "version", "case_id", "body"}
    assert d["service"] == service.name
    assert d["version"] == service.version
    assert d["case_id"] == "case-0001"
    assert isinstance(d["body"], dict)


@pytest.mark.parametrize("service", list(iter_services()), ids=lambda s: s.name)
def test_service_handles_empty_bundle(service):
    bundle = empty_bundle()
    out = service.run(bundle)
    assert out.service == service.name
    assert out.case_id == "case-empty"


@pytest.mark.parametrize("service", list(iter_services()), ids=lambda s: s.name)
def test_service_output_case_id_matches_bundle(service):
    bundle = synthetic_bundle(case_id="case-XYZ-42")
    out = service.run(bundle)
    assert out.case_id == "case-XYZ-42"


def test_workspace_bundle_aggregates_all_peer_services():
    from l2_investigation.services.workspace_bundle import run as run_bundle
    bundle = synthetic_bundle()
    out = run_bundle(bundle)
    peer = set(out.body["services"].keys())
    assert peer == EXPECTED_SERVICES - {"workspace_bundle"}


def test_workspace_bundle_evidence_fingerprint_matches_bundle():
    from l2_investigation.services.workspace_bundle import run as run_bundle
    bundle = synthetic_bundle()
    out = run_bundle(bundle)
    assert out.body["evidence_fingerprint"] == bundle.fingerprint


def test_different_bundles_produce_different_fingerprints():
    from l2_investigation.services.executive_summary import run
    a = run(synthetic_bundle("case-A"))
    b = run(synthetic_bundle("case-B"))
    assert a.fingerprint != b.fingerprint
