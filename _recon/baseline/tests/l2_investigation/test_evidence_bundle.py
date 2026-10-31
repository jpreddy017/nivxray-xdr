"""EvidenceBundle contract tests · L1 → L2 input shape."""
from __future__ import annotations

from l2_investigation.schemas import SampleMetadata, ServiceOutput

from _fixtures import synthetic_bundle


def test_bundle_fingerprint_stable():
    a = synthetic_bundle("c")
    b = synthetic_bundle("c")
    assert a.fingerprint == b.fingerprint


def test_bundle_json_sorted_and_deterministic():
    a = synthetic_bundle().to_json()
    b = synthetic_bundle().to_json()
    assert a == b
    assert a.index('"capabilities"') < a.index('"case_id"')


def test_evidence_primitives_carry_provenance():
    b = synthetic_bundle()
    for ioc in b.iocs:
        assert ioc.source_iteration >= 0
    for cap in b.capabilities:
        assert cap.source_iterations
    for m in b.mitre:
        assert m.via_capability


def test_transformation_evidence_covers_all_passes():
    b = synthetic_bundle()
    pass_names = {t.pass_name for t in b.transformations}
    assert pass_names == {"structural", "content", "decoder", "semantic"}


def test_service_output_envelope_json_stable():
    from l2_investigation.services.executive_summary import run
    a = run(synthetic_bundle()).to_json()
    b = run(synthetic_bundle()).to_json()
    assert a == b


def test_sample_metadata_optional_fields():
    m = SampleMetadata()
    assert m.family == ""
    assert m.to_dict() == {"family": "", "technique": "", "variant": "", "sample_id": ""}


def test_service_output_body_is_recursively_canonicalized():
    body = {"z": 1, "a": {"y": 1, "x": 0}, "m": [3, 1, 2]}
    out = ServiceOutput(service="s", version="0", case_id="c", body=body)
    assert list(out.to_dict()["body"]) == ["a", "m", "z"]
    assert list(out.to_dict()["body"]["a"]) == ["x", "y"]
    assert out.to_dict()["body"]["m"] == [3, 1, 2]
