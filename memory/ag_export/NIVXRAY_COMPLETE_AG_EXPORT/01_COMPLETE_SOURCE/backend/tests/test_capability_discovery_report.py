"""R28.10 · Capability Discovery Report acceptance tests."""
import base64, gzip
from services.uaie import plugins as _p           # noqa: F401
from services.uaie.orchestrator import Orchestrator
from services.uaie.discovery_report import (
    CapabilityDiscoveryReport,
    ArtifactDiscoverySection,
    build_discovery_report,
)


def _new_orch() -> Orchestrator:
    return Orchestrator(recognizers=_p.all_recognizers(),
                         max_artifacts=64, max_depth=12)


def test_report_builds_on_trivial_input():
    r = _new_orch().run(b"hello world " * 20)
    rep = build_discovery_report(r)
    assert isinstance(rep, CapabilityDiscoveryReport)
    assert rep.coverage.registered > 0
    assert len(rep.per_artifact) >= 1


def test_report_has_four_sections_per_artifact():
    r = _new_orch().run(b"hello world " * 20)
    rep = build_discovery_report(r)
    for sec in rep.per_artifact:
        # Each of the 4 fields exists (may be empty list)
        assert isinstance(sec.applicable_capabilities, list)
        assert isinstance(sec.executed,                list)
        assert isinstance(sec.produced_types,          list)
        assert isinstance(sec.not_applicable,          list)


def test_not_applicable_carries_reason():
    r = _new_orch().run(b"hello world " * 20)
    rep = build_discovery_report(r)
    joined = [na for sec in rep.per_artifact for na in sec.not_applicable]
    assert joined, "expected at least some not-applicable entries"
    for na in joined:
        assert na.get("capability")
        reason = na.get("reason") or ""
        assert reason.startswith("Requires") or "planner" in reason.lower()


def test_coverage_summary_math_is_consistent():
    r = _new_orch().run(b"hello world " * 20)
    rep = build_discovery_report(r)
    c = rep.coverage
    # Executed cannot exceed applicable
    assert c.executed <= c.applicable
    assert c.remaining_applicable == c.applicable - c.executed
    # Registered is the ceiling
    assert c.applicable <= c.registered * max(1, len(rep.per_artifact))


def test_termination_reports_fixed_point_reason():
    r = _new_orch().run(b"hello world " * 20)
    rep = build_discovery_report(r)
    if rep.termination.fixed_point:
        assert "no remaining capability" in rep.termination.reason.lower()
    else:
        assert rep.termination.reason


def test_report_as_text_renders_four_section_layout():
    r = _new_orch().run(b"hello world " * 20)
    txt = build_discovery_report(r).as_text()
    for heading in ("Applicable Capabilities", "Executed", "Produced",
                     "Not Applicable", "Coverage Summary", "Termination"):
        assert heading in txt


def test_multi_layer_run_records_execution_per_artifact():
    """A gzip-in-base64 payload should list executed capabilities
    on multiple artifacts, not just the root."""
    inner = b"a" * 200
    gz    = gzip.compress(inner)
    b64   = base64.b64encode(gz).decode()
    r = _new_orch().run(b64.encode())
    rep = build_discovery_report(r)
    executed_totals = sum(len(sec.executed) for sec in rep.per_artifact)
    assert executed_totals >= 1
    # At least one artifact must have produced children (recursion)
    produced_totals = sum(len(sec.produced_types) for sec in rep.per_artifact)
    assert produced_totals >= 1
