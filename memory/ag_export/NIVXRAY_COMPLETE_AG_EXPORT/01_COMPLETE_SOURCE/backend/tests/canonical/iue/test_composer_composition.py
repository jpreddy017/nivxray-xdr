"""T1.1 · sub-classifier composition test.

Every canonical entry point must be able to produce an IUEDecision that
reflects each sub-classifier's contribution.
"""
from canonical.iue import classify, RawInput


def test_composer_returns_iuedecision_with_all_required_fields():
    d = classify("powershell -EncodedCommand SGVsbG8=")
    # Contract fields per ADR-005 §3.2
    assert d.input_health is not None
    assert d.input_profile is not None and d.input_profile.primary_type
    assert d.intent is not None and d.intent.label
    assert isinstance(d.capabilities, list) and len(d.capabilities) > 0
    assert isinstance(d.plan, list) and len(d.plan) > 0
    assert d.confidence_matrix is not None
    assert d.dispatch_policy is not None
    assert d.provenance is not None and d.provenance.engine == "canonical.iue.composer"
    assert d.next_engine_hint
    assert isinstance(d.evidence, list) and len(d.evidence) > 0
    assert d.determinism_hash and len(d.determinism_hash) == 64


def test_all_expected_sub_classifiers_participate():
    d = classify("http://example.com evil.exe")
    sources = {e.source for e in d.evidence}
    # Every sub-classifier must have had a chance to participate.
    assert "input_health" in sources
    assert "bytes_magic" in sources
    assert "text_structure" in sources
    # IUE-3 emits from any of its detectors OR the engine fallback.
    assert any(s == "language_multi_artefact" or s.startswith("input_understanding") for s in sources)
    assert "artefact_decomp" in sources
    assert "intent" in sources


def test_every_evidence_has_provenance_envelope():
    d = classify("cmd /c whoami")
    for ev in d.evidence:
        assert ev.provenance is not None, f"evidence {ev.id} missing provenance"
        assert ev.provenance.engine.startswith("canonical.iue"), \
            f"evidence {ev.id} provenance points outside canonical.iue: {ev.provenance.engine}"
        assert ev.provenance.version
        assert ev.provenance.at == "phase1"


def test_input_kind_populated_via_bytes_magic():
    """Amendment 1 · IUE-4 must actually participate."""
    d = classify(RawInput(payload=b"MZ\x90\x00" + b"\x00" * 60 + b"PE\x00\x00",
                          filename="a.exe"))
    assert d.input_profile.input_kind, "bytes_magic did not stamp input_kind"
    assert "pe" in d.input_profile.input_kind.lower()
