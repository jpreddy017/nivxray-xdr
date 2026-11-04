"""T1.4 · Provenance envelope test.

Every emitted IUEEvidence carries Provenance{engine, version, at,
upstream_evidence_ids}. See D3-z.
"""
from canonical.iue import classify, RawInput


SAMPLES = [
    "cmd /c whoami",
    "powershell -e SGVsbG8=",
    "http://example.com and 1.2.3.4",
    b"MZ\x90\x00" + b"\x00" * 60 + b"PE\x00\x00",
    "\x00" * 30 + "!" * 5,
    "",
]


def test_every_evidence_entry_has_full_envelope():
    for s in SAMPLES:
        raw = RawInput(payload=s) if isinstance(s, (bytes, str)) else s
        d = classify(raw)
        for ev in d.evidence:
            p = ev.provenance
            assert p is not None
            assert isinstance(p.engine, str) and p.engine
            assert isinstance(p.version, str) and p.version
            assert p.at == "phase1"
            assert isinstance(p.upstream_evidence_ids, list)


def test_composer_provenance_present_on_decision_itself():
    d = classify("noop")
    assert d.provenance.engine == "canonical.iue.composer"
    assert d.provenance.version
    assert d.provenance.at == "phase1"


def test_evidence_ids_are_unique_per_decision():
    d = classify("wmic process call create \"cmd /c powershell -e SGVsbG8=\"")
    ids = [e.id for e in d.evidence]
    assert len(ids) == len(set(ids)), f"duplicate evidence ids: {ids}"


def test_provenance_engine_scope_never_leaks():
    """No evidence provenance may point to a non-canonical engine — the
    composer is the boundary; wrapped modules' output must be re-stamped
    by the adapter's own provenance envelope."""
    d = classify("normal text")
    for ev in d.evidence:
        assert ev.provenance.engine.startswith("canonical.iue"), \
            f"provenance leak: {ev.id} -> {ev.provenance.engine}"
