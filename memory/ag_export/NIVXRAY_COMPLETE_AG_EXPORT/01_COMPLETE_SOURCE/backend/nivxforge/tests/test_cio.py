"""CIO invariants — append-only + provenance."""

import pytest

from nivxforge.core.cio import CIO, CIOEntry


def test_cio_starts_empty():
    cio = CIO()
    assert cio.input == []
    assert cio.evidence == []
    assert cio.metadata.investigation_id


def test_cio_append_returns_entry_and_records_provenance():
    cio = CIO()
    entry = cio.append("evidence", engine="test_engine", payload={"kind": "smoke"})
    assert isinstance(entry, CIOEntry)
    assert entry.provenance.engine == "test_engine"
    assert entry.payload == {"kind": "smoke"}
    assert cio.evidence == [entry]


def test_cio_append_is_additive_never_overwrites():
    cio = CIO()
    a = cio.append("iocs", engine="e1", payload={"ip": "1.2.3.4"})
    b = cio.append("iocs", engine="e2", payload={"ip": "5.6.7.8"})
    # both entries present, order preserved, first entry unchanged
    assert cio.iocs == [a, b]
    assert cio.iocs[0] is a
    assert cio.iocs[0].payload == {"ip": "1.2.3.4"}


def test_cio_entry_is_frozen():
    entry = CIOEntry(
        provenance={"engine": "x"},
        payload={"k": "v"},
    )
    with pytest.raises(Exception):
        entry.payload = {"k": "mutated"}  # frozen model must forbid mutation


def test_cio_rejects_unknown_field():
    cio = CIO()
    with pytest.raises(ValueError):
        cio.append("bogus_field", engine="e", payload={})


def test_cio_append_requires_engine():
    cio = CIO()
    with pytest.raises(Exception):
        cio.append("iocs", engine="", payload={"ip": "1.2.3.4"})
