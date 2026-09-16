"""CEMv1 · schema + immutability + provenance tests."""
from __future__ import annotations

import pytest
from datetime import datetime, timezone
from pydantic import ValidationError

from nivxforge.investigation.cem import (
    CEM_VERSION, CanonicalEvent, CanonicalEventModel, ContainmentState,
    Detection, EventKind, FileEntity, Host, Incident, Network, Process,
    Provenance, Registry, SeverityLevel, User, VendorAdapter,
)


@pytest.fixture
def prov():
    return Provenance(source="test", vendor="unit",
                      timestamp=datetime.now(timezone.utc), confidence=1.0)


def test_cem_version_is_v1():
    assert CEM_VERSION == "v1"


def test_root_defaults(prov):
    m = CanonicalEventModel(provenance=prov)
    assert m.version == "v1"
    assert m.events == []
    assert m.incidents == []


def test_provenance_frozen(prov):
    with pytest.raises(ValidationError):
        prov.source = "mutated"  # type: ignore[misc]


def test_canonical_event_frozen(prov):
    e = CanonicalEvent(event_id="e1", kind=EventKind.process_create,
                       provenance=prov)
    with pytest.raises(ValidationError):
        e.event_id = "changed"  # type: ignore[misc]


def test_canonical_event_optional_fields(prov):
    e = CanonicalEvent(event_id="e1", kind=EventKind.generic,
                       provenance=prov)
    assert e.host is None
    assert e.process is None
    assert e.containment == ContainmentState.none


def test_all_kinds_present():
    kinds = {k.value for k in EventKind}
    assert "process_create" in kinds
    assert "dns_query" in kinds
    assert "detection" in kinds


def test_severity_ordering_by_enum():
    # Sanity: enum values exist and are strings.
    assert SeverityLevel.critical.value == "critical"
    assert SeverityLevel.informational.value == "informational"


def test_containment_state_values():
    values = {c.value for c in ContainmentState}
    assert {"none", "quarantined", "isolated", "prevented"}.issubset(values)


def test_vendor_adapter_is_abstract():
    a = VendorAdapter()
    with pytest.raises(NotImplementedError):
        a.can_parse("x")
    with pytest.raises(NotImplementedError):
        a.parse("x")


def test_process_and_file_frozen(prov):
    p = Process(command_line="whoami", provenance=prov)
    with pytest.raises(ValidationError):
        p.command_line = "boom"  # type: ignore[misc]
    f = FileEntity(path="/a/b", provenance=prov)
    with pytest.raises(ValidationError):
        f.path = "/x"  # type: ignore[misc]


def test_incident_carries_severity_and_state(prov):
    i = Incident(incident_id="inc-1",
                 severity=SeverityLevel.high,
                 containment=ContainmentState.isolated,
                 provenance=prov)
    assert i.severity == SeverityLevel.high
    assert i.containment == ContainmentState.isolated


def test_registry_and_network_and_dns_and_detection_construct(prov):
    Registry(key=r"HKLM\Software\X", provenance=prov)
    Network(dst_ip="1.2.3.4", provenance=prov)
    from nivxforge.investigation.cem import Dns
    Dns(query="example.com", provenance=prov)
    Detection(name="Threat X", severity=SeverityLevel.high, provenance=prov)


def test_root_carries_vendor(prov):
    m = CanonicalEventModel(vendor="Sysmon", vendor_route="sysmon",
                             provenance=prov)
    assert m.vendor == "Sysmon"
    assert m.vendor_route == "sysmon"
