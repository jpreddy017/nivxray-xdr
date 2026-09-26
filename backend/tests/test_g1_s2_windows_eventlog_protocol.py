"""G1/S2 · native Windows Event Log acquisition has its OWN protocol identity.

The defect this suite pins: `PROTOCOL_REGISTRY` had no entry for native
`EvtSubscribe` acquisition, so enrolling a Windows endpoint forced the
operator to declare `wef` — Windows Event Forwarding over WinRM, which is a
different architecture and is not implemented. The authoritative collector
document would then have recorded a false acquisition method (and
`implementation: SCAFFOLD`) for a collector that really does acquire.

Enrolment, persisted metadata, configuration validation and the data-source
vocabulary must all name the same identity.

TEST/SYNTHETIC — no collector is created here; this asserts the server-side
contract that enrolment is built on.
"""
from __future__ import annotations

import pytest
from fastapi import HTTPException

from lib.collector_catalog import CATALOG as COLLECTOR_CATALOG
from routers.xdr_collectors import (PROTOCOL_REGISTRY, CreateCollectorBody,
                                    _validate_create)
from routers.xdr_data_sources import SOURCE_KINDS

PROTO = "windows-eventlog"


def body(protocol=PROTO, **over):
    return CreateCollectorBody(name="g1-windows-endpoint", protocol=protocol,
                               **over)


# ── 1 · the protocol exists, and says what it really is ──────────────
def test_native_windows_eventlog_protocol_is_registered():
    entry = PROTOCOL_REGISTRY[PROTO]
    assert entry["implementation"] == "IMPLEMENTED"
    assert entry["transport"] == "windows-evt-api"
    assert entry["canonical_schema"] == "canonical.host.process"
    # IMPLEMENTED only because the adapter exists — name it
    assert "windows_eventlog.py" in entry["notes"]


def test_it_is_not_conflated_with_wef_or_any_other_transport():
    native = PROTOCOL_REGISTRY[PROTO]
    for other in ("wef", "syslog", "rest", "webhook", "edr"):
        assert PROTOCOL_REGISTRY[other]["transport"] != native["transport"]
    # WEF stays exactly what it is: not implemented, and over WinRM
    assert PROTOCOL_REGISTRY["wef"]["implementation"] == "SCAFFOLD"
    assert PROTOCOL_REGISTRY["wef"]["transport"] == "winrm"


# ── 2 · enrolment accepts the true declaration ───────────────────────
def test_enrolment_validation_accepts_the_native_protocol():
    _validate_create(body())  # must not raise


def test_persisted_metadata_is_taken_from_the_registry_not_the_caller():
    """`create_collector` copies implementation / transport /
    canonical_schema out of the registry, so a caller cannot assert a
    capability the platform does not have."""
    entry = PROTOCOL_REGISTRY[PROTO]
    assert set(("implementation", "transport", "canonical_schema")) \
        <= set(entry)


# ── 3 · false and unsupported declarations are refused ───────────────
@pytest.mark.parametrize("bad", ["windows_eventlog", "windows-evt-api",
                                 "evtx", "eventlog", "winrm", "WEF",
                                 "windows-eventlog "])
def test_unsupported_protocol_declarations_are_refused(bad):
    with pytest.raises(HTTPException) as e:
        _validate_create(body(protocol=bad))
    assert e.value.status_code == 400
    assert e.value.detail["code"] == "UNKNOWN_PROTOCOL"
    assert PROTO in e.value.detail["allowed"]


# ── 4 · one vocabulary across the surfaces ───────────────────────────
def test_data_source_kind_maps_to_the_same_protocol_identity():
    kind = SOURCE_KINDS["windows_eventlog_native"]
    assert kind["protocol"] == PROTO
    assert kind["canonical"] == PROTOCOL_REGISTRY[PROTO]["canonical_schema"]
    # and it is NOT the forwarding kind
    assert SOURCE_KINDS["windows_event_fwd"]["protocol"] == "wef"


def test_every_declared_protocol_in_every_surface_is_registered():
    for kind, spec in SOURCE_KINDS.items():
        assert spec["protocol"] in PROTOCOL_REGISTRY, kind
    for entry in COLLECTOR_CATALOG:
        assert entry["protocol"] in PROTOCOL_REGISTRY, entry["id"]
