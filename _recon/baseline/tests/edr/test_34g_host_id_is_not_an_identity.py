"""STEP 34G · `host.host_id` can no longer acquire platform-identity meaning.

Hermetic: no Mongo, no production, no sensor, no index, no backfill.
The invariant: `additional_fields.endpoint_id`, stamped by the authenticated
ingest boundary, is the SOLE authoritative platform endpoint identity. Every
other field — including `host.host_id` — is at most a source attribute or a
tenant-local legacy lookup value.
"""
from __future__ import annotations

import inspect
import json

from detection_content.telemetry.nivxforge_sensor_dsm import NivXForgeSensorDSM
from edr_plane import canonical_identity_contract as idc
from edr_plane import file_identity, process_identity
from edr_plane.reputation import observables as rep_observables

EP = "ep_a67be48d5b4e01d4d9e8"
AUTH = {"trust_state": "AUTHENTICATED", "source_kind": "REAL_SENSOR_DERIVED",
        "sensor_version": "1.4.2", "authenticated_endpoint_id": EP}


def sensor_payload(**kw):
    ev = {"activity": "PROCESS", "operation": "PROCESS_OBSERVED",
          "observed_at": "2026-06-06T14:00:00.123456+00:00",
          "pid": 4242, "ppid": 1, "image": "bash", "image_path": "/usr/bin/bash",
          "command_line": "bash -c id", "user": "root",
          "collection_method": "PROC_POLL", "parent_lookup_state": "OBSERVED",
          "parent_image": "sshd", "hostname": "lab-linux-01"}
    ev.update(kw)
    return ev


def normalize(ev, *, collector_id=EP):
    dsm = NivXForgeSensorDSM()
    parsed = dsm.select_parser().parse(ev)
    return dsm.select_normalizer().normalize(
        parsed, collector_id=collector_id, integration_id="t34g",
        trace_id="raw_t34g", tenant_id="ten_x")


# ── the forged claim ─────────────────────────────────────────────────────

def test_an_event_body_ep_claim_never_reaches_host_id():
    canonical = normalize(sensor_payload(endpoint_id=EP))
    assert (canonical.get("host") or {}).get("host_id") != EP
    assert (canonical.get("additional_fields") or {}).get("endpoint_id") is None
    # the hostname the source reported is still carried, as a name
    assert canonical["host"]["hostname"] == "lab-linux-01"


def test_the_collector_id_is_not_substituted_into_host_id():
    canonical = normalize(sensor_payload(), collector_id=EP)
    assert (canonical.get("host") or {}).get("host_id") != EP
    # it survives where it belongs: as collector provenance
    assert canonical["provenance"]["collector_id"] == EP


def test_a_source_declared_host_identifier_is_preserved_as_an_attribute():
    canonical = normalize(sensor_payload(host_id="vendor-host-7"))
    assert canonical["host"]["host_id"] == "vendor-host-7"
    # and it is still not an identity: whatever identity the contract resolves
    # comes from the authenticated boundary, never from this attribute
    resolved, reason = idc.classify(canonical)
    assert resolved != "vendor-host-7"
    assert reason in (idc.RESOLVED_AUTHENTICATED_BOUNDARY,
                      idc.UNRESOLVED_NAME_ONLY, idc.UNRESOLVED_NO_IDENTITY)


def test_the_authoritative_field_still_comes_only_from_the_boundary():
    canonical = normalize(sensor_payload(endpoint_id=EP))
    idc.stamp_boundary_endpoint_identity(canonical, envelope=AUTH,
                                         boundary_collector_id=EP)
    assert canonical["additional_fields"]["endpoint_id"] == EP
    assert (canonical.get("host") or {}).get("host_id") != EP

    forged = normalize(sensor_payload(endpoint_id=EP))
    idc.stamp_boundary_endpoint_identity(forged, envelope=None,
                                         boundary_collector_id=EP)
    assert "endpoint_id" not in forged["additional_fields"]
    assert (forged.get("host") or {}).get("host_id") != EP


def test_the_raw_event_claim_is_never_deleted_from_the_evidence():
    """The original claim stays readable — it is refused, not erased."""
    ev = sensor_payload(endpoint_id=EP)
    canonical = normalize(ev)
    assert json.loads(json.dumps(ev))["endpoint_id"] == EP
    assert (canonical.get("raw") or ev).get("endpoint_id", EP) == EP


# ── no reader may promote host.host_id ───────────────────────────────────

def canonical_doc(**kw):
    doc = {"tenant_id": "ten_x", "event_id": "cev_1",
           "event_time": "2026-06-06T14:00:00.123456Z",
           "host": {"host_id": EP, "hostname": "lab-linux-01"},
           "process": {"pid": 4242, "process_guid": "{g}",
                       "executable_path": "/usr/bin/bash"},
           "additional_fields": {"activity_type": "PROCESS"},
           "provenance": {"collector_id": "collector-x"}}
    doc.update(kw)
    return doc


def test_process_identity_does_not_scope_itself_from_host_id():
    view = process_identity.from_canonical(canonical_doc())
    assert not view.endpoint_id
    scoped = process_identity.from_canonical(
        canonical_doc(additional_fields={"activity_type": "PROCESS",
                                         "endpoint_id": EP}))
    assert scoped.endpoint_id == EP


def test_file_identity_does_not_scope_itself_from_host_id():
    doc = canonical_doc(file={"path": "/tmp/x", "hashes": {"sha256": "a" * 64}},
                        additional_fields={"activity_type": "FILE"})
    view = file_identity.from_canonical(doc)
    assert view is None or not view.endpoint_id


def test_reputation_observables_do_not_scope_themselves_from_host_id():
    src = inspect.getsource(rep_observables)
    assert 'or (canonical.get("host") or {}).get("host_id")' not in src


def test_no_edr_plane_identity_module_falls_back_to_host_id():
    for module in (process_identity, file_identity, rep_observables):
        src = inspect.getsource(module)
        assert '.get("host_id")' not in src, module.__name__


def test_the_incident_endpoint_scope_requires_a_platform_identity():
    from detection_content.xdr_incident import _endpoint_scope
    assert _endpoint_scope(canonical_doc()) is None          # host_id only
    assert _endpoint_scope(canonical_doc(
        additional_fields={"endpoint_id": EP})) == (EP, "lab-linux-01")
    assert _endpoint_scope(canonical_doc(
        additional_fields={"endpoint_id": "lab-linux-01"})) is None
