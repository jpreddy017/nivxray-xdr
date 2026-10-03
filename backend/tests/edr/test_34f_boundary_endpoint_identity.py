"""STEP 34F · the authoritative endpoint identity is stamped by the
AUTHENTICATED INGEST BOUNDARY, for every DSM, and by nothing else.

Hermetic: no Mongo, no production, no sensor, no real endpoint, no index, no
backfill. The pipeline's stamping call site is exercised through the pure
contract function plus a source-level assertion that the writer path uses it.
"""
from __future__ import annotations

import inspect

from detection_content import xdr_pipeline
from detection_content.telemetry import nivxforge_sensor_dsm as sensor_dsm
from edr_plane import canonical_identity_contract as idc

EP = "ep_a67be48d5b4e01d4d9e8"
OTHER_EP = "ep_0000000000000000beef"
AUTH = {"trust_state": "AUTHENTICATED", "source_kind": "REAL_SENSOR_DERIVED",
        "sensor_version": "1.4.2", "authenticated_endpoint_id": EP}


def canonical(**kw):
    """A canonical document as a normalizer leaves it: content only."""
    doc = {"tenant_id": "ten_x", "event_time": "2026-06-01T00:00:00.123456Z",
           "ingest_time": "2026-06-01T00:00:01Z",
           "event_id": "cev_1", "raw_ref": {"raw_id": "raw_1"},
           "host": {"host_id": "KUSHU", "hostname": "KUSHU"},
           "process": {"pid": 4242},
           "provenance": {"collector_id": EP, "trace_id": "raw_1",
                          "normalizer_id": "nvx.dsm.x"},
           "additional_fields": {"activity_type": "PROCESS"}}
    doc.update(kw)
    return doc


# ── the authenticated path, across DSM families ──────────────────────────

def test_every_dsm_family_gets_the_same_boundary_identity():
    """The same authenticated boundary, four different normalizer outputs —
    one identical authoritative identity. This is the G-29 fix: DSM selection
    no longer decides whether evidence has a platform endpoint identity."""
    families = {
        "nivxforge_sensor": canonical(),
        # a windows DSM writes the HOSTNAME into host_id and stamps nothing
        "windows_security": canonical(host={"host_id": "KUSHU",
                                            "hostname": "KUSHU"},
                                      additional_fields={}),
        # a network DSM has no host object at all
        "snort_eve": canonical(host={}, additional_fields={},
                               provenance={"collector_id": EP}),
        # a cloud DSM keys on an account id
        "aws_cloudtrail": canonical(host={"host_id": "123456789012"},
                                    additional_fields={}),
    }
    for name, doc in families.items():
        rec = idc.stamp_boundary_endpoint_identity(
            doc, envelope=AUTH, boundary_collector_id=EP)
        assert doc["additional_fields"]["endpoint_id"] == EP, name
        assert rec["state"] == idc.STATE_RESOLVED
        assert rec["authority"] == idc.BOUNDARY_AUTHORITY
        assert doc["provenance"]["endpoint_identity"] == rec


def test_the_envelope_identity_wins_over_the_boundary_argument():
    doc = canonical()
    rec = idc.stamp_boundary_endpoint_identity(
        doc, envelope=AUTH, boundary_collector_id=OTHER_EP)
    assert doc["additional_fields"]["endpoint_id"] == EP
    assert rec["source"] == idc.SOURCE_ENVELOPE


def test_the_boundary_argument_is_used_when_the_envelope_names_no_endpoint():
    doc = canonical()
    rec = idc.stamp_boundary_endpoint_identity(
        doc, envelope={"trust_state": "AUTHENTICATED"},
        boundary_collector_id=EP)
    assert doc["additional_fields"]["endpoint_id"] == EP
    assert rec["source"] == idc.SOURCE_BOUNDARY_ARG


# ── what may never become an identity ────────────────────────────────────

def test_identity_is_never_taken_from_the_event_content():
    """An event body claiming an endpoint id, a hostname or a vendor host id
    cannot produce an authoritative identity without an authenticated
    boundary."""
    for doc in (canonical(additional_fields={"endpoint_id": EP}),
                canonical(host={"host_id": EP, "hostname": "KUSHU"},
                          additional_fields={}),
                canonical(additional_fields={"endpoint_id": "KUSHU"})):
        rec = idc.stamp_boundary_endpoint_identity(
            doc, envelope=None, boundary_collector_id=None)
        assert "endpoint_id" not in doc["additional_fields"]
        assert rec["state"] == idc.STATE_UNRESOLVED
        assert rec["reason"] == idc.NO_AUTHENTICATED_BOUNDARY


def test_a_dsm_claim_is_refused_and_recorded_not_silently_dropped():
    doc = canonical(additional_fields={"endpoint_id": OTHER_EP})
    rec = idc.stamp_boundary_endpoint_identity(
        doc, envelope=None, boundary_collector_id="collector-snort-ref")
    assert "endpoint_id" not in doc["additional_fields"]
    assert rec["refused_claim"] == OTHER_EP
    assert rec["refused_reason"] == "NON_BOUNDARY_CLAIM_REFUSED"


def test_a_dsm_claim_that_disagrees_with_the_boundary_is_overridden():
    doc = canonical(additional_fields={"endpoint_id": OTHER_EP})
    rec = idc.stamp_boundary_endpoint_identity(
        doc, envelope=AUTH, boundary_collector_id=EP)
    assert doc["additional_fields"]["endpoint_id"] == EP
    assert rec["refused_claim"] == OTHER_EP
    assert rec["refused_reason"] == "NON_BOUNDARY_CLAIM_OVERRIDDEN"


def test_an_unauthenticated_pipeline_call_produces_no_platform_identity():
    for envelope in (None, {}, {"trust_state": "UNVERIFIED",
                                "authenticated_endpoint_id": EP},
                     {"source_kind": "REAL_SENSOR_DERIVED"}):
        doc = canonical()
        rec = idc.stamp_boundary_endpoint_identity(
            doc, envelope=envelope, boundary_collector_id=EP)
        assert "endpoint_id" not in doc["additional_fields"]
        assert rec["state"] == idc.STATE_UNRESOLVED
        assert rec["reason"] == idc.NO_AUTHENTICATED_BOUNDARY


def test_a_non_platform_boundary_value_fails_closed():
    """A third-party collector id is a collector, not an endpoint."""
    for supplied in ("collector-snort-ref", "KUSHU", "dev_d21e1278f914",
                     "10.1.2.3", "", None):
        doc = canonical()
        rec = idc.stamp_boundary_endpoint_identity(
            doc, envelope={"trust_state": "AUTHENTICATED"},
            boundary_collector_id=supplied)
        assert "endpoint_id" not in doc["additional_fields"]
        assert rec["reason"] == idc.BOUNDARY_ID_NOT_PLATFORM_MINTED


# ── everything else about the document is left alone ─────────────────────

def test_stamping_touches_nothing_but_the_identity_and_its_record():
    doc = canonical()
    before = {k: v for k, v in doc.items() if k not in
              ("additional_fields", "provenance")}
    prov_before = {k: v for k, v in doc["provenance"].items()}
    idc.stamp_boundary_endpoint_identity(doc, envelope=AUTH,
                                         boundary_collector_id=EP)
    assert {k: v for k, v in doc.items()
            if k not in ("additional_fields", "provenance")} == before
    assert doc["host"] == {"host_id": "KUSHU", "hostname": "KUSHU"}
    assert doc["tenant_id"] == "ten_x"
    assert doc["event_time"] == "2026-06-01T00:00:00.123456Z"
    assert doc["raw_ref"] == {"raw_id": "raw_1"}
    assert doc["additional_fields"]["activity_type"] == "PROCESS"
    for key, value in prov_before.items():
        assert doc["provenance"][key] == value


# ── no DSM may hold identity authority again ─────────────────────────────

def test_the_sensor_dsm_no_longer_stamps_the_authoritative_field():
    src = inspect.getsource(sensor_dsm)
    assert 'extra["endpoint_id"]' not in src
    assert "extra.setdefault(\"endpoint_id\"" not in src


def test_no_telemetry_dsm_stamps_the_authoritative_field():
    from detection_content.telemetry.registry import TELEMETRY_DSM_REGISTRY
    dsms = TELEMETRY_DSM_REGISTRY._dsms
    assert dsms, "the DSM registry must not be empty"
    for dsm in dsms:
        src = inspect.getsource(inspect.getmodule(dsm))
        dsm_id = getattr(dsm, "id", dsm.__class__.__name__)
        assert 'extra["endpoint_id"]' not in src, dsm_id
        assert '["additional_fields"]["endpoint_id"]' not in src, dsm_id


def test_the_canonical_writer_stamps_at_the_boundary_before_persisting():
    src = inspect.getsource(xdr_pipeline.process_event_through_pipeline)
    stamp = src.index("stamp_boundary_endpoint_identity")
    insert = src.index("CANONICAL_COLLECTION].insert_one")
    assert stamp < insert, "identity must be stamped BEFORE the write"
    assert "_authenticated_ingest" in src[stamp - 400:insert]
    assert "boundary_collector_id=collector_id" in src
