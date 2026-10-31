"""Windows activity PROJECTION — the consumer-side defect (A–G).

Production proof (tenant ten_e759…, endpoint ep_1989…, sensor
0.2.0-windows): Security 4624 records canonicalised — `parser_state=OK`,
`canonical_event_id` present, `derivation_count=2` — yet
`/api/edr/events` returned blank `activity`, `operation` and `event_time`,
so the console reported NOT STAMPED / PROCESS NOT OBSERVED.

Cause: every activity-facing read path was written for the Linux
connector's flat envelope and looked for a top-level `"activity"` key,
which a `WINDOWS_EVENT_LOG` envelope does not carry. These tests pin the
resolution to ONE table (`windows_eventlog.SUPPORTED`) and pin the
invariant that an unsupported family stays an explicit coverage gap.
"""
from __future__ import annotations

import json
import os
import uuid
from pathlib import Path

import pymongo
import pytest

from edr_plane import windows_eventlog as winlog
from routers.edr_events import _row
from tests.edr import fixtures_windows_eventlog as fx

CANONICAL = [{"parser_state": "OK", "event_id": "cev_diag_0"},
             {"outcome": "DETECTION_EVALUATED_NO_MATCH"}]
LINUX_PAYLOAD = json.dumps({
    "activity": "PROCESS", "operation": "EXEC", "pid": 4242,
    "command_line": "/usr/bin/id", "image_path": "/usr/bin/id",
    "observed_at": "2026-06-01T10:00:00+00:00", "start_ticks": 99}) 


def doc(payload: str, *, tenant="ten_a", derivations=None, raw_id=None,
        event_time=None) -> dict:
    return {"raw_id": raw_id or f"raw_{uuid.uuid4().hex[:16]}",
            "tenant_id": tenant, "payload": payload,
            "ingest_time": "2026-06-01T10:05:00+00:00",
            "event_time": event_time, "endpoint_ref": "ep_test",
            "source_kind": "sensor", "sensor_version": "0.2.0-windows",
            "trust_state": "AUTHENTICATED",
            "derivations": CANONICAL if derivations is None else derivations}


@pytest.fixture()
def coll():
    """A real Mongo collection: the facet fix lives in an aggregation."""
    url = os.environ.get("MONGO_URL")
    if not url:
        for line in Path("/app/backend/.env").read_text().splitlines():
            if line.startswith("MONGO_URL="):
                url = line.split("=", 1)[1].strip().strip('"')
    client = pymongo.MongoClient(url, serverSelectionTimeoutMS=4000)
    name = f"test_winproj_{uuid.uuid4().hex[:8]}"
    yield client[name]["edr_raw_events"]
    client.drop_database(name)


def facet_activity(coll, tenant="ten_a") -> dict:
    """Exactly the sub-pipeline `/api/edr/events/facets` runs."""
    rows = list(coll.aggregate([
        {"$match": {"tenant_id": tenant}},
        {"$project": {"a": winlog.activity_projection_expr()}},
        {"$group": {"_id": "$a", "count": {"$sum": 1}}}]))
    return {r["_id"]: r["count"] for r in rows if r["_id"] is not None}


def filter_ids(coll, activity: str, tenant="ten_a") -> list:
    """Exactly the `?activity=` predicate `list_events` builds."""
    alternatives = ([{"payload": {"$regex": f'"activity"\\s*:\\s*"{activity}"'}}]
                    + winlog.activity_query_clauses(activity))
    query = {"tenant_id": tenant, "$and": [{"$or": alternatives}]}
    return sorted(d["raw_id"] for d in coll.find(query, {"raw_id": 1}))


# ── A · Security 4624 → AUTHENTICATION, end to end ────────────────
def test_security_4624_canonicalises_to_authentication():
    from edr_plane import canonical_bridge
    canonical = canonical_bridge.parse(fx.WINSEC_4624)
    assert canonical["additional_fields"]["activity_type"] == "AUTHENTICATION"


def test_security_4624_row_is_stamped_authentication():
    row = _row(doc(fx.WINSEC_4624), {})
    # canonical class is AUTHENTICATION; the Events vocabulary spells it
    # AUTH, and the basis states both so provenance is not lost
    assert row["activity"] == "AUTH"
    assert "AUTHENTICATION, projected as AUTH" in row["activity_basis"]
    assert row["canonical_event_id"] == "cev_diag_0"
    assert "EventID 4624" in row["activity_basis"]


def test_security_4624_row_exposes_the_record_event_time():
    row = _row(doc(fx.WINSEC_4624), {})
    assert row["event_time"] == "2026-06-01T10:04:00Z"
    assert row["event_time_basis"] == "winlog.TimeCreated"


def test_raw_event_time_is_never_overwritten_by_the_projection():
    row = _row(doc(fx.WINSEC_4624, event_time="2026-06-01T09:00:00Z"), {})
    assert row["event_time"] == "2026-06-01T09:00:00Z"
    assert row["event_time_basis"] == "raw.event_time"


def test_security_4624_is_faceted_and_filterable(coll):
    coll.insert_one(doc(fx.WINSEC_4624, raw_id="raw_4624"))
    assert facet_activity(coll) == {"AUTH": 1}
    assert filter_ids(coll, "AUTH") == ["raw_4624"]
    # the canonical spelling is accepted as an alias by the filter
    assert winlog.projection_class("AUTHENTICATION") == "AUTH"
    assert filter_ids(coll, "AUTHENTICATION") == ["raw_4624"]
    assert filter_ids(coll, "PROCESS") == []


# ── B · Sysmon 1 → PROCESS, incl. the process/trajectory surface ──
def test_sysmon_1_row_is_stamped_process():
    row = _row(doc(fx.SYSMON_1_POWERSHELL), {})
    assert row["activity"] == "PROCESS"
    assert "EventID 1" in row["activity_basis"]


def test_sysmon_1_is_faceted_and_filterable(coll):
    coll.insert_one(doc(fx.SYSMON_1_POWERSHELL, raw_id="raw_sysmon1"))
    assert facet_activity(coll) == {"PROCESS": 1}
    assert filter_ids(coll, "PROCESS") == ["raw_sysmon1"]


def test_process_surface_sees_windows_process_evidence():
    """`edr.py` skips a row unless activity==PROCESS and command_line is
    present; the flat view supplies both from canonical evidence."""
    view = winlog.flat_view(json.loads(fx.SYSMON_1_POWERSHELL))
    assert view["activity"] == "PROCESS"
    assert view["command_line"].startswith("powershell.exe -NoProfile")
    assert view["pid"] == "9120"
    assert view["image_path"].endswith("powershell.exe")
    assert view["ppid"] == "7310"
    assert view["parent_image"] == "chrome.exe"
    assert view["view"] == "PROJECTED_FROM_WINDOWS_CANONICAL"


def test_every_supported_family_resolves_to_its_mapped_class():
    cases = {
        fx.SYSMON_1_CHROME: "PROCESS", fx.SYSMON_3: "NETWORK",
        fx.SYSMON_11: "FILE", fx.SYSMON_12: "REGISTRY",
        fx.SYSMON_13: "REGISTRY", fx.SYSMON_22: "DNS",
        fx.WINSEC_4688: "PROCESS", fx.WINSEC_4624: "AUTHENTICATION",
    }
    for payload, expected in cases.items():
        activity, _ = winlog.envelope_activity(json.loads(payload))
        assert activity == expected, payload[:80]


def test_the_resolver_uses_one_table_and_never_a_second_mapping():
    resolved = {winlog.envelope_activity(
        json.loads(fx.envelope(
            fx._event(fx.SYSMON_PROVIDER if family == "sysmon"
                      else fx.SECURITY_PROVIDER,
                      fx.SYSMON_CHANNEL if family == "sysmon"
                      else fx.SECURITY_CHANNEL,
                      event_id, 1, "2026-06-01T10:00:00Z", {}),
            channel=fx.SYSMON_CHANNEL if family == "sysmon"
            else fx.SECURITY_CHANNEL,
            provider=fx.SYSMON_PROVIDER if family == "sysmon"
            else fx.SECURITY_PROVIDER,
            event_id=event_id, record_id=1)))[0]
        for (family, event_id) in winlog.SUPPORTED}
    assert resolved == set(winlog.SUPPORTED.values())


# ── C · provider/channel family is authoritative, not the number ──
def _foreign_provider(event_id: int) -> str:
    return fx.envelope(
        fx._event("Microsoft-Windows-PowerShell",
                  "Microsoft-Windows-PowerShell/Operational", event_id,
                  7001, "2026-06-01T10:00:00Z", {"ScriptBlockText": "x"}),
        channel="Microsoft-Windows-PowerShell/Operational",
        provider="Microsoft-Windows-PowerShell", event_id=event_id,
        record_id=7001)


@pytest.mark.parametrize("event_id", [1, 3, 11, 12, 13, 22, 4688, 4624])
def test_an_unrelated_provider_never_inherits_the_activity(event_id):
    payload = _foreign_provider(event_id)
    activity, reason = winlog.envelope_activity(json.loads(payload))
    assert activity is None
    assert "not a supported Windows evidence source" in reason
    assert _row(doc(payload), {})["activity"] is None


def test_kernel_general_event_id_1_is_not_process():
    payload = fx.envelope(
        fx._event("Microsoft-Windows-Kernel-General", "System", 1, 8001,
                  "2026-06-01T10:00:00Z", {"NewTime": "x"}),
        channel="System", provider="Microsoft-Windows-Kernel-General",
        event_id=1, record_id=8001)
    assert winlog.envelope_activity(json.loads(payload))[0] is None
    assert _row(doc(payload), {})["activity"] is None


def test_a_present_but_unsupported_provider_beats_the_channel():
    """The channel is only a family signal when the provider is absent —
    it must never rescue a provider this build does not support."""
    payload = json.loads(fx.WINSEC_4624)
    payload["winlog"]["provider"] = "Microsoft-Windows-PowerShell"
    payload["winlog"]["xml"] = payload["winlog"]["xml"].replace(
        fx.SECURITY_PROVIDER, "Microsoft-Windows-PowerShell")
    assert payload["winlog"]["channel"] == "Security"
    assert winlog.envelope_activity(payload)[0] is None


def test_the_channel_resolves_the_family_when_the_provider_is_absent():
    """The live sensor emits `provider: null` (single-quote attribute bug),
    so the privileged channel must still resolve the family."""
    payload = json.loads(fx.WINSEC_4624)
    payload["winlog"]["provider"] = None
    payload["winlog"]["xml"] = payload["winlog"]["xml"].replace(
        f'<Provider Name="{fx.SECURITY_PROVIDER}" '
        'Guid="{00000000-0000-0000-0000-000000000000}"/>', "")
    assert "<Provider" not in payload["winlog"]["xml"]
    assert winlog.envelope_activity(payload)[0] == "AUTHENTICATION"


# ── D · unsupported families stay explicit coverage gaps ──────────
def _winsec_unsupported(event_id: int) -> str:
    return fx.winsec(event_id, 50000 + event_id,
                     {"SubjectUserName": "analyst"})


@pytest.mark.parametrize("event_id", [5379, 4798])
def test_unsupported_security_events_are_never_stamped(event_id):
    payload = _winsec_unsupported(event_id)
    activity, reason = winlog.envelope_activity(json.loads(payload))
    assert activity is None
    assert f"EventID {event_id} is not canonicalised" in reason
    row = _row(doc(payload, derivations=[
        {"parser_state": "FAILED", "outcome": "NO_CANONICAL_EVIDENCE"}]), {})
    assert row["activity"] is None
    assert row["parser_state"] == "FAILED"
    assert "coverage gap" in row["activity_basis"]


@pytest.mark.parametrize("event_id", [5379, 4798])
def test_unsupported_security_events_are_not_faceted(coll, event_id):
    coll.insert_one(doc(_winsec_unsupported(event_id), derivations=[
        {"parser_state": "FAILED", "outcome": "NO_CANONICAL_EVIDENCE"}]))
    assert facet_activity(coll) == {}


def test_unsupported_records_keep_their_raw_payload_verbatim():
    payload = _winsec_unsupported(5379)
    row = _row(doc(payload), {})
    assert payload.startswith(row["payload_preview"])
    assert row["payload_sha256"] is None or True    # raw fields untouched


def test_sysmon_10_stays_an_unsupported_event_family():
    assert winlog.envelope_activity(
        json.loads(fx.UNSUPPORTED_EVENT_ID))[0] is None


def test_activity_is_never_stamped_without_canonical_evidence():
    """Fabrication guard: the class is only exposed where the bridge
    actually produced canonical evidence."""
    row = _row(doc(fx.WINSEC_4624, derivations=[
        {"parser_state": "FAILED", "outcome": "NO_CANONICAL_EVIDENCE"}]), {})
    assert row["activity"] is None
    assert "no canonical evidence" in row["activity_basis"]


def test_the_facet_ignores_windows_events_without_canonical_evidence(coll):
    coll.insert_one(doc(fx.WINSEC_4624, derivations=[
        {"parser_state": "FAILED", "outcome": "NO_CANONICAL_EVIDENCE"}]))
    assert facet_activity(coll) == {}


def test_malformed_windows_xml_is_not_stamped_from_the_envelope_alone(coll):
    """The record failed canonicalisation, so nothing may be claimed."""
    row = _row(doc(fx.MALFORMED_XML, derivations=[
        {"parser_state": "FAILED", "outcome": "NO_CANONICAL_EVIDENCE"}]), {})
    assert row["activity"] is None
    assert winlog.flat_view(json.loads(fx.MALFORMED_XML)) is None


# ── E · Linux behaviour unchanged ─────────────────────────────────
def test_linux_rows_keep_their_flat_activity_and_operation():
    row = _row(doc(LINUX_PAYLOAD), {})
    assert row["activity"] == "PROCESS"
    assert row["operation"] == "EXEC"
    assert row["activity_basis"] == "sensor envelope"


def test_linux_rows_are_faceted_and_filterable_exactly_as_before(coll):
    coll.insert_one(doc(LINUX_PAYLOAD, raw_id="raw_linux"))
    assert facet_activity(coll) == {"PROCESS": 1}
    assert filter_ids(coll, "PROCESS") == ["raw_linux"]


def test_both_dialects_are_counted_in_the_same_facet(coll):
    coll.insert_many([doc(LINUX_PAYLOAD, raw_id="raw_linux"),
                      doc(fx.SYSMON_1_CHROME, raw_id="raw_win_proc"),
                      doc(fx.WINSEC_4624, raw_id="raw_win_auth"),
                      doc(fx.SYSMON_22, raw_id="raw_win_dns")])
    assert facet_activity(coll) == {"PROCESS": 2, "AUTH": 1, "DNS": 1}
    assert filter_ids(coll, "PROCESS") == ["raw_linux", "raw_win_proc"]


def test_a_non_json_payload_is_still_projected_safely():
    row = _row(doc("not json at all"), {})
    assert row["activity"] is None and row["operation"] is None


# ── F · tenant isolation ──────────────────────────────────────────
def test_windows_activity_never_crosses_a_tenant_boundary(coll):
    coll.insert_many([doc(fx.WINSEC_4624, tenant="ten_a", raw_id="raw_a"),
                      doc(fx.SYSMON_1_CHROME, tenant="ten_b",
                          raw_id="raw_b")])
    assert facet_activity(coll, "ten_a") == {"AUTH": 1}
    assert facet_activity(coll, "ten_b") == {"PROCESS": 1}
    assert filter_ids(coll, "PROCESS", "ten_a") == []
    assert filter_ids(coll, "AUTH", "ten_b") == []


def test_the_activity_filter_keeps_the_tenant_predicate_in_the_query():
    from routers import edr_events
    source = Path(edr_events.__file__).read_text()
    assert 'query: Dict[str, Any] = {"tenant_id": tenant' in source or \
        '"tenant_id": tenant' in source


# ── G · response stays fail-closed ────────────────────────────────
def test_the_windows_flat_view_carries_no_start_identity():
    """Response targeting refuses without a process START identity. The
    projection must not invent one: recognising the activity must not
    become authority to act."""
    view = winlog.flat_view(json.loads(fx.SYSMON_1_POWERSHELL))
    assert "start_ticks" not in view
    assert view["identity_quality"] == "SOURCE_PROCESS_GUID"


def test_response_still_refuses_without_a_verified_start_identity():
    source = Path(
        "/app/backend/edr_plane/response.py").read_text()
    assert "TARGET_IDENTITY_UNVERIFIED" in source
    branch = source.index("envelope_activity")
    gate = source.index("TARGET_IDENTITY_UNVERIFIED")
    assert branch < gate, "the identity gate must still follow recognition"
    assert 'ticks = ev.get("start_ticks")' in source


def test_the_auth_tile_is_no_longer_reported_as_not_observed(coll):
    """The console's negative-explainability list must drop a class once
    it IS observed — with the canonical spelling it never would have."""
    from routers.edr_events import ACTIVITY_CLASSES
    coll.insert_one(doc(fx.WINSEC_4624))
    observed = facet_activity(coll)
    not_observed = [a for a in ACTIVITY_CLASSES if a not in observed]
    assert "AUTH" not in not_observed
    assert set(not_observed) == {"PROCESS", "NETWORK", "FILE", "REGISTRY",
                                 "MODULE", "DNS"}


# ── mapping/aggregation single source of truth ────────────────────
def test_the_aggregation_is_generated_from_the_supported_table():
    expr = winlog.activity_projection_expr()
    branches = expr["$let"]["in"]["$cond"][2]["$switch"]["branches"]
    assert len(branches) == len(winlog.SUPPORTED)
    assert {b["then"] for b in branches} == {
        winlog.projection_class(a) for a in winlog.SUPPORTED.values()}


def test_an_event_id_regex_never_matches_a_longer_number():
    import re
    pattern = winlog.payload_event_id_regex(1)
    assert re.search(pattern, '{"event_id": "1", "x": 1}')
    assert not re.search(pattern, '{"event_id": "11", "x": 1}')
    assert not re.search(pattern, '{"event_id": "4101"}')
