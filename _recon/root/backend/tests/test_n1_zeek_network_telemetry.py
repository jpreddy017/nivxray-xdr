"""Gate N1 · Zeek network/DNS telemetry — evidence, routing and correlation.

What this holds, in the order the trust chain runs:

  * ONE declared source (`zeek-json`) routes to ONE DSM, aliases widen
    nothing, and a wrong declaration is refused rather than rescued;
  * the DSM fails CLOSED on a missing/unknown `_path` and on a record that
    does not carry Zeek's own connection identity;
  * Zeek's `ts` is the wire instant (ACTIVITY_TIME) and `_write_ts` is the
    log-write instant (OBSERVATION) — the two never substitute for each
    other;
  * DNS answers are split by what they ARE: address answers become
    `network.dns_response_ips`, everything else stays a record. An
    NXDOMAIN answers nothing, and that is recorded, not smoothed over;
  * GAP-1 — Sysmon EID 22 `QueryResults` reaches the same canonical field,
    so the endpoint side can evidence domain → resolved IP too;
  * GAP-2 / GAP-3 — network, historical and DNS pivots read the canonical
    shapes the DSMs actually emit;
  * the DNS → resolved IP → connection relationship is established by the
    EXISTING correlation engine, requires the same client AND the same
    address AND that order, and cites both canonical event ids;
  * nothing invents a process, a user, a device identity or an allow/deny.

EVIDENCE LABELLING — TEST/SYNTHETIC Zeek records in Zeek's documented JSON
shape. No live sensor is contacted here; real-source status is reported
separately by `scripts/p0_n1_zeek_network_live_proof.py`.
"""
from __future__ import annotations

import pytest

from detection_content.telemetry.network_signals import signals_from_canonical
from detection_content.telemetry.registry import TELEMETRY_DSM_REGISTRY
from detection_content.telemetry.sysmon_dsm import (
    SysmonDSM, SysmonNormalizer, SysmonParser, _sysmon_query_results)
from detection_content.telemetry.zeek_json_dsm import (
    ZeekJsonDSM, ZeekJsonNormalizer, ZeekJsonParser, ZeekJsonParserError,
    split_answers)
from services import source_routing

TEN = "t-n1-zeek"
OTHER_TEN = "t-n1-other"
COL = "col-zeek-1"
CLIENT = "10.8.0.31"
RESOLVER = "10.8.0.1"
ANSWER = "198.51.100.77"
DOMAIN = "updates.example-cdn.net"


def dns_record(**over):
    doc = {
        "_path": "dns", "_system_name": "zeek-sensor-01",
        "ts": 1780000000.123456, "uid": "CxYZ01aBcDeF",
        "id.orig_h": CLIENT, "id.orig_p": 51234,
        "id.resp_h": RESOLVER, "id.resp_p": 53,
        "proto": "udp", "trans_id": 41234, "rtt": 0.021,
        "query": DOMAIN, "qclass": 1, "qclass_name": "C_INTERNET",
        "qtype": 1, "qtype_name": "A", "rcode": 0, "rcode_name": "NOERROR",
        "AA": False, "TC": False, "RD": True, "RA": True, "Z": 0,
        "answers": [ANSWER], "TTLs": [60.0], "rejected": False,
    }
    doc.update(over)
    return doc


def conn_record(**over):
    doc = {
        "_path": "conn", "_system_name": "zeek-sensor-01",
        "ts": 1780000012.500000, "uid": "CqRs02GhIjKl",
        "id.orig_h": CLIENT, "id.orig_p": 44122,
        "id.resp_h": ANSWER, "id.resp_p": 443,
        "proto": "tcp", "service": "ssl", "duration": 12.5,
        "orig_bytes": 2048, "resp_bytes": 91234,
        "orig_pkts": 24, "resp_pkts": 60,
        "conn_state": "SF", "history": "ShADadFf",
        "local_orig": True, "local_resp": False,
    }
    doc.update(over)
    return doc


def normalize(doc, tenant=TEN):
    dsm = ZeekJsonDSM()
    parsed = dsm.select_parser().parse(doc)
    return dsm.select_normalizer().normalize(
        parsed, dsm.id, COL, "native", "trace-n1", tenant_id=tenant)


# ── Routing: one declared source, one DSM ─────────────────────────
def test_the_zeek_dsm_is_registered_and_loaded():
    assert TELEMETRY_DSM_REGISTRY.get("zeek-json") is not None
    assert not [f for f in TELEMETRY_DSM_REGISTRY.load_failures()
                if f["dsm_id"] == "zeek-json"]


@pytest.mark.parametrize("declared", ["zeek-json", "zeek", "bro", "corelight",
                                      "zeek-conn", "zeek-dns", "ZEEK"])
def test_every_alias_resolves_to_the_same_single_source(declared):
    assert source_routing.canonical_source(declared) == "zeek-json"
    assert source_routing.SOURCE_CATALOG["zeek-json"] == "zeek-json"


def test_an_alias_does_not_widen_authorization():
    decision, dsm = source_routing.route(
        declared="corelight", authorized=["linux-auditd"],
        raw_event=dns_record(), registry=TELEMETRY_DSM_REGISTRY)
    assert decision["routing_result"] == source_routing.BLOCKED
    assert decision["mismatch_reason"] == source_routing.SOURCE_NOT_AUTHORIZED
    assert dsm is None


def test_a_declared_zeek_record_routes_to_the_zeek_dsm():
    decision, dsm = source_routing.route(
        declared="zeek-json", authorized=["zeek-json"],
        raw_event=dns_record(), registry=TELEMETRY_DSM_REGISTRY)
    assert decision["routing_result"] == source_routing.ACCEPTED
    assert decision["selected_dsm_id"] == "zeek-json"
    assert dsm.id == "zeek-json"


def test_a_zeek_record_declared_as_another_source_is_refused():
    decision, dsm = source_routing.route(
        declared="linux-auditd", authorized=["linux-auditd", "zeek-json"],
        raw_event=conn_record(), registry=TELEMETRY_DSM_REGISTRY)
    assert decision["routing_result"] == source_routing.BLOCKED
    assert decision["mismatch_reason"] == source_routing.SOURCE_FORMAT_MISMATCH
    assert dsm is None


def test_a_non_zeek_payload_declared_as_zeek_is_refused():
    decision, _ = source_routing.route(
        declared="zeek-json", authorized=["zeek-json"],
        raw_event={"RecordType": 8, "Operation": "Add member to role",
                   "Workload": "AzureActiveDirectory"},
        registry=TELEMETRY_DSM_REGISTRY)
    assert decision["routing_result"] == source_routing.BLOCKED
    assert decision["mismatch_reason"] == source_routing.SOURCE_FORMAT_MISMATCH


# ── Fail-closed parsing ───────────────────────────────────────────
@pytest.mark.parametrize("bad,code", [
    ("not-a-dict", "INVALID_EVENT"),
    ({"uid": "C1", "id.orig_h": CLIENT}, "MISSING_ZEEK_PATH"),
    ({"_path": "ssl", "uid": "C1", "id.orig_h": CLIENT},
     "UNSUPPORTED_ZEEK_PATH"),
    ({"_path": "http", "uid": "C1"}, "UNSUPPORTED_ZEEK_PATH"),
    ({"_path": "conn", "proto": "tcp"}, "MISSING_ZEEK_CONNECTION_IDENTITY"),
])
def test_malformed_or_unsupported_records_fail_closed(bad, code):
    with pytest.raises(ZeekJsonParserError) as e:
        ZeekJsonParser().parse(bad)
    assert e.value.code == code


@pytest.mark.parametrize("ev", [
    {"_path": "ssl", "uid": "C1", "id.orig_h": CLIENT},
    {"uid": "C1", "id.orig_h": CLIENT},
    {"_path": "conn"},
    "CEF:0|Vendor|Product|1|100|Deny|5|src=10.0.0.1",
    None,
])
def test_supports_claims_nothing_it_cannot_interpret(ev):
    assert ZeekJsonDSM().supports(ev) is False


def test_supports_accepts_the_nested_id_shape_some_shippers_emit():
    doc = {"_path": "dns", "ts": 1780000000.0, "uid": "C9",
           "id": {"orig_h": CLIENT, "orig_p": 5353,
                  "resp_h": RESOLVER, "resp_p": 53},
           "query": DOMAIN, "rcode_name": "NOERROR", "answers": [ANSWER]}
    assert ZeekJsonDSM().supports(doc) is True
    out = normalize(doc)
    assert out["network"]["src_ip"] == CLIENT
    assert out["network"]["dest_port"] == 53


# ── Tenant authority ──────────────────────────────────────────────
def test_the_authenticated_tenant_owns_the_evidence():
    out = normalize(dns_record(), tenant=TEN)
    assert out["tenant_id"] == TEN


def test_a_payload_named_tenant_is_recorded_and_never_believed():
    out = normalize(dns_record(tenant_id=OTHER_TEN), tenant=TEN)
    assert out["tenant_id"] == TEN
    assert OTHER_TEN not in str(out["tenant_id"])


# ── Timestamps ────────────────────────────────────────────────────
def test_zeek_ts_is_the_activity_instant():
    out = normalize(conn_record())
    extra = out["additional_fields"]
    assert extra["event_time_basis"] == "ACTIVITY_TIME"
    assert extra["event_time_substituted"] is False
    act = out["provenance"]["timestamps"]["activity_occurred_at"]
    assert act["status"] == "AVAILABLE"
    assert act["value"].startswith("2026-")
    assert "conn.log ts" in act["source"]


def test_the_log_write_instant_is_an_observation_not_the_activity():
    out = normalize(dns_record(_write_ts=1780000001.9))
    stamps = out["provenance"]["timestamps"]
    assert stamps["sensor_observed_at"]["status"] == "AVAILABLE"
    assert "_write_ts" in stamps["sensor_observed_at"]["source"]
    assert (stamps["activity_occurred_at"]["value"]
            != stamps["sensor_observed_at"]["value"])


def test_a_record_without_ts_never_borrows_another_time():
    doc = dns_record()
    doc.pop("ts")
    out = normalize(doc)
    assert out["additional_fields"]["event_time_basis"] != "ACTIVITY_TIME"
    assert out["provenance"]["timestamps"][
        "activity_occurred_at"]["status"] == "NOT_OBSERVED"


def test_iso_timestamps_are_accepted_as_well_as_epoch():
    out = normalize(dns_record(ts="2026-06-08T10:11:12+00:00"))
    assert out["event_time"] == "2026-06-08T10:11:12+00:00"
    assert out["additional_fields"]["event_time_basis"] == "ACTIVITY_TIME"


# ── DNS evidence (GAP-1 closed on the network side) ───────────────
def test_a_dns_answer_becomes_citable_canonical_evidence():
    out = normalize(dns_record())
    net = out["network"]
    assert out["event_type"] == "dns_query"
    assert net["dns_query"] == DOMAIN
    assert net["dns_query_type"] == "A"
    assert net["dns_rcode"] == "NOERROR"
    assert net["dns_response_ips"] == [ANSWER]
    assert net["dns_response_ttls"] == [60.0]
    assert net["dns_transaction_id"] == 41234
    assert net["field_provenance"]["dns_response_ips"] == \
        "zeek:dns.log answers (address records)"


def test_multiple_answers_are_all_preserved_and_split_by_kind():
    out = normalize(dns_record(
        answers=["cdn-edge.example.net", ANSWER, "203.0.113.9",
                 "2001:db8::10"],
        TTLs=[30.0, 60.0, 60.0, 60.0]))
    net = out["network"]
    assert net["dns_response_ips"] == [ANSWER, "203.0.113.9", "2001:db8::10"]
    assert net["dns_response_records"] == ["cdn-edge.example.net"]


def test_nxdomain_answers_nothing_and_says_so():
    out = normalize(dns_record(rcode=3, rcode_name="NXDOMAIN", answers=[],
                               TTLs=[]))
    net = out["network"]
    assert net["dns_rcode"] == "NXDOMAIN"
    assert net["dns_response_ips"] == []
    assert "dns_answer_absent_reason" in out["additional_fields"]
    assert "dns_response_ips" not in net["field_provenance"]


def test_split_answers_never_calls_a_hostname_an_address():
    ips, other = split_answers(["example.com", "93.184.216.34", "-", ""])
    assert ips == ["93.184.216.34"]
    assert other == ["example.com"]


# ── Connection evidence ───────────────────────────────────────────
def test_a_connection_carries_volume_state_and_the_flow_key():
    out = normalize(conn_record(community_id="1:LQU9qZlK+B5F3KDmev6m5PMibrg="))
    net = out["network"]
    assert out["event_type"] == "network_connect"
    assert (net["src_ip"], net["dest_ip"], net["dest_port"]) == \
        (CLIENT, ANSWER, 443)
    assert net["bytes_sent"] == 2048 and net["bytes_received"] == 91234
    assert net["packets_sent"] == 24 and net["packets_received"] == 60
    assert net["duration_ms"] == 12500.0
    assert net["conn_state"] == "SF" and net["conn_history"] == "ShADadFf"
    assert net["flow_id"] == "CqRs02GhIjKl"
    assert net["community_id"].startswith("1:")


def test_community_id_is_absent_when_the_deployment_does_not_emit_one():
    out = normalize(conn_record())
    assert out["network"]["community_id"] == ""
    assert "community_id" not in out["network"]["field_provenance"]


def test_direction_is_only_reported_when_zeek_states_locality():
    stated = normalize(conn_record())
    assert stated["network"]["direction"] == "outbound"
    doc = conn_record()
    doc.pop("local_orig"); doc.pop("local_resp")
    unstated = normalize(doc)
    assert unstated["network"]["direction"] == ""
    assert "direction_absent_reason" in unstated["additional_fields"]


def test_ipv6_endpoints_are_carried_verbatim():
    out = normalize(conn_record(**{"id.orig_h": "2001:db8::1",
                                   "id.resp_h": "2001:db8::2"}))
    assert out["network"]["src_ip"] == "2001:db8::1"
    assert out["network"]["dest_ip"] == "2001:db8::2"


# ── What Zeek does NOT know ───────────────────────────────────────
def test_no_process_user_or_device_identity_is_invented():
    out = normalize(conn_record())
    assert out["process"]["name"] == "" and out["process"]["pid"] is None
    assert out["identity"]["username"] == ""
    assert out["host"]["hostname"] == "" and out["host"]["host_id"] == ""
    assert out["additional_fields"]["endpoint_identity_state"] == "NOT_OBSERVED"


def test_the_sensor_identity_is_network_evidence_not_the_endpoint():
    out = normalize(conn_record())
    assert out["network"]["sensor_device_name"] == "zeek-sensor-01"
    assert out["host"]["hostname"] == ""


def test_the_dsm_declares_what_it_cannot_evidence():
    cannot = " ".join(ZeekJsonDSM().capability["does_not_provide"]).lower()
    for claim in ("process", "user identity", "allow/deny", "reputation"):
        assert claim in cannot


# ── GAP-1 on the endpoint side · Sysmon EID 22 ────────────────────
@pytest.mark.parametrize("raw,ips,records", [
    ("type:  5 cdn.example.net;type:  1 93.184.216.34;",
     ["93.184.216.34"], ["cdn.example.net"]),
    ("::ffff:93.184.216.34;", ["93.184.216.34"], []),
    ("-", [], []),
    ("", [], []),
    (None, [], []),
])
def test_sysmon_query_results_are_split_not_guessed(raw, ips, records):
    out = _sysmon_query_results(raw)
    assert out["ips"] == ips and out["records"] == records


def test_sysmon_dns_answers_reach_the_same_canonical_field():
    ev = {"event_id": 22, "provider": "Microsoft-Windows-Sysmon",
          "Computer": "WS-014", "User": "CORP\\alice",
          "Image": "C:\\Windows\\System32\\curl.exe", "ProcessId": 4711,
          "ProcessGuid": "{aaaa-bbbb}", "QueryName": DOMAIN,
          "QueryResults": f"type:  5 cdn.example.net;type:  1 {ANSWER};",
          "utc_time": "2026-06-08T10:00:00Z"}
    dsm = SysmonDSM()
    parsed = dsm.select_parser().parse(ev)
    out = dsm.select_normalizer().normalize(
        parsed, dsm.id, COL, "native", "trace-sysmon", tenant_id=TEN)
    net = out["network"]
    assert net["dns_query"] == DOMAIN
    assert net["dns_response_ips"] == [ANSWER]
    assert net["dns_response_records"] == ["cdn.example.net"]
    assert net["field_provenance"]["dns_response_ips"] == \
        "sysmon:EventData.QueryResults"
    # The endpoint side keeps what Zeek can never supply.
    assert out["process"]["executable_path"].endswith("curl.exe")


# ── GAP-2 / GAP-3 · pivots read the shapes DSMs emit ──────────────
def test_network_and_historical_pivots_read_both_canonical_shapes():
    from services.investigator.capabilities.network_identity_file import (
        NetworkPivotCapability, ip_query, network_endpoints)
    flat = normalize(conn_record())
    assert set(network_endpoints(flat)) == {("src", CLIENT), ("dst", ANSWER)}
    nested = {"network": {"src": {"ip": "1.1.1.1"}, "dst": {"ip": "2.2.2.2"}}}
    assert set(network_endpoints(nested)) == {("src", "1.1.1.1"),
                                              ("dst", "2.2.2.2")}
    assert ip_query("dst", ANSWER) == {"$or": [{"network.dst.ip": ANSWER},
                                               {"network.dest_ip": ANSWER}]}
    state, _ = NetworkPivotCapability().check_evidence({}, flat)
    assert state == "SUFFICIENT"


def test_the_dns_pivot_sees_a_domain_nivx_actually_recorded():
    from services.investigator.capabilities.network_identity_file import (
        DnsPivotCapability)
    out = normalize(dns_record())
    state, _ = DnsPivotCapability().check_evidence({}, out)
    assert state == "SUFFICIENT"
    assert DnsPivotCapability()._domains({}, out) == [DOMAIN]


# ── The correlation projection ────────────────────────────────────
def test_one_signal_per_dns_answer_carries_the_join_key():
    out = normalize(dns_record(answers=[ANSWER, "203.0.113.9"],
                               TTLs=[60.0, 60.0]))
    sigs = signals_from_canonical(out)
    assert [s["fields"]["network_peer_ip"] for s in sigs] == \
        [ANSWER, "203.0.113.9"]
    assert all(s["fields"]["client_ip"] == CLIENT for s in sigs)
    assert all(s["source_event_id"] == out["event_id"] for s in sigs)
    assert all(s["fields"]["dns_answer_state"] == "ADDRESS_ANSWERED"
               for s in sigs)


def test_an_unanswered_dns_record_offers_no_address_to_join_on():
    out = normalize(dns_record(rcode_name="NXDOMAIN", answers=[]))
    sig = signals_from_canonical(out)[0]
    assert "network_peer_ip" not in sig["fields"]
    assert sig["fields"]["dns_answer_state"] == "NO_ADDRESS_ANSWER"
    assert sig["fields"]["dns_rcode"] == "NXDOMAIN"


def test_a_connection_signal_carries_the_same_join_key_shape():
    sig = signals_from_canonical(normalize(conn_record()))[0]
    assert sig["fields"]["network_peer_ip"] == ANSWER
    assert sig["fields"]["client_ip"] == CLIENT
    assert sig["event_kind"] == "network_connect"


def test_the_projection_reads_the_nested_snort_shape_too():
    snort_like = {"event_id": "e1", "event_type": "network_alert",
                  "event_time": "2026-06-08T10:00:00+00:00",
                  "network": {"src": {"ip": CLIENT}, "dst": {"ip": ANSWER}}}
    sig = signals_from_canonical(snort_like)[0]
    assert sig["fields"]["network_peer_ip"] == ANSWER


def test_a_non_network_event_projects_nothing():
    assert signals_from_canonical(
        {"event_type": "cloud_audit", "network": {}}) == []


# ── The relationship, through the EXISTING engine ─────────────────
def _rule(name):
    from detection_content.correlation_library import (
        NETWORK_DNS_CORRELATION_SCENARIOS)
    return next(r for r in NETWORK_DNS_CORRELATION_SCENARIOS
                if r["id"] == name)


def _evaluate(rule, signals):
    """Drive the real engine over an in-memory window."""
    from routers import xdr_correlation as xc
    buf: list[dict] = []
    real_prune, real_persist, real_load = (
        xc._prune_state, xc._persist_state, xc._load_window_state)
    xc._prune_state = lambda *a, **k: None
    xc._persist_state = lambda t, r, e, s, m: buf.append(
        {"tenant_id": t, "rule_id": r, "entity_key": e,
         "signal_id": s.get("signal_id"), "at": s.get("at"),
         "matched_condition_ids": m, "signal": s})
    xc._load_window_state = lambda t, r, e, w: [b for b in buf
                                                if b["entity_key"] == e]
    try:
        out = None
        for s in signals:
            out = xc._evaluate({**rule, "id": rule["id"]},
                               {**s, "tenant_id": TEN}) or out
        return out
    finally:
        (xc._prune_state, xc._persist_state,
         xc._load_window_state) = real_prune, real_persist, real_load


def _sig(fields, *, kind, at, event_id):
    return {"signal_id": f"sig-{event_id}", "signal_kind": "event",
            "event_kind": kind, "at": at, "source_event_id": event_id,
            "fields": fields}


def test_both_network_rules_ship_disabled():
    for rid in ("CORR-NET-001", "CORR-NET-002"):
        r = _rule(rid)
        assert r["enabled"] is False and r["state"] == "DISABLED"


def test_dns_then_connection_to_the_resolved_ip_is_supported_and_cited():
    rule = _rule("CORR-NET-002")
    dns_evt, conn_evt = "cev-dns-1", "cev-conn-1"
    match = _evaluate(rule, [
        _sig({"client_ip": CLIENT, "network_peer_ip": ANSWER,
              "dns_query": DOMAIN, "dns_answer_state": "ADDRESS_ANSWERED"},
             kind="dns_query", at="2026-06-08T10:00:00+00:00",
             event_id=dns_evt),
        _sig({"client_ip": CLIENT, "network_peer_ip": ANSWER,
              "dest_port": 443}, kind="network_connect",
             at="2026-06-08T10:00:12+00:00", event_id=conn_evt),
    ])
    assert match is not None
    assert match["level"] == "CORRELATION_SUPPORTED"
    assert match["matched_conditions"] == ["A_DNS_ANSWER", "B_CONNECTION"]
    # The relationship cites the evidence it was built from.
    assert set(match["raw_event_ids"]) == {dns_evt, conn_evt}
    assert match["entity_key"] == f"{CLIENT}|{ANSWER}"
    assert match["capability_not_verdict"] is True


def test_a_connection_before_the_dns_answer_is_not_the_relationship():
    rule = _rule("CORR-NET-002")
    match = _evaluate(rule, [
        _sig({"client_ip": CLIENT, "network_peer_ip": ANSWER},
             kind="network_connect", at="2026-06-08T10:00:00+00:00",
             event_id="cev-conn-early"),
    ])
    assert match is None or match["level"] != "CORRELATION_SUPPORTED"


def test_a_different_client_does_not_join_the_same_address():
    rule = _rule("CORR-NET-002")
    match = _evaluate(rule, [
        _sig({"client_ip": CLIENT, "network_peer_ip": ANSWER,
              "dns_answer_state": "ADDRESS_ANSWERED"}, kind="dns_query",
             at="2026-06-08T10:00:00+00:00", event_id="cev-dns-2"),
        _sig({"client_ip": "10.8.0.99", "network_peer_ip": ANSWER},
             kind="network_connect", at="2026-06-08T10:00:10+00:00",
             event_id="cev-conn-2"),
    ])
    assert match is None or match["level"] != "CORRELATION_SUPPORTED"


def test_a_connection_to_a_different_address_does_not_join():
    rule = _rule("CORR-NET-002")
    match = _evaluate(rule, [
        _sig({"client_ip": CLIENT, "network_peer_ip": ANSWER,
              "dns_answer_state": "ADDRESS_ANSWERED"}, kind="dns_query",
             at="2026-06-08T10:00:00+00:00", event_id="cev-dns-3"),
        _sig({"client_ip": CLIENT, "network_peer_ip": "203.0.113.200"},
             kind="network_connect", at="2026-06-08T10:00:10+00:00",
             event_id="cev-conn-3"),
    ])
    assert match is None or match["level"] != "CORRELATION_SUPPORTED"


def test_an_unanswered_dns_record_cannot_start_the_relationship():
    rule = _rule("CORR-NET-002")
    match = _evaluate(rule, [
        _sig({"client_ip": CLIENT, "dns_answer_state": "NO_ADDRESS_ANSWER"},
             kind="dns_query", at="2026-06-08T10:00:00+00:00",
             event_id="cev-dns-4"),
        _sig({"client_ip": CLIENT, "network_peer_ip": ANSWER},
             kind="network_connect", at="2026-06-08T10:00:10+00:00",
             event_id="cev-conn-4"),
    ])
    assert match is None or match["level"] != "CORRELATION_SUPPORTED"


def test_nxdomain_burst_needs_the_declared_threshold():
    rule = _rule("CORR-NET-001")
    threshold = rule["operators"]["threshold"]
    sigs = [_sig({"client_ip": CLIENT, "dns_rcode": "NXDOMAIN",
                  "dns_query": f"{i}-rnd.example"}, kind="dns_query",
                 at=f"2026-06-08T10:00:{i:02d}+00:00", event_id=f"cev-nx-{i}")
            for i in range(threshold - 1)]
    assert _evaluate(rule, sigs) is None
    sigs.append(_sig({"client_ip": CLIENT, "dns_rcode": "NXDOMAIN",
                      "dns_query": "last-rnd.example"}, kind="dns_query",
                     at="2026-06-08T10:00:59+00:00", event_id="cev-nx-last"))
    match = _evaluate(rule, sigs)
    assert match is not None and match["level"] == "CORRELATION_SUPPORTED"
    assert match["count"] >= threshold
    assert len(match["raw_event_ids"]) >= threshold


def test_a_noerror_answer_never_counts_toward_the_nxdomain_burst():
    rule = _rule("CORR-NET-001")
    sigs = [_sig({"client_ip": CLIENT, "dns_rcode": "NOERROR"},
                 kind="dns_query", at=f"2026-06-08T10:01:{i:02d}+00:00",
                 event_id=f"cev-ok-{i}")
            for i in range(rule["operators"]["threshold"] + 5)]
    assert _evaluate(rule, sigs) is None


def test_two_clients_do_not_pool_into_one_burst():
    rule = _rule("CORR-NET-001")
    half = rule["operators"]["threshold"]
    sigs = []
    for i in range(half):
        sigs.append(_sig({"client_ip": "10.8.0.5", "dns_rcode": "NXDOMAIN"},
                         kind="dns_query",
                         at=f"2026-06-08T10:02:{i:02d}+00:00",
                         event_id=f"cev-a-{i}"))
        sigs.append(_sig({"client_ip": "10.8.0.6", "dns_rcode": "NXDOMAIN"},
                         kind="dns_query",
                         at=f"2026-06-08T10:02:{i:02d}+00:00",
                         event_id=f"cev-b-{i}"))
    match = _evaluate(rule, sigs)
    assert match is not None
    # Every counted signal belongs to ONE client — the entity key decides.
    assert match["entity_key"] in {"10.8.0.5", "10.8.0.6"}
    assert all(e["signal"]["fields"]["client_ip"] == match["entity_key"]
               for e in match["evidence_chain"])
