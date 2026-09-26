"""Gate N2.1 · endpoint / process → network attribution.

The gate's whole claim is a negative one: NivXRay XDR must be **unable** to
turn address and time coincidence into process attribution. So most of what
follows asserts that a relationship does NOT appear.

  * Sysmon's `ProcessGuid` — parsed since forever, discarded until now —
    reaches canonical evidence on EID 1, 3 and 22, with provenance;
  * the NivXForge sensor's socket-inode PID becomes a real identity only
    when the process START identity came with it, and the endpoint scope is
    applied where the authenticated endpoint is known;
  * the three attribution states are honest and each carries WHY;
  * `CORR-EP-001` requires endpoint + process identity + peer + order, and
    a PID-only or unobserved process cannot enter it at all;
  * endpoint address observations are evidence with a lifecycle, and are
    structurally refused as identity.

EVIDENCE LABELLING — TEST/SYNTHETIC records in each source's documented
shape. Live Sysmon feed is ABSENT and the live sensor host is
EXTERNAL_ACCESS_BLOCKED; nothing here claims otherwise.
"""
from __future__ import annotations

import json

import pytest

from detection_content.telemetry.network_signals import signals_from_canonical
from detection_content.telemetry.sysmon_dsm import SysmonDSM
from edr_plane.canonical_bridge import bind_process_identity, parse

TEN = "t-n2"
EP = "ep_9f2c41aa"
OTHER_EP = "ep_0000ffff"
GUID = "{1a2b3c4d-0001-6661-0000-00000abc0001}"
PEER = "203.0.113.55"
DOMAIN = "n2-proof.example-cdn.net"


# ── A · Sysmon keeps the identity it was always given ─────────────
def sysmon(eid, **over):
    ev = {"event_id": eid, "provider": "Microsoft-Windows-Sysmon",
          "Computer": "WS-N2", "User": "CORP\\alice",
          "Image": "C:\\Windows\\System32\\curl.exe", "ProcessId": "4711",
          "ProcessGuid": GUID,
          "ParentProcessGuid": "{1a2b3c4d-0000-6661-0000-00000abc0000}",
          "UtcTime": "2026-06-08T10:00:00+00:00"}
    ev.update(over)
    return ev


def norm_sysmon(ev, tenant=TEN):
    d = SysmonDSM()
    return d.select_normalizer().normalize(
        d.select_parser().parse(ev), d.id, "col", "native", "trace",
        tenant_id=tenant)


@pytest.mark.parametrize("eid,extra", [
    (1, {"CommandLine": "curl https://x"}),
    (3, {"SourceIp": "10.9.0.4", "DestinationIp": PEER,
         "DestinationPort": "443", "Protocol": "tcp"}),
    (22, {"QueryName": DOMAIN, "QueryResults": f"type:  1 {PEER};"}),
])
def test_process_guid_reaches_canonical_evidence(eid, extra):
    out = norm_sysmon(sysmon(eid, **extra))
    proc = out["process"]
    assert proc["process_guid"] == GUID
    assert proc["parent_process_guid"].endswith("abc0000}")
    assert proc["field_provenance"]["process_guid"] == \
        "sysmon:EventData.ProcessGuid"
    assert proc["attribution_state"] == "SOURCE_PROCESS_IDENTITY"
    assert "SAME record" in proc["attribution_reason"]
    # It is reachable from the evidence reference too, not only the parser.
    assert out["raw_ref"]["process_guid"] == GUID


def test_a_sysmon_record_without_a_guid_is_pid_only():
    ev = sysmon(3, SourceIp="10.9.0.4", DestinationIp=PEER,
                DestinationPort="443")
    ev.pop("ProcessGuid")
    proc = norm_sysmon(ev)["process"]
    assert proc["process_guid"] == ""
    assert proc["attribution_state"] == "PID_ONLY_NOT_AUTHORITATIVE"
    assert "reused" in proc["attribution_reason"]


def test_the_guid_does_not_disturb_any_existing_field():
    out = norm_sysmon(sysmon(3, SourceIp="10.9.0.4", DestinationIp=PEER,
                             DestinationPort="443", Protocol="tcp"))
    assert out["event_type"] == "network_connect"
    assert out["process"]["pid"] == 4711
    assert out["process"]["executable_path"].endswith("curl.exe")
    assert out["network"]["dest_ip"] == PEER
    assert out["additional_fields"]["event_time_basis"] == "ACTIVITY_TIME"


# ── B · the Linux sensor: PID alone is never enough ───────────────
def sensor_net(**over):
    ev = {"activity": "NETWORK", "operation": "CONNECTION_OBSERVED",
          "observed_at": "2026-06-08T10:00:05+00:00", "protocol": "TCP",
          "local_ip": "10.9.0.4", "local_port": 44122,
          "remote_ip": PEER, "remote_port": 443, "direction": "OUTBOUND",
          "tcp_state": "01", "pid": 4711,
          "process_start_ticks": 998877,
          "process_start_time": "2026-06-08T09:59:00+00:00",
          "not_observed": []}
    ev.update(over)
    return ev


def bridged(ev, endpoint=EP):
    return bind_process_identity(parse(json.dumps(ev)), endpoint)


def test_start_identity_plus_endpoint_makes_a_real_process_identity():
    proc = bridged(sensor_net())["process"]
    assert proc["attribution_state"] == "SOURCE_PROCESS_IDENTITY"
    assert proc["process_iid"].startswith("proc_")
    assert proc["start_time"] == "2026-06-08T09:59:00+00:00"
    assert "PID reuse" in proc["attribution_reason"]
    assert proc["field_provenance"]["pid"].startswith("sensor:/proc/net")


def test_a_pid_without_start_identity_stays_non_authoritative():
    ev = sensor_net(not_observed=["owning_process_start_identity"])
    ev.pop("process_start_ticks"); ev.pop("process_start_time")
    proc = bridged(ev)["process"]
    assert proc["attribution_state"] == "PID_ONLY_NOT_AUTHORITATIVE"
    assert "process_iid" not in proc
    assert "exited" in proc["attribution_reason"]


def test_an_unresolved_socket_names_no_process_at_all():
    ev = sensor_net(pid=None, not_observed=["owning_process"])
    ev.pop("process_start_ticks"); ev.pop("process_start_time")
    proc = bridged(ev)["process"]
    assert proc["attribution_state"] == "NOT_OBSERVED"
    assert "pid" not in proc
    assert "not observed" in proc["attribution_reason"]


def test_without_an_endpoint_scope_the_identity_is_downgraded():
    proc = bridged(sensor_net(), endpoint=None)["process"]
    assert proc["attribution_state"] == "PID_ONLY_NOT_AUTHORITATIVE"
    assert "not unique" in proc["attribution_reason"]


def test_pid_reuse_produces_two_different_identities():
    a = bridged(sensor_net())["process"]["process_iid"]
    b = bridged(sensor_net(
        process_start_ticks=1010101,
        process_start_time="2026-06-08T10:30:00+00:00"))["process"][
            "process_iid"]
    assert a != b


def test_the_same_pid_on_two_endpoints_is_two_processes():
    a = bridged(sensor_net(), endpoint=EP)["process"]["process_iid"]
    b = bridged(sensor_net(), endpoint=OTHER_EP)["process"]["process_iid"]
    assert a != b


def test_the_process_lane_also_carries_the_lifetime_identity():
    ev = {"activity": "PROCESS", "operation": "PROCESS_OBSERVED",
          "observed_at": "2026-06-08T10:00:00+00:00",
          "start_time": "2026-06-08T09:59:00+00:00",
          "start_ticks": 998877, "pid": 4711, "ppid": 1,
          "image": "curl", "image_path": "/usr/bin/curl",
          "user": "alice", "parent_lookup_state": "OBSERVED"}
    proc = bridged(ev)["process"]
    assert proc["attribution_state"] == "SOURCE_PROCESS_IDENTITY"
    assert proc["process_iid"] == bridged(sensor_net())["process"][
        "process_iid"], "one process, one identity, on both lanes"


# ── C · the projection refuses to hand out a key it cannot back ───
def _canon_dns(state="SOURCE_PROCESS_IDENTITY", key=GUID, endpoint=EP,
               answers=(PEER,)):
    proc = {"attribution_state": state, "attribution_reason": "test",
            "pid": 4711, "executable_path": "C:\\curl.exe"}
    if key:
        proc["process_guid"] = key
    return {"event_id": "cev-dns", "event_type": "dns_query",
            "event_time": "2026-06-08T10:00:00+00:00",
            "host": {"host_id": endpoint},
            "additional_fields": {"endpoint_id": endpoint},
            "process": proc,
            "network": {"src_ip": "10.9.0.4", "dns_query": DOMAIN,
                        "dns_response_ips": list(answers)}}


def _canon_conn(state="SOURCE_PROCESS_IDENTITY", key=GUID, endpoint=EP,
                peer=PEER, event_id="cev-conn"):
    proc = {"attribution_state": state, "attribution_reason": "test",
            "pid": 4711}
    if key:
        proc["process_guid"] = key
    return {"event_id": event_id, "event_type": "network_connect",
            "event_time": "2026-06-08T10:00:20+00:00",
            "host": {"host_id": endpoint},
            "additional_fields": {"endpoint_id": endpoint},
            "process": proc,
            "network": {"src_ip": "10.9.0.4", "dest_ip": peer,
                        "dest_port": 443}}


def test_an_authoritative_process_contributes_a_key():
    f = signals_from_canonical(_canon_dns())[0]["fields"]
    assert f["process_key"] == GUID
    assert f["endpoint_id"] == EP
    assert f["process_attribution_state"] == "SOURCE_PROCESS_IDENTITY"
    assert f["endpoint_identity_basis"] == "AUTHENTICATED_ENDPOINT_ID"


def test_a_hostname_scope_is_labelled_as_inferred_not_identity():
    canonical = _canon_dns()
    canonical["additional_fields"] = {}
    canonical["host"] = {"host_id": "WS-N2"}
    f = signals_from_canonical(canonical)[0]["fields"]
    assert f["endpoint_id"] == "WS-N2"
    assert f["endpoint_identity_basis"] == "HOSTNAME_INFERRED"


@pytest.mark.parametrize("state,key", [
    ("PID_ONLY_NOT_AUTHORITATIVE", GUID),
    ("PID_ONLY_NOT_AUTHORITATIVE", None),
    ("NOT_OBSERVED", None),
])
def test_a_non_authoritative_process_contributes_no_key(state, key):
    f = signals_from_canonical(_canon_conn(state=state, key=key))[0]["fields"]
    assert "process_key" not in f
    assert f["process_attribution_state"] == state


def test_a_network_only_source_carries_no_process_state_beyond_absence():
    zeek_like = {"event_id": "cev-z", "event_type": "network_connect",
                 "event_time": "2026-06-08T10:00:00+00:00",
                 "network": {"src_ip": "10.9.0.4", "dest_ip": PEER}}
    f = signals_from_canonical(zeek_like)[0]["fields"]
    assert f["process_attribution_state"] == "NOT_OBSERVED"
    assert "process_key" not in f


# ── D · CORR-EP-001, through the EXISTING engine ──────────────────
def _rule():
    from detection_content.correlation_library import (
        ENDPOINT_PROCESS_NETWORK_SCENARIOS)
    return ENDPOINT_PROCESS_NETWORK_SCENARIOS[0]


def _evaluate(rule, signals):
    from routers import xdr_correlation as xc
    buf: list[dict] = []
    real = (xc._prune_state, xc._persist_state, xc._load_window_state)
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
            out = xc._evaluate(rule, {**s, "tenant_id": TEN}) or out
        return out
    finally:
        (xc._prune_state, xc._persist_state, xc._load_window_state) = real


def _sig(canonical, signal_id):
    s = signals_from_canonical(canonical)[0]
    return {**s, "signal_id": signal_id}


def test_the_rule_ships_disabled():
    r = _rule()
    assert r["enabled"] is False and r["state"] == "DISABLED"
    assert r["group_by"] == ["endpoint_id", "process_key", "network_peer_ip"]


def test_one_process_resolving_then_connecting_is_supported_and_cited():
    m = _evaluate(_rule(), [_sig(_canon_dns(), "s1"),
                            _sig(_canon_conn(), "s2")])
    assert m is not None and m["level"] == "CORRELATION_SUPPORTED"
    assert m["matched_conditions"] == ["A_PROC_DNS", "B_PROC_CONN"]
    assert set(m["raw_event_ids"]) == {"cev-dns", "cev-conn"}
    assert m["entity_key"] == f"{EP}|{GUID}|{PEER}"
    assert m["capability_not_verdict"] is True


def test_a_different_process_on_the_same_host_and_address_does_not_join():
    other = "{1a2b3c4d-9999-6661-0000-00000abc9999}"
    m = _evaluate(_rule(), [
        _sig(_canon_dns(), "s1"),
        _sig(_canon_conn(key=other, event_id="cev-other-proc"), "s2")])
    assert m is None or m["level"] != "CORRELATION_SUPPORTED"


def test_the_same_process_identity_on_another_endpoint_does_not_join():
    m = _evaluate(_rule(), [
        _sig(_canon_dns(), "s1"),
        _sig(_canon_conn(endpoint=OTHER_EP, event_id="cev-ep2"), "s2")])
    assert m is None or m["level"] != "CORRELATION_SUPPORTED"


def test_a_connection_to_a_different_peer_does_not_join():
    m = _evaluate(_rule(), [
        _sig(_canon_dns(), "s1"),
        _sig(_canon_conn(peer="198.51.100.9", event_id="cev-peer2"), "s2")])
    assert m is None or m["level"] != "CORRELATION_SUPPORTED"


def test_a_connection_before_the_resolution_does_not_join():
    conn = _canon_conn(event_id="cev-early")
    conn["event_time"] = "2026-06-08T09:59:00+00:00"
    m = _evaluate(_rule(), [_sig(conn, "s1")])
    assert m is None or m["level"] != "CORRELATION_SUPPORTED"


def test_pid_only_evidence_cannot_enter_the_relationship():
    m = _evaluate(_rule(), [
        _sig(_canon_dns(state="PID_ONLY_NOT_AUTHORITATIVE", key=None), "s1"),
        _sig(_canon_conn(state="PID_ONLY_NOT_AUTHORITATIVE", key=None),
             "s2")])
    assert m is None


def test_address_and_time_coincidence_alone_produce_nothing():
    """The prohibition, stated as a test: two records that agree on
    address and instant but carry no process identity."""
    dns = _canon_dns(state="NOT_OBSERVED", key=None)
    conn = _canon_conn(state="NOT_OBSERVED", key=None)
    conn["event_time"] = dns["event_time"]
    assert _evaluate(_rule(), [_sig(dns, "s1"), _sig(conn, "s2")]) is None


def test_a_process_attributed_dns_with_an_unattributed_connection_fails():
    m = _evaluate(_rule(), [
        _sig(_canon_dns(), "s1"),
        _sig(_canon_conn(state="NOT_OBSERVED", key=None,
                         event_id="cev-unattr"), "s2")])
    assert m is None or m["level"] != "CORRELATION_SUPPORTED"


def test_an_unanswered_resolution_cannot_start_the_relationship():
    m = _evaluate(_rule(), [_sig(_canon_dns(answers=()), "s1"),
                            _sig(_canon_conn(), "s2")])
    assert m is None or m["level"] != "CORRELATION_SUPPORTED"


def test_the_network_only_rule_is_unaffected_by_the_process_rule():
    from detection_content.correlation_library import (
        NETWORK_DNS_CORRELATION_SCENARIOS)
    net_rule = next(r for r in NETWORK_DNS_CORRELATION_SCENARIOS
                    if r["id"] == "CORR-NET-002")
    m = _evaluate(net_rule, [_sig(_canon_dns(), "s1"),
                             _sig(_canon_conn(), "s2")])
    assert m is not None and m["level"] == "CORRELATION_SUPPORTED"
    # …and it remains a NETWORK claim: its key names no process.
    assert m["entity_key"] == f"10.9.0.4|{PEER}"


# ── E · endpoint address observations are evidence, not identity ──
class _FakeCursor:
    def __init__(self, rows):
        self._rows = rows

    def __aiter__(self):
        async def gen():
            for r in self._rows:
                yield r
        return gen()


class _FakeColl:
    def __init__(self, rows=()):
        self.rows = list(rows)
        self.updates = []

    def find(self, *a, **k):
        return _FakeCursor(self.rows)

    async def update_one(self, flt, update, upsert=False):
        self.updates.append((flt, update, upsert))

    async def create_index(self, *a, **k):
        return None


class _FakeDb(dict):
    def __getitem__(self, k):
        return dict.setdefault(self, k, _FakeColl())


@pytest.mark.asyncio
async def test_only_the_endpoints_own_address_is_recorded():
    from edr_plane import endpoint_address_observation as eao
    db = _FakeDb()
    canonical = bridged(sensor_net())
    canonical["event_id"] = "cev-net-1"
    out = await eao.record_from_canonical(
        db, tenant_id=TEN, endpoint_id=EP, canonical=canonical)
    assert out["address"] == "10.9.0.4"          # local side only
    flt, update, upsert = db[eao.COLLECTION].updates[0]
    assert flt["endpoint_id"] == EP and upsert is True
    assert update["$setOnInsert"]["binding_policy"] == \
        "TIME_BOUNDED_OBSERVATION_NOT_IDENTITY"
    assert update["$set"]["provenance"]["observed_field"] == "network.src_ip"
    assert PEER not in json.dumps(update), "a peer address is not ours"


@pytest.mark.asyncio
async def test_a_lookup_never_returns_an_attribution():
    from edr_plane import endpoint_address_observation as eao
    db = _FakeDb()
    db[eao.COLLECTION].rows = [
        {"endpoint_id": EP, "address": "10.9.0.4",
         "first_observed_at": "2026-06-08T09:00:00+00:00",
         "last_observed_at": "2026-06-08T11:00:00+00:00"},
    ]
    one = await eao.lookup(db, tenant_id=TEN, address="10.9.0.4",
                           at="2026-06-08T10:00:00+00:00")
    assert one["state"] == "SINGLE_CANDIDATE_TIME_BOUNDED"
    assert one["usable_for_attribution"] is False
    assert "DHCP" in one["reason"]

    db[eao.COLLECTION].rows.append(
        {"endpoint_id": OTHER_EP, "address": "10.9.0.4",
         "first_observed_at": "2026-06-08T09:30:00+00:00",
         "last_observed_at": "2026-06-08T10:30:00+00:00"})
    many = await eao.lookup(db, tenant_id=TEN, address="10.9.0.4",
                            at="2026-06-08T10:00:00+00:00")
    assert many["state"] == "MULTIPLE_CANDIDATES_AMBIGUOUS"
    assert many["usable_for_attribution"] is False


@pytest.mark.asyncio
async def test_an_address_observed_at_another_time_says_nothing_about_now():
    from edr_plane import endpoint_address_observation as eao
    db = _FakeDb()
    db[eao.COLLECTION].rows = [
        {"endpoint_id": EP, "address": "10.9.0.4",
         "first_observed_at": "2026-06-07T09:00:00+00:00",
         "last_observed_at": "2026-06-07T11:00:00+00:00"}]
    out = await eao.lookup(db, tenant_id=TEN, address="10.9.0.4",
                           at="2026-06-08T10:00:00+00:00")
    assert out["state"] == "OUTSIDE_OBSERVED_WINDOW"
    assert out["usable_for_attribution"] is False


@pytest.mark.asyncio
async def test_an_unseen_address_has_no_candidates():
    from edr_plane import endpoint_address_observation as eao
    out = await eao.lookup(_FakeDb(), tenant_id=TEN, address="192.0.2.9")
    assert out["state"] == "NO_OBSERVATION" and out["candidates"] == []
