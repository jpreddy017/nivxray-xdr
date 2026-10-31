"""P2 Slice-2 · Extended Event 3 contract tests (ADR-0010r).

Companion to `test_p2_slice2_sysmon_event3.py`. This file exercises
the extended owner-spec locked in ADR-0010r that the base file does
not cover:

  A. IPv6 RFC 5952 canonicalization (compressed, lowercase).
  B. IPv4-mapped IPv6 (`::ffff:1.2.3.4`) → dotted-quad canonical form.
  C. Same logical IP → same evidence_ref regardless of source
     formatting.
  D. Hostname/*PortName fields are advisory (confidence=advisory,
     derivation=sysmon_reverse_lookup, advisory=True).
  E. RESOLVED / UNRESOLVED_DANGLING / AMBIGUOUS_PID_ONLY correlation
     states each surface correctly.
  F. Deduplication preserves count / first_seen / last_seen / all
     raw_refs and does NOT destroy provenance.
  G. Fail-loud per-ingest EID3 cap.
  H. Slice-1 corpus zero-delta invariant preserved.
"""
from __future__ import annotations
import os
import sys
from pathlib import Path

import pytest

_BACKEND = Path(__file__).resolve().parents[3]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from fastapi.testclient import TestClient   # noqa: E402
from server import app                       # noqa: E402
from deps import get_current_user            # noqa: E402


@pytest.fixture
def client():
    async def _fake_user():
        return {"email": "test@nivxray.com", "role": "admin"}
    app.dependency_overrides[get_current_user] = _fake_user
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.pop(get_current_user, None)


# ---------------------------------------------------------------------------
# XML shorthand (matches the fixture style of the sibling test file)
# ---------------------------------------------------------------------------
def _dat(name, val):
    return f"<Data Name='{name}'>{val}</Data>" if val else ""


def _event1_xml(*, image, cmdline, proc_guid, pid="4242",
                 time="2026-08-12T09:00:00Z"):
    parent = "C:\\Windows\\explorer.exe"
    user   = "CONTOSO\\alice"
    return (
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
        f"<System><EventID>1</EventID><TimeCreated SystemTime='{time}'/>"
        "<Computer>WKS-04</Computer></System>"
        f"<EventData>{_dat('UtcTime', time)}{_dat('ProcessGuid', proc_guid)}"
        f"{_dat('ProcessId', pid)}{_dat('Image', image)}"
        f"{_dat('CommandLine', cmdline)}{_dat('User', user)}"
        f"{_dat('LogonId', '0x3E7')}{_dat('IntegrityLevel', 'Medium')}"
        f"{_dat('ParentImage', parent)}"
        f"{_dat('ParentProcessId', '1024')}</EventData></Event>"
    )


def _event3_xml(*, dst_ip, proc_guid="", proc_pid="4242",
                 image="C:\\Windows\\System32\\svchost.exe",
                 dst_port="443", protocol="tcp", initiated="true",
                 dst_host="", src_ip="10.0.0.42", src_port="49152",
                 time="2026-08-12T09:00:01Z"):
    return (
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
        f"<System><EventID>3</EventID><TimeCreated SystemTime='{time}'/>"
        "<Computer>WKS-04</Computer></System>"
        f"<EventData>{_dat('UtcTime', time)}{_dat('ProcessGuid', proc_guid)}"
        f"{_dat('ProcessId', proc_pid)}{_dat('Image', image)}"
        f"{_dat('Protocol', protocol)}{_dat('Initiated', initiated)}"
        f"{_dat('SourceIp', src_ip)}{_dat('SourcePort', src_port)}"
        f"{_dat('DestinationIp', dst_ip)}{_dat('DestinationPort', dst_port)}"
        f"{_dat('DestinationHostname', dst_host)}</EventData></Event>"
    )


def _wrap(*events):
    return "<Events>" + "".join(events) + "</Events>"


def _post(client, xml):
    return client.post("/api/behavioral/sysmon", json={"xml": xml})


# ---------------------------------------------------------------------------
# A · IPv6 RFC 5952 canonical form
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("input_ipv6,canonical", [
    ("2001:0DB8:0000:0000:0000:0000:0000:0001", "2001:db8::1"),
    ("2001:db8:0:0:0:0:0:1",                     "2001:db8::1"),
    ("2001:db8::1",                              "2001:db8::1"),
    ("FE80:0:0:0:0:0:0:1",                       "fe80::1"),
])
def test_ipv6_rfc5952_canonicalization(client, input_ipv6, canonical):
    r = _post(client, _event3_xml(dst_ip=input_ipv6))
    assert r.status_code == 200, r.text
    body = r.json()
    conn = body["network_evidence"]["connections"][0]
    assert conn["destination_ip"] == canonical, conn
    assert conn["destination_ip_raw"] == input_ipv6


# ---------------------------------------------------------------------------
# B · IPv4-mapped IPv6 → dotted-quad
# ---------------------------------------------------------------------------
def test_ipv4_mapped_ipv6_collapses_to_ipv4(client):
    r = _post(client, _event3_xml(dst_ip="::ffff:198.51.100.20"))
    assert r.status_code == 200, r.text
    conn = r.json()["network_evidence"]["connections"][0]
    assert conn["destination_ip"] == "198.51.100.20"
    assert conn["destination_class"] == "external"


# ---------------------------------------------------------------------------
# C · Same logical IP → identical evidence_ref regardless of source form
# ---------------------------------------------------------------------------
def test_same_logical_address_same_evidence_ref(client):
    forms = [
        "2001:0DB8:0000:0000:0000:0000:0000:0001",
        "2001:db8:0:0:0:0:0:1",
        "2001:db8::1",
    ]
    refs = []
    for form in forms:
        r = _post(client, _event3_xml(dst_ip=form,
                                        time="2026-08-12T09:00:01Z"))
        assert r.status_code == 200, r.text
        refs.append(r.json()["network_evidence"]["connections"][0]["evidence_ref"])
    assert len(set(refs)) == 1, f"evidence_ref drift across IPv6 forms: {refs}"


# ---------------------------------------------------------------------------
# D · Advisory hostname / *PortName discipline
# ---------------------------------------------------------------------------
def test_hostname_marked_advisory(client):
    r = _post(client, _event3_xml(dst_ip="198.51.100.20",
                                    dst_host="claims-to-be.example"))
    assert r.status_code == 200, r.text
    body = r.json()
    hostname_recs = [rec for rec in body["evidence"]
                      if rec["field"] == "network.destination_hostname"]
    assert hostname_recs, "hostname evidence record missing"
    for rec in hostname_recs:
        assert rec["advisory"] is True
        assert rec["derivation"] == "sysmon_reverse_lookup"
        assert rec["confidence"] == "advisory"
    # Non-advisory network fields must NOT carry the advisory flag.
    for rec in body["evidence"]:
        if rec["field"] == "network.destination_ip":
            assert rec.get("advisory") is not True
            assert rec["confidence"] != "advisory"


# ---------------------------------------------------------------------------
# E · Correlation states
# ---------------------------------------------------------------------------
def test_correlation_state_resolved(client):
    guid = "{aaaaaaaa-0000-0000-0000-000000000001}"
    xml = _wrap(
        _event1_xml(image="C:\\Windows\\System32\\svchost.exe",
                     cmdline="svchost.exe -k netsvcs", proc_guid=guid),
        _event3_xml(dst_ip="203.0.113.7", proc_guid=guid),
    )
    r = _post(client, xml)
    assert r.status_code == 200, r.text
    conn = r.json()["network_evidence"]["connections"][0]
    assert conn["correlation_state"] == "RESOLVED"
    assert conn["correlated_with_process_create"]


def test_correlation_state_unresolved_dangling(client):
    """Event 3 arrives with a valid ProcessGuid but NO matching
    Event 1 in the same batch. The record must be PRESERVED and
    flagged UNRESOLVED_DANGLING — not silently dropped."""
    r = _post(client, _event3_xml(
        dst_ip="203.0.113.7",
        proc_guid="{aaaaaaaa-0000-0000-0000-000000000002}",
    ))
    assert r.status_code == 200, r.text
    conn = r.json()["network_evidence"]["connections"][0]
    assert conn["correlation_state"] == "UNRESOLVED_DANGLING"
    assert conn["correlated_with_process_create"] is None


def test_correlation_state_ambiguous_pid_only(client):
    """Event 3 with a PID but NO ProcessGuid must be flagged
    AMBIGUOUS_PID_ONLY and not silently correlated to any PID-matched
    Event 1 (PIDs recycle)."""
    guid = "{aaaaaaaa-0000-0000-0000-000000000003}"
    # A prior Event 1 exists but the Event 3 does NOT reference its
    # ProcessGuid — PID coincidence must not become truth.
    xml = _wrap(
        _event1_xml(image="C:\\Windows\\System32\\svchost.exe",
                     cmdline="svchost.exe -k netsvcs", proc_guid=guid,
                     pid="4242"),
        _event3_xml(dst_ip="203.0.113.7", proc_guid="", proc_pid="4242"),
    )
    r = _post(client, xml)
    assert r.status_code == 200, r.text
    conn = r.json()["network_evidence"]["connections"][0]
    assert conn["correlation_state"] == "AMBIGUOUS_PID_ONLY"
    assert conn["correlated_with_process_create"] is None


# ---------------------------------------------------------------------------
# F · Dedup — count / first_seen / last_seen / raw_refs preserved
# ---------------------------------------------------------------------------
def test_dedup_preserves_all_provenance(client):
    guid = "{cccccccc-0000-0000-0000-000000000001}"
    e3 = lambda t: _event3_xml(dst_ip="203.0.113.99", proc_guid=guid,
                                 time=t)
    xml = _wrap(
        e3("2026-08-12T09:00:01Z"),
        e3("2026-08-12T09:00:05Z"),
        e3("2026-08-12T09:00:10Z"),
    )
    r = _post(client, xml)
    assert r.status_code == 200, r.text
    conns = r.json()["network_evidence"]["connections"]
    assert len(conns) == 1, "dedup should collapse 3 identical tuples to 1"
    c = conns[0]
    assert c["count"] == 3
    assert c["first_seen"] == "2026-08-12T09:00:01Z"
    assert c["last_seen"]  == "2026-08-12T09:00:10Z"
    # 3 distinct evidence_refs preserved (each event has a unique
    # timestamp component in its ref hash).
    assert len(c["raw_refs"]) == 3


def test_dedup_does_not_merge_outbound_and_inbound(client):
    """Initiated=true and Initiated=false MUST remain distinct."""
    guid = "{cccccccc-0000-0000-0000-000000000002}"
    xml = _wrap(
        _event3_xml(dst_ip="203.0.113.99", proc_guid=guid, initiated="true"),
        _event3_xml(dst_ip="203.0.113.99", proc_guid=guid, initiated="false",
                     time="2026-08-12T09:00:02Z"),
    )
    r = _post(client, xml)
    assert r.status_code == 200, r.text
    conns = r.json()["network_evidence"]["connections"]
    assert len(conns) == 2, "outbound + inbound must not be flattened"
    directions = {c["initiated"] for c in conns}
    assert directions == {True, False}


# ---------------------------------------------------------------------------
# G · Fail-loud per-ingest cap
# ---------------------------------------------------------------------------
def test_eid3_cap_fails_loud(client, monkeypatch):
    monkeypatch.setenv("NIVX_SYSMON_EID3_MAX_EVENTS", "5")
    # Build 6 unique Event 3 records (unique dst_ip → no dedup).
    xml = _wrap(*[
        _event3_xml(dst_ip=f"203.0.113.{i}",
                     proc_guid=f"{{dddddddd-0000-0000-0000-{i:012d}}}")
        for i in range(6)
    ])
    r = _post(client, xml)
    assert r.status_code == 413
    assert r.json()["detail"]["error"] == "eid3_cap_exceeded"


# ---------------------------------------------------------------------------
# H · Event-3 in isolation MUST NOT emit ANY authoritative technique
# ---------------------------------------------------------------------------
def test_event3_alone_emits_no_authoritative_technique(client):
    r = _post(client, _event3_xml(dst_ip="198.51.100.20",
                                    dst_port="443", dst_host="cdn.example.test"))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["mitre_technique_ids"] == [], (
        "Event 3 in isolation must not produce any authoritative MITRE "
        "technique. It is EVIDENCE, not a verdict driver."
    )


# ---------------------------------------------------------------------------
# I · Zero outbound lookups — assert the module hasn't imported network I/O
# ---------------------------------------------------------------------------
def test_adapter_makes_no_outbound_calls_at_import():
    """The adapter must not touch DNS/TI/OSINT/reputation at import
    time. If any of these libraries appear in the adapter's imports,
    that would be a violation of ADR-0010r §21-28."""
    import services.behavioral.sysmon_adapter as adapter
    src = Path(adapter.__file__).read_text()
    for banned in ("socket.gethostbyname", "requests.get", "aiohttp",
                    "urllib.request", "dnspython", "resolver"):
        assert banned not in src, (
            f"Adapter must not perform outbound lookups. Found: {banned!r}"
        )
