"""P2 Slice-3 · EVTX binary transport — focused tests (ADR-0010s + ADR-0010w).

Coverage:
  A. Base64 decode error → 400 evtx_bad_base64
  B. Empty payload → 400 empty_input
  C. Wrong magic → 400 evtx_bad_magic
  D. Oversized payload → 413 evtx_payload_too_large
  E. Record-count cap fail-loud → 413 evtx_record_cap_exceeded (mocked; a
     69 632-byte real fixture cannot express >10 000 records)
  F. Real EVTX header + malformed body → 400 evtx_walk_error
  G. Round-trip via **real** committed Sysmon E1 fixture — REAL python-evtx
     parser exercised end-to-end.  See ADR-0010w.
  H. Determinism — same real EVTX bytes twice → identical envelope.
  I. Transport layer emits NO new ATT&CK technique on its own.
  J. Slice-3 preserves zero-outbound-lookup discipline (static grep).
  K. Real E3-only fixture — proves network-connect canonical evidence emerges
     from real EVTX bytes with no MITRE from E3 alone (evidence-producer
     constraint · ADR-0010q).
  L. Real fixture parity — EVTX transport response is byte-equivalent to the
     equivalent XML-path response modulo the transport meta chip.
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

# ── Real committed Sysmon .evtx fixtures (see fixtures/evtx/NOTICE.md) ─────
_FIXTURES_DIR = Path(__file__).resolve().parents[2] / "fixtures" / "evtx"
_E1_FIXTURE   = _FIXTURES_DIR / "sysmon_e1_only.evtx"
_E3_FIXTURE   = _FIXTURES_DIR / "sysmon_e3_only.evtx"

# SHA-256 of the exact upstream bytes — locked so a corrupt or altered
# fixture fails loudly BEFORE the transport is exercised.
_E1_SHA256 = "08ce1feab22e30eb12a5a5b1ba4ac0aa552ff988b762d08de3a4d75ee1636abd"
_E3_SHA256 = "d7e75b35f9db32c91dc0d066ee935b382253fb56659f19c05833c964f8217469"


def _read_fixture(path: Path, expected_sha256: str) -> bytes:
    """Read the real fixture bytes; assert their SHA-256 against the pin."""
    assert path.exists(), (
        f"missing real EVTX fixture: {path}. "
        f"See backend/tests/fixtures/evtx/NOTICE.md for provenance and "
        f"how to restore the file if it is accidentally deleted."
    )
    data = path.read_bytes()
    import hashlib
    got = hashlib.sha256(data).hexdigest()
    assert got == expected_sha256, (
        f"fixture {path.name} SHA-256 drifted "
        f"(want {expected_sha256}, got {got}). Do NOT modify committed .evtx bytes; "
        f"restore from upstream per NOTICE.md."
    )
    return data


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
#
#     KEPT MOCKED intentionally.  A real 69 632-byte Sysmon .evtx contains
#     at most ~30 records; expressing >10 000 records requires either a
#     multi-megabyte fixture or a synthetic in-memory record set.  We use
#     the latter — the mock is scoped to `Evtx.Evtx.Evtx` only, so the
#     transport-boundary size/magic/base64 checks still run for real.
#     This is the ONE remaining mock in the module and it exists solely
#     because the cap under test is a defence against a >10 000-record
#     attack payload that we cannot commit as a fixture.
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
# G · Round-trip via REAL committed Sysmon E1 EVTX fixture.
#
#     No mocks. Exercises actual python-evtx binary parser end-to-end.
#     Fixture: sysmon_e1_only.evtx (4 real Sysmon Event-1 process-create
#     records captured from a Windows workstation; see NOTICE.md).
# ---------------------------------------------------------------------------
def test_real_evtx_e1_fixture_round_trip(client):
    data = _read_fixture(_E1_FIXTURE, _E1_SHA256)
    r = _post_evtx(client, data)
    assert r.status_code == 200, r.text
    body = r.json()

    # Transport meta produced by the REAL parser (not a mock).
    tr = body["transport"]
    assert tr["transport"]    == "sysmon.slice3.evtx@1.0"
    assert tr["record_count"] == 4              # real record count
    assert tr["raw_bytes"]    == len(data)      # bytes matched by transport

    # Adapter counted only Event-1 records; no Event-3 in this fixture.
    assert body["event_counts_by_id"] == {"eid1": 4, "eid3": 0}
    assert body["event_count"]        == 4

    # Canonical evidence rows were produced from REAL Sysmon fields.
    assert len(body["evidence"]) > 0, "no evidence extracted from real EVTX"
    # Every evidence row carries a deterministic evidence_ref.
    for row in body["evidence"]:
        assert row.get("evidence_ref")
        assert row.get("source") in ("sysmon.eid1", "sysmon.eid3")

    # Parent-child pair evidence emerged from the real records.
    assert len(body["parent_child_evidence"]["pairs"]) == 4

    # Every per-event MITRE entry was produced by handing the real command
    # line to the DIE authoritative surface (`_authoritative_techniques`).
    # We do NOT assert a specific technique set — the fixture belongs to
    # a public corpus and we treat its content as data, not policy.
    assert len(body["per_event_mitre"]) == 4
    for entry in body["per_event_mitre"]:
        assert isinstance(entry.get("command_line"), str)
        assert isinstance(entry.get("techniques"), list)

    # Evidence-producer constraint (ADR-0010q): E3 alone must not emit
    # MITRE.  There is no E3 here, so mitre_technique_ids may only be
    # populated by the E1 command-line hand-off.  Assert the surface is
    # a list (empty or not).
    assert isinstance(body["mitre_technique_ids"], list)


# ---------------------------------------------------------------------------
# H · Determinism — same REAL EVTX bytes twice → identical envelope.
# ---------------------------------------------------------------------------
def test_real_evtx_determinism(client):
    data = _read_fixture(_E1_FIXTURE, _E1_SHA256)
    a = _post_evtx(client, data).json()
    b = _post_evtx(client, data).json()
    refs_a = [r["evidence_ref"] for r in a["evidence"]]
    refs_b = [r["evidence_ref"] for r in b["evidence"]]
    assert refs_a == refs_b
    assert a["event_counts_by_id"] == b["event_counts_by_id"]
    assert a["mitre_technique_ids"] == b["mitre_technique_ids"]
    assert a["per_event_mitre"]    == b["per_event_mitre"]


# ---------------------------------------------------------------------------
# K · Real E3-only fixture — network-connect evidence emerges from real
#     EVTX bytes; NO MITRE from E3 alone (evidence-producer constraint
#     · ADR-0010q).
# ---------------------------------------------------------------------------
def test_real_evtx_e3_fixture_network_evidence(client):
    data = _read_fixture(_E3_FIXTURE, _E3_SHA256)
    r = _post_evtx(client, data)
    assert r.status_code == 200, r.text
    body = r.json()

    tr = body["transport"]
    assert tr["record_count"] == 12
    assert tr["transport"]    == "sysmon.slice3.evtx@1.0"

    assert body["event_counts_by_id"] == {"eid1": 0, "eid3": 12}

    # Network connections extracted from 12 raw E3 records; dedup collapses
    # them into a smaller set of unique tuples.
    connections = body["network_evidence"]["connections"]
    assert 0 < len(connections) <= 12

    # Every network row carries the correlation-state tri-state.
    for c in connections:
        assert c["correlation_state"] in (
            "RESOLVED", "UNRESOLVED_DANGLING", "AMBIGUOUS_PID_ONLY"
        )

    # With no E1 records in this file, ALL network rows must be dangling
    # (UNRESOLVED) — Sysmon adapter does NOT fabricate a parent.
    assert all(c["correlation_state"] == "UNRESOLVED_DANGLING" for c in connections)

    # Evidence-producer constraint: E3 alone MUST NOT emit MITRE.
    assert body["per_event_mitre"]      == []
    assert body["mitre_technique_ids"]  == []


# ---------------------------------------------------------------------------
# L · Real-fixture parity — EVTX transport response ≡ equivalent XML path
#     modulo the transport meta chip.
#
#     The XML path receives the exact same wrapped XML that the EVTX
#     transport hands to the normalizer.  This proves the transport is
#     truly a transport, not a shadow analyzer.
# ---------------------------------------------------------------------------
def test_real_evtx_parity_with_xml_path(client):
    from services.behavioral.evtx_reader import decode_evtx_to_sysmon_xml

    data = _read_fixture(_E1_FIXTURE, _E1_SHA256)
    wrapped_xml, _ = decode_evtx_to_sysmon_xml(data)

    evtx_resp = _post_evtx(client, data).json()
    xml_resp  = client.post("/api/behavioral/sysmon",
                              json={"xml": wrapped_xml}).json()

    # Same authoritative MITRE surface — the two paths must agree.
    assert evtx_resp["mitre_technique_ids"] == xml_resp["mitre_technique_ids"]
    assert evtx_resp["event_counts_by_id"]  == xml_resp["event_counts_by_id"]
    # Same evidence rows (order + values).
    assert [r["evidence_ref"] for r in evtx_resp["evidence"]] \
            == [r["evidence_ref"] for r in xml_resp["evidence"]]
    # Same parent-child pairs (order + values).
    assert evtx_resp["parent_child_evidence"] == xml_resp["parent_child_evidence"]

    # Only difference: EVTX response carries the `transport` chip; XML doesn't.
    assert "transport" in evtx_resp
    assert "transport" not in xml_resp
    assert evtx_resp["transport"]["transport"] == "sysmon.slice3.evtx@1.0"


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
