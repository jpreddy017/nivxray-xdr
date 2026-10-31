"""S1.2-C2 · a FAILED CLEAN INSTALL is never an enrolled-but-silent endpoint.

The S1.2 audit found the one state defect in the installer that can leave a
real production computer dark without saying so. On a CLEAN endpoint
`prior_state` is "" — no service exists yet — so the rollback path had
nothing to restore and did nothing at all. A failure AFTER a successful
enrolment but BEFORE the service is installed and running therefore left:

    identity.json written  +  program staging present  +  NO service

The platform holds an endpoint, the computer collects nothing, and the
machine still looks installed. That is exactly the shape the platform
exists to refuse: a silent endpoint reported as if it were fine.

These tests lock the invariant:

    FAILED CLEAN INSTALL != ENROLLED-BUT-SILENT ENDPOINT

and the properties that make it safe rather than merely tidy:

  * the identity is PRESERVED, never deleted — deleting it would cost a
    second enrolment token to recover;
  * acquired evidence is PRESERVED — the state directory is not touched;
  * only program staging this attempt created is removed, and only once
    the service it may have registered is proven gone;
  * the result SAYS it is not collecting;
  * re-running `install` RESUMES with no enrolment request and no token;
  * a cleanup that cannot be PROVED is reported as incomplete, never
    claimed as success;
  * the re-enrol / Gate 4 path (a service that WAS running) is untouched.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

#: The SAME deterministic SCM stand-in the re-enrol suite uses, loaded from
#: that module rather than copied, so the two suites cannot drift apart.
_RACE_SUITE = Path(__file__).with_name(
    "test_p0_windows_reenrol_staging_race.py")
_race_spec = importlib.util.spec_from_file_location(
    "_nivx_race_suite", _RACE_SUITE)
_race = importlib.util.module_from_spec(_race_spec)
_race_spec.loader.exec_module(_race)
FakeScm = _race.FakeScm

AGENT_DIR = Path("/app/agents/nivxforge-windows")
SETUP = AGENT_DIR / "nivxforge_setup.py"

_PROD = "https://nivxray.nivxforge.com"
_TENANT = "ten_e759b7288598bd882e3dcac49d"
_ENDPOINT = "ep_1989031c8c1d0085812f"


@pytest.fixture()
def mod(tmp_path, monkeypatch):
    """The real installer module on a CLEAN endpoint: no service, no staging."""
    monkeypatch.setenv("NIVXFORGE_SENSOR_STATE", str(tmp_path / "state"))
    sys.path.insert(0, str(AGENT_DIR))
    for name in ("nivxforge_setup", "nivxforge_sensor"):
        sys.modules.pop(name, None)
    spec = importlib.util.spec_from_file_location("nivxforge_setup", SETUP)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    m.sensor.STATE_DIR.mkdir(parents=True, exist_ok=True)

    # NOTHING is installed yet — the whole point of a clean endpoint.
    m.INSTALL_DIR = tmp_path / "program_files"
    m.INSTALLED_EXE = m.INSTALL_DIR / "NivXForgeEDRSetup.exe"
    m.SERVICE_DIR = m.INSTALL_DIR / "service"
    m.SERVICE_EXE = m.SERVICE_DIR / "NivXForgeSensor.exe"

    payload = tmp_path / "payload"
    payload.mkdir()
    (payload / "NivXForgeSensor.exe").write_bytes(b"MZ new service host")
    monkeypatch.setattr(m, "_service_payload_dir", lambda: payload)
    monkeypatch.setattr(m, "_assert_admin", lambda: None)
    monkeypatch.setattr(time, "sleep", lambda _s: None)
    return m


@pytest.fixture()
def scm(monkeypatch):
    def install(fake: FakeScm) -> FakeScm:
        monkeypatch.setattr(subprocess, "run", fake)
        return fake
    return install


@pytest.fixture()
def clean_scm(scm):
    """A host where NivXForgeSensor does not exist yet."""
    return scm(FakeScm(state="", exists=False))


def _enrolment_that_succeeds(mod, spent: list[str]):
    """A real enrolment: it WRITES the durable identity, as the platform's
    response would, and it consumes the one-time secret."""
    def _enrol(api, tenant, token):
        spent.append(token)
        mod.sensor.STATE_DIR.mkdir(parents=True, exist_ok=True)
        mod.sensor.IDENTITY_FILE.write_text(json.dumps({
            "tenant_id": tenant, "endpoint_id": _ENDPOINT,
            "credential_id": "cred_first_install",
            "agent_credential": "nvx_placeholder_value_for_test_only",
            "enrolled_at": "2026-10-06T07:00:00+00:00"}))
        return {"endpoint_id": _ENDPOINT}
    return _enrol


def _seed_acquired_evidence(mod) -> dict:
    """Evidence this computer already owns. It must survive any rollback."""
    state = mod.sensor.STATE_DIR
    state.mkdir(parents=True, exist_ok=True)
    (state / "outbox.jsonl").write_bytes(b'{"evidence": 1}\n' * 8)
    (state / "outbox.offset").write_text("64")
    (state / "channels.json").write_text(json.dumps({"Security": 991}))
    (state / "journal.sqlite3").write_bytes(b"SQLite format 3\x00cursors")
    return {name: (state / name).read_bytes()
            for name in ("outbox.jsonl", "outbox.offset", "channels.json",
                         "journal.sqlite3")}


def _fail_at_stage_four(mod, monkeypatch):
    """The failure the audit is about: enrolment succeeded, stage 4 did not."""
    def _boom(*_a, **_k):
        raise SystemExit("service creation failed: ERROR 1073")
    monkeypatch.setattr(mod, "_install_service", _boom)


# ── 1 · identity and evidence survive ─────────────────────────────
def test_clean_install_failure_after_enrolment_preserves_the_identity(
        mod, clean_scm, monkeypatch):
    before = _seed_acquired_evidence(mod)
    spent: list[str] = []
    monkeypatch.setattr(mod.sensor, "read_enrolment_secret",
                        lambda: "a-single-use-secret")
    monkeypatch.setattr(mod.sensor, "enrol",
                        _enrolment_that_succeeds(mod, spent))
    _fail_at_stage_four(mod, monkeypatch)

    with pytest.raises(SystemExit) as err:
        mod.install(_PROD, _TENANT, True, 30, False)

    assert "service creation failed" in str(err.value)
    assert spent == ["a-single-use-secret"]
    ident = json.loads(mod.sensor.IDENTITY_FILE.read_text())
    assert ident["endpoint_id"] == _ENDPOINT
    assert ident["tenant_id"] == _TENANT
    assert ident["agent_credential"]
    state = mod.sensor.STATE_DIR
    assert {name: (state / name).read_bytes() for name in before} == before


def test_the_state_directory_itself_is_never_removed(
        mod, clean_scm, monkeypatch):
    _seed_acquired_evidence(mod)
    monkeypatch.setattr(mod.sensor, "read_enrolment_secret", lambda: "s")
    monkeypatch.setattr(mod.sensor, "enrol",
                        _enrolment_that_succeeds(mod, []))
    _fail_at_stage_four(mod, monkeypatch)
    with pytest.raises(SystemExit):
        mod.install(_PROD, _TENANT, True, 30, False)
    assert mod.sensor.STATE_DIR.is_dir()


# ── 2 · only program staging is cleaned ───────────────────────────
def test_partial_program_staging_is_removed(mod, clean_scm, monkeypatch):
    monkeypatch.setattr(mod.sensor, "read_enrolment_secret", lambda: "s")
    monkeypatch.setattr(mod.sensor, "enrol",
                        _enrolment_that_succeeds(mod, []))
    _fail_at_stage_four(mod, monkeypatch)
    with pytest.raises(SystemExit):
        mod.install(_PROD, _TENANT, True, 30, False)
    assert not mod.INSTALL_DIR.exists()
    assert not mod.SERVICE_EXE.exists()


def test_a_service_this_attempt_registered_is_removed_and_proved_gone(
        mod, clean_scm, monkeypatch):
    """`sc create` succeeded, the service would not start: the half-created
    service must not be left behind on a clean endpoint."""
    fake = clean_scm
    fake.start_works = False
    monkeypatch.setattr(mod.sensor, "read_enrolment_secret", lambda: "s")
    monkeypatch.setattr(mod.sensor, "enrol",
                        _enrolment_that_succeeds(mod, []))
    with pytest.raises(SystemExit) as err:
        mod.install(_PROD, _TENANT, True, 30, False)
    assert "service did not start" in str(err.value)
    assert any("sc.exe delete" in call for call in fake.calls)
    assert not mod._service_exists()
    assert not mod.INSTALL_DIR.exists()


# ── 3 · the result says what it is ────────────────────────────────
def test_the_failure_declares_the_endpoint_not_collecting(
        mod, clean_scm, monkeypatch, capsys):
    monkeypatch.setattr(mod.sensor, "read_enrolment_secret", lambda: "s")
    monkeypatch.setattr(mod.sensor, "enrol",
                        _enrolment_that_succeeds(mod, []))
    _fail_at_stage_four(mod, monkeypatch)
    with pytest.raises(SystemExit):
        mod.install(_PROD, _TENANT, True, 30, False)
    out = capsys.readouterr().out
    assert "=== ROLLBACK ===" in out
    assert "THIS ENDPOINT IS NOT COLLECTING" in out
    assert "INSTALL INCOMPLETE" in out
    assert "IS ENROLLED" in out
    assert "NO second enrolment token" in out
    assert "PRESERVED" in out
    assert "CLEANUP INCOMPLETE" not in out


def test_a_cleanup_that_cannot_be_proved_is_reported_not_claimed(
        mod, clean_scm, monkeypatch, capsys):
    """A service that refuses to disappear is an honest INCOMPLETE, and the
    image it still references is deliberately left in place."""
    fake = clean_scm
    fake.start_works = False
    monkeypatch.setattr(mod.sensor, "read_enrolment_secret", lambda: "s")
    monkeypatch.setattr(mod.sensor, "enrol",
                        _enrolment_that_succeeds(mod, []))

    real_call = fake.__call__

    def delete_never_works(cmd, *a, **k):
        line = cmd if isinstance(cmd, str) else subprocess.list2cmdline(cmd)
        if "sc.exe delete" in line:
            fake.calls.append(line)
            return subprocess.CompletedProcess(cmd, 1, "", "access denied")
        return real_call(cmd, *a, **k)

    monkeypatch.setattr(subprocess, "run", delete_never_works)
    with pytest.raises(SystemExit):
        mod.install(_PROD, _TENANT, True, 30, False)
    out = capsys.readouterr().out
    assert "CLEANUP INCOMPLETE" in out
    assert "THIS ENDPOINT IS NOT COLLECTING" in out
    assert mod.INSTALL_DIR.exists()           # the service still needs it


def test_a_failure_before_enrolment_says_no_token_was_consumed(
        mod, clean_scm, monkeypatch, capsys):
    spent: list[str] = []
    monkeypatch.setattr(mod.sensor, "read_enrolment_secret",
                        lambda: spent.append("read") or "s")
    monkeypatch.setattr(mod, "_service_payload_dir", lambda: None)
    with pytest.raises(SystemExit) as err:
        mod.install(_PROD, _TENANT, True, 30, False)
    assert "carries no Windows service host payload" in str(err.value)
    assert spent == []
    assert not mod.sensor.IDENTITY_FILE.exists()
    out = capsys.readouterr().out
    assert "no token was consumed" in out
    assert "THIS ENDPOINT IS NOT COLLECTING" in out


# ── 4 · the endpoint is deterministically resumable ───────────────
def test_rerunning_install_resumes_without_a_second_token(
        mod, scm, monkeypatch):
    before = _seed_acquired_evidence(mod)
    spent: list[str] = []
    monkeypatch.setattr(mod.sensor, "read_enrolment_secret",
                        lambda: spent.append("read") or "a-single-use-secret")
    monkeypatch.setattr(mod.sensor, "enrol",
                        _enrolment_that_succeeds(mod, spent))

    scm(FakeScm(state="", exists=False))
    _fail_at_stage_four(mod, monkeypatch)
    with pytest.raises(SystemExit):
        mod.install(_PROD, _TENANT, True, 30, False)
    assert spent == ["read", "a-single-use-secret"]

    # SECOND RUN · same clean-looking host, identity still on disk.
    monkeypatch.undo()
    monkeypatch.setattr(time, "sleep", lambda _s: None)
    monkeypatch.setattr(mod, "_assert_admin", lambda: None)
    payload = mod.INSTALL_DIR.parent / "payload"
    monkeypatch.setattr(mod, "_service_payload_dir", lambda: payload)
    monkeypatch.setattr(mod.sensor, "read_enrolment_secret",
                        lambda: spent.append("read") or "second-secret")
    monkeypatch.setattr(
        mod.sensor, "enrol",
        lambda *a, **k: spent.append("enrol-again"))
    fake = scm(FakeScm(state="", exists=False))

    mod.install(_PROD, None, False, 30, False)

    # NOTHING more was spent: no second stdin read, no second enrolment.
    assert spent == ["read", "a-single-use-secret"]
    assert mod._service_state() == "RUNNING"
    assert any("sc.exe create" in call for call in fake.calls)
    state = mod.sensor.STATE_DIR
    assert {name: (state / name).read_bytes() for name in before} == before
    assert json.loads(
        mod.sensor.IDENTITY_FILE.read_text())["endpoint_id"] == _ENDPOINT


# ── 5 · the re-enrol / Gate 4 path is untouched ───────────────────
def test_a_previously_running_service_still_takes_the_restore_path(
        mod, scm, monkeypatch, capsys):
    mod.INSTALL_DIR.mkdir(parents=True, exist_ok=True)
    mod.SERVICE_DIR.mkdir(parents=True, exist_ok=True)
    mod.SERVICE_EXE.write_bytes(b"MZ old service host")
    fake = scm(FakeScm(state="RUNNING"))
    monkeypatch.setattr(mod, "_service_payload_dir", lambda: None)
    with pytest.raises(SystemExit):
        mod.install(_PROD, _TENANT, False, 30, False)
    out = capsys.readouterr().out
    assert fake.started_once()
    assert mod._service_state() == "RUNNING"
    assert "was RUNNING before this attempt" in out
    assert "INSTALL INCOMPLETE" not in out
    assert mod.INSTALL_DIR.exists()           # nothing was cleaned away


def test_a_deliberately_stopped_service_is_not_treated_as_a_clean_endpoint(
        mod, scm, monkeypatch, capsys):
    mod.INSTALL_DIR.mkdir(parents=True, exist_ok=True)
    mod.SERVICE_DIR.mkdir(parents=True, exist_ok=True)
    mod.SERVICE_EXE.write_bytes(b"MZ old service host")
    fake = scm(FakeScm(state="STOPPED"))
    monkeypatch.setattr(mod, "_service_payload_dir", lambda: None)
    with pytest.raises(SystemExit):
        mod.install(_PROD, _TENANT, False, 30, False)
    out = capsys.readouterr().out
    assert not fake.started_once()
    assert "INSTALL INCOMPLETE" not in out
    assert mod.INSTALL_DIR.exists()
    assert mod._service_exists()
