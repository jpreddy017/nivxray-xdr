"""Windows installer · P0 re-enrol staging race, file lock and rollback.

LIVE-HOST FINDING (DESKTOP-A9HGFJJ, real recovery attempt with the
verified artifact): STAGE died with

    Permission denied:
    C:\\Program Files\\NivXForge\\sensor\\service\\NivXForgeSensor.exe

and the service was afterwards confirmed STOPPED. `sc.exe stop` is
ASYNCHRONOUS — it asks the SCM to begin a transition and returns, usually
reporting STOP_PENDING — so the installer replaced the service image while
the previous process still held it. The copy failed AFTER the service had
been stopped and BEFORE step 4 could start it again, which turned a failed
re-enrolment into a blind endpoint.

These tests lock the three properties that failure demands:

  1. the stop is PROVED, not assumed, and the image is PROVED released;
  2. if either cannot be proved, the installer REFUSES and replaces
     nothing — a running sensor is never put at risk to install an update;
  3. if ANY step fails after a service that WAS running was stopped, the
     service is restarted before the error is re-raised.

Plus the invariants that make a retry safe: no token is consumed when the
failure precedes enrolment, and identity/outbox/offset/cursors are never
touched by a failed — or a successful — re-enrolment.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

AGENT_DIR = Path("/app/agents/nivxforge-windows")
SETUP = AGENT_DIR / "nivxforge_setup.py"

_PROD = "https://nivxray.nivxforge.com"
_TENANT = "ten_e759b7288598bd882e3dcac49d"
_ENDPOINT = "ep_1989031c8c1d0085812f"


class FakeScm:
    """A deterministic stand-in for the Windows SCM.

    `stop_pending_polls` is the whole point: it makes `sc.exe stop`
    asynchronous, exactly as the real thing is, so a caller that does not
    wait is observably wrong.
    """

    _CODES = {"RUNNING": 4, "STOPPED": 1, "STOP_PENDING": 3,
              "START_PENDING": 2}

    def __init__(self, state: str = "RUNNING", stop_pending_polls: int = 0,
                 exists: bool = True, start_works: bool = True):
        self.state = state
        self.stop_pending_polls = stop_pending_polls
        self.exists = exists
        self.start_works = start_works
        self.calls: list[str] = []
        self.queries = 0

    def _ok(self, cmd, stdout: str = ""):
        return subprocess.CompletedProcess(cmd, 0, stdout, "")

    def __call__(self, cmd, *_args, **_kwargs):
        line = cmd if isinstance(cmd, str) else subprocess.list2cmdline(cmd)
        self.calls.append(line)
        if "icacls" in line:
            return self._ok(cmd)
        if "sc.exe query" in line:
            self.queries += 1
            if not self.exists:
                return subprocess.CompletedProcess(
                    cmd, 1060, "", "The specified service does not exist")
            if self.state == "STOP_PENDING":
                if self.stop_pending_polls > 0:
                    self.stop_pending_polls -= 1
                else:
                    self.state = "STOPPED"
            return self._ok(cmd, (
                "SERVICE_NAME: NivXForgeSensor\n"
                "        TYPE               : 10  WIN32_OWN_PROCESS\n"
                f"        STATE              : {self._CODES.get(self.state, 0)}"
                f"  {self.state}\n"
                "        WIN32_EXIT_CODE    : 0  (0x0)\n"))
        if "sc.exe stop" in line:
            self.state = ("STOP_PENDING" if self.stop_pending_polls
                          else "STOPPED")
            return self._ok(cmd)
        if "sc.exe start" in line:
            self.state = "RUNNING" if self.start_works else "STOPPED"
            return subprocess.CompletedProcess(
                cmd, 0 if self.start_works else 1, "", "start failed")
        if "sc.exe delete" in line:
            self.exists = False
            self.state = ""
            return self._ok(cmd)
        if "sc.exe create" in line:
            self.exists = True
            self.state = "STOPPED"
            return self._ok(cmd)
        if "sc.exe qc" in line:
            return self._ok(cmd, "        START_TYPE : 2   AUTO_START\n")
        return self._ok(cmd)

    def stopped_once(self) -> bool:
        return any("sc.exe stop" in c for c in self.calls)

    def started_once(self) -> bool:
        return any("sc.exe start" in c for c in self.calls)


@pytest.fixture()
def mod(tmp_path, monkeypatch):
    """The real installer module, with every path inside a temp dir."""
    monkeypatch.setenv("NIVXFORGE_SENSOR_STATE", str(tmp_path / "state"))
    sys.path.insert(0, str(AGENT_DIR))
    for name in ("nivxforge_setup", "nivxforge_sensor"):
        sys.modules.pop(name, None)
    spec = importlib.util.spec_from_file_location("nivxforge_setup", SETUP)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    m.sensor.STATE_DIR.mkdir(parents=True, exist_ok=True)

    m.INSTALL_DIR = tmp_path / "program_files"
    m.INSTALL_DIR.mkdir(parents=True, exist_ok=True)
    m.INSTALLED_EXE = m.INSTALL_DIR / "NivXForgeEDRSetup.exe"
    m.INSTALLED_EXE.write_bytes(b"MZ old installer")
    m.SERVICE_DIR = m.INSTALL_DIR / "service"
    m.SERVICE_DIR.mkdir(parents=True, exist_ok=True)
    m.SERVICE_EXE = m.SERVICE_DIR / "NivXForgeSensor.exe"
    m.SERVICE_EXE.write_bytes(b"MZ old service host")

    # the onedir payload only exists inside a frozen build
    payload = tmp_path / "payload"
    payload.mkdir()
    (payload / "NivXForgeSensor.exe").write_bytes(b"MZ new service host")
    monkeypatch.setattr(m, "_service_payload_dir", lambda: payload)
    monkeypatch.setattr(m, "_assert_admin", lambda: None)
    # real waits, zero wall clock
    monkeypatch.setattr(time, "sleep", lambda _s: None)
    return m


@pytest.fixture()
def scm(monkeypatch):
    def install(fake: FakeScm) -> FakeScm:
        monkeypatch.setattr(subprocess, "run", fake)
        return fake
    return install


def _seed_local_evidence(mod) -> dict:
    """An enrolled endpoint mid-flight: identity, backlog, cursors."""
    state = mod.sensor.STATE_DIR
    state.mkdir(parents=True, exist_ok=True)
    mod.sensor.IDENTITY_FILE.write_text(json.dumps({
        "tenant_id": _TENANT,
        "endpoint_id": _ENDPOINT,
        "credential_id": "cred_before_recovery",
        "agent_credential": "nvx_placeholder_value_for_test_only",
        "enrolled_at": "2026-09-27T03:57:00+00:00",
    }))
    (state / "outbox.jsonl").write_bytes(b'{"evidence": 1}\n' * 64)
    (state / "outbox.offset").write_text("512")
    (state / "channels.json").write_text(json.dumps({"Security": 4242}))
    (state / "journal.sqlite3").write_bytes(b"SQLite format 3\x00cursors")
    return _snapshot(mod)


def _snapshot(mod) -> dict:
    state = mod.sensor.STATE_DIR
    out = {}
    for name in ("identity.json", "outbox.jsonl", "outbox.offset",
                 "channels.json", "journal.sqlite3"):
        path = state / name
        out[name] = path.read_bytes() if path.exists() else None
    return out


# ── 1 · the stop is proved, not assumed ───────────────────────────
def test_running_service_is_stopped_and_proved_before_staging(mod, scm):
    fake = scm(FakeScm(state="RUNNING"))
    assert mod._stop_service_and_wait() == "RUNNING"
    assert fake.stopped_once()
    assert mod._service_state() == "STOPPED"


def test_delayed_scm_stop_is_waited_for_not_assumed(mod, scm):
    """STOP_PENDING for several polls is the real behaviour."""
    fake = scm(FakeScm(state="RUNNING", stop_pending_polls=5))
    assert mod._stop_service_and_wait() == "RUNNING"
    assert mod._service_state() == "STOPPED"
    # it had to keep asking: one query could not have seen STOPPED
    assert fake.queries >= 6


def test_absent_service_needs_no_stop(mod, scm):
    fake = scm(FakeScm(exists=False))
    assert mod._stop_service_and_wait() == ""
    assert not fake.stopped_once()


# ── 2 · fail closed, replace nothing ──────────────────────────────
def test_stop_timeout_fails_closed_and_replaces_nothing(mod, scm,
                                                        monkeypatch):
    """The SCM never reports STOPPED: refuse, do not overwrite."""
    monkeypatch.setattr(mod, "SERVICE_STOP_TIMEOUT_SECONDS", 0.2)
    scm(FakeScm(state="RUNNING", stop_pending_polls=10 ** 6))
    before = mod.SERVICE_EXE.read_bytes()
    with pytest.raises(SystemExit) as err:
        mod._stop_service_and_wait()
    assert "did not reach STOPPED" in str(err.value)
    assert "no token was consumed" in str(err.value)
    assert mod.SERVICE_EXE.read_bytes() == before


def test_locked_executable_refuses_and_replaces_nothing(mod, scm,
                                                        monkeypatch):
    """THE LIVE DEFECT: SCM says STOPPED, the image is still held."""
    monkeypatch.setattr(mod, "IMAGE_RELEASE_TIMEOUT_SECONDS", 0.2)
    monkeypatch.setattr(mod, "_image_is_released", lambda _p: False)
    scm(FakeScm(state="RUNNING"))
    before = mod.SERVICE_EXE.read_bytes()
    with pytest.raises(SystemExit) as err:
        mod._stop_service_and_wait()
    assert "still holds its image" in str(err.value)
    assert mod.SERVICE_EXE.read_bytes() == before


def test_staging_refuses_while_the_service_is_running(mod, scm):
    scm(FakeScm(state="RUNNING"))
    before = mod.SERVICE_EXE.read_bytes()
    with pytest.raises(SystemExit) as err:
        mod._stage_service_host()
    assert "RUNNING" in str(err.value)
    assert mod.SERVICE_EXE.read_bytes() == before


def test_staging_replaces_the_image_once_stopped(mod, scm):
    scm(FakeScm(state="RUNNING"))
    mod._stop_service_and_wait()
    assert mod._stage_service_host() == mod.SERVICE_EXE
    assert mod.SERVICE_EXE.read_bytes() == b"MZ new service host"


# ── 3 · rollback: a failed install never leaves an endpoint dark ──
def test_staging_failure_restores_a_previously_running_service(mod, scm,
                                                               monkeypatch):
    fake = scm(FakeScm(state="RUNNING"))
    _seed_local_evidence(mod)
    monkeypatch.setattr(mod, "_service_payload_dir", lambda: None)
    with pytest.raises(SystemExit) as err:
        mod.install(_PROD, _TENANT, False, 30, False)
    assert "carries no Windows service host payload" in str(err.value)
    assert fake.started_once()
    assert mod._service_state() == "RUNNING"


def test_enrolment_failure_restores_the_service_and_spends_no_token(
        mod, scm, monkeypatch):
    """--token-stdin missing on a re-enrol: the classic operator mistake."""
    fake = scm(FakeScm(state="RUNNING"))
    _seed_local_evidence(mod)
    spent: list[str] = []
    monkeypatch.setattr(mod.sensor, "read_enrolment_secret",
                        lambda: spent.append("read") or "secret")
    monkeypatch.setattr(mod.sensor, "enrol",
                        lambda *a, **k: spent.append("enrol"))
    with pytest.raises(SystemExit) as err:
        mod.install(_PROD, _TENANT, False, 30, True)
    assert "--token-stdin is required" in str(err.value)
    assert spent == []                      # no token read, none consumed
    assert fake.started_once()
    assert mod._service_state() == "RUNNING"


def test_rollback_does_not_start_a_service_the_operator_had_stopped(
        mod, scm, monkeypatch):
    fake = scm(FakeScm(state="STOPPED"))
    _seed_local_evidence(mod)
    monkeypatch.setattr(mod, "_service_payload_dir", lambda: None)
    with pytest.raises(SystemExit):
        mod.install(_PROD, _TENANT, False, 30, False)
    assert not fake.started_once()


def test_the_live_desktop_failure_is_reproduced_and_rolled_back(
        mod, scm, monkeypatch):
    """EXACT live failure: Permission denied on the service image.

    DESKTOP-A9HGFJJ, real artifact, real recovery attempt. Before the fix
    this aborted with the service stopped. Now the copy is retried inside
    a bounded window, the refusal is explicit, and the service that WAS
    running is running again when the error surfaces.
    """
    monkeypatch.setattr(mod, "IMAGE_RELEASE_TIMEOUT_SECONDS", 0.2)
    fake = scm(FakeScm(state="RUNNING"))
    before = _seed_local_evidence(mod)
    locked = PermissionError(
        13, "Permission denied",
        r"C:\Program Files\NivXForge\sensor\service\NivXForgeSensor.exe")

    def still_locked(*_a, **_k):
        raise locked

    monkeypatch.setattr(mod.shutil, "copytree", still_locked)
    with pytest.raises(SystemExit) as err:
        mod.install(_PROD, _TENANT, False, 30, False)
    message = str(err.value)
    assert "service host staging failed" in message
    assert "Permission denied" in message
    assert "no token was consumed" in message
    assert fake.started_once()
    assert mod._service_state() == "RUNNING"
    assert _snapshot(mod) == before


def test_failed_install_leaves_identity_outbox_offset_cursors_untouched(
        mod, scm, monkeypatch):
    scm(FakeScm(state="RUNNING"))
    before = _seed_local_evidence(mod)
    monkeypatch.setattr(mod, "_service_payload_dir", lambda: None)
    with pytest.raises(SystemExit):
        mod.install(_PROD, _TENANT, False, 30, False)
    assert _snapshot(mod) == before


# ── 4 · a successful re-enrol preserves everything but the credential ──
def test_successful_reenrol_preserves_identity_outbox_offset_cursors(
        mod, scm, monkeypatch):
    fake = scm(FakeScm(state="RUNNING"))
    before = _seed_local_evidence(mod)

    def server_issues_a_new_credential(api, tenant, token):
        assert token == "a-single-use-secret"
        ident = json.loads(mod.sensor.IDENTITY_FILE.read_text())
        # the platform mints the endpoint_id deterministically, so the SAME
        # host comes back as the SAME endpoint
        ident.update({"credential_id": "cred_after_recovery",
                      "agent_credential": "nvx_new_placeholder_value"})
        mod.sensor.IDENTITY_FILE.write_text(json.dumps(ident))
        return ident

    monkeypatch.setattr(mod.sensor, "read_enrolment_secret",
                        lambda: "a-single-use-secret")
    monkeypatch.setattr(mod.sensor, "enrol", server_issues_a_new_credential)

    mod.install(_PROD, _TENANT, True, 30, True)

    after = _snapshot(mod)
    for name in ("outbox.jsonl", "outbox.offset", "channels.json",
                 "journal.sqlite3"):
        assert after[name] == before[name], name
    ident = json.loads(mod.sensor.IDENTITY_FILE.read_text())
    assert ident["endpoint_id"] == _ENDPOINT
    assert ident["tenant_id"] == _TENANT
    assert ident["credential_id"] == "cred_after_recovery"
    assert mod._service_state() == "RUNNING"
    assert fake.stopped_once() and fake.started_once()


def test_resume_after_a_failed_stage_needs_no_token(mod, scm, monkeypatch):
    """An already-enrolled host repairs itself without spending a token."""
    fake = scm(FakeScm(state="RUNNING"))
    _seed_local_evidence(mod)
    spent: list[str] = []
    monkeypatch.setattr(mod.sensor, "read_enrolment_secret",
                        lambda: spent.append("read") or "secret")
    mod.install(_PROD, None, False, 30, False)
    assert spent == []
    assert mod._service_state() == "RUNNING"
    assert fake.stopped_once()


# ── 5 · an ignored flag is how a wrong build lies ─────────────────
def test_unknown_install_argument_is_refused_not_ignored(mod):
    with pytest.raises(SystemExit) as err:
        mod.main(["install", "--backend", _PROD, "--tenant", _TENANT,
                  "--token-stdin", "--not-a-real-flag"])
    message = str(err.value)
    assert "unrecognized argument" in message
    assert "--not-a-real-flag" in message


def test_token_stdin_is_still_the_only_secret_interface(mod):
    flags = {action.option_strings[0]
             for action in mod.build_parser()._subparsers._group_actions[0]
             .choices["install"]._actions if action.option_strings}
    assert "--token-stdin" in flags
    assert "--token" not in flags


# ── 6 · provenance: a stale installer must be recognisable ────────
def test_build_identity_declares_an_unofficial_local_build(mod):
    identity = mod.build_identity()
    assert identity["build_commit"] == "UNOFFICIAL_BUILD"
    assert identity["sensor_version"] == mod.sensor.SENSOR_VERSION
    assert identity["setup_version"] == mod.SETUP_VERSION


def test_self_digest_is_a_sha256_of_the_running_artifact(mod):
    digest = mod.self_digest()
    assert len(digest) == 64
    assert digest == digest.upper()
    int(digest, 16)
