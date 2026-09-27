"""Windows installer · Stage 4 service-creation defect + resume safety.

Live-host finding: enrolment succeeded, then Stage 4 died with
`ERROR: Invalid start= field` and no service was registered.

These tests reproduce the tokenisation that caused it (using the real
`subprocess.list2cmdline`, which is what mangled the arguments), lock the
corrected `sc.exe` syntax, and prove the installer can resume after a
post-enrolment failure WITHOUT a second enrolment token.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

AGENT_DIR = Path("/app/agents/nivxforge-windows")
SETUP = AGENT_DIR / "nivxforge_setup.py"


@pytest.fixture()
def mod(tmp_path, monkeypatch):
    """Fresh module with STATE_DIR redirected into a temp dir."""
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
    m.INSTALLED_EXE.write_bytes(b"MZ stub")
    m.SERVICE_DIR = m.INSTALL_DIR / "service"
    m.SERVICE_DIR.mkdir(parents=True, exist_ok=True)
    m.SERVICE_EXE = m.SERVICE_DIR / "NivXForgeSensor.exe"
    m.SERVICE_EXE.write_bytes(b"MZ stub")
    # the onedir service-host payload only exists inside a frozen build
    m._stage_service_host = lambda: m.SERVICE_EXE
    return m


@pytest.fixture()
def patch_run(monkeypatch):
    """Install a fake `subprocess.run` for the lifetime of ONE test.

    `mod.subprocess` IS the stdlib module singleton, so the previous
    `mod.subprocess.run = fake` leaked out of this file and poisoned
    every later test in the same xdist worker. pytest restores the real
    callable at teardown.
    """
    def install(fake):
        monkeypatch.setattr(subprocess, "run", fake)
        return fake
    return install


def _valid_identity(mod):
    mod.sensor.IDENTITY_FILE.write_text(json.dumps({
        "tenant_id": "ten_e759b7288598bd882e3dcac49d",
        "endpoint_id": "ep_1989031c8c1d0085812f",
        "credential_id": "cred_abc123",
        "agent_credential": "nvx_placeholder_value_for_test_only",
        "enrolled_at": "2026-09-27T03:57:00+00:00",
    }))


# ── 1 · the defect, reproduced ────────────────────────────────────
def test_list_form_reproduces_the_invalid_start_field_defect():
    """Proof of root cause: a list element containing a space gets QUOTED
    by Windows argument building, so `start=` and `auto` arrive as ONE
    token and sc.exe cannot split key from value."""
    broken = subprocess.list2cmdline(
        ["sc.exe", "create", "NivXForgeSensor", "start= auto"])
    assert '"start= auto"' in broken, (
        "this quoting is exactly what produced ERROR: Invalid start= field")


def test_raw_command_line_keeps_start_and_auto_as_separate_tokens(mod,
                                                                  patch_run):
    seen: list[str] = []

    def fake_run(cmdline, **kw):
        assert isinstance(cmdline, str), (
            "sc.exe must be invoked from a RAW command line so the space "
            "after `=` stays an argument separator")
        seen.append(cmdline)
        return subprocess.CompletedProcess(cmdline, 0, "AUTO_START", "")

    patch_run(fake_run)
    mod._install_service("https://nivxray.nivxforge.com", 30)
    create = next(c for c in seen if c.startswith("sc.exe create"))
    assert "start= auto" in create
    assert '"start= auto"' not in create, "the value must not be quoted with the key"
    assert "obj= LocalSystem" in create


# ── 2 · corrected sc.exe contract ─────────────────────────────────
def test_service_creation_uses_the_approved_design(mod, patch_run):
    calls: list[str] = []

    def fake_run(cmdline, **kw):
        line = cmdline if isinstance(cmdline, str) \
            else subprocess.list2cmdline(cmdline)
        calls.append(line)
        out = "AUTO_START" if line.startswith("sc.exe qc") else ""
        return subprocess.CompletedProcess(cmdline, 0, out, "")

    patch_run(fake_run)
    mod._install_service("https://nivxray.nivxforge.com", 30)
    joined = "\n".join(calls)
    create = next(c for c in calls if c.startswith("sc.exe create"))
    assert '"NivXForgeSensor"' in create
    assert "start= auto" in create                     # automatic startup
    assert "obj= LocalSystem" in create                # LocalSystem account
    assert "--service-run" in create                   # service dispatch mode
    assert "--backend https://nivxray.nivxforge.com" in create
    # exe path quoted INSIDE the binPath value so image != arguments
    assert '\\"' in create and "NivXForgeSensor.exe" in create
    # recovery policy preserved exactly as approved
    assert "reset= 86400" in joined
    assert "actions= restart/60000/restart/60000/restart/60000" in joined
    assert 'sc.exe start "NivXForgeSensor"' in joined
    assert 'sc.exe qc "NivXForgeSensor"' in joined      # config verified


def test_service_creation_failure_is_surfaced_not_swallowed(mod, patch_run):
    def fake_run(cmdline, **kw):
        line = cmdline if isinstance(cmdline, str) \
            else subprocess.list2cmdline(cmdline)
        if line.startswith("sc.exe create"):
            return subprocess.CompletedProcess(
                cmdline, 1, "ERROR: Invalid start= field", "")
        return subprocess.CompletedProcess(cmdline, 0, "", "")

    patch_run(fake_run)
    with pytest.raises(SystemExit) as ex:
        mod._install_service("https://nivxray.nivxforge.com", 30)
    assert "service creation failed" in str(ex.value)


def test_service_created_but_not_auto_start_is_rejected(mod, patch_run):
    def fake_run(cmdline, **kw):
        line = cmdline if isinstance(cmdline, str) \
            else subprocess.list2cmdline(cmdline)
        out = "START_TYPE : 3 DEMAND_START" if line.startswith("sc.exe qc") else ""
        return subprocess.CompletedProcess(cmdline, 0, out, "")

    patch_run(fake_run)
    with pytest.raises(SystemExit) as ex:
        mod._install_service("https://nivxray.nivxforge.com", 30)
    assert "not AUTO_START" in str(ex.value)


def test_existing_service_is_replaced_not_duplicated(mod, patch_run):
    calls: list[str] = []

    def fake_run(cmdline, **kw):
        line = cmdline if isinstance(cmdline, str) \
            else subprocess.list2cmdline(cmdline)
        calls.append(line)
        rc = 0
        out = "AUTO_START" if line.startswith("sc.exe qc") else ""
        return subprocess.CompletedProcess(cmdline, rc, out, "")

    patch_run(fake_run)                    # query returns 0 → service exists
    mod._install_service("https://nivxray.nivxforge.com", 30)
    assert any(c.startswith('sc.exe stop') for c in calls)
    assert any(c.startswith('sc.exe delete') for c in calls)
    assert sum(c.startswith("sc.exe create") for c in calls) == 1


# ── 3 · resume after post-enrolment failure ───────────────────────
def test_resume_completes_stage_4_without_a_second_token(mod, monkeypatch, capsys):
    """The live-host case: enrolled, service creation failed, re-run."""
    _valid_identity(mod)
    enrol_calls = []
    monkeypatch.setattr(mod.sensor, "enrol",
                        lambda *a, **k: enrol_calls.append(a))
    monkeypatch.setattr(mod, "_assert_admin", lambda: None)
    monkeypatch.setattr(mod, "_protect_state_dir", lambda: None)
    monkeypatch.setattr(mod, "_install_service", lambda api, iv: None)
    monkeypatch.setattr(mod, "_self_path", lambda: mod.INSTALLED_EXE)

    # NO --tenant and NO --token supplied.
    mod.install("https://nivxray.nivxforge.com", None, None, 30, False)

    out = capsys.readouterr().out
    assert enrol_calls == [], "resume must NOT send a second enrolment request"
    assert "RESUME: already enrolled" in out
    assert "ep_1989031c8c1d0085812f" in out
    assert "no token required or consumed" in out
    assert "credential  : present" in out


def test_resume_preserves_the_existing_credential_untouched(mod, monkeypatch):
    _valid_identity(mod)
    before = mod.sensor.IDENTITY_FILE.read_bytes()
    monkeypatch.setattr(mod, "_assert_admin", lambda: None)
    monkeypatch.setattr(mod, "_protect_state_dir", lambda: None)
    monkeypatch.setattr(mod, "_install_service", lambda api, iv: None)
    monkeypatch.setattr(mod, "_self_path", lambda: mod.INSTALLED_EXE)
    mod.install("https://nivxray.nivxforge.com", None, None, 30, False)
    assert mod.sensor.IDENTITY_FILE.read_bytes() == before


def test_resume_never_prints_the_credential_value(mod, monkeypatch, capsys):
    _valid_identity(mod)
    monkeypatch.setattr(mod, "_assert_admin", lambda: None)
    monkeypatch.setattr(mod, "_protect_state_dir", lambda: None)
    monkeypatch.setattr(mod, "_install_service", lambda api, iv: None)
    monkeypatch.setattr(mod, "_self_path", lambda: mod.INSTALLED_EXE)
    mod.install("https://nivxray.nivxforge.com", None, None, 30, False)
    out = capsys.readouterr().out
    assert "nvx_placeholder_value_for_test_only" not in out
    assert "cred_abc123" not in out


def test_running_service_is_stopped_before_the_binary_is_replaced(mod, monkeypatch):
    _valid_identity(mod)
    calls: list[str] = []
    monkeypatch.setattr(mod, "_assert_admin", lambda: None)
    monkeypatch.setattr(mod, "_protect_state_dir", lambda: None)
    monkeypatch.setattr(mod, "_install_service", lambda api, iv: None)
    monkeypatch.setattr(mod, "_service_exists", lambda: True)
    monkeypatch.setattr(mod, "_sc", lambda c: calls.append(c))
    monkeypatch.setattr(mod.shutil, "copy2", lambda *a: calls.append("copy2"))
    monkeypatch.setattr(mod, "_self_path", lambda: Path("/tmp/downloaded.exe"))
    mod.install("https://nivxray.nivxforge.com", None, None, 30, False)
    assert calls.index(f'sc.exe stop "{mod.SERVICE_NAME}"') < calls.index("copy2")


# ── 4 · fail-closed on inconsistent local identity ────────────────
@pytest.mark.parametrize("bad", [
    {"tenant_id": "ten_x"},                                    # no endpoint
    {"endpoint_id": "ep_x", "tenant_id": "ten_x"},             # no credential
    {"endpoint_id": "ep_x", "tenant_id": "ten_x",
     "credential_id": "c"},                                    # no secret
])
def test_incomplete_identity_is_refused_not_assumed_enrolled(mod, bad):
    mod.sensor.IDENTITY_FILE.write_text(json.dumps(bad))
    with pytest.raises(SystemExit) as ex:
        mod._validate_identity()
    assert "incomplete" in str(ex.value)
    assert "--re-enrol" in str(ex.value)


def test_corrupt_identity_file_is_refused(mod):
    mod.sensor.IDENTITY_FILE.write_text("{ this is not json")
    with pytest.raises(SystemExit) as ex:
        mod._validate_identity()
    assert "unreadable" in str(ex.value)
    assert "Refusing to guess" in str(ex.value)


def test_valid_identity_is_accepted(mod):
    _valid_identity(mod)
    ident = mod._validate_identity()
    assert ident["endpoint_id"] == "ep_1989031c8c1d0085812f"
    assert ident["tenant_id"] == "ten_e759b7288598bd882e3dcac49d"


def test_re_enrol_still_demands_an_explicit_tenant_and_token(mod, monkeypatch):
    _valid_identity(mod)
    monkeypatch.setattr(mod, "_assert_admin", lambda: None)
    monkeypatch.setattr(mod, "_protect_state_dir", lambda: None)
    monkeypatch.setattr(mod, "_self_path", lambda: mod.INSTALLED_EXE)
    with pytest.raises(SystemExit) as ex:
        mod.install("https://nivxray.nivxforge.com", "ten_x", None, 30, True)
    assert "--token is required" in str(ex.value)
