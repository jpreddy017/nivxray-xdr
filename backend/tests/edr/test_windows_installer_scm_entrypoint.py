"""Windows installer · Stage 4 SCM RUNTIME defect (error 1053).

Live-host finding on the enrolled validation endpoint
(`ep_1989031c8c1d0085812f`): enrolment resumed correctly, `sc.exe create`
succeeded, `sc qc` proved WIN32_OWN_PROCESS / AUTO_START / LocalSystem and
the expected binPath — yet the service failed with Windows 1053, and
running the exact SCM command line by hand produced:

    NivXForgeEDRSetup: error: argument cmd: invalid choice:
    'https://nivxray.nivxforge.com' (choose from 'install', 'uninstall',
    'status', 'version')

Root cause: `main()` parsed the SCM command line with the INSTALLER's
subcommand parser. `--backend` is not a top-level option there, so
`parse_known_args` set it aside as unknown and then offered the NEXT
token — the backend URL — to the subparsers as the positional command.
argparse exited 2 before `StartServiceCtrlDispatcher()` was ever reached,
so the process died without ever talking to the SCM.

These tests derive the argv from the command line `_install_service`
ACTUALLY writes (no hand-written string), and prove that argv reaches the
service dispatcher.
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
    return m


@pytest.fixture()
def patch_run(monkeypatch):
    """Install a fake `subprocess.run` for the lifetime of ONE test.

    `mod.subprocess` IS the stdlib module singleton, so the previous
    `mod.subprocess.run = fake` poisoned every later test in the same
    xdist worker — the next list-argv call reached the fake and raised
    `'list' object has no attribute 'startswith'`. pytest owns the
    lifecycle here and restores the real callable at teardown.
    """
    def install(fake):
        monkeypatch.setattr(subprocess, "run", fake)
        return fake
    return install


def _sc_run(calls: list[str]):
    """Fake `sc.exe` runner that tolerates EITHER command representation
    the production code may pass — a raw command line today, a list if
    that ever changes — instead of assuming `str`."""
    def fake_run(cmdline, **kw):
        line = cmdline if isinstance(cmdline, str) \
            else subprocess.list2cmdline(cmdline)
        calls.append(line)
        out = "AUTO_START" if line.startswith("sc.exe qc") else ""
        return subprocess.CompletedProcess(cmdline, 0, out, "")
    return fake_run


def _sc_create_line(mod, patch_run, api="https://nivxray.nivxforge.com",
                    interval=30):
    """The real `sc.exe create` command line the installer emits."""
    calls: list[str] = []
    patch_run(_sc_run(calls))
    mod._install_service(api, interval)
    return next(c for c in calls if c.startswith("sc.exe create"))


def _scm_argv(create_line: str) -> list[str]:
    """argv[1:] the Windows SCM hands the image, from the real binPath.

    The binPath VALUE is everything between `binPath= "` and the closing
    quote that precedes ` start= `. Inside it the image path is quoted
    (escaped as \\") so CreateProcess can tell the image from its
    arguments — exactly the split reproduced here.
    """
    head = create_line.split('binPath= "', 1)[1]
    value = head.rsplit('" start= ', 1)[0].replace('\\"', '"')
    assert value.startswith('"'), f"image path must be quoted: {value}"
    _image, _, rest = value[1:].partition('"')
    return rest.split()


# ── 1 · the defect, reproduced from the real command line ─────────
def test_installer_subcommand_parser_rejects_the_real_scm_invocation(
        mod, patch_run):
    """Proof of root cause: the SCM argv IS invalid to the installer CLI,
    so nothing may route it there."""
    argv = _scm_argv(_sc_create_line(mod, patch_run))
    assert argv[0] == "--service-run"
    with pytest.raises(SystemExit) as ex:
        mod.build_parser().parse_args(argv)
    assert ex.value.code == 2, "argparse exits 2 — the 1053 the SCM saw"


def test_parse_known_args_also_fails_on_the_scm_invocation(mod, patch_run):
    """The previous implementation used parse_known_args and still died:
    an unknown OPTION is tolerated, the positional after it is not."""
    argv = _scm_argv(_sc_create_line(mod, patch_run))
    with pytest.raises(SystemExit):
        mod.build_parser().parse_known_args(argv)


# ── 2 · main() must reach the SCM dispatcher, not the CLI ─────────
def test_main_routes_the_real_scm_invocation_to_the_service_dispatcher(
        mod, monkeypatch, patch_run):
    argv = _scm_argv(_sc_create_line(mod, patch_run))
    seen: list[list[str]] = []
    monkeypatch.setattr(mod, "_run_as_service", lambda a: seen.append(a))
    monkeypatch.setattr(mod, "install", lambda *a, **k:
                        pytest.fail("install must not run under the SCM"))
    mod.main(argv)
    assert seen == [argv], "the SCM command line must reach the service path"


def test_service_dispatch_happens_before_any_argument_parsing(mod,
                                                              monkeypatch,
                                                              patch_run):
    """Regression on the exact failure: `invalid choice` must be
    impossible for the SCM invocation, whatever the parser looks like."""
    argv = _scm_argv(_sc_create_line(mod, patch_run))
    monkeypatch.setattr(mod, "build_parser", lambda:
                        pytest.fail("the installer parser must never see "
                                    "the SCM command line"))
    monkeypatch.setattr(mod, "_run_as_service", lambda a: None)
    mod.main(argv)


def test_normal_cli_commands_are_unaffected(mod, monkeypatch, capsys):
    monkeypatch.setattr(mod, "_run_as_service", lambda a:
                        pytest.fail("version is not a service invocation"))
    mod.main(["version"])
    out = json.loads(capsys.readouterr().out)
    assert out["service_name"] == "NivXForgeSensor"


def test_install_is_still_routed_to_install(mod, monkeypatch):
    seen: list[tuple] = []
    monkeypatch.setattr(mod, "install", lambda *a: seen.append(a))
    mod.main(["install", "--backend", "https://nivxray.nivxforge.com",
              "--tenant", "ten_x", "--token", "nvxenr_x"])
    assert seen and seen[0][0] == "https://nivxray.nivxforge.com"


# ── 3 · service arguments come from the passed argv ───────────────
def test_service_args_are_read_from_the_scm_argv_not_a_global(mod,
                                                              monkeypatch,
                                                              patch_run):
    argv = _scm_argv(_sc_create_line(
        mod, patch_run, "https://nivxray.nivxforge.com", 45))
    monkeypatch.setattr(sys, "argv", ["NivXForgeSensor.exe"])  # empty global
    api, interval = mod._service_args(argv)
    assert api == "https://nivxray.nivxforge.com"
    assert interval == 45


def test_service_args_default_when_the_scm_passes_nothing(mod):
    api, interval = mod._service_args(["--service-run"])
    assert api == mod.DEFAULT_BACKEND
    assert interval == 30


def test_service_refuses_a_non_production_backend_from_the_scm(mod):
    with pytest.raises(SystemExit) as ex:
        mod._service_args(["--service-run", "--backend",
                           "http://localhost:8001"])
    assert "refusing to install" in str(ex.value)


def test_service_start_refusal_is_recorded_for_the_operator(mod):
    with pytest.raises(SystemExit):
        mod._run_as_service(["--service-run", "--backend",
                             "http://localhost:8001"])
    log = (mod.sensor.STATE_DIR / "service.log").read_text()
    assert "service entrypoint reached" in log
    assert "refused to start" in log


def test_service_log_write_failure_never_breaks_the_service(mod,
                                                            monkeypatch):
    monkeypatch.setattr(mod.sensor.STATE_DIR.__class__, "mkdir",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("ro")))
    mod._service_log("must not raise")


# ── 4 · the source must implement a real SCM service ──────────────
def test_source_implements_the_scm_dispatcher_and_control_handlers():
    text = SETUP.read_text()
    assert "win32serviceutil.ServiceFramework" in text
    assert "servicemanager.StartServiceCtrlDispatcher()" in text
    assert "servicemanager.PrepareToHostSingle" in text
    assert "SERVICE_START_PENDING" in text
    assert "SERVICE_RUNNING" in text
    assert "SERVICE_STOPPED" in text
    assert "def SvcStop" in text
    assert "def SvcShutdown" in text        # shutdown is a stop, not a crash
    # collection is REUSED, not reimplemented inside the service
    assert "sensor.run(self.api, self.interval, once=True)" in text
    assert text.count("def collect(") == 0


def test_a_failed_cycle_does_not_stop_the_service():
    """`sensor.run` calls sys.exit when the host is not enrolled yet; an
    unhandled SystemExit inside the run loop would kill the service."""
    text = SETUP.read_text()
    assert "except (Exception, SystemExit) as ex:" in text


@pytest.mark.parametrize("line", [
    "service entrypoint reached",
    "START_PENDING",
    "RUNNING",
    "control STOP received",
    "stop event signalled",
    "STOPPED",
])
def test_the_lifecycle_lines_the_ci_gate_asserts_are_emitted(line):
    """CI fails the build unless service.log contains these, so the source
    must keep emitting them: the two must not drift apart."""
    assert line in SETUP.read_text()


# ── 6 · the SERVICE IMAGE must be a onedir host, not the onefile ──
def test_service_binpath_points_at_the_onedir_service_host(mod, patch_run):
    create = _sc_create_line(mod, patch_run)
    assert str(mod.SERVICE_EXE) in create.replace('\\"', '')
    assert "NivXForgeSensor.exe" in create
    assert "NivXForgeEDRSetup.exe" not in create, (
        "a PyInstaller ONE-FILE binary re-executes itself as a child "
        "process, so the process the SCM started is not the one that "
        "calls StartServiceCtrlDispatcher — that is a 1053 by design")


def test_service_creation_refuses_a_missing_service_image(mod):
    mod.SERVICE_EXE.unlink()
    with pytest.raises(SystemExit) as ex:
        mod._install_service("https://nivxray.nivxforge.com", 30)
    assert "does not exist" in str(ex.value)


def test_staging_unpacks_the_payload_carried_by_the_installer(mod,
                                                              monkeypatch,
                                                              tmp_path):
    payload = tmp_path / "meipass" / "service"
    payload.mkdir(parents=True)
    (payload / "NivXForgeSensor.exe").write_bytes(b"MZ host")
    (payload / "_internal").mkdir()
    (payload / "_internal" / "python311.dll").write_bytes(b"dll")
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path / "meipass"),
                        raising=False)
    monkeypatch.setattr(mod, "_service_exists", lambda: False)
    staged = mod._stage_service_host()
    assert staged == mod.SERVICE_EXE
    assert mod.SERVICE_EXE.read_bytes() == b"MZ host"
    assert (mod.SERVICE_DIR / "_internal" / "python311.dll").exists()


def test_staging_is_idempotent_for_a_repair_install(mod, monkeypatch,
                                                    tmp_path):
    payload = tmp_path / "meipass" / "service"
    payload.mkdir(parents=True)
    (payload / "NivXForgeSensor.exe").write_bytes(b"MZ host v2")
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path / "meipass"),
                        raising=False)
    monkeypatch.setattr(mod, "_service_exists", lambda: False)
    mod._stage_service_host()
    mod._stage_service_host()
    assert mod.SERVICE_EXE.read_bytes() == b"MZ host v2"


def test_staging_stops_a_running_service_before_overwriting_the_image(
        mod, monkeypatch, tmp_path):
    payload = tmp_path / "meipass" / "service"
    payload.mkdir(parents=True)
    (payload / "NivXForgeSensor.exe").write_bytes(b"MZ host")
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path / "meipass"),
                        raising=False)
    monkeypatch.setattr(mod, "_service_exists", lambda: True)
    calls: list[str] = []
    monkeypatch.setattr(mod, "_sc", lambda c: calls.append(c))
    mod._stage_service_host()
    assert calls == [f'sc.exe stop "{mod.SERVICE_NAME}"']


def test_a_build_without_a_service_payload_is_refused(mod, monkeypatch):
    monkeypatch.delattr(sys, "_MEIPASS", raising=False)
    with pytest.raises(SystemExit) as ex:
        mod._stage_service_host()
    assert "no Windows service host payload" in str(ex.value)


def test_version_declares_the_service_host_layout(mod, capsys):
    mod.main(["version"])
    out = json.loads(capsys.readouterr().out)
    assert out["service_host"] == "ONEDIR_PAYLOAD"
    assert out["service_exe"].endswith("NivXForgeSensor.exe")


def test_build_freezes_a_onedir_service_host_and_embeds_it():
    ps1 = (AGENT_DIR / "build" / "build_windows_installer.ps1").read_text()
    assert "--onedir --name NivXForgeSensor" in ps1
    assert "--add-data" in ps1 and "';service'" in ps1
    assert "--onefile" in ps1, "the installer download stays a single file"
    assert "service_host_sha256" in ps1


# ── 7 · the STATE ROOT must be told, never inferred ───────────────
def test_binpath_carries_the_installer_resolved_state_dir(mod, patch_run):
    create = _sc_create_line(mod, patch_run)
    assert "--state-dir" in create
    assert str(mod.sensor.STATE_DIR) in create.replace('\\"', '')
    argv = _scm_argv(create)
    assert mod._argv_value(argv, "--state-dir") == str(mod.sensor.STATE_DIR)


def test_the_service_command_line_carries_no_secret(mod, patch_run):
    create = _sc_create_line(mod, patch_run)
    for shape in ("nvx_", "nvxenr_", "nvxses_", "nvxcrd_", "--token",
                  "agent_credential"):
        assert shape not in create, f"{shape} must never reach the SCM"


def test_state_dir_is_applied_before_anything_state_dependent(mod,
                                                              monkeypatch,
                                                              tmp_path):
    """The log must land in the dir the installer passed, which proves the
    re-point happened before the FIRST state-dependent line."""
    explicit = tmp_path / "canonical"
    argv = ["--service-run", "--backend", "https://nivxray.nivxforge.com",
            "--interval", "30", "--state-dir", f'"{explicit}"']
    with pytest.raises(ModuleNotFoundError):        # no pywin32 on Linux
        mod._run_as_service(argv)
    log = (explicit / "service.log").read_text()
    assert "service entrypoint reached" in log
    assert f"state dir: {explicit} (explicit=True)" in log
    assert not (mod.sensor.STATE_DIR / "service.log").exists() or \
        mod.sensor.STATE_DIR == explicit


def test_every_state_path_follows_the_state_root(mod, tmp_path):
    root = tmp_path / "canonical"
    mod.sensor.use_state_dir(root)
    s = mod.sensor
    assert s.STATE_DIR == root
    assert s.IDENTITY_FILE == root / "identity.json"
    assert s.QUEUE_FILE == root / "outbox.jsonl"
    assert s.OFFSET_FILE == root / "outbox.offset"
    assert s.BOOKMARK_FILE == root / "channels.json"
    assert s.POLICY_FILE == root / "policy.json"
    assert s.EXCLUSION_JOURNAL == root / "exclusion_enforcement.json"


def test_repointing_only_the_log_would_not_be_enough(mod, tmp_path):
    """Regression on the failure class: a service that logs in the right
    place but reads the identity somewhere else looks healthy and delivers
    nothing."""
    root = tmp_path / "canonical"
    mod.sensor.use_state_dir(root)
    assert mod.sensor.IDENTITY_FILE.parent == root
    assert mod.sensor.QUEUE_FILE.parent == root


@pytest.mark.parametrize("env,expected", [
    ({"ProgramData": r"D:\PD", "ALLUSERSPROFILE": r"D:\AUP"}, r"D:\PD"),
    ({"ALLUSERSPROFILE": r"D:\AUP"}, r"D:\AUP"),          # ProgramData absent
    ({"SystemDrive": "C:"}, "C:"),                        # bare service env
    ({}, "/var/lib"),
])
def test_state_root_survives_a_localsystem_environment(mod, monkeypatch,
                                                       env, expected):
    """A LocalSystem service inherits services.exe's environment and may
    not carry ProgramData at all. The fallback must never silently pick a
    path that exists nowhere the installer wrote."""
    for key in ("ProgramData", "ALLUSERSPROFILE", "SystemDrive"):
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    assert mod.sensor._default_state_root().startswith(expected)


def test_explicit_state_dir_beats_the_environment(mod, monkeypatch,
                                                  tmp_path):
    monkeypatch.setenv("ProgramData", str(tmp_path / "wrong"))
    explicit = tmp_path / "right"
    mod.sensor.use_state_dir(explicit)
    assert mod.sensor.IDENTITY_FILE == explicit / "identity.json"


def test_version_reports_the_state_dir_for_comparison(mod, capsys):
    mod.main(["version"])
    out = json.loads(capsys.readouterr().out)
    assert out["state_dir"] == str(mod.sensor.STATE_DIR)


# ── 8 · the shutdown record must survive the teardown race ────────
@pytest.fixture()
def pywin32_stubs(monkeypatch):
    """Minimal SCM stand-ins so the real service class can be driven here.

    pywin32 does not exist on this platform, but the lifecycle ORDER is
    platform-independent and is what the CI gate asserts.
    """
    import types

    reported: list[tuple[int, str]] = []

    class ServiceFramework:
        def __init__(self, args):
            self.args = args

        def ReportServiceStatus(self, status, waitHint=None):  # noqa: N802
            log = mod_log()
            reported.append((status, log))

    win32service = types.SimpleNamespace(
        SERVICE_STOPPED=1, SERVICE_START_PENDING=2,
        SERVICE_STOP_PENDING=3, SERVICE_RUNNING=4)
    win32event = types.SimpleNamespace(
        WAIT_OBJECT_0=0,
        CreateEvent=lambda *a: object(),
        SetEvent=lambda e: None,
        WaitForSingleObject=lambda e, ms: 0)
    servicemanager = types.SimpleNamespace(
        LogInfoMsg=lambda m: None, LogErrorMsg=lambda m: None,
        Initialize=lambda: None, PrepareToHostSingle=lambda c: None,
        StartServiceCtrlDispatcher=lambda: None)
    for name, module in (
            ("win32service", win32service),
            ("win32event", win32event),
            ("servicemanager", servicemanager),
            ("win32serviceutil",
             types.SimpleNamespace(ServiceFramework=ServiceFramework))):
        monkeypatch.setitem(sys.modules, name, module)
    return types.SimpleNamespace(reported=reported, win32event=win32event,
                                 win32service=win32service)


_LOG_HOLDER: dict[str, Path] = {}


def mod_log() -> str:
    log = _LOG_HOLDER.get("path")
    return log.read_text() if log and log.exists() else ""


def _drive_lifecycle(mod, pywin32_stubs, monkeypatch):
    _LOG_HOLDER["path"] = mod.sensor.STATE_DIR / "service.log"
    cls = mod._service_class("https://nivxray.nivxforge.com", 30)
    svc = cls(["NivXForgeSensor"])
    # the host is not enrolled — exactly the CI runner's situation
    monkeypatch.setattr(mod.sensor, "run",
                        lambda *a, **k: sys.exit("not enrolled"))
    stopped = {"done": False}

    def wait(event, ms):
        if not stopped["done"]:          # the SCM stops us mid-wait
            stopped["done"] = True
            svc.SvcStop()
        return 0
    pywin32_stubs.win32event.WaitForSingleObject = wait
    svc.SvcRun()
    return svc


def test_the_service_emits_the_full_lifecycle_in_order(mod, pywin32_stubs,
                                                       monkeypatch):
    _drive_lifecycle(mod, pywin32_stubs, monkeypatch)
    log = (mod.sensor.STATE_DIR / "service.log").read_text()
    order = ["START_PENDING", "RUNNING", "control STOP received",
             "stop event signalled", "STOPPED"]
    positions = []
    for needle in order:
        assert needle in log, f"{needle} was never recorded"
        positions.append(log.index(needle))
    assert positions == sorted(positions), f"out of order:\n{log}"


def test_stopped_is_on_disk_before_the_scm_is_told(mod, pywin32_stubs,
                                                   monkeypatch):
    """The exact defect: reporting SERVICE_STOPPED first let the SCM tear
    the process down before the final record reached disk."""
    _drive_lifecycle(mod, pywin32_stubs, monkeypatch)
    stopped_reports = [snapshot for status, snapshot
                       in pywin32_stubs.reported
                       if status == pywin32_stubs.win32service.SERVICE_STOPPED]
    assert stopped_reports, "SERVICE_STOPPED was never reported to the SCM"
    assert "STOPPED" in stopped_reports[-1], (
        "the shutdown record must already be on disk when the SCM is told "
        "STOPPED — afterwards is a race the service loses")


def test_the_service_survives_an_unenrolled_cycle_and_still_stops(
        mod, pywin32_stubs, monkeypatch):
    _drive_lifecycle(mod, pywin32_stubs, monkeypatch)
    log = (mod.sensor.STATE_DIR / "service.log").read_text()
    assert "cycle failed — retrying" in log and "not enrolled" in log
    assert "STOPPED" in log


def test_the_shutdown_record_is_flushed_to_disk():
    text = SETUP.read_text()
    assert "os.fsync(fh.fileno())" in text
    # and the write must precede the SCM notification in the source
    finally_block = text.split("self.SvcDoRun()", 1)[1][:600]
    assert finally_block.index('_service_log("STOPPED")') < \
        finally_block.index("ReportServiceStatus(win32service.SERVICE_STOPPED)")


# ── 5 · CI must accept the artifact on a REAL service lifecycle ───
def test_ci_workflow_runs_a_real_scm_lifecycle_smoke_test():
    wf = Path("/app/.github/workflows/windows-sensor-installer.yml").read_text()
    assert "--service-run" in wf, "CI must exercise the SCM invocation"
    # the service is created by the PRODUCTION code path, not a hand-written
    # sc.exe line that could drift from what the installer really does
    assert "_install_service" in wf
    assert "sc.exe query" in wf
    assert "RUNNING" in wf
    assert "sc.exe stop" in wf
    assert "STOPPED" in wf
    assert "sc.exe delete" in wf
    assert "stage-host" in wf, "CI must prove the service host unpacks"
    # service.log is an ACCEPTANCE ASSERTION, not optional output
    assert "service diagnostics missing" in wf
    assert "service diagnostics incomplete" in wf
    assert "stop diagnostics incomplete" in wf
    assert "'service entrypoint reached', 'START_PENDING'" in wf
    assert "'control STOP received'" in wf
    assert "Remove-Item $log" in wf, (
        "the log must be cleared first so the assertions prove the SERVICE "
        "wrote it, not an earlier gate")
    assert "if (Test-Path $log) { Write-Host (Get-Content $log -Raw) }" not in wf, (
        "the diagnostics check must not be conditional")
    assert "invalid choice" in wf, (
        "CI must fail explicitly if the SCM command line reaches the "
        "installer's subcommand parser again")


def test_ci_workflow_proves_installer_and_service_share_the_state_root():
    wf = Path("/app/.github/workflows/windows-sensor-installer.yml").read_text()
    assert "INSTALLER_STATE_DIR" in wf
    assert "installer resolved an unexpected state dir" in wf
    assert "state dir: $installerState" in wf
    assert "explicit=True" in wf
    assert "is not using the installer state dir" in wf


def test_ci_workflow_dumps_evidence_before_asserting():
    wf = Path("/app/.github/workflows/windows-sensor-installer.yml").read_text()
    assert "EVIDENCE DUMP" in wf
    assert "EXPECTED SERVICE LOG" in wf
    assert "FOUND SERVICE LOG" in wf
    assert "sc.exe qc" in wf
    # the dump must precede the mandatory diagnostics assertions
    assert wf.index("EVIDENCE DUMP") < wf.index("service diagnostics missing")
