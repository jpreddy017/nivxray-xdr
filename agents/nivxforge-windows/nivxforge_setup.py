#!/usr/bin/env python3
"""NivXForge EDR · Windows installer + Windows Service host (Track B V1).

ONE frozen executable, built on Windows by
`.github/workflows/windows-sensor-installer.yml`, that replaces the
PowerShell + "install Python first" experience:

    NivXForgeEDRSetup.exe install --tenant ten_... --token nvxenr_...
    NivXForgeEDRSetup.exe status
    NivXForgeEDRSetup.exe uninstall [--purge]

It creates NO second sensor. Collection, enrolment, the durable journal,
heartbeat, policy fetch/ACK and the Gate 7 exclusion evaluator all come
from `nivxforge_sensor.py`, imported here and bundled into the same
artifact. This module adds exactly three things the scheduled-task
installer could not provide:

  1. a real **Windows Service** (SCM-controlled, automatic start, crash
     recovery) hosting the existing `sensor.run()` loop,
  2. a self-installing binary that needs **no Python on the endpoint**,
  3. a **production-origin guard** so an endpoint can never be pointed at
     a preview or localhost backend, and never at a fallback tenant.

The artifact carries NO credential: the enrolment token is supplied at
install time and exchanged once for this computer's own endpoint-scoped
credential. Nothing secret is ever printed.
"""
from __future__ import annotations

import argparse
import ctypes
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse

import nivxforge_sensor as sensor

SETUP_VERSION = "1.0.0"
SERVICE_NAME = "NivXForgeSensor"
SERVICE_DISPLAY = "NivXForge EDR Sensor"
SERVICE_DESCRIPTION = ("Collects authorised Windows security telemetry and "
                       "delivers it to NivXForge EDR. Enrolment identity is "
                       "per-computer and never shared.")
DEFAULT_BACKEND = "https://nivxray.nivxforge.com"
INSTALL_DIR = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) \
    / "NivXForge" / "sensor"
#: the installer/CLI copy kept on the endpoint for status and uninstall
INSTALLED_EXE = INSTALL_DIR / "NivXForgeEDRSetup.exe"
#: The SERVICE image is a **onedir** build shipped as a payload inside the
#: one-file installer. A PyInstaller one-file binary is a poor Windows
#: service host: its bootloader unpacks to a temp dir and re-executes
#: itself as a CHILD process, so the process the SCM started is not the
#: process that calls StartServiceCtrlDispatcher(). That is a documented
#: cause of "error 1053: the service did not respond in a timely fashion".
#: The onedir host starts immediately in the SCM-launched process.
SERVICE_DIR = INSTALL_DIR / "service"
SERVICE_EXE = SERVICE_DIR / "NivXForgeSensor.exe"

#: A tenant identifier that must never be accepted as a silent fallback.
_FORBIDDEN_TENANTS = {"", "default", "test", "test_database", "preview",
                      "unknown", "none", "null"}
#: Hosts that must never receive production endpoint telemetry.
_FORBIDDEN_HOST_MARKERS = ("localhost", "127.0.0.1", "::1", "0.0.0.0",
                           "preview.emergentagent.com", ".local")


# ── guards ────────────────────────────────────────────────────────
def _assert_backend(api: str) -> str:
    """Refuse anything that is not a real remote HTTPS backend.

    An endpoint pointed at preview or localhost produces evidence that
    looks delivered and is investigable nowhere, which is precisely the
    failure mode the platform's investigability state exists to expose.
    """
    api = (api or "").strip().rstrip("/")
    parsed = urlparse(api)
    if parsed.scheme != "https":
        raise SystemExit("refusing to install: --backend must be https "
                         f"(got {parsed.scheme or 'no scheme'})")
    host = (parsed.hostname or "").lower()
    if not host:
        raise SystemExit("refusing to install: --backend has no host")
    if any(marker in host for marker in _FORBIDDEN_HOST_MARKERS):
        raise SystemExit(f"refusing to install: {host} is not a production "
                         "backend (localhost/preview origins are rejected)")
    if parsed.port in (8001, 3000):
        raise SystemExit("refusing to install: development port "
                         f"{parsed.port} is not a production backend")
    return api


def _assert_tenant(tenant: str) -> str:
    tenant = (tenant or "").strip()
    if tenant.lower() in _FORBIDDEN_TENANTS:
        raise SystemExit("refusing to install: --tenant must be the explicit "
                         "tenant id issued by the platform; there is no "
                         "default tenant fallback")
    return tenant


def _assert_admin() -> None:
    try:
        elevated = bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        elevated = False
    if not elevated:
        raise SystemExit("run this installer from an ELEVATED prompt "
                         "(Administrator). Nothing was installed.")


def _sc(cmdline: str) -> subprocess.CompletedProcess:
    """Run `sc.exe` from a RAW command line.

    `sc.exe` uses `key= value` syntax where the space after `=` is an
    ARGUMENT SEPARATOR, not part of the value: `start=` and `auto` must
    arrive as two distinct argv tokens. Passing a Python list means
    `subprocess.list2cmdline` quotes any element containing a space, so
    `"start= auto"` reached sc as one quoted token and it answered
    `ERROR: Invalid start= field`. On Windows a string command line is
    handed to CreateProcess verbatim, which is the only way to control
    that tokenisation exactly — including quoting a binPath value that
    itself contains spaces and its own arguments.
    """
    return subprocess.run(cmdline, capture_output=True, text=True)


def _service_exists() -> bool:
    q = _sc(f'sc.exe query "{SERVICE_NAME}"')
    return q.returncode == 0


def _service_config() -> str:
    return _sc(f'sc.exe qc "{SERVICE_NAME}"').stdout or ""


# ── install ───────────────────────────────────────────────────────
def _self_path() -> Path:
    return Path(sys.executable if getattr(sys, "frozen", False)
                else __file__).resolve()


def _protect_state_dir() -> None:
    """SYSTEM + Administrators only — the endpoint credential lives here."""
    state = sensor.STATE_DIR
    state.mkdir(parents=True, exist_ok=True)
    subprocess.run(["icacls", str(state), "/inheritance:r",
                    "/grant:r", "*S-1-5-18:(OI)(CI)F",
                    "/grant:r", "*S-1-5-32-544:(OI)(CI)F"],
                   capture_output=True, text=True)


def _service_payload_dir() -> Path | None:
    """The onedir service host carried inside this one-file installer."""
    base = getattr(sys, "_MEIPASS", None)
    if not base:
        return None
    candidate = Path(base) / "service"
    return candidate if (candidate / SERVICE_EXE.name).exists() else None


def _stage_service_host() -> Path:
    """Unpack the onedir service host next to the installer copy.

    The service image must be a normal directory layout on disk: see
    SERVICE_EXE. Staging is idempotent so a repair install overwrites the
    host without touching the enrolment identity, which lives in the
    separate protected state directory.
    """
    payload = _service_payload_dir()
    if payload is None:
        raise SystemExit(
            "this build carries no Windows service host payload. Refusing "
            "to create a service with no valid image. Use an installer "
            "produced by the windows-sensor-installer workflow.")
    if _service_exists():
        _sc(f'sc.exe stop "{SERVICE_NAME}"')       # release the open image
    SERVICE_DIR.mkdir(parents=True, exist_ok=True)
    shutil.copytree(payload, SERVICE_DIR, dirs_exist_ok=True)
    if not SERVICE_EXE.exists():
        raise SystemExit(f"service host staging failed: {SERVICE_EXE} "
                         "is missing after unpack")
    return SERVICE_EXE


def _install_service(api: str, interval: int) -> None:
    if not SERVICE_EXE.exists():
        raise SystemExit(f"refusing to create a service: {SERVICE_EXE} does "
                         "not exist (service host was not staged)")
    # binPath value is quoted as a whole; the exe path is quoted INSIDE it so
    # Windows can tell the image path from the arguments.
    # --state-dir is AUTHORITATIVE: the installer resolves the canonical
    # state root here (as an elevated interactive user, with a full
    # environment) and tells the service explicitly, because a LocalSystem
    # service cannot be trusted to infer the same path. No credential,
    # token or secret is ever placed on the command line — only a
    # directory.
    bin_value = (f'\\"{SERVICE_EXE}\\" --service-run '
                 f'--backend {api} --interval {interval} '
                 f'--state-dir \\"{sensor.STATE_DIR}\\"')
    if _service_exists():
        print(f"  existing service found — replacing {SERVICE_NAME}")
        _sc(f'sc.exe stop "{SERVICE_NAME}"')
        _sc(f'sc.exe delete "{SERVICE_NAME}"')
    created = _sc(
        f'sc.exe create "{SERVICE_NAME}" binPath= "{bin_value}" '
        f'start= auto obj= LocalSystem DisplayName= "{SERVICE_DISPLAY}"')
    if created.returncode != 0:
        raise SystemExit("service creation failed: "
                         f"{(created.stdout or created.stderr).strip()[:300]}")
    _sc(f'sc.exe description "{SERVICE_NAME}" "{SERVICE_DESCRIPTION}"')
    # Crash recovery: restart after 60s, three times, counter resets daily.
    _sc(f'sc.exe failure "{SERVICE_NAME}" reset= 86400 '
        f'actions= restart/60000/restart/60000/restart/60000')
    started = _sc(f'sc.exe start "{SERVICE_NAME}"')
    if started.returncode != 0:
        raise SystemExit("service did not start: "
                         f"{(started.stdout or started.stderr).strip()[:300]}")
    # Prove the SCM actually recorded what we asked for.
    config = _service_config()
    if "AUTO_START" not in config:
        raise SystemExit("service was created but is not AUTO_START: "
                         f"{config.strip()[:300]}")


def _validate_identity() -> dict:
    """Fail-closed check on an existing enrolment.

    A resume must only skip enrolment when the local identity is genuinely
    complete. A truncated or half-written identity.json must NOT be treated
    as "already enrolled", because that would leave a computer permanently
    unable to deliver evidence while looking installed.
    """
    try:
        ident = json.loads(sensor.IDENTITY_FILE.read_text())
    except (OSError, ValueError) as ex:
        raise SystemExit(
            f"existing {sensor.IDENTITY_FILE} is unreadable ({type(ex).__name__}). "
            "Refusing to guess. Re-run with --re-enrol and a fresh token, or "
            "remove the file deliberately.") from None
    missing = [k for k in ("tenant_id", "endpoint_id", "credential_id",
                           "agent_credential") if not ident.get(k)]
    if missing:
        raise SystemExit(
            f"existing enrolment is incomplete (missing: {', '.join(missing)}). "
            "Refusing to start a service that cannot authenticate. Re-run with "
            "--re-enrol and a fresh token.")
    return ident


def install(api: str, tenant: str | None, token: str | None,
            interval: int, re_enrol: bool) -> None:
    # Pure argument validation FIRST: it has no side effects, so it is safe
    # to run before the elevation check, and it makes the refusal
    # deterministic on any host (including an already-elevated CI runner).
    # Nothing is written until _assert_admin() has passed.
    api = _assert_backend(api)
    _assert_admin()
    print(f"=== 1 . STAGE ===\n  install dir : {INSTALL_DIR}")
    INSTALL_DIR.mkdir(parents=True, exist_ok=True)
    source = _self_path()
    if source != INSTALLED_EXE:
        # A running service holds the binary open; stop it before replacing.
        if _service_exists():
            _sc(f'sc.exe stop "{SERVICE_NAME}"')
        shutil.copy2(source, INSTALLED_EXE)
    print(f"  binary      : {INSTALLED_EXE}")
    _stage_service_host()
    print(f"  service host: {SERVICE_EXE}  (onedir, SCM-hosted)")

    print("\n=== 2 . PROTECTED STATE ===")
    _protect_state_dir()
    print(f"  state dir   : {sensor.STATE_DIR}  (SYSTEM + Administrators)")

    print("\n=== 3 . ENROLMENT ===")
    if sensor.IDENTITY_FILE.exists() and not re_enrol:
        # RESUME. This computer is already enrolled, so no token is required
        # and none is consumed: recovering from a later-stage failure must
        # never cost an enrolment token or a second endpoint identity.
        existing = _validate_identity()
        print(f"  RESUME: already enrolled — endpoint_id="
              f"{existing['endpoint_id']}")
        print(f"  tenant      : {existing['tenant_id']}")
        print("  credential  : present (kept; never re-issued here)")
        print("  no enrolment request sent, no token required or consumed")
    else:
        tenant = _assert_tenant(tenant or "")
        if not (token or "").strip():
            raise SystemExit("--token is required to enrol. The installer "
                             "carries no credential by design.")
        sensor.enrol(api, tenant, token.strip())

    print("\n=== 4 . WINDOWS SERVICE ===")
    _install_service(api, interval)
    print(f"  service     : {SERVICE_NAME} (LocalSystem, automatic, running)")

    print("\n=== 5 . IDENTITY ===")
    print(json.dumps(sensor.status(), indent=2))
    print("\nNivXForge sensor installed. This computer appears under "
          "Management > Computers once AUTHENTICATED TELEMETRY arrives; "
          "CONNECTED is not the same as INVESTIGABLE.")


def uninstall(purge: bool) -> None:
    _assert_admin()
    _sc(f'sc.exe stop "{SERVICE_NAME}"')
    _sc(f'sc.exe delete "{SERVICE_NAME}"')
    if INSTALL_DIR.exists():
        shutil.rmtree(INSTALL_DIR, ignore_errors=True)
    if purge and sensor.STATE_DIR.exists():
        shutil.rmtree(sensor.STATE_DIR, ignore_errors=True)
        print("  state directory PURGED (identity and journal removed)")
    else:
        print(f"  state directory kept at {sensor.STATE_DIR} "
              "(use --purge to remove the identity and journal)")
    print("NivXForge sensor uninstalled.")


# ── Windows Service host ──────────────────────────────────────────
SERVICE_FLAG = "--service-run"


def _service_log(message: str) -> None:
    """Append a service-lifecycle line to a file the SCM cannot swallow.

    Error 1053 ("the service did not respond to the start request") is the
    only thing Windows tells an operator when a service process dies
    before it reaches the control dispatcher. That is exactly how the
    argparse defect hid: the process exited with code 2 and left no trace
    anywhere. This log makes the next such failure self-evident on the
    endpoint instead of requiring a console repro.
    """
    try:
        sensor.STATE_DIR.mkdir(parents=True, exist_ok=True)
        with open(sensor.STATE_DIR / "service.log", "a",
                  encoding="utf-8") as fh:
            fh.write(f"{sensor._now()} {message}\n")
            # Flushed to DISK, not just to the OS buffer: the final record
            # is written while the SCM may already be tearing the process
            # down, so a buffered line would simply be lost.
            fh.flush()
            os.fsync(fh.fileno())
    except (OSError, AttributeError, ValueError):
        pass                                    # logging must never kill it


def _service_class(api: str, interval: int):
    """Built lazily so the CLI works on a host without pywin32.

    `api`/`interval` are baked into the class because the SCM constructs
    the service object itself: the runtime must not re-read the process
    argv (or any global) at construction time.
    """
    import servicemanager                                  # noqa: PLC0415
    import win32event                                      # noqa: PLC0415
    import win32service                                    # noqa: PLC0415
    import win32serviceutil                                # noqa: PLC0415

    def _event_log(kind: str, message: str) -> None:
        """Event-log writes are best-effort: a missing message resource
        must never be the reason the service fails to start."""
        try:
            if kind == "error":
                servicemanager.LogErrorMsg(message)
            else:
                servicemanager.LogInfoMsg(message)
        except Exception:                        # noqa: BLE001
            pass

    class NivXForgeSensorService(win32serviceutil.ServiceFramework):
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = SERVICE_DISPLAY
        _svc_description_ = SERVICE_DESCRIPTION
        api = ""
        interval = 30

        def __init__(self, args):
            super().__init__(args)
            self.stop_event = win32event.CreateEvent(None, 0, 0, None)

        def SvcStop(self):                       # noqa: N802
            _service_log("control STOP received")
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING,
                                     waitHint=20000)
            win32event.SetEvent(self.stop_event)

        def SvcShutdown(self):                   # noqa: N802
            """Machine shutdown is a stop, not a crash."""
            _service_log("control SHUTDOWN received")
            self.SvcStop()

        def SvcRun(self):                        # noqa: N802
            # Reported explicitly (rather than relying on the framework
            # default) so the transition SCM waits for is unambiguous.
            self.ReportServiceStatus(win32service.SERVICE_START_PENDING,
                                     waitHint=30000)
            _service_log(f"START_PENDING api={self.api} "
                         f"interval={self.interval}")
            self.ReportServiceStatus(win32service.SERVICE_RUNNING)
            _service_log("RUNNING")
            _event_log("info", f"{SERVICE_NAME} running (api={self.api})")
            try:
                self.SvcDoRun()
            finally:
                # ORDER IS THE CONTRACT: the final record is written and
                # fsynced BEFORE the SCM is told STOPPED. Once SERVICE_STOPPED
                # is reported the SCM may tear the process down immediately,
                # so a line written afterwards is a race the service loses —
                # which is exactly why the shutdown record went missing.
                _service_log("STOPPED")
                self.ReportServiceStatus(win32service.SERVICE_STOPPED)

        def SvcDoRun(self):                      # noqa: N802
            while True:
                try:
                    # ONE cycle per iteration so a stop request is honoured
                    # promptly; the sensor owns collection and delivery.
                    sensor.run(self.api, self.interval, once=True)
                except (Exception, SystemExit) as ex:   # noqa: BLE001
                    # A cycle failure (not enrolled yet, backend
                    # unreachable, a channel unreadable) must NOT stop the
                    # service: `sensor.run` raises SystemExit when there is
                    # no local identity, and an unhandled SystemExit here
                    # would make Windows report a service failure instead
                    # of a retryable condition.
                    detail = f"{type(ex).__name__}: {str(ex)[:300]}"
                    _service_log(f"cycle failed — retrying: {detail}")
                    _event_log("error",
                               f"{SERVICE_NAME} cycle failed: {detail}")
                if win32event.WaitForSingleObject(
                        self.stop_event,
                        max(5, self.interval) * 1000) == win32event.WAIT_OBJECT_0:
                    _service_log("stop event signalled — leaving run loop")
                    break

    NivXForgeSensorService.api = api
    NivXForgeSensorService.interval = interval
    return NivXForgeSensorService


def _argv_value(argv: list[str], flag: str) -> str | None:
    """Value after `flag`, with any wrapping quotes removed.

    The Windows CRT strips the quotes the SCM stored around a path that
    may contain spaces; this keeps the same argv usable in tests.
    """
    for i, value in enumerate(argv):
        if value == flag and i + 1 < len(argv):
            return argv[i + 1].strip('"')
    return None


def _service_args(argv: list[str]) -> tuple[str, int]:
    """Backend/interval as the SCM passed them in the service binPath.

    Parsed from the given argv WITHOUT argparse on purpose. The service
    command line is written by `_install_service`, not by a human, and the
    installer's subcommand parser must never see it: `--backend` is not a
    top-level option there, so argparse treated the URL that follows it as
    the positional subcommand and exited 2 ("invalid choice") long before
    `StartServiceCtrlDispatcher()` — which is what Windows surfaced as
    error 1053.
    """
    api = _argv_value(argv, "--backend") or DEFAULT_BACKEND
    raw_interval = _argv_value(argv, "--interval")
    try:
        interval = int(raw_interval) if raw_interval else 30
    except ValueError:
        interval = 30
    return _assert_backend(api), interval


def _run_as_service(argv: list[str]) -> None:
    # STATE ROOT FIRST. Every later line — the diagnostics log, the
    # enrolment identity, the durable journal, the offset, the bookmarks,
    # the policy and the enforcement journal — resolves from it, so it is
    # applied before ANY state-dependent work, including logging.
    explicit = _argv_value(argv, "--state-dir")
    if explicit:
        sensor.use_state_dir(explicit)
    _service_log(f"service entrypoint reached: {' '.join(argv)}")
    _service_log(f"state dir: {sensor.STATE_DIR} "
                 f"(explicit={bool(explicit)})")
    try:
        api, interval = _service_args(argv)
    except SystemExit as ex:
        _service_log(f"refused to start: {ex}")
        raise
    import servicemanager                                  # noqa: PLC0415
    try:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(_service_class(api, interval))
        servicemanager.StartServiceCtrlDispatcher()
    except BaseException as ex:                  # noqa: BLE001
        # Includes the expected failure when the binary is run by hand
        # instead of by the SCM (error 1063): still logged, never silent.
        _service_log(f"dispatcher exited: {type(ex).__name__}: "
                     f"{str(ex)[:300]}")
        raise


# ── CLI ───────────────────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="NivXForgeEDRSetup",
        description="NivXForge EDR sensor installer for Windows")
    ap.add_argument("--service-run", action="store_true",
                    help=argparse.SUPPRESS)
    sub = ap.add_subparsers(dest="cmd")
    i = sub.add_parser("install", help="install, enrol and start the service")
    i.add_argument("--backend", default=DEFAULT_BACKEND)
    i.add_argument("--tenant")
    i.add_argument("--token")
    i.add_argument("--interval", type=int, default=30)
    i.add_argument("--re-enrol", action="store_true")
    u = sub.add_parser("uninstall", help="stop and remove the service")
    u.add_argument("--purge", action="store_true")
    sub.add_parser("status", help="local enrolment and queue state")
    sub.add_parser("version", help="installer and sensor versions")
    sub.add_parser("stage-host",
                   help="(internal) unpack the Windows service host only")
    j = sub.add_parser("journal-selftest",
                       help="prove the evidence journal works IN THIS BINARY")
    j.add_argument("--dir", default=None,
                   help="scratch directory (default: a temp dir)")
    j.add_argument("--json-out", default=None,
                   help="write the machine-readable Gate 0 result here")
    j.add_argument("--restart-check", action="store_true",
                   help="re-open an EXISTING --dir and prove the journal "
                        "survived a full process restart of this binary")
    return ap


#: value used for a check that CANNOT be answered off Windows. It is NOT
#: a pass: the Gate 0 CI contract demands the literal string "PASS", so a
#: Linux run can never be mistaken for Windows evidence.
NOT_WINDOWS = "N/A_NON_WINDOWS"
_IS_WINDOWS = os.name == "nt"
#: modules the frozen artifact MUST carry for the evidence journal to work
#: on an endpoint with no Python installed.
_REQUIRED_BUNDLED = ("nivxforge_sensor", "nivxforge_journal", "sqlite3",
                     "_sqlite3")
_SELFTEST_EVENT = {
    "observed_at": "selftest", "kind": "WINDOWS_EVENT_LOG",
    "winlog": {"channel": "SelfTest", "record_id": 1, "event_id": "1",
               "provider": "selftest", "time_created": "selftest",
               "xml": "<Event/>"}}


def _volume_filesystem(path: str | os.PathLike) -> str:
    """Filesystem name of the volume holding `path` (NTFS / FAT32 / ...)."""
    if not _IS_WINDOWS:
        return NOT_WINDOWS
    drive = os.path.splitdrive(str(Path(path).resolve()))[0]
    if not drive:
        return "UNKNOWN"
    fs = ctypes.create_unicode_buffer(261)
    name = ctypes.create_unicode_buffer(261)
    try:
        ok = ctypes.windll.kernel32.GetVolumeInformationW(  # type: ignore[attr-defined]
            ctypes.c_wchar_p(drive + "\\"), name, 261, None, None, None,
            fs, 261)
    except (AttributeError, OSError):
        return "UNKNOWN"
    return fs.value.upper() if ok else "UNKNOWN"


def _module_provenance() -> dict:
    """Where each required module actually came from IN THIS PROCESS.

    Packaging regressions are silent by construction: a missing hidden
    import only fails on the endpoint, at the moment evidence would have
    been journaled. So the artifact reports its own provenance and the
    build FAILS CLOSED on it.
    """
    import importlib                                       # noqa: PLC0415

    bundle = getattr(sys, "_MEIPASS", None)
    out: dict = {}
    for name in _REQUIRED_BUNDLED:
        try:
            module = importlib.import_module(name)
        except Exception as ex:                            # noqa: BLE001
            out[name] = {"present": False,
                         "error": f"{type(ex).__name__}: {str(ex)[:200]}"}
            continue
        file = getattr(module, "__file__", None)
        info: dict = {"present": True, "file": file,
                      "file_on_disk": bool(file and Path(file).exists())}
        if bundle and file:
            try:
                info["in_frozen_bundle"] = Path(file).resolve().is_relative_to(
                    Path(bundle).resolve())
            except (OSError, ValueError):
                info["in_frozen_bundle"] = False
        out[name] = info
    return out


def _packaging_regression_ok(provenance: dict) -> bool:
    """No required module may be absent, and the NATIVE sqlite extension
    must be a real file inside the frozen bundle."""
    if any(not info.get("present") for info in provenance.values()):
        return False
    native = provenance.get("_sqlite3", {})
    if not native.get("file_on_disk"):
        return False
    if getattr(sys, "frozen", False):
        return all(info.get("in_frozen_bundle") is not False
                   for info in provenance.values()) \
            and bool(native.get("in_frozen_bundle"))
    return True


def _sqlite_runtime_binaries() -> list[str]:
    """Native SQLite files found next to / inside this process image."""
    roots = [Path(p) for p in
             {getattr(sys, "_MEIPASS", None), str(Path(sys.executable).parent)}
             if p]
    found: list[str] = []
    for root in roots:
        for pattern in ("sqlite3.dll", "_sqlite3*.pyd", "_sqlite3*.so",
                        "libsqlite3*"):
            found += [str(hit) for hit in root.glob(pattern)]
    return sorted(set(found))


def _state_dir_access() -> object:
    """The SERVICE writes evidence here, so write access is a gate."""
    if not _IS_WINDOWS:
        return NOT_WINDOWS
    try:
        state = sensor.STATE_DIR
        state.mkdir(parents=True, exist_ok=True)
        probe = state / ".gate0-probe"
        probe.write_text("gate0", encoding="ascii")
        ok = probe.read_text(encoding="ascii") == "gate0"
        probe.unlink()
        return ok
    except OSError:
        return False


def _service_permission_check() -> object:
    """SYSTEM (or Administrators) must own the state dir, and it must not
    be writable by everyone: the endpoint credential lives there."""
    if not _IS_WINDOWS:
        return NOT_WINDOWS
    try:
        acl = subprocess.run(["icacls", str(sensor.STATE_DIR)],
                             capture_output=True, text=True,
                             timeout=60).stdout or ""
    except (OSError, subprocess.SubprocessError):
        return False
    dense = acl.upper().replace(" ", "")
    privileged = ("NTAUTHORITY\\SYSTEM" in dense
                  or "BUILTIN\\ADMINISTRATORS" in dense
                  or "S-1-5-18" in dense or "S-1-5-32-544" in dense)
    world_writable = ("EVERYONE:(F)" in dense or "EVERYONE:(M)" in dense
                      or "EVERYONE:(W)" in dense)
    return bool(privileged and not world_writable)


def _pragmas(db) -> dict:
    return {
        "wal_mode": str(db.execute(
            "PRAGMA journal_mode").fetchone()[0]).lower() == "wal",
        "synchronous_full": int(
            db.execute("PRAGMA synchronous").fetchone()[0]) == 2,
        "auto_vacuum_incremental": int(
            db.execute("PRAGMA auto_vacuum").fetchone()[0]) == 2,
    }


def journal_selftest(scratch: str | None = None, *,
                     restart_check: bool = False) -> dict:
    """GATE 0 · prove the LOCAL EVIDENCE JOURNAL inside the real artifact.

    A Linux unit test cannot answer the only questions that matter for the
    frozen Windows binary: did PyInstaller actually pack `sqlite3` and its
    native `_sqlite3` extension, does WAL + `synchronous=FULL` behave on
    NTFS, does a WAL reopen recover, and can the service reach its state
    directory? So the binary proves it about ITSELF and the Windows build
    gates on the answer. Anything unanswerable on this platform is
    reported as NOT_WINDOWS, never as a pass.

    `restart_check` re-opens an EXISTING `scratch` directory in a NEW
    process of this same executable, which is the only honest proof that
    committed evidence survives a frozen-executable restart.
    """
    import sqlite3 as _sqlite3                             # noqa: PLC0415
    import tempfile                                        # noqa: PLC0415

    phase = "RESTART" if restart_check else "PRIMARY"
    if restart_check and not scratch:
        return {"result": "FAIL", "phase": phase,
                "failed": ["restart_check_requires_dir"], "checks": {}}
    provenance = _module_provenance()
    checks: dict = {
        "frozen": bool(getattr(sys, "frozen", False)),
        "python_bundled": not bool(
            os.environ.get("NIVX_SELFTEST_EXPECT_SYSTEM_PYTHON")),
        "executable": sys.executable,
        "platform": "windows" if _IS_WINDOWS else os.name,
        "sqlite3_importable": True,
        "sqlite_library_version": _sqlite3.sqlite_version,
        "sqlite3_native_binary": bool(
            provenance.get("_sqlite3", {}).get("file_on_disk")),
        "sqlite3_native_binary_path":
            provenance.get("_sqlite3", {}).get("file"),
        "sqlite_runtime_binaries": _sqlite_runtime_binaries(),
        "journal_module_importable": bool(
            sensor.nvx_journal.JOURNAL_VERSION),
        "journal_version": sensor.nvx_journal.JOURNAL_VERSION,
        "schema_version": sensor.nvx_journal.SCHEMA_VERSION,
        "module_provenance": provenance,
        "packaging_regression_free": _packaging_regression_ok(provenance),
    }
    root = scratch or tempfile.mkdtemp(prefix="nivxforge-journal-selftest-")
    checks["scratch_filesystem"] = _volume_filesystem(root)
    journal = sensor.nvx_journal.open_journal(root)
    try:
        db = journal._db                                   # noqa: SLF001
        checks["database_created"] = Path(journal.path).exists()
        checks.update(_pragmas(db))
        checks["ntfs_database_create"] = (
            NOT_WINDOWS if not _IS_WINDOWS else
            bool(checks["database_created"]
                 and checks["scratch_filesystem"] == "NTFS"))
        tables = {row[0] for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        checks["schema_initialized"] = {
            "evidence", "cursors", "acquisition_gaps", "integrity", "meta"
        } <= tables
        first = journal.commit_page("SelfTest", [_SELFTEST_EVENT], 1, [])
        replay = journal.commit_page("SelfTest", [_SELFTEST_EVENT], 1, [])
        checks["durable_commit"] = (first["journaled"] == 1
                                    if phase == "PRIMARY"
                                    else first["journaled"] == 0)
        checks["cursor_committed"] = journal.cursor("SelfTest") == 1
        checks["replay_is_idempotent"] = replay["journaled"] == 0
        checks["evidence_rows"] = int(db.execute(
            "SELECT COUNT(*) FROM evidence").fetchone()[0])
        checks["wal_file_created"] = (
            NOT_WINDOWS if not _IS_WINDOWS
            else Path(str(journal.path) + "-wal").exists())
        checks["integrity_snapshot"] = Path(
            journal.write_integrity_snapshot(journal.health())).exists()
        gap = sensor.nvx_journal.build_gap("SelfTest", 101, 105, "LEADING")
        checks["gap_contract"] = (gap["missing_record_id_count"] == 4
                                  and gap["cause"] == "NOT_PROVEN")
    finally:
        journal.close()

    # WAL REOPEN / RECOVERY — same process, second connection: the WAL
    # left on disk by the close above must be recovered, not discarded.
    reopened = sensor.nvx_journal.open_journal(root)
    try:
        pragmas = _pragmas(reopened._db)                   # noqa: SLF001
        checks["wal_reopen_recovery"] = bool(
            pragmas["wal_mode"] and pragmas["synchronous_full"]
            and reopened.cursor("SelfTest") == 1
            and int(reopened._db.execute(                  # noqa: SLF001
                "SELECT COUNT(*) FROM evidence").fetchone()[0]) == 1)
    finally:
        reopened.close()

    # FROZEN RESTART — only a NEW process of this executable can prove it.
    checks["frozen_restart_recovery"] = (
        bool(checks["cursor_committed"] and checks["replay_is_idempotent"]
             and checks["evidence_rows"] == 1 and checks["wal_reopen_recovery"])
        if phase == "RESTART" else "PENDING_RESTART_PHASE")
    checks["state_dir"] = str(sensor.STATE_DIR)
    checks["state_dir_access"] = _state_dir_access()
    checks["service_permission_check"] = _service_permission_check()

    required = ["sqlite3_importable", "sqlite3_native_binary",
                "journal_module_importable", "packaging_regression_free",
                "database_created", "wal_mode", "synchronous_full",
                "auto_vacuum_incremental", "schema_initialized",
                "durable_commit", "cursor_committed",
                "replay_is_idempotent", "integrity_snapshot",
                "gap_contract", "wal_reopen_recovery"]
    if _IS_WINDOWS:
        required += ["ntfs_database_create", "wal_file_created",
                     "state_dir_access", "service_permission_check"]
    if phase == "RESTART":
        required.append("frozen_restart_recovery")
    failed = [name for name in required if checks.get(name) is not True]
    return {"result": "PASS" if not failed else "FAIL", "failed": failed,
            "phase": phase, "scratch_dir": root,
            "sensor_version": sensor.SENSOR_VERSION,
            "setup_version": SETUP_VERSION,
            "gate0": _gate0_verdicts(checks), "checks": checks}


def _verdict(value: object) -> str:
    if value is True:
        return "PASS"
    if value is False:
        return "FAIL"
    return str(value)


def _gate0_verdicts(checks: dict) -> dict:
    """The owner-facing Gate 0 field names, one verdict each."""
    return {
        "WINDOWS_FROZEN": "TRUE" if checks.get("frozen") else "FALSE",
        "WINDOWS_SQLITE": _verdict(checks.get("sqlite3_importable")),
        "WINDOWS_SQLITE_LIBRARY_VERSION":
            checks.get("sqlite_library_version") or "ABSENT",
        "WINDOWS_SQLITE_NATIVE_BINARY":
            _verdict(checks.get("sqlite3_native_binary")),
        "WINDOWS_JOURNAL_MODULE":
            _verdict(checks.get("journal_module_importable")),
        "WINDOWS_NTFS_DATABASE_CREATE":
            _verdict(checks.get("ntfs_database_create")),
        "WINDOWS_WAL_CREATE": ("FAIL" if checks.get("wal_mode") is not True
                               else _verdict(checks.get("wal_file_created"))),
        "WINDOWS_WAL_REOPEN_RECOVERY":
            _verdict(checks.get("wal_reopen_recovery")),
        "WINDOWS_SYNCHRONOUS_FULL":
            _verdict(checks.get("synchronous_full")),
        "WINDOWS_AUTO_VACUUM_INCREMENTAL":
            _verdict(checks.get("auto_vacuum_incremental")),
        "WINDOWS_SCHEMA": _verdict(checks.get("schema_initialized")),
        "WINDOWS_DURABLE_COMMIT": _verdict(checks.get("durable_commit")),
        "WINDOWS_CURSOR_COMMIT": _verdict(checks.get("cursor_committed")),
        "WINDOWS_REPLAY_IDEMPOTENCY":
            _verdict(checks.get("replay_is_idempotent")),
        "WINDOWS_INTEGRITY_SNAPSHOT":
            _verdict(checks.get("integrity_snapshot")),
        "WINDOWS_GAP_CONTRACT": _verdict(checks.get("gap_contract")),
        "WINDOWS_FROZEN_RESTART":
            _verdict(checks.get("frozen_restart_recovery")),
        "WINDOWS_STATE_DIR_ACCESS": _verdict(checks.get("state_dir_access")),
        "WINDOWS_SERVICE_PERMISSION_CHECK":
            _verdict(checks.get("service_permission_check")),
        "PACKAGING_REGRESSION":
            _verdict(checks.get("packaging_regression_free")),
    }


def main(argv: list[str] | None = None) -> None:
    raw = list(sys.argv[1:] if argv is None else argv)
    # SERVICE DISPATCH FIRST. The SCM invokes this binary as
    #   NivXForgeSensor.exe --service-run --backend <url> --interval <n>
    # and that command line must never reach the installer's subcommand
    # parser: `--backend` is unknown there, so argparse consumed the URL
    # that follows it as the positional subcommand and exited 2 with
    # "invalid choice", which Windows reported as error 1053.
    if SERVICE_FLAG in raw:
        _run_as_service(raw)
        return
    args = build_parser().parse_known_args(raw)[0]
    if args.cmd == "install":
        install(args.backend, args.tenant, args.token, args.interval,
                args.re_enrol)
    elif args.cmd == "uninstall":
        uninstall(args.purge)
    elif args.cmd == "status":
        print(json.dumps(sensor.status(), indent=2))
    elif args.cmd == "stage-host":
        _assert_admin()
        INSTALL_DIR.mkdir(parents=True, exist_ok=True)
        print(f"service host staged at {_stage_service_host()}")
    elif args.cmd == "journal-selftest":
        out = journal_selftest(args.dir, restart_check=args.restart_check)
        rendered = json.dumps(out, indent=2)
        print(rendered)
        if args.json_out:
            Path(args.json_out).parent.mkdir(parents=True, exist_ok=True)
            Path(args.json_out).write_text(rendered, encoding="ascii")
        if out["result"] != "PASS":
            sys.exit(f"journal selftest FAILED: {out['failed']}")
    elif args.cmd == "version":
        print(json.dumps({"setup_version": SETUP_VERSION,
                          "sensor_version": sensor.SENSOR_VERSION,
                          "service_name": SERVICE_NAME,
                          "service_exe": str(SERVICE_EXE),
                          "service_host": "ONEDIR_PAYLOAD",
                          "state_dir": str(sensor.STATE_DIR),
                          "default_backend": DEFAULT_BACKEND}, indent=2))
    else:
        build_parser().print_help()


if __name__ == "__main__":
    main()
