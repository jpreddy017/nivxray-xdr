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
    except (OSError, AttributeError):
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
                self.ReportServiceStatus(win32service.SERVICE_STOPPED)
                _service_log("STOPPED")

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
    return ap


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
