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
INSTALLED_EXE = INSTALL_DIR / "NivXForgeSensor.exe"

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


def _install_service(api: str, interval: int) -> None:
    # binPath value is quoted as a whole; the exe path is quoted INSIDE it so
    # Windows can tell the image path from the arguments.
    bin_value = (f'\\"{INSTALLED_EXE}\\" --service-run '
                 f'--backend {api} --interval {interval}')
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
def _service_class():
    """Built lazily so the CLI works on a host without pywin32."""
    import servicemanager                                  # noqa: PLC0415
    import win32event                                      # noqa: PLC0415
    import win32service                                    # noqa: PLC0415
    import win32serviceutil                                # noqa: PLC0415

    class NivXForgeSensorService(win32serviceutil.ServiceFramework):
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = SERVICE_DISPLAY
        _svc_description_ = SERVICE_DESCRIPTION

        def __init__(self, args):
            super().__init__(args)
            self.stop_event = win32event.CreateEvent(None, 0, 0, None)
            self.api, self.interval = _service_args()

        def SvcStop(self):                       # noqa: N802
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            win32event.SetEvent(self.stop_event)

        def SvcDoRun(self):                      # noqa: N802
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, f" api={self.api}"))
            while True:
                try:
                    # ONE cycle per iteration so a stop request is honoured
                    # promptly; the sensor owns collection and delivery.
                    sensor.run(self.api, self.interval, once=True)
                except Exception as ex:          # noqa: BLE001
                    servicemanager.LogErrorMsg(
                        f"{SERVICE_NAME} cycle failed: {str(ex)[:400]}")
                if win32event.WaitForSingleObject(
                        self.stop_event,
                        max(5, self.interval) * 1000) == win32event.WAIT_OBJECT_0:
                    break

    return NivXForgeSensorService


def _service_args() -> tuple[str, int]:
    """Backend/interval as the SCM passed them in the service binPath."""
    argv = sys.argv
    api, interval = DEFAULT_BACKEND, 30
    for i, value in enumerate(argv):
        if value == "--backend" and i + 1 < len(argv):
            api = argv[i + 1]
        if value == "--interval" and i + 1 < len(argv):
            try:
                interval = int(argv[i + 1])
            except ValueError:
                interval = 30
    return _assert_backend(api), interval


def _run_as_service() -> None:
    import servicemanager                                  # noqa: PLC0415
    servicemanager.Initialize()
    servicemanager.PrepareToHostSingle(_service_class())
    servicemanager.StartServiceCtrlDispatcher()


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
    return ap


def main(argv: list[str] | None = None) -> None:
    args, _unknown = build_parser().parse_known_args(argv)
    if args.service_run:
        _run_as_service()
        return
    if args.cmd == "install":
        install(args.backend, args.tenant, args.token, args.interval,
                args.re_enrol)
    elif args.cmd == "uninstall":
        uninstall(args.purge)
    elif args.cmd == "status":
        print(json.dumps(sensor.status(), indent=2))
    elif args.cmd == "version":
        print(json.dumps({"setup_version": SETUP_VERSION,
                          "sensor_version": sensor.SENSOR_VERSION,
                          "service_name": SERVICE_NAME,
                          "default_backend": DEFAULT_BACKEND}, indent=2))
    else:
        build_parser().print_help()


if __name__ == "__main__":
    main()
