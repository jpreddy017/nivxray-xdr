#!/usr/bin/env python3
"""NivXForge EDR · Windows installer + Windows Service host (Track B V1).

ONE frozen executable, built on Windows by
`.github/workflows/windows-sensor-installer.yml`, that replaces the
PowerShell + "install Python first" experience:

    <secret source> | NivXForgeEDRSetup.exe install --tenant ten_... \
                                                    --token-stdin
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

The artifact carries NO credential: the enrolment secret is supplied at
install time ON STDIN ONLY and exchanged once for this computer's own
endpoint-scoped credential. Nothing secret is ever printed.

The secret is never accepted as a command-line value. Windows records
process command lines in several places an EDR itself collects — Sysmon
EID 1 `CommandLine`, the service `binPath`, PowerShell history — so a
secret passed as `--token <value>` would become endpoint telemetry and
could be delivered to the very backend it authenticates against. The
single-use lifetime of the secret reduces the window but does not remove
the exposure, so the interface refuses it outright.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
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
#: VERSIONED SERVICE IMAGES. The previous installer copied the new payload
#: file-by-file ON TOP of the live image directory
#: (`shutil.copytree(..., dirs_exist_ok=True)`), so every upgrade had to
#: win a write race against every DLL/PYD Windows may still have MAPPED.
#: On a real endpoint that failed as
#:     Permission denied: ...\service\_internal\win32\servicemanager.pyd
#: AFTER the service had already been stopped — the SCM reported STOPPED
#: with PID 0, ACLs were correct, no handle was findable and a reboot did
#: not help, because an image SECTION (and, for a pywin32 service, the
#: Event Log's message-file mapping) is not a file handle and is re-taken
#: on the next boot. A file that must not be overwritten is therefore
#: never overwritten: each build is staged into its OWN directory and the
#: SCM is re-pointed at it. The old image is left on disk, untouched, as
#: the rollback source.
VERSIONS_DIR = INSTALL_DIR / "versions"
#: Which versioned image the SCM is pointed at, written only AFTER the
#: service has started successfully.
ACTIVE_FILE = INSTALL_DIR / "active.json"
#: Incomplete staging is recognisable by name and swept on the next run.
STAGING_PREFIX = ".staging-"

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
    if parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ("", "/"):
        raise SystemExit("refusing to install: backend must be an origin without credentials, path, query or fragment")
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

    A MISSING `sc.exe` is reported as a failed command, never raised: off
    Windows (CI unit tests, a Linux developer box) the honest answer to
    "what state is the service in" is "there is no service", and every
    caller here already fails closed on a non-zero result.
    """
    try:
        return subprocess.run(cmdline, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as ex:
        return subprocess.CompletedProcess(cmdline, 1, "", str(ex))


def _sc_argv(*argv: str) -> subprocess.CompletedProcess:
    r"""Run `sc.exe` from an ARGUMENT LIST, for commands that carry a value.

    `binPath=` is the reason this exists. Its value is itself a command
    line — a QUOTED executable path followed by arguments — and building
    that by hand inside an outer quoted string nested quotes wrongly: the
    restored value arrived as `binPath= ""C:\Program Files\...exe" ..."`
    and Windows then read the image path as `C:\Program`. A list hands the
    value to `CreateProcess` through `list2cmdline`, which escapes the
    inner quotes correctly, and it keeps `start=` and `auto` as the two
    SEPARATE tokens `sc.exe` requires — the same property the raw-string
    form was chosen for, without the quoting hazard.
    """
    try:
        return subprocess.run(list(argv), capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as ex:
        return subprocess.CompletedProcess(list(argv), 1, "", str(ex))


#: True on a host that actually HAS an SCM. Off Windows there is no
#: service to misread, so "no service" is the honest answer and every
#: mutation path below is unreachable; on Windows a failed lookup is a
#: failed lookup and must never be rendered as "absent".
WINDOWS = os.name == "nt"
#: `net helpmsg 1060` — ERROR_SERVICE_DOES_NOT_EXIST. This is the ONLY
#: `sc.exe query` failure that means the service is genuinely not there.
_ERROR_SERVICE_DOES_NOT_EXIST = 1060


def _service_lookup() -> tuple[str, str]:
    """Tri-state: ('ABSENT' | 'PRESENT' | 'UNREADABLE', detail).

    The two-state `_service_exists()` this replaces was the R4 defect: it
    answered False for ERROR_ACCESS_DENIED (5), RPC-unavailable (1722) and
    ERROR_SERVICE_MARKED_FOR_DELETE (1072) exactly as it did for a service
    that is genuinely absent. Rollback then classified a real, unreadable
    service as "debris this attempt created" and DELETED it.
    """
    q = _sc(f'sc.exe query "{SERVICE_NAME}"')
    if q.returncode == 0:
        return "PRESENT", q.stdout or ""
    if q.returncode == _ERROR_SERVICE_DOES_NOT_EXIST:
        return "ABSENT", ""
    if not WINDOWS:
        return "ABSENT", ""
    return "UNREADABLE", ((q.stdout or "") + " " + (q.stderr or "")).strip()


def _service_exists() -> bool:
    return _service_lookup()[0] == "PRESENT"


def _service_qc() -> tuple[str, str]:
    """('OK' | 'FAILED', text) for `sc.exe qc`. The exit code is read.

    `_service_config()` discarded it and returned `""`, so a failed query
    became an EMPTY configuration that every field default then silently
    filled in with a guess.
    """
    q = _sc(f'sc.exe qc "{SERVICE_NAME}"')
    if q.returncode != 0:
        return "FAILED", ((q.stdout or "") + " " + (q.stderr or "")).strip()
    return "OK", q.stdout or ""


def _service_config() -> str:
    status, text = _service_qc()
    return text if status == "OK" else ""


# ── service lifecycle, proven rather than assumed ─────────────────
#: `sc.exe stop` is ASYNCHRONOUS: it asks the SCM to begin a transition and
#: returns immediately, usually reporting STOP_PENDING. Replacing the
#: service image straight afterwards raced the dying process and produced,
#: on a real endpoint,
#:     Permission denied: C:\Program Files\NivXForge\sensor\service\
#:                        NivXForgeSensor.exe
#: which aborted the install AFTER the service had already been stopped and
#: BEFORE step 4 could start it again — leaving a previously healthy
#: endpoint dark. Everything below exists to make that impossible.
SERVICE_STOP_TIMEOUT_SECONDS = 60
#: The SCM reporting STOPPED only means it accepted the transition. The
#: image can stay mapped for a short while after the process exits.
IMAGE_RELEASE_TIMEOUT_SECONDS = 30
_POLL_SECONDS = 0.5
_SERVICE_STATES = ("STOPPED", "START_PENDING", "STOP_PENDING", "RUNNING",
                   "CONTINUE_PENDING", "PAUSE_PENDING", "PAUSED")


def _service_state() -> str:
    """The SCM's own word for the service state, "" if it does not exist.

    `sc.exe query` prints `STATE : 4  RUNNING`; the NAME is the authority,
    not the number, because the number is positional and a localised
    Windows still emits the English state name here.
    """
    q = _sc(f'sc.exe query "{SERVICE_NAME}"')
    if q.returncode != 0:
        return ""
    for line in (q.stdout or "").splitlines():
        if "STATE" not in line.upper():
            continue
        for token in line.replace(",", " ").split():
            name = token.strip().upper()
            if name in _SERVICE_STATES:
                return name
    return "UNKNOWN"


def _wait_for_service_state(target: str, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while True:
        if _service_state() == target:
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(_POLL_SECONDS)


def _image_is_released(path: Path) -> bool:
    """Side-by-side upgrades never require release or rename the old image."""
    return path.is_file()


def _wait_for_image_release(path: Path, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while True:
        if _image_is_released(path):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(_POLL_SECONDS)


def _stop_service_and_wait() -> str:
    """Stop the service and PROVE it stopped. Returns the state BEFORE.

    Fails closed. If the SCM will not report STOPPED, or the old image is
    still held, we refuse instead of overwriting the binary of a live
    service — the sensor keeps running and no evidence is put at risk.
    """
    prior = _service_state()
    if not prior:
        return ""
    if prior != "STOPPED":
        print(f"  service     : {prior} — requesting STOP")
        _sc(f'sc.exe stop "{SERVICE_NAME}"')
    if not _wait_for_service_state("STOPPED", SERVICE_STOP_TIMEOUT_SECONDS):
        raise SystemExit(
            f"refusing to replace a live service image: {SERVICE_NAME} did "
            f"not reach STOPPED within {SERVICE_STOP_TIMEOUT_SECONDS}s (the "
            f"SCM reports {_service_state() or 'UNKNOWN'}). Nothing was "
            "replaced, nothing was enrolled and no token was consumed.")
    if not _wait_for_image_release(_active_service_exe(),
                                   IMAGE_RELEASE_TIMEOUT_SECONDS):
        # NOT fatal any more, and this is the whole point of the repair:
        # the new build is staged into its own directory, so a still-mapped
        # previous image blocks nothing. It is reported because it is the
        # evidence that the old in-place copy could never have succeeded.
        print("  service     : STOPPED; previous image still mapped — not "
              "required (new version is staged side-by-side)")
        return prior
    print("  service     : STOPPED, image released")
    return prior


def _restore_service(prior: str, previous_exe: Path | None = None,
                     api: str | None = None,
                     interval: int | None = None,
                     snapshot: dict | None = None) -> bool:
    """Rollback. Returns True only when the endpoint was genuinely restored.

    Two defects shaped this. The first returned immediately unless the
    prior state was RUNNING, which abandoned a deliberately STOPPED
    service after `_create_service` had already deleted and re-created the
    entry. The second is worse, and is why `prior` alone is no longer
    trusted: a failure AFTER activation (the `active.json` commit, for
    example) left the NEW image RUNNING while the old configuration was
    written back underneath it — `sc config` does not touch a running
    process — so the installer announced a rollback that had not happened
    and the endpoint ran an image no record described.

    The transaction is therefore ordered by what the SCM reports NOW:
      1. if anything is running, STOP it and PROVE it stopped;
      2. restore the previous configuration;
      3. restore the previous RUN state — STOPPED stays stopped, RUNNING is
         started again AND the actually-running image is verified;
      4. anything that cannot be proved is an explicit ROLLBACK FAILURE.
    Nothing is force-terminated, no mapped image is deleted, and the new
    image is left on disk for inspection.
    """
    snapshot = snapshot or {}
    current = _service_state()
    if current in ("RUNNING", "START_PENDING", "CONTINUE_PENDING", "PAUSED"):
        print(f"  ROLLBACK: {SERVICE_NAME} is {current} on the image this "
              "attempt activated — stopping it before anything is restored")
        _sc(f'sc.exe stop "{SERVICE_NAME}"')
        if not _wait_for_service_state("STOPPED",
                                       SERVICE_STOP_TIMEOUT_SECONDS):
            print("  ROLLBACK FAILED: could not stop the newly activated "
                  f"service (the SCM reports {_service_state() or 'UNKNOWN'})"
                  ". THE ENDPOINT IS RUNNING AN IMAGE THIS INSTALL DID NOT "
                  "COMMIT. Stop it manually and re-run the installer.")
            return False
    if not _restore_service_config(snapshot, previous_exe, api, interval):
        return False
    if prior == "RUNNING":
        if not _service_exists():
            print(f"  ROLLBACK FAILED: {SERVICE_NAME} no longer exists. THIS "
                  "ENDPOINT IS NOT COLLECTING. Re-run the installer.")
            return False
        _sc(f'sc.exe start "{SERVICE_NAME}"')
        if not _wait_for_service_state("RUNNING",
                                       SERVICE_STOP_TIMEOUT_SECONDS):
            print("  ROLLBACK FAILED: the previous image did not return to "
                  f"RUNNING (the SCM reports {_service_state() or 'UNKNOWN'})"
                  ". THIS ENDPOINT IS NOT COLLECTING.")
            return False
        expected = (_exe_from_binpath(snapshot.get("binpath") or "")
                    or previous_exe)
        if expected is None:
            print("  ROLLBACK FAILED: the previous image path could not be "
                  "determined, so a restored service cannot be proved to be "
                  "running it. THE ENDPOINT'S IMAGE IS UNVERIFIED.")
            return False
        verdict = _verify_running_image(expected)
        if verdict != "MATCH":
            print("  ROLLBACK FAILED: the SCM reports RUNNING but the live "
                  f"process could not be PROVED to be {expected} (verdict "
                  f"{verdict}"
                  + (f", live image {_running_image()}" if verdict ==
                     "MISMATCH" else ", the running executable could not be "
                     "read")
                  + "). THE ENDPOINT MAY BE RUNNING AN UNEXPECTED IMAGE.")
            return False
        print(f"  ROLLBACK: {SERVICE_NAME} was RUNNING before this attempt "
              f"and is RUNNING again on {expected} (live image MATCH). "
              "Identity, journal, cursors and queued evidence were never "
              "touched.")
        return True
    # Previously STOPPED, or there was no service at all.
    state_now = _service_state()
    if state_now not in ("", "STOPPED"):
        print(f"  ROLLBACK FAILED: {SERVICE_NAME} is {state_now} but was not "
              "running before this attempt. THE ENDPOINT IS RUNNING AN IMAGE "
              "IT WAS NOT MEANT TO.")
        return False
    live = _running_image()
    if live is not None:
        print(f"  ROLLBACK FAILED: {SERVICE_NAME} is reported {state_now or 'absent'} "
              f"but a live service process is still running {live}. THE "
              "ENDPOINT IS RUNNING AN IMAGE IT WAS NOT MEANT TO.")
        return False
    if prior == "STOPPED":
        print(f"  ROLLBACK: {SERVICE_NAME} was STOPPED before this attempt "
              "and is STOPPED again, with its previous configuration "
              "restored and no live process. It was NOT started.")
    return True


def _service_pid() -> int:
    """The PID the SCM says is hosting the service, 0 when none."""
    q = _sc(f'sc.exe queryex "{SERVICE_NAME}"')
    if q.returncode != 0:
        return 0
    for line in (q.stdout or "").splitlines():
        if "PID" not in line.upper():
            continue
        for token in line.replace(":", " ").split():
            if token.isdigit():
                return int(token)
    return 0


def _running_image() -> Path | None:
    """The executable the LIVE service process is actually running.

    The SCM's binPath is a CONFIGURATION, not an observation: after a
    failed post-activation commit the two deliberately disagree, which is
    exactly the state the previous rollback mis-reported. None means
    "could not be determined" and is never treated as proof of anything.
    """
    pid = _service_pid()
    if pid <= 0:
        return None
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             "(Get-CimInstance Win32_Process -Filter "
             f'"ProcessId={pid}").ExecutablePath'],
            capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    rendered = [line.strip() for line in (proc.stdout or "").splitlines()
                if line.strip()]
    if proc.returncode != 0 or not rendered:
        return None
    return Path(rendered[0])


def _verify_running_image(expected: Path) -> str:
    """MATCH / MISMATCH / UNVERIFIED for the LIVE service process."""
    actual = _running_image()
    if actual is None:
        return "UNVERIFIED"
    try:
        same = actual.resolve() == Path(expected).resolve()
    except OSError:
        same = str(actual).lower() == str(expected).lower()
    return "MATCH" if same else "MISMATCH"


# ── service configuration, captured and restorable ────────────────
#: `sc.exe qc` field -> snapshot key. The SCM's own words are the record:
#: anything this installer did not read cannot be claimed to be restored.
_QC_FIELDS = {
    "SERVICE_NAME": "qc_name",
    "TYPE": "type",
    "START_TYPE": "start_type",
    "ERROR_CONTROL": "error_control",
    "BINARY_PATH_NAME": "binpath",
    "LOAD_ORDER_GROUP": "load_order_group",
    "DEPENDENCIES": "dependencies",
    "SERVICE_START_NAME": "account",
    "DISPLAY_NAME": "display_name",
}
#: `sc.exe qc` prints the START_TYPE as "2   AUTO_START" (optionally with
#: "(DELAYED)"); `sc.exe config` takes a different vocabulary entirely.
_START_TYPE_TO_SC = {
    "BOOT_START": "boot", "SYSTEM_START": "system", "AUTO_START": "auto",
    "DEMAND_START": "demand", "DISABLED": "disabled",
}
_TYPE_TO_SC = {
    "WIN32_OWN_PROCESS": "own", "WIN32_SHARE_PROCESS": "share",
    "KERNEL_DRIVER": "kernel", "FILE_SYSTEM_DRIVER": "filesys",
    "RECOGNIZER_DRIVER": "rec",
}
_ERROR_CONTROL_TO_SC = {
    "IGNORE": "ignore", "NORMAL": "normal", "SEVERE": "severe",
    "CRITICAL": "critical",
}
#: Every field that must be READ before anything is mutated. A snapshot
#: missing any of them cannot be restored, so it is not a snapshot.
#: LOAD_ORDER_GROUP and DEPENDENCIES are legitimately empty on this
#: service and are therefore recorded but not required.
_REQUIRED_SNAPSHOT_FIELDS = (
    "qc_name", "state", "type", "type_sc", "start_type", "start_type_sc",
    "error_control", "error_control_sc", "binpath", "service_exe",
    "account", "display_name",
)
#: Every field rollback must PROVE it put back, by reading the SCM again.
_VERIFIED_SNAPSHOT_FIELDS = ("binpath", "start_type_sc", "account",
                             "display_name", "type_sc", "error_control_sc")


def _qc_enum(value: str, table: dict) -> str:
    """`sc.exe config`'s word for a `sc.exe qc` enum, "" if unrecognised.

    Unrecognised is deliberately EMPTY rather than a default: a value this
    installer cannot express in a `sc config` command is a value it cannot
    restore, and the preflight has to say so instead of guessing.
    """
    upper = (value or "").upper()
    for name, sc_value in table.items():
        if name in upper:
            return sc_value
    return ""


def _capture_service_config() -> dict:
    """What the SCM says this service IS, before anything is changed.

    Returns a dict carrying its own verdict in "snapshot":

      ABSENT    there is genuinely no such service (ERROR 1060).
      COMPLETE  every field required for restoration was read.
      FAILED    the service could not be read, `sc.exe qc` failed, the
                output was malformed or incomplete, or the identity was
                ambiguous.

    FAILED is NOT a kind of ABSENT. Conflating them is what let the
    installer delete an unreadable service as "debris", and what let
    rollback restore fabricated defaults — LocalSystem, auto, an empty
    binPath — over configuration it had never actually read.
    """
    status, detail = _service_lookup()
    if status == "ABSENT":
        return {"snapshot": "ABSENT", "exists": False}
    if status == "UNREADABLE":
        return {"snapshot": "FAILED", "exists": None, "missing": [],
                "reason": f"the existing {SERVICE_NAME} service could not be "
                          "read, so it must not be assumed absent",
                "detail": detail[:400]}
    qc_status, text = _service_qc()
    if qc_status != "OK":
        return {"snapshot": "FAILED", "exists": True, "missing": [],
                "reason": f'sc.exe qc "{SERVICE_NAME}" failed',
                "detail": text[:400]}
    snapshot: dict = {"exists": True, "state": _service_state()}
    for line in text.splitlines():
        if ":" not in line:
            continue
        label, _, value = line.partition(":")
        key = _QC_FIELDS.get(label.strip().upper())
        if key:
            snapshot[key] = value.strip()
    start_type = (snapshot.get("start_type") or "").upper()
    base = _qc_enum(start_type, _START_TYPE_TO_SC)
    if base:
        snapshot["start_type_sc"] = ("delayed-auto"
                                     if "(DELAYED)" in start_type
                                     and base == "auto" else base)
    for key, table in (("type", _TYPE_TO_SC),
                       ("error_control", _ERROR_CONTROL_TO_SC)):
        rendered = _qc_enum(snapshot.get(key) or "", table)
        if rendered:
            snapshot[f"{key}_sc"] = rendered
    exe = _exe_from_binpath(snapshot.get("binpath") or "")
    if exe is not None:
        snapshot["service_exe"] = str(exe)
    if (snapshot.get("state") or "") not in _SERVICE_STATES:
        return {**snapshot, "snapshot": "FAILED", "missing": [],
                "reason": "the SCM did not report a usable run state "
                          f"({snapshot.get('state') or 'none'})",
                "detail": text.strip()[:400]}
    if (snapshot.get("qc_name") or "").strip().lower() \
            != SERVICE_NAME.lower():
        return {**snapshot, "snapshot": "FAILED", "missing": [],
                "reason": "ambiguous service identity: sc.exe qc answered "
                          f"for {snapshot.get('qc_name') or 'no service'!r}, "
                          f"not {SERVICE_NAME!r}",
                "detail": text.strip()[:400]}
    missing = [field for field in _REQUIRED_SNAPSHOT_FIELDS
               if not snapshot.get(field)]
    if missing:
        return {**snapshot, "snapshot": "FAILED", "missing": missing,
                "reason": "the service configuration was incomplete or "
                          "malformed",
                "detail": text.strip()[:400]}
    snapshot["snapshot"] = "COMPLETE"
    return snapshot


def _require_service_snapshot() -> dict:
    """PREFLIGHT. No service is stopped, deleted, reconfigured or started
    until the SCM has given a complete, validated account of what is
    already there — or has proved that nothing is.
    """
    snapshot = _capture_service_config()
    if snapshot.get("snapshot") == "FAILED":
        missing = snapshot.get("missing") or []
        raise SystemExit(
            "PREFLIGHT FAILED: refusing to touch the Windows service — "
            + str(snapshot.get("reason"))
            + (f" (missing: {', '.join(missing)})" if missing else "")
            + (f" [{snapshot.get('detail')}]" if snapshot.get("detail")
               else "")
            + ". Nothing was stopped, deleted, reconfigured, staged or "
              "activated, so there is nothing to roll back; identity, "
              "credentials, policy, journal, cursors and queued evidence "
              "are untouched. Re-run from an ELEVATED prompt once "
              f'`sc.exe qc "{SERVICE_NAME}"` answers completely.')
    if snapshot.get("snapshot") == "ABSENT":
        print(f"  preflight   : no existing {SERVICE_NAME} service "
              "(clean install)")
    else:
        print(f"  preflight   : {SERVICE_NAME} snapshot COMPLETE — "
              f"{snapshot['state']}, {snapshot['type_sc']}, "
              f"{snapshot['start_type_sc']}, {snapshot['account']}, "
              f"error={snapshot['error_control_sc']}")
        print(f"  current cfg : {snapshot['binpath']}")
    return snapshot


def _verify_restored_config(snapshot: dict) -> bool:
    """Read the SCM back and PROVE it matches the captured snapshot.

    A field the SCM will not return is a field that cannot be claimed as
    restored, so an unreadable or incomplete read-back is a rollback
    FAILURE — never a match. The previous code skipped any field absent
    from the snapshot (`and snapshot.get(key)`), which meant a snapshot
    that had captured nothing compared equal to everything.
    """
    current = _capture_service_config()
    if current.get("snapshot") != "COMPLETE":
        print("  ROLLBACK FAILED: the restored service configuration could "
              f"not be read back ({current.get('reason', 'unknown')}). IT "
              "CANNOT BE PROVED THAT THIS ENDPOINT WAS RESTORED.")
        return False
    unreadable = [key for key in _VERIFIED_SNAPSHOT_FIELDS
                  if not current.get(key) or not snapshot.get(key)]
    drift = [f"{key}: expected {snapshot.get(key)!r}, SCM reports "
             f"{current.get(key)!r}" for key in _VERIFIED_SNAPSHOT_FIELDS
             if (current.get(key) or "") != (snapshot.get(key) or "")]
    if unreadable or drift:
        print("  ROLLBACK FAILED: the restored configuration does not match "
              "the pre-install snapshot"
              + (f"; fields that could not be compared: "
                 f"{', '.join(sorted(set(unreadable)))}" if unreadable
                 else "")
              + (f"; differences: {' | '.join(drift)}" if drift else "")
              + ". THIS ENDPOINT NEEDS MANUAL ATTENTION.")
        return False
    print("  ROLLBACK: configuration verified identical to the pre-install "
          f"snapshot ({len(_VERIFIED_SNAPSHOT_FIELDS)} fields: "
          f"{', '.join(_VERIFIED_SNAPSHOT_FIELDS)})")
    return True


def _restore_service_config(snapshot: dict, previous_exe: Path | None = None,
                            api: str | None = None,
                            interval: int | None = None) -> bool:
    """Put the service entry back exactly as it was found.

    Covers every failure point the installer has: a DELETED service is
    re-created from the snapshot, a RE-POINTED one is configured back, and
    a service that never existed is removed again rather than left behind
    half-made. Idempotent: running it twice is indistinguishable from
    running it once, because it only ever acts on a DIFFERENCE.
    """
    if not snapshot:
        print("ROLLBACK FAILED: no complete original snapshot")
        return False
    if snapshot.get("snapshot") == "FAILED":
        # Unreachable through install() — the preflight refuses first — but
        # it is the one state that must never be reported as restored.
        print("  ROLLBACK FAILED: the original service configuration was "
              f"never captured completely ({snapshot.get('reason')}), so it "
              "cannot be restored and must not be claimed as restored.")
        return False
    if snapshot.get("snapshot") == "ABSENT" or not snapshot.get("exists"):
        status, _ = _service_lookup()
        if status == "UNREADABLE":
            return False
        if status == "PRESENT":
            _sc(f'sc.exe stop "{SERVICE_NAME}"')
            if not _wait_for_service_state("STOPPED", SERVICE_STOP_TIMEOUT_SECONDS):
                return False
            result = _sc(f'sc.exe delete "{SERVICE_NAME}"')
            if result.returncode != 0:
                return False
        return _service_lookup()[0] == "ABSENT"
    binpath = snapshot.get("binpath") or ""
    start_type = snapshot.get("start_type_sc") or ""
    account = snapshot.get("account") or ""
    display = snapshot.get("display_name") or ""
    service_type = snapshot.get("type_sc") or ""
    error_control = snapshot.get("error_control_sc") or ""
    if not all((binpath, start_type, account, display, service_type,
                error_control)):
        # A default here would be a FABRICATION presented as a restoration.
        print("  ROLLBACK FAILED: the captured snapshot is missing fields "
              "required to restore the service entry "
              f"({', '.join(f for f, v in (('binpath', binpath), ('start_type', start_type), ('account', account), ('display_name', display), ('type', service_type), ('error_control', error_control)) if not v)})"
              ". No configuration was guessed and none was written.")
        return False
    if not _service_exists():
        print(f"  ROLLBACK: re-creating {SERVICE_NAME} with its previous "
              f"configuration ({start_type}, {account})")
        created = _sc_argv("sc.exe", "create", SERVICE_NAME,
                           "binPath=", binpath, "start=", start_type,
                           "obj=", account, "DisplayName=", display,
                           "type=", service_type, "error=", error_control)
        if created.returncode != 0:
            print("  ROLLBACK FAILED: could not re-create "
                  f"{SERVICE_NAME}: "
                  f"{(created.stdout or created.stderr).strip()[:200]}. THIS "
                  "ENDPOINT IS NOT COLLECTING.")
            return False
        _sc(f'sc.exe description "{SERVICE_NAME}" "{SERVICE_DESCRIPTION}"')
        _sc(f'sc.exe failure "{SERVICE_NAME}" reset= 86400 '
            f'actions= restart/60000/restart/60000/restart/60000')
        return _verify_restored_config(snapshot)
    current = _capture_service_config()
    if current.get("snapshot") != "COMPLETE":
        print("  ROLLBACK FAILED: the service entry could not be read before "
              f"restoring it ({current.get('reason', 'unknown')}).")
        return False
    drifted = [key for key in _VERIFIED_SNAPSHOT_FIELDS
               if (current.get(key) or "") != (snapshot.get(key) or "")]
    if not drifted:
        return _verify_restored_config(snapshot)
    print(f"  ROLLBACK: restoring {SERVICE_NAME} configuration "
          f"({', '.join(drifted)})")
    configured = _sc_argv("sc.exe", "config", SERVICE_NAME,
                          "binPath=", binpath, "start=", start_type,
                          "obj=", account, "DisplayName=", display,
                          "type=", service_type, "error=", error_control)
    if configured.returncode != 0:
        print("  ROLLBACK FAILED: could not restore the service "
              f"configuration: "
              f"{(configured.stdout or configured.stderr).strip()[:200]}")
        return False
    return _verify_restored_config(snapshot)


# ── versioned service images ──────────────────────────────────────
def _read_active() -> dict:
    try:
        record = json.loads(ACTIVE_FILE.read_text())
        return record if isinstance(record, dict) else {}
    except (OSError, ValueError):
        return {}


def _service_binpath() -> str:
    for line in _service_config().splitlines():
        if "BINARY_PATH_NAME" in line.upper():
            return line.split(":", 1)[-1].strip()
    return ""


def _exe_from_binpath(binpath: str) -> Path | None:
    """The image path out of an `sc.exe` binPath value, arguments removed."""
    head = (binpath or "").strip()
    if not head:
        return None
    candidate = head[1:].split('"', 1)[0] if head.startswith('"') \
        else head.split(" ")[0]
    return Path(candidate) if candidate.lower().endswith(".exe") else None


def _active_service_exe() -> Path:
    """The image the SCM is CURRENTLY pointed at.

    `active.json` is the record this installer writes, but the SCM is the
    authority: an interrupted upgrade, a manual `sc config` or a pre-repair
    installation can disagree with the record, and in that case the
    service entry wins. The legacy in-place path is the last resort so an
    endpoint installed before this repair still has a valid previous image
    to roll back to.
    """
    exe = _exe_from_binpath(_service_binpath())
    if exe is not None:
        return exe
    recorded = _read_active().get("service_exe")
    if recorded:
        return Path(recorded)
    return SERVICE_EXE


def _payload_fingerprint(payload: Path) -> str:
    """Content identity of a service image: same bytes -> same directory.

    Keyed on content rather than on the build commit so that a rebuilt
    identical payload reuses its directory instead of accumulating copies,
    and so that two DIFFERENT builds can never collide on one path.
    """
    digest = hashlib.sha256()
    for path in sorted(p for p in payload.rglob("*") if p.is_file()):
        digest.update(str(path.relative_to(payload)).replace("\\", "/")
                      .encode("utf-8"))
        digest.update(str(path.stat().st_size).encode("ascii"))
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                digest.update(chunk)
    return digest.hexdigest()[:16]


def _manifest(tree: Path) -> dict:
    return {str(p.relative_to(tree)).replace("\\", "/"): p.stat().st_size
            for p in sorted(tree.rglob("*")) if p.is_file()}


def _validate_staged(payload: Path, staged: Path) -> None:
    from nivxforge_transaction import inventory, validate, TransactionError
    try:
        validate(staged, inventory(payload))
    except TransactionError as ex:
        raise SystemExit("staged service image is INCOMPLETE or differs from payload") from ex


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sweep_staging() -> None:
    """Remove leftovers from an INTERRUPTED staging attempt.

    A staging directory is never activated, so deleting one can never
    remove a working image; it is also never the active one, because the
    rename to the final name is the last step.
    """
    if not VERSIONS_DIR.exists():
        return
    for path in VERSIONS_DIR.iterdir():
        if path.name.startswith(STAGING_PREFIX) and path.is_dir():
            _prune_tree(path)


def _prune_tree(path: Path) -> list[str]:
    """Delete a tree, SKIPPING anything Windows still holds.

    Never force-unlocks, never kills a process and never schedules a
    delete that could surprise an operator later: a file that cannot be
    removed is reported and left exactly as it is.
    """
    skipped: list[str] = []

    def _on_error(_func, failed_path, _exc):
        skipped.append(str(failed_path))

    shutil.rmtree(path, onerror=_on_error)
    return skipped


def _stage_version(payload: Path) -> Path:
    """Copy the payload into a NEW directory and return it, validated.

    Nothing in the live installation is written, so a mapped DLL/PYD in
    the running image cannot fail an upgrade. If an identical image is
    already on disk it is validated and reused.
    """
    VERSIONS_DIR.mkdir(parents=True, exist_ok=True)
    _sweep_staging()
    final = VERSIONS_DIR / _payload_fingerprint(payload)
    if final.exists():
        _validate_staged(payload, final)
        print(f"  staged      : {final.name} (identical image already "
              "present, validated)")
        return final
    staging = VERSIONS_DIR / f"{STAGING_PREFIX}{os.getpid()}-{int(time.time())}"
    try:
        shutil.copytree(payload, staging)
        _validate_staged(payload, staging)
        os.replace(staging, final)
    except OSError as ex:
        _prune_tree(staging)
        raise SystemExit(
            f"service host staging failed: {ex}. NOTHING in the running "
            "installation was modified, nothing was enrolled and no token "
            "was consumed.") from None
    except BaseException:
        _prune_tree(staging)
        raise
    print(f"  staged      : {final.name} (new image, {len(_manifest(final))} "
          "files validated)")
    return final


def _write_active(service_exe: Path, previous: Path | None) -> None:
    """Commit the active-image record ATOMICALLY.

    A half-written record is worse than none: rollback and the next
    upgrade both read it. The temp file is written and renamed, so the
    previous record survives any failure here intact.
    """
    staging = ACTIVE_FILE.with_name(ACTIVE_FILE.name + ".new")
    staging.write_text(json.dumps({
        "service_exe": str(service_exe),
        "version_dir": str(service_exe.parent),
        "previous_version_dir": str(previous) if previous else None,
        "activated_at": sensor._now(),          # noqa: SLF001
        "build": build_identity(),
    }, indent=2))
    os.replace(staging, ACTIVE_FILE)


def _prune_versions(keep: list[Path]) -> None:
    """Keep the active and the previous image; drop older ones politely."""
    if not VERSIONS_DIR.exists():
        return
    keep_names = {p.name for p in keep if p is not None}
    for path in VERSIONS_DIR.iterdir():
        if not path.is_dir() or path.name in keep_names:
            continue
        if path.name.startswith(STAGING_PREFIX):
            _prune_tree(path)
            continue
        skipped = _prune_tree(path)
        if skipped:
            print(f"  retained    : {path.name} (still held by Windows; "
                  "left in place, not forced)")


# ── build provenance ──────────────────────────────────────────────
def build_identity() -> dict:
    """What this binary IS, so a stale exe can never be mistaken for a fix.

    `nivxforge_build.py` is generated by the installer workflow from the
    commit being built. A local or unofficial build says so.
    """
    try:
        import nivxforge_build as _b          # type: ignore[import-not-found]
        commit = str(getattr(_b, "BUILD_COMMIT", "") or "UNOFFICIAL_BUILD")
        built_at = str(getattr(_b, "BUILD_TIME", "") or "unknown")
        run_id = str(getattr(_b, "BUILD_RUN_ID", "") or "unknown")
    except ImportError:
        commit, built_at, run_id = "UNOFFICIAL_BUILD", "unknown", "unknown"
    return {"setup_version": SETUP_VERSION,
            "sensor_version": sensor.SENSOR_VERSION,
            "build_commit": commit,
            "build_time": built_at,
            "build_run_id": run_id}


def self_digest() -> str:
    """SHA256 of the running artifact, printed before anything is changed.

    An operator comparing this line to the SHA256 they were given is the
    only check that catches a stale installer still sitting on the host.
    """
    try:
        digest = hashlib.sha256()
        with open(_self_path(), "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                digest.update(chunk)
        return digest.hexdigest().upper()
    except OSError:
        return "UNAVAILABLE"


# ── install ───────────────────────────────────────────────────────
def _self_path() -> Path:
    return Path(sys.executable if getattr(sys, "frozen", False)
                else __file__).resolve()


def _protect_state_dir() -> None:
    from nivxforge_transaction import WindowsBackend
    WindowsBackend(sys.modules[__name__], DEFAULT_BACKEND, 30).protect(sensor.STATE_DIR)


def _service_payload_dir() -> Path | None:
    """The onedir service host carried inside this one-file installer."""
    base = getattr(sys, "_MEIPASS", None)
    if not base:
        return None
    candidate = Path(base) / "service"
    return candidate if (candidate / SERVICE_EXE.name).exists() else None


def _stage_service_host() -> Path:
    """Stage the onedir service host as a NEW versioned image.

    Returns the staged executable. Nothing in the active installation is
    written: the payload goes into `versions/<content-fingerprint>/`, is
    validated file-by-file, and only then becomes a candidate the SCM can
    be pointed at. The enrolment identity, the journal and the cursors
    live in the separate protected state directory and are never touched
    by staging.

    STOPPING THE SERVICE IS THE CALLER'S JOB. It used to be done here,
    with a bare `sc.exe stop` and no wait, which raced the dying process
    and left the endpoint stopped when the copy then failed.
    """
    payload = _service_payload_dir()
    if payload is None:
        raise SystemExit(
            "this build carries no Windows service host payload. Refusing "
            "to create a service with no valid image. Use an installer "
            "produced by the windows-sensor-installer workflow.")
    if _service_state() == "RUNNING":
        raise SystemExit(
            f"refusing to stage over a RUNNING {SERVICE_NAME}. "
            "Stop it first; nothing was replaced.")
    staged = _stage_version(payload)
    service_exe = staged / SERVICE_EXE.name
    if not service_exe.exists():
        raise SystemExit(f"service host staging failed: {service_exe} "
                         "is missing after unpack")
    return service_exe


def _bin_value(service_exe: Path, api: str, interval: int) -> str:
    """The binPath VALUE, in its real form — one argv token for `sc.exe`.

    The executable path is quoted inside the value so Windows can tell the
    image from its arguments. Nothing is pre-escaped here: the value is
    handed to `sc.exe` as a single list argument (`_sc_argv`), which is
    what escapes it correctly for CreateProcess. Hand-escaping it was the
    R3 defect — a restored value nested its quotes and Windows read
    `C:\\Program` as the image.

    --state-dir is AUTHORITATIVE: the installer resolves the canonical
    state root here (as an elevated interactive user, with a full
    environment) and tells the service explicitly, because a LocalSystem
    service cannot be trusted to infer the same path. No credential, token
    or secret is ever placed on the command line — only a directory.
    """
    return (f'"{service_exe}" --service-run '
            f'--backend {api} --interval {interval} '
            f'--state-dir "{sensor.STATE_DIR}"')


def _create_service(service_exe: Path, api: str, interval: int) -> None:
    """(Re)create the service entry against a specific image. No start."""
    bin_value = _bin_value(service_exe, api, interval)
    if _service_exists():
        _sc(f'sc.exe stop "{SERVICE_NAME}"')
        _wait_for_service_state("STOPPED", SERVICE_STOP_TIMEOUT_SECONDS)
        _sc(f'sc.exe delete "{SERVICE_NAME}"')
    created = _sc_argv("sc.exe", "create", SERVICE_NAME,
                       "binPath=", bin_value, "start=", "auto",
                       "obj=", "LocalSystem",
                       "DisplayName=", SERVICE_DISPLAY)
    if created.returncode != 0:
        raise SystemExit("service creation failed: "
                         f"{(created.stdout or created.stderr).strip()[:300]}")
    _sc(f'sc.exe description "{SERVICE_NAME}" "{SERVICE_DESCRIPTION}"')
    # Crash recovery: restart after 60s, three times, counter resets daily.
    _sc(f'sc.exe failure "{SERVICE_NAME}" reset= 86400 '
        f'actions= restart/60000/restart/60000/restart/60000')


def _install_service(api: str, interval: int,
                     service_exe: Path | None = None) -> None:
    service_exe = service_exe if service_exe is not None else SERVICE_EXE
    if not service_exe.exists():
        raise SystemExit(f"refusing to create a service: {service_exe} does "
                         "not exist (service host was not staged)")
    if _service_exists():
        print(f"  existing service found — replacing {SERVICE_NAME}")
    _create_service(service_exe, api, interval)
    started = _sc(f'sc.exe start "{SERVICE_NAME}"')
    if started.returncode != 0:
        raise SystemExit("service did not start: "
                         f"{(started.stdout or started.stderr).strip()[:300]}")
    if not _wait_for_service_state("RUNNING", SERVICE_STOP_TIMEOUT_SECONDS):
        raise SystemExit(
            f"service was created against {service_exe} but did not reach "
            f"RUNNING (the SCM reports {_service_state() or 'UNKNOWN'}).")
    # Prove the SCM actually recorded what we asked for.
    config = _service_config()
    if "AUTO_START" not in config:
        raise SystemExit("service was created but is not AUTO_START: "
                         f"{config.strip()[:300]}")
    # And prove the LIVE process is this image. "RUNNING" plus a binPath is
    # a claim about configuration; the running executable is the fact.
    verdict = _verify_running_image(service_exe)
    if verdict != "MATCH":
        raise SystemExit(
            "refusing to accept this activation: the live service process "
            f"could not be PROVED to be {service_exe} (verdict {verdict}"
            + (f", live image {_running_image()}" if verdict == "MISMATCH"
               else ", the running executable could not be read")
            + "). active.json is NOT committed, so no unverified image is "
              "ever recorded as active.")
    print(f"  live image  : {service_exe} (MATCH)")


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


def install(api: str, tenant: str | None, token_stdin: bool,
            interval: int, re_enrol: bool) -> None:
    """The sole production install path: durable transaction engine."""
    from nivxforge_transaction import Engine, WindowsBackend, TransactionError
    api = _assert_backend(api)
    _assert_admin()
    if re_enrol:
        raise SystemExit("transaction recovery never re-enrolls an endpoint")
    if interval <= 0:
        raise SystemExit("interval must be positive")
    payload = _service_payload_dir()
    bundle = getattr(sys, "_MEIPASS", None)
    manifest_path = Path(bundle) / "payload-manifest.json" if bundle else None
    if payload is None or manifest_path is None or not manifest_path.is_file():
        raise SystemExit("refusing an unpinned installer: embedded payload manifest required")
    manifest = json.loads(manifest_path.read_text())
    backend = WindowsBackend(sys.modules[__name__], api, interval)
    if sensor.IDENTITY_FILE.exists():
        _validate_identity()
    elif not token_stdin or not tenant:
        raise SystemExit("first install requires explicit tenant and --token-stdin")
    if tenant:
        _assert_tenant(tenant)
    def prepare():
        # Runs under installer ownership and before service mutation/credential writes.
        backend.protect(sensor.STATE_DIR)
        if sensor.IDENTITY_FILE.exists():
            _validate_identity()
        else:
            sensor.enrol(api, _assert_tenant(tenant or ""), sensor.read_enrolment_secret())
            _validate_identity()
        backend.protect(sensor.STATE_DIR)
    try:
        result = Engine(INSTALL_DIR, backend).run(payload, manifest, prepare)
    except (TransactionError, OSError, ValueError) as ex:
        raise SystemExit(str(ex)) from ex
    print("TRANSACTION STATUS: " + result)


def recover_transaction() -> None:
    from nivxforge_transaction import Engine, WindowsBackend, Owner
    _assert_admin()
    backend = WindowsBackend(sys.modules[__name__], DEFAULT_BACKEND, 30)
    with Owner(INSTALL_DIR):
        backend.protect(INSTALL_DIR)
        result = Engine(INSTALL_DIR, backend).reconcile()
    print("RECOVERY STATUS: " + str(result or "NO_TRANSACTION"))


def resolve_operation(identity: str, expect_state: str) -> None:
    """Supported, authenticated settlement of ONE uncertain SCM operation.

    Authenticated by elevation, by the SYSTEM/Administrators-only DACL the
    installer applies over the operations directory, and by the operator's
    assertion being CHECKED against the live SCM rather than believed. The
    record is amended with the evidence and kept; nothing is deleted.
    """
    from nivxforge_transaction import Owner, TransactionError, WindowsBackend
    _assert_admin()
    backend = WindowsBackend(sys.modules[__name__], DEFAULT_BACKEND, 30)
    try:
        with Owner(INSTALL_DIR):
            backend.protect(INSTALL_DIR)
            state = backend.resolve_operation(identity, expect_state)
    except TransactionError as ex:
        raise SystemExit(str(ex)) from ex
    print("OPERATION " + identity + ": " + str(state))
    print("The record and its history were preserved. Re-run "
          "`recover-transaction` to reconcile the transaction itself.")


def uninstall(purge: bool) -> None:
    # Recovery builds retain all payloads/records and evidence. Uninstall is
    # deliberately refused until separately accepted as a destructive operation.
    raise SystemExit("uninstall/purge unavailable in transaction validation builds; "
                     "preserve payloads and evidence for reviewed manual recovery")


# ── telemetry baseline (EXPLICIT, never part of an upgrade) ───────
def _channel_tail(channel: str) -> int | None:
    """The newest EventRecordID currently in a channel, or None.

    None means "could not be read", and every caller treats that as a
    STOP: a channel whose tail is unknown would be collected from
    RecordID 0, which replays the whole retained log.
    """
    try:
        proc = subprocess.run(
            ["wevtutil", "qe", channel, "/c:1", "/rd:true", "/f:RenderedXml"],
            capture_output=True, text=True)
    except OSError:
        return None
    if proc.returncode != 0:
        return None
    marker = "<EventRecordID>"
    text = proc.stdout or ""
    if marker not in text:
        return None
    raw = text.split(marker, 1)[1].split("<", 1)[0].strip()
    try:
        value = int(raw)
    except ValueError:
        return None
    return value if value > 0 else None


def _parse_channel_args(pairs: list[str]) -> dict:
    marks: dict[str, int] = {}
    for pair in pairs or []:
        name, _, raw = pair.partition("=")
        name = name.strip()
        if not _ or name not in sensor.CHANNELS:
            raise SystemExit(
                f"--channel expects 'NAME=RECORDID' for a CONFIGURED channel "
                f"({', '.join(sensor.CHANNELS)}); got {pair!r}")
        try:
            marks[name] = int(raw.strip())
        except ValueError:
            raise SystemExit(f"--channel {name}: {raw!r} is not an "
                             "EventRecordID") from None
        if marks[name] <= 0:
            raise SystemExit(f"--channel {name}: a baseline RecordID must be "
                             "a positive integer")
    return marks


def telemetry_baseline(channel_args: list[str], from_tails: bool,
                       discard_queued: bool) -> dict:
    """Set the collection baseline to CURRENT event-log tails. Explicit only.

    This is deliberately NOT part of install or upgrade. An upgrade must
    leave the journal and the cursors exactly as they are; deciding that
    history will not be collected is an owner decision with its own
    command, its own refusals and its own printed record.

    Fails closed on anything it cannot prove:
      · the service must be STOPPED, so acquisition cannot race the write;
      · EVERY configured channel must have a baseline — a missing one
        would be collected from RecordID 0 and replay the retained log;
      · a cursor is never moved backward;
      · queued, unacknowledged evidence is never discarded unless the
        operator asks for it in so many words.
    """
    _assert_admin()
    state = _service_state()
    if state not in ("", "STOPPED"):
        raise SystemExit(
            f"refusing to re-baseline while {SERVICE_NAME} is {state}: stop "
            "the service first so acquisition cannot race this change. "
            "Nothing was modified.")
    marks = _parse_channel_args(channel_args)
    if from_tails:
        unreadable = []
        for channel in sensor.CHANNELS:
            if channel in marks:
                continue
            tail = _channel_tail(channel)
            if tail is None:
                unreadable.append(channel)
            else:
                marks[channel] = tail
        if unreadable:
            raise SystemExit(
                "ABORTING: could not read the current tail of "
                f"{', '.join(unreadable)}. A channel with no baseline is "
                "collected from RecordID 0, which replays its entire "
                "retained history. Nothing was modified. Read the tails "
                "manually and pass them with --channel NAME=RECORDID.")
    missing = [c for c in sensor.CHANNELS if c not in marks]
    if missing:
        raise SystemExit(
            f"ABORTING: no baseline for {', '.join(missing)}. Every "
            f"configured channel ({', '.join(sensor.CHANNELS)}) must be "
            "given, because a channel without a cursor replays its whole "
            "retained history. Nothing was modified.")

    journal = sensor.nvx_journal.open_journal(sensor.STATE_DIR)
    try:
        counts = journal.counts_by_state()
        queued = int(journal.depth()) + int(counts.get(
            sensor.nvx_journal.REFUSED_UNACCEPTABLE, 0))
        if queued and not discard_queued:
            raise SystemExit(
                f"ABORTING: {queued} event(s) are still queued and "
                "unacknowledged. Re-baselining does not deliver them and "
                "this command will not destroy them silently. Either let "
                "the sensor drain them first, or re-run with "
                "--discard-queued-evidence to state explicitly that this "
                "backlog is to be abandoned. Nothing was modified.")
        discarded = 0
        if queued and discard_queued:
            discarded = journal.discard_undelivered()
            print(f"  DISCARDED   : {discarded} queued, unacknowledged "
                  "event(s) on explicit instruction")
        applied = {}
        for channel in sensor.CHANNELS:
            before = journal.rebaseline_cursor(channel, marks[channel])
            applied[channel] = {"from": before, "to": marks[channel]}
    finally:
        journal.close()
    # The legacy mirror is kept consistent so a future migration cannot
    # re-seed a stale value. It is NOT the authority; the journal is.
    try:
        sensor.BOOKMARK_FILE.write_text(
            json.dumps({c: marks[c] for c in sensor.CHANNELS}, indent=2))
    except OSError as ex:
        print(f"  note        : could not refresh {sensor.BOOKMARK_FILE} "
              f"({ex}); the journal cursors are authoritative")
    out = {"result": "BASELINE_SET", "service_state": state or "NO_SERVICE",
           "channels": applied, "queued_discarded": discarded,
           "state_dir": str(sensor.STATE_DIR),
           "identity_preserved": sensor.IDENTITY_FILE.exists()}
    return out


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


#: Bounded drain-mode policy. Kept module-level and pure so it is testable
#: without a Windows service, an SCM or a sensor.
DRAIN_MIN_BACKLOG = 500        # below this the normal cadence is fine
DRAIN_MAX_CONSECUTIVE = 20     # then take a full interval regardless
DRAIN_WAIT_SECONDS = 5         # floor between back-to-back drain cycles


def _drain_wait(report, interval: int, drain_cycles: int) -> tuple[float, int]:
    """Return (seconds to wait, next drain counter).

    Drain mode engages ONLY when all of these hold:
      · the cycle reported a real backlog above `DRAIN_MIN_BACKLOG`;
      · the backend was reachable;
      · delivery actually accepted something this cycle (proven progress);
      · fewer than `DRAIN_MAX_CONSECUTIVE` drain cycles have run back to
        back, after which one full interval is always taken.
    Anything else returns the normal cadence, so a stuck queue, an
    unreachable backend or an empty journal can never spin the CPU or
    hammer the platform.
    """
    normal = float(max(5, interval))
    if not isinstance(report, dict):
        return normal, 0
    backlog = int(report.get("delivery_backlog") or 0)
    sent = int(report.get("sent") or 0)
    if report.get("backend_unreachable"):
        return normal, 0
    if backlog < DRAIN_MIN_BACKLOG or sent <= 0:
        return normal, 0
    if drain_cycles + 1 >= DRAIN_MAX_CONSECUTIVE:
        # Deliberate breather: hand the endpoint and the backend a full
        # interval before resuming, even if the backlog persists.
        return normal, 0
    return float(DRAIN_WAIT_SECONDS), drain_cycles + 1


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
            # ── bounded drain mode ────────────────────────────────────
            # Normally the service waits a full interval between cycles.
            # While a backlog exists that wait is dead time the endpoint
            # cannot afford, so consecutive cycles may follow quickly —
            # but only while delivery is PROVING progress, only for a
            # bounded number of cycles, and never against an unreachable
            # backend. Everything else falls back to the normal cadence,
            # so this can never become a hot loop or a backend hammer.
            drain_cycles = 0
            while True:
                wait_seconds = max(5, self.interval)
                try:
                    # ONE cycle per iteration so a stop request is honoured
                    # promptly; the sensor owns collection and delivery.
                    report = sensor.run(self.api, self.interval, once=True)
                    wait_seconds, drain_cycles = _drain_wait(
                        report, self.interval, drain_cycles)
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
                    drain_cycles = 0
                    wait_seconds = max(5, self.interval)
                if win32event.WaitForSingleObject(
                        self.stop_event,
                        int(wait_seconds * 1000)) == win32event.WAIT_OBJECT_0:
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
    ap.add_argument("--m1-service-run", action="store_true",
                    help=argparse.SUPPRESS)
    sub = ap.add_subparsers(dest="cmd")
    i = sub.add_parser("install", help="install, enrol and start the service")
    i.add_argument("--backend", default=DEFAULT_BACKEND)
    i.add_argument("--tenant")
    i.add_argument("--token-stdin", action="store_true",
                   help="read the one-time enrolment secret from stdin "
                        "(the ONLY accepted input; never an argv value)")
    i.add_argument("--interval", type=int, default=30)
    i.add_argument("--re-enrol", action="store_true")
    u = sub.add_parser("uninstall", help="stop and remove the service")
    u.add_argument("--purge", action="store_true")
    sub.add_parser("status", help="local enrolment and queue state")
    m1i = sub.add_parser("m1-install",
                         help="M1 CLEAN install on an isolated test VM "
                              "(no upgrade, no transaction engine)")
    m1i.add_argument("--m1-config", required=True,
                     help="path to the pre-provisioned, protected M1 "
                          "configuration")
    m1u = sub.add_parser("m1-uninstall",
                         help="ownership-bound M1 uninstall (preserves "
                              "identity, journal, cursors and evidence)")
    m1u.add_argument("--m1-config", required=True)
    m1r = sub.add_parser("m1-reconcile-enrollment",
                         help="resolve an M1 enrolment attempt whose outcome "
                              "is unknown")
    m1r.add_argument("--m1-config", required=True)
    m1r.add_argument("--operator-confirmed", action="store_true",
                     help="the operator has verified backend-side that this "
                          "endpoint has exactly one identity")
    sub.add_parser("version", help="installer and sensor versions")
    sub.add_parser("recover-transaction", help="reconcile durable installer intent")
    r = sub.add_parser("resolve-operation",
                       help="record a VERIFIED operator settlement of one "
                            "uncertain SCM operation (never deletes it)")
    r.add_argument("--id", required=True, dest="operation_id",
                   help="operation record name, without .json")
    r.add_argument("--expect-state", required=True,
                   choices=["RUNNING", "STOPPED", "ABSENT"],
                   help="the state the operator asserts; CHECKED against "
                        "the live SCM and refused if it disagrees")
    sub.add_parser("stage-host",
                   help="(internal) unpack the Windows service host only")
    b = sub.add_parser("telemetry-baseline",
                       help="EXPLICITLY set the collection baseline to the "
                            "current Windows event-log tails (never part "
                            "of install or upgrade)")
    b.add_argument("--channel", action="append", default=[],
                   metavar="NAME=RECORDID",
                   help="baseline for one CONFIGURED channel; repeatable")
    b.add_argument("--from-current-tails", action="store_true",
                   help="read the newest EventRecordID of every configured "
                        "channel from this computer and use it as the "
                        "baseline; aborts if any channel cannot be read")
    b.add_argument("--discard-queued-evidence", action="store_true",
                   help="state explicitly that queued, unacknowledged "
                        "evidence is to be abandoned")
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
_REQUIRED_BUNDLED = ("nivxforge_transaction", "nivxforge_scm_worker",
                     "nivxforge_sensor", "nivxforge_journal", "sqlite3",
                     "_sqlite3", "nivxforge_m1", "nivxforge_exclusions",
                     "nivxforge_delivery_counters",
                     "nivxforge_content_acquisition")
#: pywin32 modules the M1 service-security and effective-access evaluation
#: needs. They are declared to the BUILD (--hidden-import) rather than to the
#: cross-platform provenance gate above, which must stay importable off
#: Windows; a missing one is caught by the frozen smoke run in the G4
#: checklist, where pywin32 is actually present.
_M1_REQUIRED_WIN32 = ("win32security", "win32con", "win32api", "win32service",
                      "ntsecuritycon")
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
                      "file_on_disk": bool(file and Path(file).exists()),
                      "builtin": bool(name in sys.builtin_module_names and
                                      getattr(getattr(module, "__spec__", None), "origin", None) == "built-in") }
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
    if not native.get("file_on_disk") and not (not getattr(sys, "frozen", False) and native.get("builtin")):
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
            provenance.get("_sqlite3", {}).get("file_on_disk") or
            (not getattr(sys, "frozen", False) and provenance.get("_sqlite3", {}).get("builtin"))),
        "sqlite3_builtin_source_runtime": bool(provenance.get("_sqlite3", {}).get("builtin")),
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


def m1_payload_source() -> tuple[Path, dict]:
    """P1-3 — the attested payload that ships INSIDE this installer.

    Refuses an unpinned build: without the embedded manifest there is
    nothing to verify the service image against, and M1 must never register
    a service that points at an unverified binary.
    """
    bundle = getattr(sys, "_MEIPASS", None)
    payload = _service_payload_dir()
    if bundle is None or payload is None:
        raise SystemExit(
            "refusing an unpinned installer: the M1 clean install requires "
            "the embedded Windows service payload. Run the signed frozen "
            "build, not a loose script.")
    manifest_path = Path(bundle) / "payload-manifest.json"
    if not manifest_path.is_file():
        raise SystemExit(
            "refusing an unpinned installer: embedded payload manifest "
            f"required at {manifest_path}")
    manifest = json.loads(manifest_path.read_text())
    if not isinstance(manifest, dict) or not manifest:
        raise SystemExit("the embedded payload manifest is empty or malformed")
    return payload, manifest


def m1_dispatch(args) -> None:
    """Additive M1 entrypoint. Imported lazily so the enterprise commands
    carry no new import cost and so the M1 module stays independently
    testable."""
    import nivxforge_m1 as m1
    host = m1.WindowsHost(authorization=m1.AUTH_INSTALLER)
    if args.cmd == "m1-install":
        def enroll(config):
            token = sensor.read_enrolment_secret()
            sensor.use_state_dir(config.state_dir)
            return sensor.enrol(config.origin, config.tenant_id, token,
                                single_attempt=True, attempt_marker=True)

        bundle_root, manifest = m1_payload_source()
        print(json.dumps(m1.m1_install(args.m1_config, host, enroll=enroll,
                                       bundle_root=bundle_root,
                                       manifest=manifest),
                         indent=2))
    elif args.cmd == "m1-uninstall":
        print(json.dumps(m1.m1_uninstall(args.m1_config, host), indent=2))
    else:
        def session_probe(config, identity):
            try:
                sensor.use_state_dir(config.state_dir)
                token = sensor._open_session(config.origin, identity)
                return {"ok": bool(token), "detail": "session opened"}
            except Exception as ex:                          # noqa: BLE001
                return {"ok": False, "detail": type(ex).__name__}

        print(json.dumps(m1.m1_reconcile_enrollment(
            args.m1_config, host, session_probe=session_probe,
            operator_confirmed=args.operator_confirmed), indent=2))


def main(argv: list[str] | None = None) -> None:
    raw = list(sys.argv[1:] if argv is None else argv)
    # SERVICE DISPATCH FIRST. The SCM invokes this binary as
    #   NivXForgeSensor.exe --service-run --backend <url> --interval <n>
    # and that command line must never reach the installer's subcommand
    # parser: `--backend` is unknown there, so argparse consumed the URL
    # that follows it as the positional subcommand and exited 2 with
    # "invalid choice", which Windows reported as error 1053.
    if raw == ["--transaction-scm-worker"]:
        from nivxforge_scm_worker import entry
        entry()
        return
    if "--m1-service-run" in raw:
        # The M1 service adapter. It deliberately does NOT call
        # `_run_as_service`, which is production-oriented and unchanged.
        import nivxforge_m1 as m1
        m1.m1_service_run(raw)
        return
    if SERVICE_FLAG in raw:
        _run_as_service(raw)
        return
    # BEFORE the parser. `parse_known_args` would silently DISCARD a
    # `--token <secret>` pair, which is worse than failing: the operator
    # would believe the old interface still worked while the secret had
    # already been recorded in the command line of this process.
    sensor.refuse_secret_on_command_line(raw)
    sensor.refuse_secret_on_command_line(raw)
    args, unknown = build_parser().parse_known_args(raw)
    if unknown:
        # A SILENTLY IGNORED FLAG IS HOW A WRONG BUILD LIES. A pre-hardening
        # installer accepted `--token-stdin`, discarded it here, and then
        # refused with "--token is required", which reads like a backend or
        # token problem instead of a wrong binary.
        raise SystemExit(
            "unrecognized argument(s): " + " ".join(unknown) + ". Refusing "
            "to continue, because an ignored flag makes a wrong installer "
            "version look like a credential failure. Check "
            "`NivXForgeEDRSetup.exe version` and `install --help`.")
    if args.cmd in ("m1-install", "m1-uninstall", "m1-reconcile-enrollment"):
        # The M1 clean-install path. It NEVER reaches the enterprise
        # transaction/recovery engine, and the enterprise commands below are
        # unchanged by its presence.
        m1_dispatch(args)
        return
    if args.cmd == "install":
        install(args.backend, args.tenant, args.token_stdin, args.interval,
                args.re_enrol)
    elif args.cmd == "recover-transaction":
        recover_transaction()
    elif args.cmd == "resolve-operation":
        resolve_operation(args.operation_id, args.expect_state)
    elif args.cmd == "uninstall":
        uninstall(args.purge)
    elif args.cmd == "status":
        print(json.dumps(sensor.status(), indent=2))
    elif args.cmd == "stage-host":
        raise SystemExit("legacy stage-host is disabled; use the serialized transaction entrypoint")
    elif args.cmd == "telemetry-baseline":
        print(json.dumps(
            telemetry_baseline(args.channel, args.from_current_tails,
                               args.discard_queued_evidence), indent=2))
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
        print(json.dumps({**build_identity(),
                          "artifact_sha256": self_digest(),
                          "service_name": SERVICE_NAME,
                          "service_exe": str(_active_service_exe()),
                          "service_host": "ONEDIR_PAYLOAD_VERSIONED",
                          "active_image": _read_active().get("version_dir")
                          or "UNRECORDED",
                          "previous_image":
                              _read_active().get("previous_version_dir")
                              or "NONE",
                          "service_state": _service_state() or "NO_SERVICE",
                          "state_dir": str(sensor.STATE_DIR),
                          "default_backend": DEFAULT_BACKEND}, indent=2))
    else:
        build_parser().print_help()


if __name__ == "__main__":
    main()
