"""NivXForge Windows Installer V1 · focused contract tests.

These run on Linux and assert the things that are decidable here: the
installer's guards, the single-sensor reuse rule, credential hygiene, the
service model, and that the Windows build is defined to run on Windows.

What they deliberately do NOT claim: that the EXE builds, installs, starts
as a service or uninstalls. A Windows PE cannot be produced or executed
here, so those are proven only by the `windows-latest` CI job and the
first controlled install. Nothing in this file may be read as evidence of
a working binary.
"""
from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

import pytest
import yaml

AGENT_DIR = Path("/app/agents/nivxforge-windows")
SETUP = AGENT_DIR / "nivxforge_setup.py"
SENSOR = AGENT_DIR / "nivxforge_sensor.py"
BUILD = AGENT_DIR / "build" / "build_windows_installer.ps1"
WORKFLOW = Path("/app/.github/workflows/windows-sensor-installer.yml")

_SECRET_SHAPES = (
    re.compile(r"nvx_[0-9a-f]{48}"),
    re.compile(r"nvxenr_[A-Za-z0-9_\-]{16,}"),
    re.compile(r"nvxses_[A-Za-z0-9_\-]{16,}"),
    re.compile(r"nvxcrd_[A-Za-z0-9_\-]{16,}"),
    re.compile(r"ten_[0-9a-f]{26}"),
)
_PACKAGE_FILES = (SETUP, SENSOR, AGENT_DIR / "nivxforge_exclusions.py",
                  AGENT_DIR / "Install-NivXForgeSensor.ps1", BUILD)
#: Files SHIPPED TO an endpoint. The build script is excluded from the
#: banned-NAME check because it is the scanner: it must name the secrets
#: it refuses to publish. Secret VALUE shapes are still checked everywhere.
_SHIPPED_FILES = (SETUP, SENSOR, AGENT_DIR / "nivxforge_exclusions.py",
                  AGENT_DIR / "Install-NivXForgeSensor.ps1")


@pytest.fixture(scope="module")
def setup_mod():
    """Import the installer entry without needing Windows."""
    sys.path.insert(0, str(AGENT_DIR))
    spec = importlib.util.spec_from_file_location("nivxforge_setup", SETUP)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ── credential hygiene ────────────────────────────────────────────
def test_no_credential_or_secret_is_committed_in_the_package():
    for path in _PACKAGE_FILES:
        text = path.read_text(encoding="utf-8", errors="replace")
        for shape in _SECRET_SHAPES:
            assert not shape.search(text), f"{path.name} matches {shape.pattern}"
    for path in _SHIPPED_FILES:
        text = path.read_text(encoding="utf-8", errors="replace")
        for banned in ("EDR_AUTH_PEPPER", "uulVDp5cCSB3Hva99s7UUAwK",
                       "admin@nivxray.com", "Authorization: Bearer ey"):
            assert banned not in text, f"{path.name} contains {banned}"


def test_build_script_only_names_secrets_inside_its_refusal_scan():
    """The scanner must name what it rejects — but only there."""
    text = BUILD.read_text(encoding="utf-8")
    shapes_block = text[text.index("$shapes = @("):text.index("$text = [System")]
    assert "EDR_AUTH_PEPPER" in shapes_block
    assert text.count("EDR_AUTH_PEPPER") == 1
    assert "REFUSED: artifact contains" in text


def test_no_preview_or_localhost_origin_is_baked_into_the_installer():
    text = SETUP.read_text(encoding="utf-8")
    # The only occurrences allowed are inside the REFUSAL list.
    forbidden_block = text[text.index("_FORBIDDEN_HOST_MARKERS"):
                           text.index("# ── guards")]
    assert "preview.emergentagent.com" in forbidden_block
    assert text.count("preview.emergentagent.com") == 1
    assert "http://" not in text.replace("http://localhost", "")


def test_enrollment_token_is_never_written_to_disk_or_logged(setup_mod):
    text = SETUP.read_text(encoding="utf-8")
    assert "--token" in text
    # No print/log statement may take the token VALUE. Mentioning the word
    # (e.g. "no token required or consumed") is fine; interpolating the
    # variable is not.
    for stmt in re.findall(r"(?:print|Log(?:Error)?Msg)\((?:[^()]|\([^()]*\))*\)", text):
        assert not re.search(r"\{\s*token", stmt), stmt
        assert not re.search(r"\btoken\.strip\(\)|\+\s*token\b|,\s*token\s*[,)]", stmt), stmt
    # The installer must not persist the token itself anywhere.
    assert not re.search(r"write_text\([^)]*token", text)


# ── single sensor, no second implementation ───────────────────────
def test_installer_reuses_the_existing_sensor_and_exclusion_evaluator(setup_mod):
    text = SETUP.read_text(encoding="utf-8")
    assert "import nivxforge_sensor as sensor" in text
    for reimplemented in ("wevtutil", "def collect(", "def _drain(",
                          "def _heartbeat(", "/api/edr/agent/enroll"):
        assert reimplemented not in text, (
            f"{reimplemented} must come from nivxforge_sensor, not be "
            "reimplemented in the installer")
    assert setup_mod.sensor.SENSOR_VERSION


def test_service_hosts_the_sensor_run_loop(setup_mod):
    text = SETUP.read_text(encoding="utf-8")
    assert "win32serviceutil.ServiceFramework" in text
    assert "sensor.run(self.api, self.interval, once=True)" in text
    assert "StartServiceCtrlDispatcher" in text


# ── guards ────────────────────────────────────────────────────────
@pytest.mark.parametrize("bad", [
    "http://localhost:8001",
    "https://localhost",
    "http://127.0.0.1:8001",
    "https://greeting-app-5782.preview.emergentagent.com",
    "http://nivxray.nivxforge.com",
    "https://nivxray.nivxforge.com:8001",
    "ftp://nivxray.nivxforge.com",
    "",
])
def test_backend_guard_refuses_non_production_origins(setup_mod, bad):
    with pytest.raises(SystemExit):
        setup_mod._assert_backend(bad)


def test_backend_guard_accepts_the_production_origin(setup_mod):
    assert setup_mod._assert_backend("https://nivxray.nivxforge.com/") == \
        "https://nivxray.nivxforge.com"
    assert setup_mod.DEFAULT_BACKEND == "https://nivxray.nivxforge.com"


@pytest.mark.parametrize("bad", ["", "  ", "default", "DEFAULT", "test",
                                 "test_database", "unknown", "none"])
def test_tenant_guard_refuses_fallback_tenants(setup_mod, bad):
    with pytest.raises(SystemExit):
        setup_mod._assert_tenant(bad)


def test_tenant_guard_accepts_an_explicit_platform_tenant(setup_mod):
    explicit = "ten_e759b7288598bd882e3dcac49d"
    assert setup_mod._assert_tenant(explicit) == explicit


# ── service / install model ───────────────────────────────────────
def test_real_windows_service_not_a_scheduled_task(setup_mod):
    text = SETUP.read_text(encoding="utf-8")
    assert "schtasks" not in text, "Track B must not use a scheduled task"
    assert 'start= auto' in text, "service must start automatically"
    assert "actions= restart/60000/restart/60000/restart/60000" in text
    assert "reset= 86400" in text
    assert setup_mod.SERVICE_NAME == "NivXForgeSensor"


def test_uninstall_keeps_evidence_unless_purge_is_requested():
    text = SETUP.read_text(encoding="utf-8")
    body = text[text.index("def uninstall("):text.index("# ── Windows Service")]
    assert 'sc.exe stop' in body and 'sc.exe delete' in body
    assert "if purge and sensor.STATE_DIR.exists()" in body
    assert "state directory kept at" in body


def test_endpoint_credential_directory_is_restricted():
    text = SETUP.read_text(encoding="utf-8")
    assert "icacls" in text and "/inheritance:r" in text
    assert "*S-1-5-18:(OI)(CI)F" in text        # SYSTEM
    assert "*S-1-5-32-544:(OI)(CI)F" in text    # Administrators


def test_install_requires_elevation():
    text = SETUP.read_text(encoding="utf-8")
    assert "IsUserAnAdmin" in text
    assert text.index("_assert_admin()") < text.index("=== 1 . STAGE ===")


def test_argument_guards_run_before_the_elevation_check():
    """Pure validation first, so a refusal is deterministic on any host
    (including an elevated CI runner) — but still nothing is written
    before elevation is proven."""
    body = SETUP.read_text(encoding="utf-8")
    body = body[body.index("def install("):body.index("def uninstall(")]
    # Compare executable statements only: a comment naming a guard must not
    # be mistaken for the call site.
    code = "\n".join(line for line in body.splitlines()
                     if not line.strip().startswith("#"))
    assert code.index("_assert_backend(api)") < code.index("_assert_admin()")
    assert code.index("_assert_admin()") < code.index("INSTALL_DIR.mkdir")


def test_ci_verify_step_does_not_leak_the_intentional_guard_exit_code():
    """The guard probe MUST exit non-zero; GitHub's pwsh wrapper appends
    `exit $LASTEXITCODE`, so that 1 must be captured and cleared or the
    step fails despite every assertion passing."""
    text = WORKFLOW.read_text(encoding="utf-8")
    verify = text[text.index("Verify artifact contract"):
                  text.index("- uses: actions/upload-artifact")]
    assert "$guardExit = $LASTEXITCODE" in verify
    assert "if ($guardExit -eq 0) { throw" in verify, (
        "a guard that exits 0 for localhost must still fail the build")
    assert "$global:LASTEXITCODE = 0" in verify
    assert verify.rstrip().endswith("exit 0")
    # Security assertions must all survive the fix.
    for kept in ("not a Windows PE", "refusing to install", "sensor_version",
                 "NivXForgeSensor", "build-info.json", "SHA256SUMS.txt"):
        assert kept in verify


def test_cli_contract_is_stable(setup_mod):
    parser = setup_mod.build_parser()
    args, _ = parser.parse_known_args(
        ["install", "--tenant", "ten_x", "--token", "nvxenr_y"])
    assert args.cmd == "install" and args.interval == 30
    assert args.backend == "https://nivxray.nivxforge.com"
    assert parser.parse_known_args(["--service-run"])[0].service_run is True
    assert parser.parse_known_args(["uninstall", "--purge"])[0].purge is True


# ── build definition ──────────────────────────────────────────────
def test_windows_build_is_defined_to_run_on_windows():
    wf = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    job = wf["jobs"]["build"]
    assert job["runs-on"] == "windows-latest"
    steps = yaml.dump(job["steps"])
    assert "build_windows_installer.ps1" in steps
    assert "upload-artifact" in steps
    assert "NivXForgeEDRSetup.exe" in steps


def test_build_workflow_requires_no_secrets():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "secrets." not in text, "the installer build must need no secret"
    assert "permissions:\n  contents: read" in text


def test_build_script_bundles_the_runtime_and_refuses_credentials():
    text = BUILD.read_text(encoding="utf-8")
    assert "--onefile" in text and "pyinstaller" in text.lower()
    assert "pywin32" in text
    for hidden in ("win32timezone", "servicemanager", "nivxforge_sensor",
                   "nivxforge_exclusions"):
        assert hidden in text
    assert "0x4D" in text and "0x5A" in text        # PE header check
    assert "UNSIGNED_INTERNAL_VALIDATION_BUILD" in text
    assert "MUST run on Windows" in text
    assert "python_required_on_endpoint = $false" in text


def test_phase0_event_families_remain_the_declared_coverage():
    """Coverage must stay truthful: the sensor ships the channels the
    Phase 0 bridge can canonicalise, and claims nothing beyond them."""
    text = SENSOR.read_text(encoding="utf-8")
    assert 'CHANNELS = ("Security", "System",' in text
    assert "Microsoft-Windows-Sysmon/Operational" in text
    assert "WINDOWS_EVENT_LOG" in text
    # No cosmetic capability inflation.
    for never in ("ETW", "kernel driver", "AMSI"):
        assert f'"{never}"' not in text
