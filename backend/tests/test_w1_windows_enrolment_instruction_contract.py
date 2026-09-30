"""P0 · the CONSOLE must not teach what the INSTALLER refuses.

Three surfaces each wrote their own Windows enrolment instruction and
drifted apart. Two taught `-EnrollmentToken <token>`; the deployment
response INTERPOLATED THE MINTED PLAINTEXT into an executable command
(`install_invocation`), and the Add-Device page rebuilt the same string in
the browser. Windows records process command lines in places NivXForge
itself collects — Sysmon EID 1 `CommandLine`, the service `binPath`,
PowerShell history — so those instructions taught operators to turn a
live credential into endpoint telemetry, and the hardened installer now
refuses them outright.

`edr_plane/enrollment/instructions.py` is the single authority. These
tests prove every operator-facing Windows instruction comes from it,
carries no secret, and names the stdin mechanism — and that nothing about
token semantics, runtime credentials or LINUX behaviour moved with it.
"""
from __future__ import annotations

import importlib.util
import os
import sys
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("XDR_AUDIT_MASTER_SECRET", "test-master-secret")
os.environ.setdefault("XDR_SECRETS_MASTER", "test-secrets-master-passphrase")

from edr_plane.enrollment import instructions           # noqa: E402
from routers import xdr_rbac as rb                      # noqa: E402
from server import app                                  # noqa: E402
from services import tenant_registry as reg             # noqa: E402

client = TestClient(app)

SUF = uuid.uuid4().hex[:8]
T_LAB = f"w1-lab-{SUF}"
U_PLATFORM = f"w1-platform-{SUF}@nivxray.test"
#: A secret-SHAPED probe value. Never a real token.
PROBE = "enr_ci_probe_not_a_real_secret"

CONNECTOR = Path("/app/backend/routers/edr_connector.py")
ONBOARDING = Path("/app/backend/routers/edr_onboarding.py")
ADD_DEVICE = Path("/app/apps/nivxray-xdr/src/nivxforge/pages/"
                  "EdrAddDevicePage.jsx")
DOWNLOADS = Path("/app/apps/nivxray-xdr/src/nivxforge/pages/"
                 "EdrDownloadsPage.jsx")
WIN_SENSOR = Path("/app/agents/nivxforge-windows/nivxforge_sensor.py")
LINUX_SENSOR = Path("/app/agents/nivxforge-linux/nivxforge_sensor.py")


@pytest.fixture(scope="module", autouse=True)
def _seed():
    if rb._db() is None:
        pytest.skip("MONGO_URL not configured")
    from deps import sync_collection
    users = sync_collection("users")
    users.update_one({"email": U_PLATFORM}, {"$set": {
        "email": U_PLATFORM, "role": "admin",
        "authority_scope": "PLATFORM"}}, upsert=True)
    org = (reg._orgs().find_one({"slug": f"w1-org-{SUF}"})
           or reg.create_organization(slug=f"w1-org-{SUF}",
                                      display_name=f"W1 fixture {SUF}",
                                      kind="CUSTOMER",
                                      created_by="test-suite"))
    reg.adopt_legacy(tenant_id=T_LAB, organization_id=org["id"],
                     slug=T_LAB, display_name=f"W1 {T_LAB}",
                     created_by="test-suite")
    with client:
        yield
    users.delete_many({"email": U_PLATFORM})
    reg._tenants().delete_many({"id": T_LAB})
    reg._orgs().delete_many({"id": org["id"]})


def _auth(tenant: str | None = None) -> dict:
    from deps import create_token
    headers = {"Authorization": f"Bearer {create_token(U_PLATFORM)}"}
    if tenant:
        headers["X-Tenant-Id"] = tenant
    return headers


def _no_argv_secret_form(text: str) -> None:
    for form in instructions.ARGV_SECRET_FORMS:
        assert form not in text, f"instruction teaches argv secret: {form}"


# ── W1 · no plaintext secret in any emitted instruction ───────────
def test_w1_windows_instruction_never_carries_a_secret_value():
    for entry in ("NivXForgeEDRSetup.exe", "Install-NivXForgeSensor.ps1"):
        text = instructions.windows_invocation(
            entrypoint=entry, backend="https://edr.example",
            tenant_id=T_LAB)
        assert PROBE not in text
        assert "enr_" not in text
        assert "<ENROLLMENT_TOKEN>" not in text, (
            "not even a placeholder that a caller could substitute a real "
            "secret into — that substitution WAS the defect")


def test_w1_deployment_response_no_longer_substitutes_the_secret():
    source = CONNECTOR.read_text(encoding="utf-8")
    assert 'invocation.replace("<ENROLLMENT_TOKEN>"' not in source
    assert "instructions.invocation(" in source
    assert '"install_invocation_carries_secret": False' in source


# ── W2 · no argv token form anywhere operator-facing ──────────────
def test_w2_formatter_emits_no_argv_secret_form():
    for entry in ("NivXForgeEDRSetup.exe", "Install-NivXForgeSensor.ps1"):
        _no_argv_secret_form(instructions.windows_invocation(
            entrypoint=entry, backend="https://edr.example",
            tenant_id=T_LAB))


def test_w2_published_windows_packages_teach_no_argv_secret():
    r = client.get("/api/edr/onboarding/packages", headers=_auth(T_LAB))
    assert r.status_code == 200, r.text
    windows = [p for p in r.json()["packages"]
               if p.get("os") == "WINDOWS" and p.get("silent_install")]
    assert windows, "no Windows package published an instruction"
    for pkg in windows:
        _no_argv_secret_form(pkg["silent_install"])
        assert PROBE not in pkg["silent_install"]


def test_w2_consoles_do_not_rebuild_an_argv_instruction():
    add_device = ADD_DEVICE.read_text(encoding="utf-8")
    # The page must not compose a command at all beyond substituting the
    # backend/tenant placeholders into the SERVER's instruction.
    assert "pkg.silent_install" in add_device
    assert "-EnrollmentToken ${" not in add_device
    assert "installCommand(pkg, tenant)" in add_device
    downloads = DOWNLOADS.read_text(encoding="utf-8")
    assert "carries NO secret" in downloads


# ── W3 · the instruction names the stdin mechanism ────────────────
def test_w3_exe_instruction_is_stdin_only():
    text = instructions.windows_exe_invocation(
        entrypoint="NivXForgeEDRSetup.exe", backend="https://edr.example",
        tenant_id=T_LAB)
    assert instructions.WINDOWS_STDIN_FLAG in text
    assert "-AsSecureString" in text
    assert "ZeroFreeBSTR" in text            # the secret is freed, not left
    assert text.count("|") == 1              # piped to stdin, once


def test_w3_script_instruction_passes_a_securestring_not_an_argument():
    text = instructions.windows_script_invocation(
        entrypoint="Install-NivXForgeSensor.ps1",
        backend="https://edr.example", tenant_id=T_LAB)
    assert "-AsSecureString" in text
    assert "@args" in text, "splatted, so no -EnrollmentToken pair is typed"
    _no_argv_secret_form(text)


def test_w3_deployment_response_states_the_secret_contract():
    assert "STDIN" in instructions.WINDOWS_SECRET_CONTRACT
    assert "Sysmon EID 1" in instructions.WINDOWS_SECRET_CONTRACT
    assert '"secret_handling"' in CONNECTOR.read_text(encoding="utf-8")


# ── W4 · the installer still refuses the legacy argv form ─────────
def test_w4_windows_sensor_still_refuses_argv_secrets():
    sys.path.insert(0, str(WIN_SENSOR.parent))
    spec = importlib.util.spec_from_file_location("w1_win_sensor",
                                                  WIN_SENSOR)
    sensor = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sensor)
    for argv in (["install", "--token", PROBE], ["install", PROBE],
                 ["install", "--provisioning-key=" + PROBE]):
        with pytest.raises(SystemExit) as ex:
            sensor.refuse_secret_on_command_line(argv)
        assert PROBE not in str(ex.value)
    assert sensor.looks_like_enrolment_secret(PROBE) is True


# ── W5/W6 · nothing about the credential lifecycle moved ──────────
def test_w5_token_semantics_are_untouched():
    store = Path("/app/backend/edr_plane/enrollment/store.py").read_text(
        encoding="utf-8")
    assert 'r["single_use"] = True' in store
    assert "EDR_ENROLLMENT_TOKEN_TTL_SECONDS" in store
    # ONE atomic burn, still filtered on unused + unrevoked + unexpired.
    assert "find_one_and_update" in store
    assert '"used_at": None' in store
    assert '"revoked_at": None' in store


def test_w6_runtime_credential_flow_is_untouched():
    store = Path("/app/backend/edr_plane/enrollment/store.py").read_text(
        encoding="utf-8")
    for fn in ("async def enroll(", "async def open_session(",
               "async def rotate_credential(", "async def revoke_endpoint("):
        assert fn in store
    assert "agent_credential" in store


# ── W7 · Linux is NOT silently changed by a Windows patch ─────────
def test_w7_linux_sensor_still_accepts_its_own_token_flag():
    linux = LINUX_SENSOR.read_text(encoding="utf-8")
    assert '"--token"' in linux, (
        "the Linux argv exposure is DECLARED P0 debt; this patch must "
        "neither fix nor hide it")


def test_w7_linux_instruction_is_unchanged_and_declared():
    text = instructions.linux_invocation(entrypoint="install.sh",
                                         backend="https://edr.example",
                                         tenant_id=T_LAB)
    assert "--enrollment-token <ENROLLMENT_TOKEN>" in text
    module = Path(instructions.__file__).read_text(encoding="utf-8")
    assert "LINUX is deliberately UNCHANGED" in module
    assert "declared P0" in module
