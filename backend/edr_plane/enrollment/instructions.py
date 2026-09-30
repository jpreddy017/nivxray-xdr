"""The ONE place an operator-facing enrolment instruction is written.

Every console surface, package description and deployment response builds
its install instruction here. Three routers used to compose their own, and
they drifted: two still taught `-EnrollmentToken <token>` and one
INTERPOLATED THE MINTED PLAINTEXT into an executable command string.

WINDOWS CONTRACT (authoritative, matches the shipped artifact):

    secure local entry (SecureString)
      → converted only inside the parent process
      → written to the child's STDIN
      → installer reads it with `--token-stdin`
      → the plaintext never appears in the child's command line

This matters because Windows records process command lines in places
NivXForge itself collects — Sysmon EID 1 `CommandLine`, the service
`binPath`, PowerShell history. A secret taught onto a command line becomes
endpoint telemetry. The installer refuses argv-carried secrets outright
(`nivxforge_sensor.refuse_secret_on_command_line`), so an instruction that
teaches one is not merely unsafe, it no longer works.

LINUX is deliberately UNCHANGED here. `agents/nivxforge-linux` still
accepts `--token` on argv; that exposure is separately declared P0
security debt and is not silently altered by a Windows patch.
"""
from __future__ import annotations

#: The only accepted Windows secret input.
WINDOWS_STDIN_FLAG = "--token-stdin"

#: Argv forms that must never appear in an operator-facing Windows
#: instruction. Tests assert their absence.
ARGV_SECRET_FORMS = ("--token ", "--token=", "-token ", "-EnrollmentToken ",
                     "--enrollment-token", "--enrolment-token",
                     "--provisioning-key")

WINDOWS_SECRET_CONTRACT = (
    "The enrolment secret is entered locally as a SecureString and handed "
    "to the installer on STDIN. It is never a command-line value: Windows "
    "records process command lines (Sysmon EID 1, service binPath, "
    "PowerShell history), and the installer refuses an argv-carried "
    "secret.")


def windows_exe_invocation(*, entrypoint: str, backend: str,
                           tenant_id: str) -> str:
    """Frozen one-file installer (`NivXForgeEDRSetup.exe`)."""
    return "\n".join((
        "$secret = Read-Host 'NivXForge enrolment secret' -AsSecureString",
        "$bstr   = "
        "[Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret)",
        "try {",
        "  [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) |",
        f"    .\\{entrypoint} install --backend {backend} "
        f"--tenant {tenant_id} {WINDOWS_STDIN_FLAG}",
        "} finally {",
        "  [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)",
        "  Remove-Variable secret, bstr -ErrorAction SilentlyContinue",
        "}",
    ))


def windows_script_invocation(*, entrypoint: str, backend: str,
                              tenant_id: str) -> str:
    """PowerShell installer script.

    The parameter is passed by SPLATTING a SecureString, so the secret is
    an in-process object and no `-EnrollmentToken <value>` pair is ever
    typed, recorded in history or seen by the SCM. The script itself then
    delivers it to the sensor on stdin.
    """
    return "\n".join((
        "$args = @{",
        f"  BackendUrl = '{backend}'",
        f"  TenantId   = '{tenant_id}'",
        "  EnrollmentToken = "
        "(Read-Host 'NivXForge enrolment secret' -AsSecureString)",
        "}",
        f"powershell -ExecutionPolicy Bypass -File .\\{entrypoint} @args",
    ))


def windows_invocation(*, entrypoint: str, backend: str,
                       tenant_id: str) -> str:
    """Authoritative Windows instruction for either entrypoint form."""
    entry = entrypoint or "NivXForgeEDRSetup.exe"
    kwargs = {"entrypoint": entry, "backend": backend or "<backend url>",
              "tenant_id": tenant_id or "<tenant>"}
    if entry.lower().endswith(".ps1"):
        return windows_script_invocation(**kwargs)
    return windows_exe_invocation(**kwargs)


def linux_invocation(*, entrypoint: str, backend: str,
                     tenant_id: str) -> str:
    """UNCHANGED Linux behaviour, centralised only so it stops being
    re-written per router. The argv exposure here is declared debt."""
    return (f"sudo ./{entrypoint or 'install.sh'} "
            f"--backend {backend or '<backend url>'} "
            f"--tenant {tenant_id or '<tenant>'} "
            f"--enrollment-token <ENROLLMENT_TOKEN>")


def invocation(*, os_name: str, entrypoint: str, backend: str,
               tenant_id: str) -> str:
    if str(os_name or "").upper() == "WINDOWS":
        return windows_invocation(entrypoint=entrypoint, backend=backend,
                                  tenant_id=tenant_id)
    return linux_invocation(entrypoint=entrypoint, backend=backend,
                            tenant_id=tenant_id)
