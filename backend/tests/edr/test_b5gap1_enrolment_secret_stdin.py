"""NivXForge Windows enrolment · the secret is STDIN-ONLY.

Owner directive (C0.5 HOLD, blocker ENROLLMENT_TOKEN_COMMAND_LINE_EXPOSURE):
the one-time enrolment secret must never reach a process command line,
because this product itself collects command lines (Sysmon EID 1
`CommandLine`, the service `binPath`, PowerShell history) and a recorded
secret would become endpoint telemetry delivered to the very backend it
authenticates against.

These tests decide on Linux everything that is decidable here:

  1. the plaintext `--token` flag is GONE from both CLIs,
  2. a legacy or secret-shaped command line is REFUSED without echoing
     the value,
  3. the secret is read from stdin,
  4. a LIVE child process that received the secret on stdin has a
     kernel-reported command line (`/proc/<pid>/cmdline`) that does not
     contain it,
  5. the service command line carries no secret,
  6. a FAILED enrolment (including a backend that echoes the request
     body, as a 422 does) does not leak the secret into the message,
  7. a SUCCESSFUL enrolment still creates the identity, and neither the
     identity nor anything else in the state directory holds the secret.

What they do NOT claim: that Sysmon EID 1 on a real Windows host records
no secret. That is proven only on the canary host after the new artifact
is owner-reviewed (see docs/B5_GAP_1_ENROLMENT_SECRET_STDIN.md §6).
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

AGENT_DIR = Path("/app/agents/nivxforge-windows")
SETUP = AGENT_DIR / "nivxforge_setup.py"
SENSOR = AGENT_DIR / "nivxforge_sensor.py"
PS1 = AGENT_DIR / "Install-NivXForgeSensor.ps1"
DOC = Path("/app/docs/B5_GAP_1_ENROLMENT_SECRET_STDIN.md")
CANARY_PLAN = Path("/app/docs/B5_GAP_1_CANARY_PLAN.md")
GATE0 = Path("/app/docs/B5_GAP_1_WINDOWS_GATE0_CI_CONTRACT.md")

#: A secret-SHAPED value, assembled at runtime so this file never carries
#: a literal that a credential scanner should flag.
SECRET = "nvxenr_" + "Kq7Zt3Vb9Lm2Xn5Pd8Rc4Ws"
TENANT = "ten_e759b7288598bd882e3dcac49d"


def _load(path: Path, name: str):
    """Load a module BY PATH, under a private name.

    The Linux sensor is also called `nivxforge_sensor`, and other test
    modules import it, so `sys.modules` cannot be trusted to hold the
    Windows one. Every module here is loaded explicitly from its own path
    and wired together by hand.
    """
    sys.path.insert(0, str(AGENT_DIR))
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def sensor_mod():
    return _load(SENSOR, "nivxforge_windows_sensor_under_test")


@pytest.fixture(scope="module")
def setup_mod(sensor_mod):
    mod = _load(SETUP, "nivxforge_windows_setup_under_test")
    mod.sensor = sensor_mod            # never the Linux sensor
    return mod


# ── 1 · the plaintext interface is gone ───────────────────────────
def test_installer_cli_has_no_plaintext_token_flag(setup_mod):
    parser = setup_mod.build_parser()
    args, _ = parser.parse_known_args(["install", "--tenant", TENANT,
                                       "--token-stdin"])
    assert args.token_stdin is True
    assert not hasattr(args, "token")


def test_sensor_cli_requires_token_stdin(sensor_mod, monkeypatch):
    monkeypatch.setattr(sys, "argv",
                        ["nivxforge_sensor.py", "enrol", "--api",
                         "https://nivxray.nivxforge.com", "--tenant", TENANT])
    with pytest.raises(SystemExit):
        sensor_mod.main()


def test_install_refuses_to_enrol_without_stdin(setup_mod, monkeypatch):
    monkeypatch.setattr(setup_mod, "_assert_admin", lambda: None)
    monkeypatch.setattr(setup_mod, "_protect_state_dir", lambda: None)
    monkeypatch.setattr(setup_mod, "_self_path",
                        lambda: setup_mod.INSTALLED_EXE)
    monkeypatch.setattr(setup_mod, "_stage_service_host",
                        lambda: setup_mod.SERVICE_EXE)
    monkeypatch.setattr(setup_mod.INSTALL_DIR.__class__, "mkdir",
                        lambda self, **kw: None)
    monkeypatch.setattr(setup_mod.sensor, "IDENTITY_FILE",
                        Path("/nonexistent/identity.json"))
    with pytest.raises(SystemExit) as ex:
        setup_mod.install("https://nivxray.nivxforge.com", TENANT, False,
                          30, False)
    assert "--token-stdin is required" in str(ex.value)


# ── 2 · a command line that carries the secret is refused ─────────
@pytest.mark.parametrize("argv", [
    ["install", "--tenant", TENANT, "--token", SECRET],
    ["install", "--tenant", TENANT, "--token=" + SECRET],
    ["install", "--tenant", TENANT, "--enrollment-token", SECRET],
    ["install", "--tenant", TENANT, "--enrolment-token", SECRET],
    ["install", "--tenant", TENANT, SECRET],
    ["install", "--tenant", TENANT, "--secret=" + SECRET],
])
def test_legacy_or_secret_shaped_command_line_is_refused(setup_mod, argv):
    with pytest.raises(SystemExit) as ex:
        setup_mod.main(argv)
    message = str(ex.value)
    assert SECRET not in message, "the refusal must not echo the value"
    assert "--token-stdin" in message


def test_refusal_runs_before_argparse_can_echo_the_value(setup_mod, capsys):
    """`parse_known_args` would DISCARD `--token <secret>` silently, and
    `parse_args` would print it in an 'unrecognized arguments' error."""
    with pytest.raises(SystemExit):
        setup_mod.main(["install", "--tenant", TENANT, "--token", SECRET])
    captured = capsys.readouterr()
    assert SECRET not in captured.out + captured.err


# ── 3 · the secret comes from stdin ───────────────────────────────
def test_secret_is_read_from_stdin(sensor_mod, tmp_path):
    source = tmp_path / "secret.txt"
    source.write_text(SECRET + "\n")
    with source.open() as stream:
        assert sensor_mod.read_enrolment_secret(stream) == SECRET


@pytest.mark.parametrize("payload", ["", "\n", "   \n"])
def test_empty_stdin_is_refused(sensor_mod, tmp_path, payload):
    source = tmp_path / "empty.txt"
    source.write_text(payload)
    with source.open() as stream:
        with pytest.raises(SystemExit) as ex:
            sensor_mod.read_enrolment_secret(stream)
    assert "no enrolment secret" in str(ex.value)


# ── 4 · LIVE proof: argv of a real child process ──────────────────
_ARGV_PROBE = '''
import json, sys
sys.path.insert(0, {agent!r})
import nivxforge_sensor as sensor
secret = sensor.read_enrolment_secret()
cmdline = open("/proc/self/cmdline", "rb").read().decode(errors="replace")
print(json.dumps({{
    "secret_read": bool(secret),
    "in_argv": any(secret in arg for arg in sys.argv),
    "in_kernel_cmdline": secret in cmdline,
    "cmdline": cmdline.replace("\\x00", " ").strip(),
}}))
'''


def test_live_child_process_command_line_never_holds_the_secret(tmp_path):
    probe = tmp_path / "argv_probe.py"
    probe.write_text(_ARGV_PROBE.format(agent=str(AGENT_DIR)))
    out = subprocess.run(
        [sys.executable, str(probe), "enrol", "--api",
         "https://nivxray.nivxforge.com", "--tenant", TENANT,
         "--token-stdin"],
        input=SECRET + "\n", capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    result = json.loads(out.stdout)
    assert result["secret_read"] is True
    assert result["in_argv"] is False
    assert result["in_kernel_cmdline"] is False, (
        "the secret reached /proc/<pid>/cmdline, which is exactly what "
        "Sysmon EID 1 records on Windows")
    assert "--token-stdin" in result["cmdline"]
    assert SECRET not in out.stdout + out.stderr


# ── 5 · the service command line carries no secret ────────────────
def test_service_command_line_carries_no_secret(setup_mod, monkeypatch):
    seen: list[str] = []

    def fake_sc(cmdline: str):
        seen.append(cmdline)
        return subprocess.CompletedProcess(cmdline, 0, "AUTO_START", "")

    monkeypatch.setattr(setup_mod, "_sc", fake_sc)
    monkeypatch.setattr(setup_mod, "_service_exists", lambda: False)
    monkeypatch.setattr(setup_mod, "_service_config", lambda: "AUTO_START")
    monkeypatch.setattr(setup_mod.SERVICE_EXE.__class__, "exists",
                        lambda self: True)
    setup_mod._install_service("https://nivxray.nivxforge.com", 30)
    joined = "\n".join(seen)
    assert "binPath=" in joined
    for banned in (SECRET, "nvxenr_", "--token", "agent_credential"):
        assert banned not in joined, f"{banned} must never reach the SCM"


# ── 6/7 · enrolment behaviour against a real local backend ────────
class _Handler(BaseHTTPRequestHandler):
    status = 200
    echo_body = False

    def do_POST(self) -> None:                       # noqa: N802
        raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if type(self).echo_body:
            # What a FastAPI 422 does: it repeats the offending input.
            payload = json.dumps({"detail": [{"loc": ["body",
                                                      "enrollment_token"],
                                              "msg": "invalid",
                                              "input": json.loads(raw)}]})
        else:
            payload = json.dumps({"endpoint_id": "ep_1989031c8c1d0085812f",
                                  "credential_id": "cred_local_test",
                                  "agent_credential": "credential-value",
                                  "sensor_state": "ENROLLED_NO_TELEMETRY"})
        body = payload.encode()
        self.send_response(type(self).status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args) -> None:           # silence the server
        return


@pytest.fixture
def backend():
    def start(status: int, echo_body: bool) -> str:
        handler = type("H", (_Handler,),
                       {"status": status, "echo_body": echo_body})
        server = HTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        started.append(server)
        return f"http://127.0.0.1:{server.server_port}"

    started: list[HTTPServer] = []
    yield start
    for server in started:
        server.shutdown()


@pytest.fixture
def state(sensor_mod, monkeypatch, tmp_path):
    root = tmp_path / "state"
    root.mkdir()
    monkeypatch.setattr(sensor_mod, "STATE_DIR", root)
    monkeypatch.setattr(sensor_mod, "IDENTITY_FILE", root / "identity.json")
    monkeypatch.setattr(sensor_mod, "_machine_facts", lambda: {
        "processor_id": "cpu-test", "machine_guid": "guid-test",
        "hostname": "canary-test", "platform": "WINDOWS",
        "os_version": "Windows 10 test"})
    monkeypatch.setattr(sensor_mod, "TRANSPORT", sensor_mod._Transport())
    return root


def test_failed_enrolment_does_not_leak_the_secret(sensor_mod, backend,
                                                   state, capsys):
    api = backend(422, echo_body=True)
    with pytest.raises(SystemExit) as ex:
        sensor_mod.enrol(api, TENANT, SECRET)
    message = str(ex.value)
    assert "enrolment failed" in message
    assert SECRET not in message, "a rejected enrolment leaked the secret"
    assert sensor_mod.SECRET_REDACTED in message
    assert ex.value.__cause__ is None and ex.value.__context__ is None
    captured = capsys.readouterr()
    assert SECRET not in captured.out + captured.err
    assert not (state / "identity.json").exists()


def test_successful_enrolment_creates_identity_without_the_secret(
        sensor_mod, backend, state, capsys):
    api = backend(200, echo_body=False)
    result = sensor_mod.enrol(api, TENANT, SECRET)
    assert result["endpoint_id"] == "ep_1989031c8c1d0085812f"
    identity = json.loads((state / "identity.json").read_text())
    assert identity["endpoint_id"] == "ep_1989031c8c1d0085812f"
    assert identity["credential_id"] == "cred_local_test"
    assert identity["agent_credential"] == "credential-value"
    # 3 · the one-time secret is NOT persisted after enrolment.
    assert SECRET not in json.dumps(identity)
    assert "enrollment_token" not in identity
    captured = capsys.readouterr()
    assert SECRET not in captured.out + captured.err


def test_nothing_in_the_state_directory_holds_the_secret(sensor_mod, backend,
                                                         state):
    sensor_mod.enrol(backend(200, echo_body=False), TENANT, SECRET)
    for path in state.rglob("*"):
        if path.is_file():
            assert SECRET not in path.read_text(encoding="utf-8",
                                                errors="replace"), path


def test_enrol_refuses_when_the_secret_is_also_in_argv(sensor_mod, backend,
                                                       state, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["nivxforge_setup.py", "install",
                                      "--token", SECRET])
    with pytest.raises(SystemExit) as ex:
        sensor_mod.enrol(backend(200, echo_body=False), TENANT, SECRET)
    assert SECRET not in str(ex.value)


# ── the PowerShell path and the documentation ─────────────────────
def test_powershell_installer_uses_a_securestring_and_stdin():
    text = PS1.read_text(encoding="utf-8")
    assert "[System.Security.SecureString]$EnrollmentToken" in text
    assert "RedirectStandardInput" in text
    assert "--token-stdin" in text
    assert "ZeroFreeBSTR" in text
    # The old argv invocation must be gone.
    assert "--token $EnrollmentToken" not in text


def test_documentation_states_the_secure_invocation():
    assert DOC.exists(), "the enrolment-secret change record is missing"
    doc = DOC.read_text(encoding="utf-8")
    for required in ("--token-stdin", "Sysmon EID 1", "argv",
                     "ENROLLMENT_TOKEN_COMMAND_LINE_EXPOSURE"):
        assert required in doc
    plan = CANARY_PLAN.read_text(encoding="utf-8")
    assert "--token-stdin" in plan
    assert "--token <one-time enrolment token>" not in plan


def test_gate0_artifact_evidence_is_left_immutable():
    """The hardening must not rewrite the frozen Gate-0 evidence."""
    gate0 = GATE0.read_text(encoding="utf-8")
    assert "2cb841db10e4262bba89c115bfa8c3058f61fda4" in gate0


def test_windows_workflow_proves_the_legacy_flag_is_gone_from_the_binary():
    workflow = Path(
        "/app/.github/workflows/windows-sensor-installer.yml"
    ).read_text(encoding="utf-8")
    verify = workflow[workflow.index("Verify artifact contract"):
                      workflow.index("- uses: actions/upload-artifact")]
    assert "--token x" in verify, "the legacy interface must still be probed"
    assert "if ($legacyExit -eq 0) { throw" in verify
    assert "is REMOVED" in verify
    # The localhost origin probe must no longer carry a token value.
    assert "--backend http://localhost:8001 --tenant t --token-stdin" in verify
