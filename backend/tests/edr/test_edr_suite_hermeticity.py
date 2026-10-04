"""The deterministic EDR gate must be HERMETIC.

Why this file exists: the first authoritative GitHub CI run of the
`tests/edr` gate was red for three reasons, none of them a product
defect — a test permanently replaced the shared stdlib
`subprocess.run`, the runner had no `backend/.env`, and one suite relied
on a pre-seeded `users` document. This file pins the first of those (the
only one expressible as a test) plus the configuration contract, so the
gate cannot silently regress into order-dependence again.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

EDR_TESTS = Path(__file__).parent
AGENT_DIR = Path("/app/agents/nivxforge-windows")

# Captured at IMPORT time, before any test in this worker has run.
_ORIGINAL_RUN = subprocess.run


# ── 1 · nothing may mutate the shared subprocess module ───────────
def test_no_edr_test_assigns_to_the_shared_subprocess_run():
    """`mod.subprocess` is `sys.modules["subprocess"]`. Assigning to its
    `run` attribute outlives the test and poisons the whole worker — the
    exact cause of the two 'intermittent' CI failures. Patch via
    `monkeypatch` instead, which restores at teardown."""
    # An ASSIGNMENT STATEMENT only — prose about the defect is not one.
    pattern = re.compile(r"^\s*(?:\w+\.)*subprocess\.run\s*=[^=]",
                         re.MULTILINE)
    offenders = [p.name for p in sorted(EDR_TESTS.glob("*.py"))
                 if p.name != Path(__file__).name
                 and pattern.search(p.read_text())]
    assert not offenders, (
        "these tests mutate the shared stdlib subprocess module: "
        f"{offenders}")


def test_monkeypatch_restores_the_real_run_at_teardown():
    original = subprocess.run
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(subprocess, "run", lambda *a, **k: None)
        assert subprocess.run is not original
    assert subprocess.run is original


# ── 2 · the real installer path, then proof of restoration ────────
# These two run in file order on the same worker (loadscope keeps a
# module together), which is what makes the second one a real teardown
# proof rather than a restated assumption.
def test_the_installer_service_path_runs_with_a_scoped_fake(monkeypatch,
                                                            tmp_path):
    import importlib.util

    monkeypatch.setenv("NIVXFORGE_SENSOR_STATE", str(tmp_path / "state"))
    sys.path.insert(0, str(AGENT_DIR))
    for name in ("nivxforge_setup", "nivxforge_sensor"):
        sys.modules.pop(name, None)
    spec = importlib.util.spec_from_file_location(
        "nivxforge_setup", AGENT_DIR / "nivxforge_setup.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.sensor.STATE_DIR.mkdir(parents=True, exist_ok=True)
    mod.SERVICE_DIR = tmp_path / "service"
    mod.SERVICE_DIR.mkdir(parents=True, exist_ok=True)
    mod.SERVICE_EXE = mod.SERVICE_DIR / "NivXForgeSensor.exe"
    mod.SERVICE_EXE.write_bytes(b"MZ stub")
    mod._stage_service_host = lambda: mod.SERVICE_EXE

    calls: list[str] = []

    def fake_run(cmdline, **kw):
        line = cmdline if isinstance(cmdline, str) \
            else subprocess.list2cmdline(cmdline)
        calls.append(line)
        out = "AUTO_START" if line.startswith("sc.exe qc") else ""
        return subprocess.CompletedProcess(cmdline, 0, out, "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    mod._install_service("https://nivxray.nivxforge.com", 30)
    assert any(c.startswith("sc.exe create") for c in calls)
    assert subprocess.run is fake_run       # patched inside the test


def test_a_list_argv_call_is_unaffected_after_the_installer_test():
    """The victims were `["git", "check-ignore", ...]` and
    `[sys.executable, LAUNCHER]`. Both must work here."""
    assert subprocess.run is _ORIGINAL_RUN, (
        "a previous test left the stdlib subprocess.run replaced")
    done = subprocess.run([sys.executable, "-c", "print('ok')"],
                          capture_output=True, text=True, check=False)
    assert done.returncode == 0 and done.stdout.strip() == "ok"


# ── 3 · the configuration contract the runner must satisfy ────────
def test_every_required_config_var_is_present_without_a_dotenv():
    """`deps.validate_config()` is fail-closed and is reached by several
    deterministic suites. On a runner there is no `backend/.env`, so the
    workflow (or conftest) must supply every required var explicitly."""
    from deps import _REQUIRED_ENV
    missing = [k for k in _REQUIRED_ENV if not os.environ.get(k)]
    assert not missing, (
        f"the CI environment is incomplete: {missing}. Add CI-only values "
        "to the workflow step — do not weaken validate_config().")


def test_the_ci_workflow_supplies_that_config_itself():
    wf = Path("/app/.github/workflows/rc4x_quality_gate.yml").read_text()
    step = wf.split("Unit tests — EDR plane", 1)[1]
    for key in ("MONGO_URL", "DB_NAME", "JWT_SECRET", "EMERGENT_LLM_KEY",
                "ADMIN_EMAIL", "ADMIN_PASSWORD"):
        assert key in step, f"{key} must be set by the CI step, not by .env"
    assert "NIVX_AI_ENABLED: \"false\"" in step, (
        "no deterministic test may make a real external LLM request")


def test_no_ci_config_value_looks_like_a_real_credential():
    wf = Path("/app/.github/workflows/rc4x_quality_gate.yml").read_text()
    step = wf.split("Unit tests — EDR plane", 1)[1].split("run:", 1)[0]
    for line in step.splitlines():
        if ":" not in line:
            continue
        value = line.split(":", 1)[1].strip().strip('"')
        if not value or value.startswith("mongodb://"):
            continue
        if any(t in line for t in ("JWT_SECRET", "EMERGENT_LLM_KEY",
                                   "ADMIN_PASSWORD")):
            assert "ci-only" in value, (
                f"CI config must be obviously synthetic: {line.strip()}")
            for shape in ("sk-", "sk_live", "emergent-", "nvx_"):
                assert shape not in value, "that looks like a real key"
