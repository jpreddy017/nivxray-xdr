"""B5-GAP-1 WINDOWS GATE 0 · CI ACCEPTANCE CONTRACT.

Gate 0 asks one question a Linux test can never answer: does the REAL
frozen Windows artifact carry a working evidence journal? These tests do
NOT answer it. They prove the two things that make the answer trustworthy
when the owner runs `windows-sensor-installer.yml`:

  1. the selftest the artifact runs about ITSELF emits every mandatory
     assertion, and reports anything unanswerable off Windows as
     `N/A_NON_WINDOWS` — never as a pass, so a Linux run can never be
     mistaken for Windows evidence;
  2. the Windows job FAILS CLOSED on a missing or non-PASS assertion.

EVIDENCE LABELLING — TEST/SYNTHETIC. No endpoint contact.
"""
from __future__ import annotations

import importlib.util
import json
import sys

import pytest
from tests.edr import fixtures_b5_gap1_source as fx

REPO = fx.AGENT_DIR.parents[1]
WORKFLOW = REPO / ".github/workflows/windows-sensor-installer.yml"

#: the owner-mandated Gate 0 assertion names
MANDATORY = (
    "WINDOWS_SQLITE", "WINDOWS_SQLITE_NATIVE_BINARY",
    "WINDOWS_JOURNAL_MODULE", "WINDOWS_NTFS_DATABASE_CREATE",
    "WINDOWS_WAL_CREATE", "WINDOWS_WAL_REOPEN_RECOVERY",
    "WINDOWS_SYNCHRONOUS_FULL", "WINDOWS_AUTO_VACUUM_INCREMENTAL",
    "WINDOWS_SCHEMA", "WINDOWS_DURABLE_COMMIT", "WINDOWS_CURSOR_COMMIT",
    "WINDOWS_REPLAY_IDEMPOTENCY", "WINDOWS_INTEGRITY_SNAPSHOT",
    "WINDOWS_GAP_CONTRACT", "WINDOWS_STATE_DIR_ACCESS",
    "WINDOWS_SERVICE_PERMISSION_CHECK", "PACKAGING_REGRESSION",
)
#: answerable only on a Windows volume with a Windows security descriptor
WINDOWS_ONLY = ("WINDOWS_NTFS_DATABASE_CREATE", "WINDOWS_WAL_CREATE",
                "WINDOWS_STATE_DIR_ACCESS",
                "WINDOWS_SERVICE_PERMISSION_CHECK")


@pytest.fixture()
def setup(tmp_path, monkeypatch):
    monkeypatch.setenv("NIVXFORGE_SENSOR_STATE", str(tmp_path / "state"))
    sys.path.insert(0, str(fx.AGENT_DIR))
    for name in ("nivxforge_setup", "nivxforge_sensor", "nivxforge_journal"):
        sys.modules.pop(name, None)
    spec = importlib.util.spec_from_file_location(
        "nivxforge_setup", fx.AGENT_DIR / "nivxforge_setup.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["nivxforge_setup"] = module
    spec.loader.exec_module(module)
    return module


# ═══════════ THE ARTIFACT'S OWN SELFTEST ═════════════════════════
def test_selftest_emits_every_mandatory_gate0_assertion(setup, tmp_path):
    out = setup.journal_selftest(str(tmp_path / "scratch"))
    assert out["result"] == "PASS", out["failed"]
    assert out["phase"] == "PRIMARY"
    for name in (*MANDATORY, "WINDOWS_FROZEN", "WINDOWS_FROZEN_RESTART",
                 "WINDOWS_SQLITE_LIBRARY_VERSION"):
        assert name in out["gate0"], f"Gate 0 field absent: {name}"
    assert out["gate0"]["WINDOWS_SQLITE_LIBRARY_VERSION"] not in (
        "", "ABSENT"), "the SQLite runtime version must be PRESENT"


def test_non_windows_checks_are_never_reported_as_pass(setup, tmp_path):
    """A Linux run must be UNABLE to claim Windows evidence."""
    if sys.platform.startswith("win"):
        pytest.skip("this invariant is about the non-Windows case")
    out = setup.journal_selftest(str(tmp_path / "scratch"))
    for name in WINDOWS_ONLY:
        assert out["gate0"][name] == setup.NOT_WINDOWS, (
            f"{name} must not read PASS off Windows")
    assert out["gate0"]["WINDOWS_FROZEN"] == "FALSE", (
        "an interpreted run is not a frozen artifact")


def test_restart_phase_proves_evidence_survives_a_new_process(setup,
                                                              tmp_path):
    scratch = str(tmp_path / "scratch")
    first = setup.journal_selftest(scratch)
    assert first["checks"]["durable_commit"] is True

    second = setup.journal_selftest(scratch, restart_check=True)
    assert second["phase"] == "RESTART"
    assert second["result"] == "PASS", second["failed"]
    assert second["checks"]["evidence_rows"] == 1, (
        "the committed page must still be there, exactly once")
    assert second["checks"]["cursor_committed"] is True
    assert second["checks"]["frozen_restart_recovery"] is True
    assert second["gate0"]["WINDOWS_FROZEN_RESTART"] == "PASS"


def test_primary_phase_does_not_claim_restart_recovery(setup, tmp_path):
    out = setup.journal_selftest(str(tmp_path / "scratch"))
    assert out["checks"]["frozen_restart_recovery"] == \
        "PENDING_RESTART_PHASE"
    assert out["gate0"]["WINDOWS_FROZEN_RESTART"] == "PENDING_RESTART_PHASE"


def test_restart_check_refuses_to_guess_a_directory(setup):
    out = setup.journal_selftest(None, restart_check=True)
    assert out["result"] == "FAIL"
    assert out["failed"] == ["restart_check_requires_dir"]


def test_packaging_provenance_is_reported_and_fails_closed(setup, tmp_path):
    out = setup.journal_selftest(str(tmp_path / "scratch"))
    provenance = out["checks"]["module_provenance"]
    for module in ("nivxforge_journal", "nivxforge_sensor", "sqlite3",
                   "_sqlite3"):
        assert provenance[module]["present"] is True, module
    assert provenance["_sqlite3"]["file_on_disk"] is True, (
        "the NATIVE sqlite extension must be a real file")
    assert out["checks"]["packaging_regression_free"] is True

    absent = {"nivxforge_journal": {"present": False, "error": "x"},
              "_sqlite3": {"present": True, "file_on_disk": True}}
    assert setup._packaging_regression_ok(absent) is False
    unbundled = {"nivxforge_journal": {"present": True,
                                       "in_frozen_bundle": False},
                 "_sqlite3": {"present": True, "file_on_disk": False}}
    assert setup._packaging_regression_ok(unbundled) is False


def test_cli_writes_machine_readable_gate0_evidence(setup, tmp_path,
                                                    capsys):
    target = tmp_path / "out" / "gate0.json"
    setup.main(["journal-selftest", "--dir", str(tmp_path / "scratch"),
                "--json-out", str(target)])
    capsys.readouterr()
    report = json.loads(target.read_text())
    assert report["result"] == "PASS", report["failed"]
    assert report["gate0"]["WINDOWS_SQLITE"] == "PASS"
    assert report["sensor_version"]
    assert report["setup_version"]


# ═══════════ THE WINDOWS JOB MUST FAIL CLOSED ════════════════════
def test_workflow_runs_both_selftest_phases_from_the_frozen_exe():
    wf = WORKFLOW.read_text()
    assert "journal-selftest --dir $scratch `" in wf
    assert "--restart-check" in wf, (
        "restart recovery is only provable by a SECOND process")
    assert "NivXForgeEDRSetup.exe" in wf
    assert "runs-on: windows-latest" in wf


def test_workflow_requires_every_mandatory_assertion():
    wf = WORKFLOW.read_text()
    for name in MANDATORY:
        assert f"'{name}'" in wf, f"Gate 0 job does not assert {name}"
    assert "WINDOWS_FROZEN_RESTART" in wf


def test_workflow_fails_closed_on_missing_or_non_pass():
    wf = WORKFLOW.read_text()
    assert "mandatory, must be PASS" in wf
    assert "return 'MISSING'" in wf, (
        "an absent assertion must be a FAILURE, not a silent skip")
    assert "if ($problems.Count -gt 0 -or -not $buildOk) {" in wf
    assert "exit 1" in wf, "the job must fail, not warn"
    assert "system Python is NOT acceptable" in wf


def test_workflow_publishes_the_gate0_report_for_owner_review():
    wf = WORKFLOW.read_text()
    assert "GATE0_WINDOWS_REPORT.json" in wf
    assert "gate0/*.json" in wf
    assert "GITHUB_STEP_SUMMARY" in wf
    for identity in ("ARTIFACT_FILENAME", "ARTIFACT_VERSION",
                     "ARTIFACT_SHA256", "COMMIT_SHA", "WORKFLOW_RUN_ID",
                     "BUILD_TIMESTAMP", "PYINSTALLER_VERSION",
                     "SIGNING_STATUS"):
        assert identity in wf, f"artifact identity field missing: {identity}"


def test_workflow_declares_the_owner_stop_boundary():
    wf = WORKFLOW.read_text()
    for flag in ("CANARY_STARTED                = 'NO'",
                 "CORRELATION_CACHE_IMPLEMENTED = 'NO'",
                 "COUNTER_BATCHING_IMPLEMENTED  = 'NO'",
                 "RAW_EVENT_PATH_MODIFIED       = 'NO'",
                 "DESKTOP_A9HGFJJ_TOUCHED       = 'NO'",
                 "PRODUCTION_DEPLOYED           = 'NO'"):
        assert flag in wf, flag


def test_build_still_declares_the_journal_hidden_imports():
    build = (fx.AGENT_DIR / "build/build_windows_installer.ps1").read_text()
    assert "'nivxforge_journal'" in build
    assert "'sqlite3'" in build
