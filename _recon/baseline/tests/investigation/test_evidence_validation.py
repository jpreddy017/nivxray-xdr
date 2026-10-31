"""Stage 9 · Evidence Validation tests."""
import json

from nivxforge.investigation.pipeline.evidence_validation import (
    Severity, validate,
)
from nivxforge.investigation.pipeline.orchestrator import run_phase1


def test_valid_input_has_no_errors():
    state = run_phase1(json.dumps({
        "EventID": 1, "Computer": "host-a",
        "Image": "cmd.exe", "CommandLine": "cmd /c whoami",
        "Hashes": "SHA256=" + "d" * 64,
    }))
    assert not state.validation.errors


def test_bad_sha256_length_flagged():
    state = run_phase1(json.dumps({
        "EventID": 1, "Computer": "host-a",
        "Image": "cmd.exe", "CommandLine": "cmd /c whoami",
        "Hashes": "SHA256=deadbeef",  # too short
    }))
    codes = {f.code for f in state.validation.findings}
    assert "hash.length_mismatch" in codes


def test_non_hex_hash_flagged():
    state = run_phase1(json.dumps({
        "EventID": 1, "Computer": "host-a",
        "Image": "cmd.exe", "CommandLine": "cmd /c whoami",
        "Hashes": "SHA256=" + "z" * 64,   # non-hex
    }))
    codes = {f.code for f in state.validation.findings}
    assert "hash.not_hex" in codes


def test_validation_summary_shape():
    state = run_phase1(json.dumps({"EventID": 1, "Computer": "h",
                                    "Image": "cmd.exe",
                                    "CommandLine": "cmd"}))
    s = state.validation.summary()
    assert set(s.keys()) >= {"info", "warn", "error"}
