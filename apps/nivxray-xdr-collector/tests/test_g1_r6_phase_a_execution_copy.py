"""Static guards for the R6 Phase A PowerShell execution copy.

pwsh is unavailable in this container, so these assert the published block's
safety properties: it points at the real monorepo path, pins the reviewed
repair tool, defaults to a dry run, refuses the untrusted authority sibling,
and reports every failure with a non-zero process exit code.
"""
from __future__ import annotations

import hashlib
import os
import re

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.abspath(os.path.join(_HERE, os.pardir, os.pardir,
                                          os.pardir))
_PS1 = os.path.join(_REPO_ROOT, "memory", "G1_R6_PHASE_A_EXECUTION_COPY.ps1")
_TOOL = os.path.join(_HERE, os.pardir, "scripts",
                     "g1_r6_local_accounting_repair.py")


@pytest.fixture(scope="module")
def block() -> str:
    with open(_PS1, encoding="utf-8") as fh:
        return fh.read()


def test_defaults_to_a_dry_run(block):
    assert re.search(r"^\$Apply = \$false\s*$", block, re.MULTILINE), (
        "Phase A must never default to the mutating path")
    assert not re.search(r"^\$Apply = \$true", block, re.MULTILINE), (
        "the block must never assign $Apply = $true itself; only the operator "
        "flips it")


def test_tool_path_is_under_apps_and_pinned_to_the_reviewed_tool(block):
    assert r'$Repo     = "$Work\apps\nivxray-xdr-collector"' in block
    assert r"$Work\nivxray-xdr-collector" not in block
    assert r'$Tool     = "$Repo\scripts\g1_r6_local_accounting_repair.py"' \
        in block
    with open(_TOOL, "rb") as fh:
        actual = hashlib.sha256(fh.read()).hexdigest().upper()
    match = re.search(r"\$ExpectToolSha = '([0-9A-F]{64})'", block)
    assert match, "the repair tool SHA is not pinned"
    assert match.group(1) == actual


def test_consumes_the_authoritative_exact50_file_only(block):
    assert (r'$Authority = "$ProofDir\r5-inflight-50-server-reconciliation'
            r'.json"') in block
    # the FAILED-UNTRUSTED sibling carries a VERDICT banner and must be refused
    assert "contains 'VERDICT'" in block
    assert "FAILED/UNTRUSTED forensic sibling" in block
    assert "$auth.pass -ne $true" in block


def test_asserts_the_22_28_split_and_per_row_evidence(block):
    assert "$ExpectCanonical = 22" in block
    assert "$ExpectRetryable = 28" in block
    assert "$ExpectTotalRows = 125452" in block
    assert "DELIVERED_CANONICAL" in block and "RETRYABLE_STILL_QUEUED" in block
    assert "$_.claim.canonical_event_id" in block
    assert "$_.evidence_ref" in block
    assert "--expect-canonical" in block and "--expect-retryable" in block
    assert "--expect-total" in block


def test_dry_run_must_pass_before_apply_is_reachable(block):
    dry_gate = block.index("the dry run did not pass")
    apply_call = block.index("--apply")
    assert dry_gate < apply_call, (
        "the apply invocation must sit after the dry-run gate")
    assert "if (-not $Apply)" in block
    assert "return 0" in block


def test_backs_up_the_database_before_the_only_mutating_step(block):
    backup = block.index("Copy-Item $db $backup")
    apply_call = block.index("--apply")
    assert backup < apply_call, "the backup must precede the apply"
    assert "outbox-pre-r6a-" in block
    assert '"$db-wal", "$db-shm"' in block


def test_verifies_the_contracted_post_state_independently(block):
    for token in ("[int]$c.delivered -eq 3306", "[int]$c.delivering -eq 28",
                  "[int]$c.queued -eq 121993", "[int]$c.retrying -eq 125",
                  "repaired_marker_rows", "G1-R6-A"):
        assert token in block, token


def test_no_network_or_delivery_surface_is_invoked(block):
    for forbidden in ("Invoke-RestMethod", "Invoke-WebRequest",
                      "/api/auth/login", "routing/reconcile",
                      "Read-Host", "Start-Service", "DeliveryWorker("):
        assert forbidden not in block, forbidden
    assert "no destination, no credential required" in block


def test_every_failure_returns_non_zero(block):
    catch = block.split("\ncatch {", 1)
    assert len(catch) == 2
    catch_body = catch[1].split("\n}", 1)[0]
    assert "HARD STOP" in catch_body
    assert re.search(r"^\s*return 1\s*$", catch_body, re.MULTILINE)
    assert "$NivxExit = Invoke-G1R6PhaseA" in block
    assert "if ($null -eq $NivxExit) { $NivxExit = 1 }" in block
    assert "if ($PSCommandPath) { exit $NivxExit }" in block
    assert not re.search(r"^Invoke-G1R6PhaseA\s*$", block, re.MULTILINE)
    for match in re.finditer(r"^\s*throw ", block, re.MULTILINE):
        assert block.index("\ntry {") < match.start() < block.index(
            "\ncatch {"), "a throw outside the try would bypass return 1"


def test_writer_guard_precedes_everything(block):
    guard = block.index("a collector process is running")
    dry_run = block.index("--proof")
    assert guard < dry_run
