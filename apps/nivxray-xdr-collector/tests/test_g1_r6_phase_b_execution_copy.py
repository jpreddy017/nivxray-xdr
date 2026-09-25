"""Static guards for the R6 Phase B PowerShell execution copy.

pwsh is unavailable in this container, so these assert the published block's
safety properties: readiness by default, both tool SHAs pinned, the same-client
edge probe before any credential, a backup before the first mutating call, and
a verdict that treats a partial outcome as legitimate while still enforcing the
conservation law.
"""
from __future__ import annotations

import fnmatch
import hashlib
import os
import re

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.abspath(os.path.join(_HERE, os.pardir, os.pardir,
                                          os.pardir))
_PS1 = os.path.join(_REPO_ROOT, "memory", "G1_R6_PHASE_B_EXECUTION_COPY.ps1")
_SCRIPTS = os.path.join(_HERE, os.pardir, "scripts")


@pytest.fixture(scope="module")
def block() -> str:
    with open(_PS1, encoding="utf-8") as fh:
        return fh.read()


def _sha(path: str) -> str:
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest().upper()


def test_defaults_to_readiness(block):
    assert re.search(r"^\$Apply = \$false\s*$", block, re.MULTILINE)
    assert not re.search(r"^\$Apply = \$true", block, re.MULTILINE)
    # readiness must run and gate the apply
    readiness = block.index("the readiness pass did not pass")
    apply_call = block.index("--apply")
    assert readiness < apply_call


def test_both_tool_shas_are_pinned_to_the_reviewed_files(block):
    expected = {
        "ExpectToolSha": _sha(os.path.join(
            _SCRIPTS, "g1_r6_phase_b_exact28_recovery.py")),
        "ExpectExact50Sha": _sha(os.path.join(
            _SCRIPTS, "g1_r5_inflight50_reconcile.py")),
    }
    for name, actual in expected.items():
        match = re.search(r"\$" + name + r"\s*=\s*'([0-9A-F]{64})'", block)
        assert match, f"${name} is not pinned"
        assert match.group(1) == actual, name
    assert r'$Repo      = "$Work\apps\nivxray-xdr-collector"' in block


def test_authority_file_is_validated_before_anything(block):
    assert "r5-inflight-50-server-reconciliation.json" in block
    assert "contains 'VERDICT'" in block
    assert "$auth.pass -ne $true" in block
    assert "$ExpectExcluded = 22" in block
    assert "$ExpectTarget   = 28" in block
    authority = block.index("the authority file is not the exact-50")
    readiness = block.index("--authority")
    assert authority < readiness


def test_credential_free_probes_precede_the_prompt(block):
    probe = block.index("edge_banned")
    prompt = block.index('Read-Host ("  " + $principal + " Email")')
    assert probe < prompt, (
        "the python-client edge probe must run before any credential is asked "
        "for; that asymmetry cost a credential attempt once already")
    assert "DO NOT RETYPE PASSWORD" in block
    assert "HARD STOP - AUTH TARGET AMBIGUOUS" in block
    assert "print(m.USER_AGENT)" in block
    assert "print(m.RECONCILE_PATH)" in block


def test_prompt_names_the_product_and_environment(block):
    assert ("$principal = $Target.Product + ' ' + $Target.Environment + "
            "' Admin'") in block
    assert not re.search(r"Read-Host\s+'[^']*[Pp]assword", block)


def test_backup_precedes_the_first_mutating_call(block):
    backup = block.index("Copy-Item $db $backup")
    apply_call = block.index("--apply")
    assert backup < apply_call
    assert "outbox-pre-r6b-" in block
    assert '"$db-wal", "$db-shm"' in block


def test_bounded_canary_shape_is_configured(block):
    assert "$RemainderBatch = 7" in block
    assert "--remainder-batch" in block
    assert "canary(1) -> reconcile -> remainder(27)" in block
    assert ("HTTP accepted != canonicalized != durably evidenced") in block


def test_verdict_enforces_conservation_not_a_particular_split(block):
    assert "A PARTIAL OUTCOME IS" in block
    assert "($deliveredN + $deliveringN) -eq (3306 + 28)" in block
    assert "[int]$after.phase_b_markers -eq ($deliveredN - 3306)" in block
    assert "[int]$after.phase_a_markers -eq $ExpectExcluded" in block
    assert "[int]$c.queued -eq $ExpectQueued" in block
    assert "[int]$c.retrying -eq $ExpectRetrying" in block
    assert "[int]$after.total -eq $ExpectTotalRows" in block


def test_canary_stop_is_reported_distinctly(block):
    assert "$appExit -eq 3" in block
    assert "STOPPED AT THE CANARY" in block
    assert "The remaining 27 were NOT sent" in block
    assert "return 3" in block


def test_no_worker_acquisition_or_credential_lifecycle(block):
    # the header comment declares what is deliberately NOT used; only the
    # executable lines are scanned
    code = "\n".join(line for line in block.splitlines()
                     if not line.strip().startswith("#"))
    for forbidden in ("DeliveryWorker", "Start-Service", "next_batch",
                      "Outbox(", "--drain", "--all", "--revoke", "--rotate"):
        assert forbidden not in code, forbidden
    assert "neither creates, rotates, revokes" in block


def test_every_failure_returns_non_zero(block):
    catch = block.split("\ncatch {", 1)
    assert len(catch) == 2
    catch_body = catch[1].split("\n}", 1)[0]
    assert "HARD STOP" in catch_body
    assert re.search(r"^\s*return 1\s*$", catch_body, re.MULTILINE)
    assert "Remove-Item Env:\\NIVX_RECONCILE_TOKEN" in catch_body, (
        "the token must be cleared even on the failure path")
    assert "$NivxExit = Invoke-G1R6PhaseB" in block
    assert "if ($null -eq $NivxExit) { $NivxExit = 1 }" in block
    assert "if ($PSCommandPath) { exit $NivxExit }" in block
    for match in re.finditer(r"^\s*throw ", block, re.MULTILINE):
        assert block.index("\ntry {") < match.start() < block.index(
            "\ncatch {")


_HOST_ROW = re.compile(
    r"HostPattern = '([^']+)'\s*\n\s*Product     = '([^']+)'\s*\n\s*"
    r"Environment = '([^']+)'")


@pytest.mark.parametrize("host,environment", [
    ("greeting-app-5782.preview.emergentagent.com", "PREVIEW"),
    ("nivxray.nivxforge.com", "PRODUCTION"),
])
def test_known_hosts_classify(block, host, environment):
    rows = _HOST_ROW.findall(block)
    assert rows
    matched = [r for r in rows if fnmatch.fnmatchcase(host, r[0])]
    assert matched and matched[0][2] == environment


def test_unregistered_hosts_stay_ambiguous(block):
    rows = _HOST_ROW.findall(block)
    for host in ("edr.nivxforge.com", "localhost", "evil.attacker.test"):
        assert not [r for r in rows if fnmatch.fnmatchcase(host, r[0])], host
