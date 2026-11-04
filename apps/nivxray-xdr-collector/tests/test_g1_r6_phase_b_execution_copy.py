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
    # clearing now lives in the finally block, which also covers the catch
    assert "\nfinally {" in block, (
        "the token must be cleared on every exit path, not just this one")
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


# ---------------------------------------------------------------------------
# Ingest configuration remediation. The first APPLY stopped before the canary
# because `IngestClient.configured()` is literally `bool(NIVX_INGEST_URL)` and
# the wrapper never exported the delivery environment the historically
# successful G1/R5 runs did. These guards keep that gap closed, and keep the
# collector ingest secret out of everything.
# ---------------------------------------------------------------------------
_HISTORICAL_ENV = {
    "NIVX_INGEST_URL": '"$BaseUrl/api/xdr/ingest/telemetry"',
    "NIVX_INGEST_AUTH_MODE": "'api_key'",
    "XDR_STATE_DIR": "$StateDir",
    "XDR_AUTO_START_CONNECTORS": "'0'",
}


@pytest.mark.parametrize("name,value", sorted(_HISTORICAL_ENV.items()))
def test_wrapper_establishes_the_historical_delivery_environment(block, name,
                                                                 value):
    assert re.search(r"\$env:" + name + r"\s*=\s*" + re.escape(value), block), (
        f"{name} must be exported exactly as the working G1/R5 blocks did")


def test_delivery_environment_is_established_before_readiness(block):
    env_set = block.index("$env:NIVX_INGEST_URL")
    readiness = block.index("--authority")
    assert env_set < readiness


def test_readiness_requires_no_ingest_secret(block):
    """The token prompt must sit behind the $Apply branch."""
    readiness_return = block.index("STOP (READINESS ONLY)")
    prompt = block.index("Collector Ingest API Key")
    assert readiness_return < prompt, (
        "readiness must complete and return before any ingest secret is asked "
        "for")
    # and a pre-existing token in the session is refused outright
    assert "NIVX_INGEST_TOKEN is already present in this session" in block
    assert "(absent, as required for readiness)" in block


def test_apply_asserts_presence_of_every_precondition(block):
    for check in ("'NIVX_INGEST_URL present'",
                  "'NIVX_INGEST_AUTH_MODE is api_key'",
                  "'NIVX_INGEST_TOKEN present'",
                  "'NIVX_COLLECTOR_ID present'",
                  "'XDR_AUTO_START_CONNECTORS is 0'",
                  "'NIVX_RECONCILE_TOKEN present'"):
        assert check in block, check
    assert "pre-canary preconditions unmet" in block
    # presence only - never the value
    assert "IsNullOrWhiteSpace($env:NIVX_INGEST_TOKEN)" in block
    assert "no secret value was inspected, printed or stored" in block
    # and the gate sits before the delivery call
    assert block.index("pre-canary preconditions unmet") < block.index("--apply")


def test_auth_mode_is_asserted_case_sensitively(block):
    assert "$env:NIVX_INGEST_AUTH_MODE -ceq 'api_key'" in block, (
        "auth_mode must be exactly api_key: `bearer` would route the key down "
        "the JWT path where it can only fail")


def test_the_wrong_variable_is_not_used_as_a_substitute(block):
    code = "\n".join(line for line in block.splitlines()
                     if not line.strip().startswith("#"))
    assert "NIVX_XDR_API_KEY" not in code, (
        "IngestClient reads NIVX_INGEST_TOKEN; the forwarder's variable is "
        "not a substitute")
    assert "$env:NIVX_INGEST_TOKEN = Get-PlainFromSecure $ingestSecret" in block
    assert "-AsSecureString" in block


def test_the_secret_cannot_reach_stdout_logs_or_evidence(block):
    """No line may both reference the token and emit or persist it."""
    emitters = ("Write-Host", "Out-File", "Set-Content", "Add-Content",
                "ConvertTo-Json", "Get-FileHash", "Export-Csv", "Tee-Object")
    for line in block.splitlines():
        if "NIVX_INGEST_TOKEN" not in line and "ingestSecret" not in line:
            continue
        if "IsNullOrWhiteSpace" in line:          # presence check only
            continue
        if "(absent, as required" in line:        # fixed, value-free label
            continue
        if "Remove-Item Env:" in line:            # clearing, not emitting
            continue
        for emitter in emitters:
            assert emitter not in line, (
                f"a line references the ingest secret and {emitter}: {line!r}")
    # the only Write-Host mentioning it prints a fixed, value-free label
    assert ("Write-Host '  NIVX_INGEST_TOKEN         = (absent, as required "
            "for readiness)' -ForegroundColor Green") in block


def test_secret_is_cleared_on_every_exit_path_via_finally(block):
    finally_block = block.split("\nfinally {", 1)
    assert len(finally_block) == 2, (
        "clearing must be in a finally block, not only on the happy path")
    body = finally_block[1].split("\n}", 1)[0]
    assert "Remove-Item Env:\\NIVX_INGEST_TOKEN" in body
    assert "Remove-Item Env:\\NIVX_RECONCILE_TOKEN" in body
    assert "could not clear" in body, (
        "the wrapper must say so if a secret survived the clear")
    # finally runs after both the success and failure returns
    assert block.index("return 0") < block.index("\nfinally {")
    assert block.index("\ncatch {") < block.index("\nfinally {")


def test_engine_and_reconciliation_client_remain_byte_identical(block):
    """The remediation is wrapper-only; the pinned SHAs prove it."""
    assert re.search(
        r"\$ExpectToolSha\s*=\s*'"
        + _sha(os.path.join(_SCRIPTS, "g1_r6_phase_b_exact28_recovery.py"))
        + r"'", block)
    assert re.search(
        r"\$ExpectExact50Sha\s*=\s*'"
        + _sha(os.path.join(_SCRIPTS, "g1_r5_inflight50_reconcile.py"))
        + r"'", block)


# ---------------------------------------------------------------------------
# Credential format gate. The first APPLY spent the canary on a value the
# server refused as `malformed-api-key` before credential lookup. The wrapper
# now refuses that class of paste locally, and the engine enforces the same
# requirement independently.
# ---------------------------------------------------------------------------
def test_wrapper_validates_the_credential_format_case_sensitively(block):
    assert "-cmatch '^nvx_[0-9a-f]{48}$'" in block, (
        "the guard must be case-sensitive: uppercase hex is not an issued key")
    assert "$ingestLen -eq 52" in block
    assert "CREDENTIAL FORMAT GATE" in block


def test_the_format_gate_sits_between_the_prompt_and_any_delivery(block):
    prompt = block.index("$env:NIVX_INGEST_TOKEN = Get-PlainFromSecure")
    gate = block.index("-cmatch '^nvx_[0-9a-f]{48}$'")
    apply_call = block.index("--apply")
    assert prompt < gate < apply_call, (
        "validation must happen after the SecureString conversion and before "
        "any delivery")


def test_a_malformed_credential_hard_stops_and_clears_the_session(block):
    gate = block.index("CREDENTIAL FORMAT GATE")
    tail = block[gate:block.index("=== 4c .")]
    assert "if (-not $ingestFormatOk) {" in tail
    assert "Remove-Item Env:\\NIVX_INGEST_TOKEN" in tail
    assert "throw (" in tail
    assert "the canary was not spent" in tail


def test_the_gate_never_repairs_or_normalises_the_value(block):
    gate = block[block.index("CREDENTIAL FORMAT GATE"):
                 block.index("=== 4c .")]
    for forbidden in (".Trim(", ".ToLower(", ".ToUpper(", "-replace",
                      "-imatch", "-match "):
        assert forbidden not in gate, forbidden
    assert "NOT trimmed, case-folded or repaired" in block


def test_only_the_public_prefix_may_be_displayed(block):
    assert "$ingestPrefix = ([string]$env:NIVX_INGEST_TOKEN).Substring(0, 12)" \
        in block
    assert "the remaining 40 characters are never displayed" in block
    # the displayed value comes from the prefix variable, never the token
    for line in block.splitlines():
        if "Write-Host" in line and "$ingestPrefix" in line:
            assert "NIVX_INGEST_TOKEN" not in line


def test_the_operator_is_told_to_paste_the_full_secret(block):
    assert "Paste the FULL 52-character secret" in block
    assert "public prefix alone is NOT the credential" in block


def test_engine_enforces_the_identical_format_gate():
    """Defense in depth: the wrapper is not the only gate."""
    with open(os.path.join(_SCRIPTS, "g1_r6_phase_b_exact28_recovery.py"),
              encoding="utf-8") as fh:
        engine = fh.read()
    assert r'INGEST_KEY_PATTERN = r"^nvx_[0-9a-f]{48}$"' in engine
    assert "def assert_ingest_credential(" in engine
    assert engine.index("assert_ingest_credential(client)") < engine.index(
        'report["canary_delivery"]')
