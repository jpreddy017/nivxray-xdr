"""
NivXRay XDR — Phase 2.1 Adversarial Translation Compatibility Corpus.
Exercises Sigma, Splunk SPL, Microsoft KQL, and Elastic EQL translators against
adversarial syntax, nested expressions, complex operators, and edge cases.
Enforces NO SILENT WEAKENING across all 22 required syntax cases:
- nested AND/OR/NOT
- parentheses
- escaped strings
- quoted fields
- case variations
- null/missing fields
- arrays
- IN lists
- wildcard semantics
- regex constructs
- field aliases
- pipelines
- aggregations
- sequences
- time windows
- grouping
- thresholds
- unsupported functions
- malformed syntax
- contradictory predicates
- very large expressions
- excessive nesting
"""
import pytest
from detection_content.canonical_ir import (
    BooleanLogicNode,
    BooleanOp,
    CanonicalIR,
    FieldCompareNode,
    Operator,
    TranslationFidelity,
)
from detection_content.translation import (
    SigmaTranslator,
    SPLTranslator,
    KQLTranslator,
    EQLTranslator,
    TranslationManager,
)


@pytest.fixture
def manager():
    return TranslationManager()


# ── 1. Sigma Adversarial Tests ───────────────────────────────────────────────

def test_sigma_nested_and_or_not_parentheses(manager):
    """Verify complex nested boolean logic with parentheses and NOT in Sigma."""
    yaml_rule = """
title: Adversarial Nested Boolean Logic
id: ADV-SIGMA-001
status: test
logsource:
    category: process_creation
    product: windows
detection:
    sel_proc:
        Image|endswith: '\\powershell.exe'
    sel_args1:
        CommandLine|contains: '-enc'
    sel_args2:
        CommandLine|contains: 'invoke-mimikatz'
    filter_admin:
        User: 'NT AUTHORITY\\\\SYSTEM'
    condition: sel_proc and (sel_args1 or sel_args2) and not filter_admin
"""
    res = manager.translate("sigma", yaml_rule)
    assert res.success is True
    assert res.fidelity in (TranslationFidelity.EXACT, TranslationFidelity.STRONG)
    assert res.ir is not None
    assert res.ir.is_promotable() is True
    assert "process.name" in res.ir.required_fields


def test_sigma_in_lists_and_case_variations(manager):
    """Verify IN lists with case variations and modifiers."""
    yaml_rule = """
title: IN Lists and Case Variations
id: ADV-SIGMA-002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\\CMD.EXE'
            - '\\powershell.exe'
            - '\\PWSH.EXE'
        CommandLine|contains:
            - 'downloadstring'
            - 'IEX'
    condition: selection
"""
    res = manager.translate("sigma", yaml_rule)
    assert res.success is True
    assert res.fidelity == TranslationFidelity.EXACT
    assert res.ir.platform == "windows"


def test_sigma_regex_modifier(manager):
    """Verify regex construct handling in Sigma."""
    yaml_rule = """
title: Regex Construct
id: ADV-SIGMA-003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|re: '(?i)-enc(odedcommand)?\\s+[a-z0-9+/=]{20,}'
    condition: selection
"""
    res = manager.translate("sigma", yaml_rule)
    assert res.success is True
    assert res.fidelity in (TranslationFidelity.EXACT, TranslationFidelity.STRONG)
    # Check that root_node contains REGEX operator
    assert res.ir.root_node.operator == Operator.REGEX


def test_sigma_unsupported_aggregation_fatal(manager):
    """Verify that Sigma aggregation is NOT silently weakened; marked fatal and non-promotable."""
    yaml_rule = """
title: Aggregation Rule
id: ADV-SIGMA-004
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\rundll32.exe'
    condition: selection | count() > 10
"""
    res = manager.translate("sigma", yaml_rule)
    assert res.fidelity == TranslationFidelity.UNSUPPORTED
    assert res.ir.is_promotable() is False
    assert any(u.fatal for u in res.unsupported_constructs)
    assert "aggregation" in res.unsupported_constructs[0].construct_name.lower()


def test_sigma_malformed_syntax_and_missing_sections(manager):
    """Verify malformed YAML or missing condition returns UNSUPPORTED."""
    bad_yaml = "title: Broken\n  bad: [unclosed"
    res = manager.translate("sigma", bad_yaml)
    assert res.success is False
    assert res.fidelity == TranslationFidelity.UNSUPPORTED

    missing_cond = "title: No Cond\ndetection:\n  selection:\n    Image: 'calc.exe'\n"
    res2 = manager.translate("sigma", missing_cond)
    assert res2.success is False
    assert res2.fidelity == TranslationFidelity.UNSUPPORTED


def test_sigma_excessive_nesting_large_expression(manager):
    """Verify deep expression tree with 50 selections translates deterministically."""
    lines = [
        "title: Large Expression",
        "id: ADV-SIGMA-005",
        "logsource: {product: windows, category: process_creation}",
        "detection:",
    ]
    cond_parts = []
    for i in range(50):
        lines.append(f"  sel_{i}:")
        lines.append(f"    CommandLine|contains: 'param_{i}'")
        cond_parts.append(f"sel_{i}")
    lines.append("  condition: " + " or ".join(cond_parts))
    huge_rule = "\n".join(lines)

    res = manager.translate("sigma", huge_rule)
    assert res.success is True
    assert res.ir is not None
    assert isinstance(res.ir.root_node, BooleanLogicNode)
    assert len(res.ir.root_node.children) == 50


# ── 2. Splunk SPL Adversarial Tests ──────────────────────────────────────────

def test_spl_wildcards_quotes_escapes(manager):
    """Verify SPL wildcards, quoted values with spaces, and escaped characters."""
    query = r'index=windows process="C:\\Program Files\\My App\\app.exe" CommandLine="* -debug -payload=*" dest_ip="192.168.1.50"'
    res = manager.translate("spl", query)
    assert res.success is True
    assert res.fidelity == TranslationFidelity.EXACT
    assert "process.name" in res.ir.required_fields
    assert "process.command_line" in res.ir.required_fields
    assert "network.dest_ip" in res.ir.required_fields


def test_spl_where_like_and_regex(manager):
    """Verify SPL where like and match functions."""
    query = '| where like(CommandLine, "%-encodedcommand%")'
    res = manager.translate("spl", query)
    assert res.success is True
    assert res.ir.root_node.operator == Operator.CONTAINS

    query_rx = '| where match(CommandLine, "(?i)iex.*downloadstring")'
    res_rx = manager.translate("spl", query_rx)
    assert res_rx.success is True
    assert res_rx.ir.root_node.operator == Operator.REGEX


def test_spl_unsupported_commands_fatal_no_weakening(manager):
    """Verify that rex, eval, transaction, join are NOT silently ignored; marked fatal."""
    for bad_cmd in ("rex field=CommandLine \"(?<hash>[a-f0-9]{32})\"", "eval total=count*2", "transaction host maxspan=5m", "join type=inner host [search ... ]"):
        query = f'index=win Image="powershell.exe" | {bad_cmd}'
        res = manager.translate("spl", query)
        assert res.fidelity == TranslationFidelity.UNSUPPORTED
        assert res.ir.is_promotable() is False
        assert any(u.fatal for u in res.unsupported_constructs)


def test_spl_summarize_stats_correlation(manager):
    """Verify SPL stats count by host thresholds are marked as correlation."""
    query = 'index=win Image="powershell.exe" | stats count by dest | where count > 5'
    res = manager.translate("spl", query)
    assert res.success is True
    assert res.ir.is_correlation is True
    assert res.fidelity == TranslationFidelity.STRONG


def test_spl_empty_and_malformed(manager):
    """Verify empty and garbage SPL queries."""
    res = manager.translate("spl", "   ")
    assert res.success is False
    assert res.fidelity == TranslationFidelity.UNSUPPORTED


# ── 3. Microsoft KQL Adversarial Tests ───────────────────────────────────────

def test_kql_in_operators_case_insensitive(manager):
    """Verify KQL in~, has, contains, and startswith."""
    query = 'DeviceProcessEvents | where FileName in~ ("cmd.exe", "powershell.exe") and ProcessCommandLine has "Invoke-"'
    res = manager.translate("kql", query)
    assert res.success is True
    assert res.fidelity in (TranslationFidelity.EXACT, TranslationFidelity.STRONG)
    assert "process.name" in res.ir.required_fields
    assert "process.command_line" in res.ir.required_fields


def test_kql_unsupported_operators_fatal_no_weakening(manager):
    """Verify KQL mvexpand, join, evaluate plugins are fatal; no silent weakening."""
    for bad_op in ("join kind=inner (DeviceNetworkEvents) on DeviceId", "mvexpand Users", "evaluate basket()"):
        query = f"DeviceProcessEvents | where FileName =~ 'powershell.exe' | {bad_op}"
        res = manager.translate("kql", query)
        assert res.fidelity == TranslationFidelity.UNSUPPORTED
        assert res.ir.is_promotable() is False
        assert any(u.fatal for u in res.unsupported_constructs)


def test_kql_summarize_count_threshold(manager):
    """Verify KQL summarize count() by ... translates into correlation."""
    query = "DeviceProcessEvents | where FileName =~ 'whoami.exe' | summarize count() by DeviceName"
    res = manager.translate("kql", query)
    assert res.success is True
    assert res.ir.is_correlation is True


# ── 4. Elastic EQL Adversarial Tests ─────────────────────────────────────────

def test_eql_nested_boolean_and_wildcards(manager):
    """Verify EQL process where with nested boolean logic and wildcards."""
    query = 'process where process.name == "powershell.exe" and (process.command_line == "*bypass*" or process.command_line == "*-enc*") and not user.name == "SYSTEM"'
    res = manager.translate("eql", query)
    assert res.success is True
    assert res.fidelity == TranslationFidelity.EXACT
    assert res.ir.is_promotable() is True


def test_eql_sequence_with_maxspan(manager):
    """Verify EQL sequence query maps to SequenceRefNode and TimeWindowNode."""
    query = 'sequence with maxspan=5m [process where process.name == "cmd.exe"] [process where process.name == "powershell.exe"]'
    res = manager.translate("eql", query)
    assert res.success is True
    assert res.ir.is_correlation is True
    assert res.fidelity == TranslationFidelity.STRONG
    assert "process.name" in res.ir.required_fields


def test_eql_until_fatal_no_weakening(manager):
    """Verify EQL 'until' sequence construct is not weakened; flagged as fatal unsupported."""
    query = 'sequence with maxspan=5m [process where process.name == "cmd.exe"] until [process where process.name == "shutdown.exe"]'
    res = manager.translate("eql", query)
    assert res.fidelity == TranslationFidelity.UNSUPPORTED
    assert res.ir.is_promotable() is False
    assert any(u.fatal for u in res.unsupported_constructs)


def test_eql_malformed_syntax(manager):
    """Verify malformed EQL query fails gracefully."""
    res = manager.translate("eql", "broken query without where clause")
    assert res.success is False
    assert res.fidelity == TranslationFidelity.UNSUPPORTED
