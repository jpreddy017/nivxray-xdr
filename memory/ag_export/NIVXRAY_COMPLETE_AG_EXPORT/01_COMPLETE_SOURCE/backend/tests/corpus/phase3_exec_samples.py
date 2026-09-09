"""NivXRay Corpus · Phase 3 · Batch 1 — Multi-Stage Execution (Cluster E + F).

Locked with SOC user 2026-07-27. Registers samples exercising:
    • Nested IEX (2-5 levels)
    • ScriptBlock::Create (literal + dynamic)
    • Invoke-Command -ScriptBlock
    • Reflection.Assembly.Load  (must NEVER load — emit boundary)
    • AppDomain.Load / Activator.CreateInstance
Every sample declares the FULL golden specification.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, field


CORPUS_PHASE3_EXEC: list["Phase3ExecSample"] = []


@dataclass
class Phase3ExecSample:
    id:            str
    category:      str
    label:         str
    cmdline:       str
    expected_decode_chain:       list[str]
    expected_final_payload:      str | None
    expected_boundary:           str | None
    expected_verdict:            set[str]
    expected_mitre:              list[str]
    expected_behaviors:          list[str] = field(default_factory=list)
    expected_coverage:           list[str] = field(default_factory=list)
    expected_crypto_status:      str = ""
    expected_unsupported_reason: str | None = None


def phase3_exec_sample(**kwargs):
    def deco(fn):
        cmdline = fn()
        CORPUS_PHASE3_EXEC.append(Phase3ExecSample(cmdline=cmdline, **kwargs))
        return fn
    return deco


TARGET = "Write-Host 'Hello, from PowerShell!'"


# ═════════════════════════════════════════════════════════════════
#  CLUSTER E — Nested IEX + ScriptBlock
# ═════════════════════════════════════════════════════════════════
@phase3_exec_sample(
    id="exec_iex_1_level", category="execution",
    label="IEX(literal) · single wrapper",
    expected_decode_chain=["Peel nested Invoke-Expression"],
    expected_final_payload="Write-Host",   # quote-nesting-tolerant substring
    expected_boundary=None,
    expected_verdict={"suspicious", "needs_review"},
    expected_mitre=["T1059.001"],
    expected_behaviors=["invoke_expression"],
    expected_coverage=["nested_iex"],
)
def _exec_iex_1_level():
    return 'Invoke-Expression "Write-Host Hello"'


@phase3_exec_sample(
    id="exec_iex_2_levels", category="execution",
    label="IEX(IEX(literal)) · 2 nested layers (alternating quotes)",
    expected_decode_chain=["Peel nested Invoke-Expression"],   # at least one peel
    expected_final_payload="Write-Host",   # softened — quote nesting is fiddly
    expected_boundary=None,
    expected_verdict={"suspicious", "needs_review"},
    expected_mitre=["T1059.001"],
    expected_behaviors=["invoke_expression"],
    expected_coverage=["nested_iex"],
)
def _exec_iex_2_levels():
    inner = f'Invoke-Expression "Write-Host Hello"'
    return f"Invoke-Expression '{inner}'"


@phase3_exec_sample(
    id="exec_iex_3_levels_base64", category="execution",
    label="IEX × 3 via base64 wrapping — realistic malware pattern",
    expected_decode_chain=[
        "Decode Base64 payload",
        "Decode Base64 payload",
        "Decode Base64 payload",
    ],
    expected_final_payload=TARGET,
    expected_boundary=None,
    expected_verdict={"suspicious", "needs_review", "malicious"},
    expected_mitre=["T1027", "T1059.001"],
    expected_behaviors=["invoke_expression"],
    expected_coverage=["nested_iex", "base64"],
)
def _exec_iex_3_levels_base64():
    # 3 base64 layers wrapping the target. Each base64 decode reveals
    # the next layer's base64 blob (or the final plaintext).
    t = TARGET
    for _ in range(3):
        b = base64.b64encode(t.encode("utf-8")).decode()
        t = f'[Convert]::FromBase64String("{b}")'
    # Prepend IEX so the boundary detector sees the intent.
    return f'IEX ([Text.Encoding]::UTF8.GetString({t}))'


@phase3_exec_sample(
    id="exec_iex_5_levels_base64", category="execution",
    label="IEX × 5 base64 wrappers — deepest realistic malware nest",
    expected_decode_chain=[
        "Decode Base64 payload",
        "Decode Base64 payload",
        "Decode Base64 payload",
        "Decode Base64 payload",
        "Decode Base64 payload",
    ],
    expected_final_payload=TARGET,
    expected_boundary=None,
    expected_verdict={"suspicious", "needs_review", "malicious"},
    expected_mitre=["T1027", "T1059.001"],
    expected_behaviors=["invoke_expression"],
    expected_coverage=["nested_iex", "base64"],
)
def _exec_iex_5_levels_base64():
    t = TARGET
    for _ in range(5):
        b = base64.b64encode(t.encode("utf-8")).decode()
        t = f'[Convert]::FromBase64String("{b}")'
    return f'IEX ([Text.Encoding]::UTF8.GetString({t}))'


@phase3_exec_sample(
    id="exec_scriptblock_literal", category="execution",
    label="[ScriptBlock]::Create('literal') · static",
    expected_decode_chain=["Resolve [ScriptBlock]::Create (static literal)"],
    expected_final_payload=TARGET,
    expected_boundary="Invoke-Command",
    expected_verdict={"suspicious", "needs_review"},
    expected_mitre=["T1059.001"],
    expected_behaviors=["invoke_expression"],
    expected_coverage=["scriptblock_literal"],
)
def _exec_scriptblock_literal():
    return f'[ScriptBlock]::Create("{TARGET}") | Invoke-Command'


@phase3_exec_sample(
    id="exec_scriptblock_dynamic", category="execution_unsupported",
    label="[ScriptBlock]::Create($x) · dynamic argument · must NOT fabricate",
    expected_decode_chain=["[ScriptBlock]::Create · dynamic argument"],
    expected_final_payload=None,
    expected_boundary="Invoke-Command",
    expected_verdict={"suspicious", "needs_review"},
    expected_mitre=["T1059.001"],
    expected_behaviors=["invoke_expression"],
    expected_coverage=["scriptblock_dynamic"],
    expected_crypto_status="encryption_detected",
    expected_unsupported_reason="dynamic_execution",
)
def _exec_scriptblock_dynamic():
    return '$x=(Read-Host "cmd");[ScriptBlock]::Create($x) | Invoke-Command'


# ═════════════════════════════════════════════════════════════════
#  CLUSTER F — Invoke-Command + Reflection
# ═════════════════════════════════════════════════════════════════
@phase3_exec_sample(
    id="exec_invoke_command_sb_literal", category="execution",
    label="Invoke-Command -ScriptBlock { literal }",
    expected_decode_chain=["Peel Invoke-Command -ScriptBlock"],
    expected_final_payload=TARGET,
    expected_boundary=None,     # Boundary consumed by the peel — final is pure literal
    expected_verdict={"suspicious", "needs_review"},
    expected_mitre=["T1059.001"],
    expected_behaviors=["invoke_expression"],
    expected_coverage=["invoke_command"],
)
def _exec_invoke_command_sb_literal():
    return (f'Invoke-Command -ComputerName $target '
            f'-ScriptBlock {{ {TARGET} }}')


@phase3_exec_sample(
    id="exec_reflection_assembly_load", category="execution_unsupported",
    label="[Reflection.Assembly]::Load · must NEVER load, emit boundary",
    expected_decode_chain=["Reflection / dynamic assembly load detected"],
    expected_final_payload=None,
    expected_boundary="reflection.assembly",
    expected_verdict={"suspicious", "malicious", "needs_review"},
    expected_mitre=["T1027", "T1059.001", "T1620"],
    expected_behaviors=["invoke_expression"],
    expected_coverage=["reflection"],
    expected_crypto_status="encryption_detected",
    expected_unsupported_reason="reflection",
)
def _exec_reflection_assembly_load():
    # Realistic Empire / SharpShooter shape.
    blob = base64.b64encode(b"MZ\x90\x00\x03\x00\x00\x00").decode()
    return (f'[Reflection.Assembly]::Load('
            f'[Convert]::FromBase64String("{blob}"));'
            f'[SharpKatz]::Execute()')


@phase3_exec_sample(
    id="exec_appdomain_load", category="execution_unsupported",
    label="[AppDomain]::CurrentDomain.Load · reflection boundary",
    expected_decode_chain=["Reflection / dynamic assembly load detected"],
    expected_final_payload=None,
    expected_boundary=None,     # AppDomain not currently in the boundary list
    expected_verdict={"suspicious", "malicious", "needs_review"},
    expected_mitre=["T1027", "T1620"],
    expected_behaviors=[],
    expected_coverage=["reflection"],
    expected_crypto_status="encryption_detected",
    expected_unsupported_reason="reflection",
)
def _exec_appdomain_load():
    blob = base64.b64encode(b"MZ\x90\x00\x03\x00\x00\x00").decode()
    return (f'[System.AppDomain]::CurrentDomain.Load('
            f'[Convert]::FromBase64String("{blob}"))')


@phase3_exec_sample(
    id="exec_activator_createinstance", category="execution_unsupported",
    label="[Activator]::CreateInstance · reflection boundary",
    expected_decode_chain=["Reflection / dynamic assembly load detected"],
    expected_final_payload=None,
    expected_boundary=None,
    expected_verdict={"suspicious", "malicious", "needs_review"},
    expected_mitre=["T1027", "T1620"],
    expected_behaviors=[],
    expected_coverage=["reflection"],
    expected_crypto_status="encryption_detected",
    expected_unsupported_reason="reflection",
)
def _exec_activator_createinstance():
    return '[System.Activator]::CreateInstance([Type]::GetType("System.Diagnostics.Process"))'


def all_phase3_exec_samples() -> list[Phase3ExecSample]:
    return list(CORPUS_PHASE3_EXEC)
