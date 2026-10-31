"""NivXRay Corpus · Phase 3 · Batch 2 — Dynamic Invocation + Env-Var.

Locked with SOC user 2026-07-27. Covers Cluster G:
    • Dynamic method invocation (GetType().GetMethod().Invoke())
    • [Type]::GetType (literal + dynamic argument)
    • Environment-variable reconstruction (surface, never substitute)
"""
from __future__ import annotations

from dataclasses import dataclass, field


CORPUS_PHASE3_G: list["Phase3GSample"] = []


@dataclass
class Phase3GSample:
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
    expected_unsupported_component: str | None = None


def phase3g_sample(**kwargs):
    def deco(fn):
        CORPUS_PHASE3_G.append(Phase3GSample(cmdline=fn(), **kwargs))
        return fn
    return deco


TARGET = "Write-Host 'Hello, from PowerShell!'"


# ── Dynamic method invocation ────────────────────────────────────
@phase3g_sample(
    id="exec_dynamic_method_invoke", category="execution_unsupported",
    label="Dynamic reflection · GetType().GetMethod().Invoke()",
    expected_decode_chain=["Dynamic method invocation detected"],
    expected_final_payload=None,
    expected_boundary=None,
    expected_verdict={"suspicious", "needs_review"},
    expected_mitre=["T1620"],
    expected_behaviors=[],
    expected_coverage=["dynamic_invocation"],
    expected_crypto_status="encryption_detected",
    expected_unsupported_reason="dynamic_execution",
    expected_unsupported_component="dynamic_method_invocation",
)
def _exec_dynamic_method_invoke():
    return ('$asm=[Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms");'
            '$m=$asm.GetType().GetMethod("Show");$m.Invoke($null,@("Popup"))')


# ── [Type]::GetType — literal + dynamic ──────────────────────────
@phase3g_sample(
    id="exec_type_gettype_literal", category="execution",
    label="[Type]::GetType('literal') · static",
    expected_decode_chain=["Resolve [Type]::GetType (literal)"],
    expected_final_payload="System.Diagnostics.Process",
    expected_boundary=None,
    expected_verdict={"suspicious", "needs_review"},
    expected_mitre=["T1059.001"],
    expected_behaviors=[],
    expected_coverage=["type_gettype"],
)
def _exec_type_gettype_literal():
    return '$t=[Type]::GetType("System.Diagnostics.Process");$t::Start("cmd")'


@phase3g_sample(
    id="exec_type_gettype_dynamic", category="execution_unsupported",
    label="[Type]::GetType($x) · dynamic",
    expected_decode_chain=["[Type]::GetType · dynamic argument"],
    expected_final_payload=None,
    expected_boundary=None,
    expected_verdict={"suspicious", "needs_review"},
    expected_mitre=["T1027", "T1620"],
    expected_behaviors=[],
    expected_coverage=["type_gettype_dynamic"],
    expected_crypto_status="encryption_detected",
    expected_unsupported_reason="dynamic_execution",
    expected_unsupported_component="type_gettype",
)
def _exec_type_gettype_dynamic():
    return ('$x=(Read-Host "Type name");$t=[Type]::GetType($x);'
            '$t::CreateInstance()')


# ── Environment-variable reconstruction ──────────────────────────
@phase3g_sample(
    id="exec_env_var_localappdata", category="execution",
    label="Env-var reference · $env:LOCALAPPDATA in a path",
    expected_decode_chain=[],   # non-mutating detection
    expected_final_payload=None,
    expected_boundary=None,
    expected_verdict={"suspicious", "needs_review", "benign"},
    expected_mitre=[],
    expected_behaviors=[],
    expected_coverage=["env_var"],
    expected_unsupported_reason="environment_dependent",
    expected_unsupported_component="env_var_reconstruction",
)
def _exec_env_var_localappdata():
    return ('$dst = "$env:LOCALAPPDATA\\Microsoft\\Update\\payload.ps1";'
            '[IO.File]::WriteAllText($dst, "Write-Host running")')


@phase3g_sample(
    id="exec_env_var_getenvironmentvariable", category="execution",
    label="Env-var reference · [Environment]::GetEnvironmentVariable('PATH')",
    expected_decode_chain=[],
    expected_final_payload=None,
    expected_boundary=None,
    expected_verdict={"suspicious", "needs_review", "benign"},
    expected_mitre=[],
    expected_behaviors=[],
    expected_coverage=["env_var"],
    expected_unsupported_reason="environment_dependent",
    expected_unsupported_component="env_var_reconstruction",
)
def _exec_env_var_getenvironmentvariable():
    return ('$p=[Environment]::GetEnvironmentVariable("PATH");'
            'Write-Host $p')


def all_phase3g_samples() -> list[Phase3GSample]:
    return list(CORPUS_PHASE3_G)
