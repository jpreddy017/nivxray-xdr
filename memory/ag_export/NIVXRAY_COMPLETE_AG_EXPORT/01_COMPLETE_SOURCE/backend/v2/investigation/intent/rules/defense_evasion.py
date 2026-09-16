"""defense_evasion · the artefact takes deterministic steps to hide
from defensive tooling (AMSI bypass, ETW patch, Defender tamper,
execution policy bypass, hidden window).
"""
from __future__ import annotations

import re

from ...evidence import Evidence
from ..models import Intent, IntentCategory, RiskBand

_SIGNATURES: list[tuple[re.Pattern, str, str, RiskBand, str]] = [
    (
        re.compile(r"(?i)amsiInitFailed|amsi\s*\.\s*dll|amsiscanbuffer"),
        "AMSI bypass",
        "Disables Anti-Malware Scan Interface so subsequent script "
        "content is not inspected by AV / EDR.",
        RiskBand.HIGH,
        "T1562.001",
    ),
    (
        re.compile(r"(?i)EtwEventWrite|etw\s*\.\s*dll"),
        "ETW patch",
        "Patches Event Tracing for Windows to blind kernel-level "
        "telemetry collection.",
        RiskBand.HIGH,
        "T1562.006",
    ),
    (
        re.compile(r"(?i)Set-MpPreference|Add-MpPreference|"
                    r"Defender\s+.*(?:Disable|Exclusion)"),
        "Defender tamper",
        "Modifies Microsoft Defender policy (disable / add exclusion) "
        "to suppress detection of subsequent execution.",
        RiskBand.HIGH,
        "T1562.001",
    ),
    (
        re.compile(r"(?i)-ExecutionPolicy\s+(?:Bypass|Unrestricted)|"
                    r"-ep\s+(?:bypass|unrestricted)|-exec\s+bypass"),
        "Execution Policy bypass",
        "Runs PowerShell with `-ExecutionPolicy Bypass` so the "
        "script executes without policy checks.",
        RiskBand.MEDIUM,
        "T1059.001",
    ),
    (
        re.compile(r"(?i)-WindowStyle\s+Hidden|-w\s+Hidden|-noni|-noninteractive"),
        "Hidden window",
        "Runs the interpreter with a hidden / non-interactive window "
        "to avoid user awareness of the running process.",
        RiskBand.LOW,
        "T1564.003",
    ),
    (
        re.compile(r"(?i)\[Ref\]\.Assembly\.GetType|System\.Management\.Automation\.AmsiUtils"),
        "Reflective AmsiUtils tamper",
        "Reflects into `System.Management.Automation.AmsiUtils` to "
        "disable AMSI at runtime — the canonical AmsiBypass pattern.",
        RiskBand.HIGH,
        "T1562.001",
    ),
    # ── v1.5.2 · reflective in-memory shellcode injection primitives ──
    # These patterns are the canonical building blocks of every PowerShell
    # shellcode loader (Metasploit `windows/x64/meterpreter/*`, Cobalt
    # Strike Beacon PS stager, PowerSploit `Invoke-Shellcode`, Nishang
    # `Invoke-ReflectivePEInjection`, and every hand-rolled variant).
    # They are NOT sample-specific — they encode generic Windows-API and
    # .NET reflection capabilities that only make sense as unmanaged code
    # execution primitives.
    (
        # `VirtualAlloc(NULL, size, 0x3000, 0x40)` — the canonical
        # RWX allocation for shellcode staging. Also matches
        # `VirtualAllocEx` / any protection literal containing 0x40
        # (PAGE_EXECUTE_READWRITE) or 0x20 (PAGE_EXECUTE_READ). The
        # protection literal is often on a different line from the
        # `VirtualAlloc` name reference (which appears in the
        # GetProcAddress resolution) so the gap-matcher must be
        # multiline-tolerant but still bounded to prevent runaway
        # backtracking.
        re.compile(r"(?is)VirtualAlloc(?:Ex)?\b[\s\S]{0,400}?0x(?:40|20|60|80)\b"),
        "RWX shellcode allocation",
        "Allocates memory with EXECUTE + WRITE protection — the canonical "
        "staging step for in-memory shellcode. Benign scripts have no "
        "reason to request PAGE_EXECUTE_READWRITE.",
        RiskBand.HIGH,
        "T1055",
    ),
    (
        # `Marshal::GetDelegateForFunctionPointer` — creates a callable
        # .NET delegate from a raw pointer. In combination with
        # VirtualAlloc + Marshal.Copy this is the invoke half of the
        # inject-and-run primitive.
        re.compile(r"(?i)GetDelegateForFunctionPointer\s*\("),
        "Delegate-invoked function pointer",
        "Converts a raw pointer into a callable .NET delegate — the "
        "canonical unmanaged-code invocation primitive used by every "
        "reflective PowerShell shellcode loader.",
        RiskBand.HIGH,
        "T1055",
    ),
    (
        # PowerSploit's `func_get_proc_address` pattern: reaches into
        # `Microsoft.Win32.UnsafeNativeMethods` to reflectively resolve
        # a Win32 export (typically GetProcAddress → VirtualAlloc,
        # CreateThread, LoadLibrary, …). Not a normal-script pattern.
        re.compile(r"(?i)Microsoft\.Win32\.UnsafeNativeMethods"),
        "Reflective Win32 API resolution",
        "Reflects into `Microsoft.Win32.UnsafeNativeMethods` to resolve "
        "Win32 exports at runtime — the canonical PowerSploit / "
        "Metasploit stager reflection pattern.",
        RiskBand.HIGH,
        "T1055",
    ),
    (
        # `Marshal.Copy(byteArray, 0, IntPtr, len)` writing a byte
        # array into an unmanaged pointer previously returned by
        # VirtualAlloc — the shellcode copy step.
        re.compile(r"(?i)Marshal\s*(?:\]\s*::|::|\.)\s*Copy\s*\([^)]{0,120}?IntPtr"),
        "Shellcode copy to unmanaged memory",
        "Copies a managed byte array into an unmanaged buffer — combined "
        "with a prior RWX allocation this stages arbitrary machine code "
        "for in-process execution.",
        RiskBand.HIGH,
        "T1055",
    ),
    (
        # DynamicMethod / DefineDynamicAssembly with `Run` access — the
        # in-memory type / delegate builder scaffolding every reflective
        # loader emits. Combined with unmanaged execution primitives
        # this is a strong injection signal.
        re.compile(r"(?i)DefineDynamicAssembly\s*\([^)]{0,200}?AssemblyBuilderAccess\s*(?:\]\s*::|::|\.)\s*Run"),
        "In-memory dynamic assembly build",
        "Constructs a .NET assembly in memory with `Run` access — the "
        "canonical delegate-scaffold step of every reflective PowerShell "
        "shellcode loader.",
        RiskBand.MEDIUM,
        "T1055",
    ),
]


class DefenseEvasionRule:
    NAME = "defense_evasion"

    def detect(self, artefact_text: str, meta: dict) -> list[Intent]:
        text = artefact_text or ""
        intents: list[Intent] = []
        for pat, name, rationale, risk, tid in _SIGNATURES:
            m = pat.search(text)
            if not m:
                continue
            evidence = [Evidence(
                source="intent.defense_evasion",
                observation=m.group(0)[:120],
                confidence=90,
                rationale=rationale,
                meta={"signature": name, "mitre": tid},
            )]
            intents.append(Intent(
                category=IntentCategory.DEFENSE_EVASION,
                purpose=f"Evade defensive tooling via {name}.",
                risk=risk,
                rationale=rationale,
                evidence=evidence,
                confidence=90 if risk == RiskBand.HIGH else 80,
                mitre_ids=[tid],
            ))
        return intents


RULE = DefenseEvasionRule()
