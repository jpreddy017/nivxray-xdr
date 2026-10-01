"""ADR-0004 · MITRE Attribution Accuracy · Shape Discriminator.

Distinguishes:
  A · PowerShell string-XOR obfuscation  →  T1027.010 (+ T1140 if key recovered)
  B · True RC4 stream cipher              →  T1027.013
  C · Ambiguous                           →  no RC4/shellcode attribution

Deterministic. Read-only. No decoders. No engines. No Workspace calls.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional


# PowerShell integer-array + inline XOR pipeline.
# Requires: powershell/pwsh command head, integer-array literal,
# -bxor operator, character conversion, and IEX-style pipeline.
_POWERSHELL_HEAD = re.compile(r"\b(?:powershell|pwsh)\b", re.IGNORECASE)
_INT_ARRAY = re.compile(r"\(\s*[\d][\d,\s]{6,}[\d]\s*\)")
_BXOR = re.compile(r"-\s*b?xor", re.IGNORECASE)
_CHAR_CAST = re.compile(r"\[\s*char\s*\]", re.IGNORECASE)
_IEX_STYLE = re.compile(r"invoke\s*-\s*expression|\biex\b", re.IGNORECASE)
_BXOR_HEX_KEY = re.compile(r"-\s*b?xor\s*'?\s*(0x[0-9a-f]{1,4})'?", re.IGNORECASE)

# True RC4 signal — presence of an RC4-specific op name in the chain
# or documented RC4 key-schedule / PRGA construction indicators. In
# NivXForge we key off explicit op names because we do not modify the
# Workspace decoder.
_RC4_OP_NAMES = frozenset({
    "rc4-inline-decrypt", "rc4-decrypt", "rc4",
})


@dataclass(frozen=True)
class Attribution:
    """The output of the discriminator — a set of MITRE IDs and the shape label."""
    shape: str                       # "A_powershell_xor" | "B_true_rc4" | "C_ambiguous"
    mitre_ids: List[str] = field(default_factory=list)
    recovered_xor_key: Optional[str] = None
    reasons: List[str] = field(default_factory=list)


def classify(input_text: str, *, chain_ops: Optional[List[str]] = None) -> Attribution:
    """Return the MITRE attribution for a given artifact.

    Args:
        input_text: The raw artifact (script, command line, or decoder input).
        chain_ops: Optional list of already-executed decoder op names.
    """
    chain_ops = [str(x).lower() for x in (chain_ops or [])]

    # Shape B — true RC4 is the strongest signal; check first.
    if any(op in _RC4_OP_NAMES for op in chain_ops):
        return Attribution(
            shape="B_true_rc4",
            mitre_ids=["T1027.013"],
            reasons=[f"chain contains RC4 op: {sorted(set(chain_ops) & _RC4_OP_NAMES)}"],
        )

    # Shape A — PowerShell string-XOR pipeline invariants.
    has_ps_head = bool(_POWERSHELL_HEAD.search(input_text or ""))
    has_int_array = bool(_INT_ARRAY.search(input_text or ""))
    has_bxor = bool(_BXOR.search(input_text or ""))
    has_char = bool(_CHAR_CAST.search(input_text or ""))
    has_iex = bool(_IEX_STYLE.search(input_text or ""))

    if has_ps_head and has_int_array and has_bxor and has_char and has_iex:
        key_match = _BXOR_HEX_KEY.search(input_text or "")
        recovered_key = key_match.group(1) if key_match else None
        mitre_ids = ["T1027.010"]
        if recovered_key:
            mitre_ids.append("T1140")
        reasons = [
            "powershell command head present",
            "integer-array literal present",
            "-bxor operator present",
            "[char] conversion present",
            "Invoke-Expression / IEX pipeline present",
        ]
        if recovered_key:
            reasons.append(f"XOR key recovered: {recovered_key}")
        return Attribution(
            shape="A_powershell_xor",
            mitre_ids=mitre_ids,
            recovered_xor_key=recovered_key,
            reasons=reasons,
        )

    # Shape C — insufficient evidence for A or B.
    return Attribution(
        shape="C_ambiguous",
        mitre_ids=[],
        reasons=["no A/B invariants satisfied"],
    )
