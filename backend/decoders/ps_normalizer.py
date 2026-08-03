"""RC4.3 · PowerShell Normalization & Runtime Reconstruction (Feb 2026).

Deterministically mimics PowerShell's argument-parsing stage before execution:

  * Normalizes comma-token separators to spaces (only outside quoted strings)
  * Canonicalizes `powershell.exe` casing
  * Canonicalizes parameter names case-insensitively
    (`-NoPrOfIlE` → `-NoProfile`, `-ExEcUtIoNpOlIcY` → `-ExecutionPolicy`,
     `ByPaSs` → `Bypass`, `-CoMmAnD` → `-Command`, ...)
  * Preserves quoted payloads exactly
  * If the payload is a safe built-in (`Write-Host`, `Write-Output`, `Echo`,
    `Out-Host`), emits a deterministic "Runtime Output (Simulation)".
  * Never emulates Invoke-Expression, external binaries, network,
    registry, process-creation, or anything dangerous.

Zero LLM. Zero heuristics. Zero invented output.
"""
from __future__ import annotations
import base64
import binascii
import re
from typing import Any, Dict, List, Tuple
from operations import op


# ── Parameter canonicalization map ────────────────────────────────
_CANONICAL_PARAMS = {
    "noprofile": "-NoProfile",
    "noninteractive": "-NonInteractive",
    "nologo": "-NoLogo",
    "noexit": "-NoExit",
    "executionpolicy": "-ExecutionPolicy",
    "command": "-Command",
    "encodedcommand": "-EncodedCommand",
    "enc": "-EncodedCommand",
    "windowstyle": "-WindowStyle",
    "w": "-WindowStyle",
    "file": "-File",
    "inputformat": "-InputFormat",
    "outputformat": "-OutputFormat",
    "psconsolefile": "-PSConsoleFile",
    "version": "-Version",
    "sta": "-STA",
    "mta": "-MTA",
}
_CANONICAL_VALUES = {
    "bypass": "Bypass",
    "unrestricted": "Unrestricted",
    "restricted": "Restricted",
    "remotesigned": "RemoteSigned",
    "allsigned": "AllSigned",
    "hidden": "Hidden",
    "normal": "Normal",
    "minimized": "Minimized",
    "maximized": "Maximized",
}
_CANONICAL_EXE = {
    "powershell.exe": "powershell.exe",
    "powershell": "powershell.exe",
    "pwsh.exe":      "pwsh.exe",
    "pwsh":          "pwsh.exe",
    "cmd.exe":       "cmd.exe",
    "cmd":           "cmd.exe",
}


# ── Quote-aware tokenizer ─────────────────────────────────────────
def _tokenize(cmd: str) -> List[Tuple[str, str]]:
    """Return list of (kind, value). kind ∈ {'quoted', 'raw', 'sep'}.
    Preserves quoted strings verbatim (single or double)."""
    tokens: List[Tuple[str, str]] = []
    i = 0
    n = len(cmd)
    while i < n:
        c = cmd[i]
        if c in ('"', "'"):
            # Find matching close quote — handle escaped `` and doubled quotes
            j = i + 1
            while j < n:
                if cmd[j] == "`" and j + 1 < n:
                    j += 2; continue
                if cmd[j] == c:
                    if j + 1 < n and cmd[j + 1] == c:  # doubled = literal
                        j += 2; continue
                    break
                j += 1
            tokens.append(("quoted", cmd[i:j + 1]))
            i = j + 1
        elif c in (" ", "\t", ","):
            # Comma acts as separator ONLY outside quotes (already handled)
            tokens.append(("sep", " "))
            i += 1
        else:
            j = i
            while j < n and cmd[j] not in (" ", "\t", ",", '"', "'"):
                j += 1
            tokens.append(("raw", cmd[i:j]))
            i = j
    return tokens


def _normalize_exe(tok: str) -> str:
    low = tok.lower()
    return _CANONICAL_EXE.get(low, tok)


def _normalize_param(tok: str) -> str:
    if not tok.startswith("-"):
        return tok
    key = tok[1:].lower()
    return _CANONICAL_PARAMS.get(key, "-" + tok[1:])  # keep original casing rules


def _normalize_value(tok: str) -> str:
    low = tok.lower()
    return _CANONICAL_VALUES.get(low, tok)


# ── Safe built-in simulator ───────────────────────────────────────
_SAFE_BUILTINS = {"write-host", "write-output", "echo", "out-host"}


def _simulate_safe_builtin(payload: str) -> str | None:
    """If the payload is a single safe built-in with a literal string argument,
    return the deterministic output. Otherwise None."""
    # Strip outer quotes if the payload is one quoted string
    p = payload.strip()
    if (p.startswith('"') and p.endswith('"')) or (p.startswith("'") and p.endswith("'")):
        p = p[1:-1]
    m = re.match(r"^\s*(Write-Host|Write-Output|Echo|Out-Host)\s+(.+?)\s*$", p,
                  re.IGNORECASE | re.DOTALL)
    if not m:
        return None
    cmd = m.group(1).lower()
    arg = m.group(2).strip()
    # Only accept a SINGLE literal string argument (single or double quoted)
    lit_m = re.match(r"""^(['"])(.*)\1\s*$""", arg, re.DOTALL)
    if not lit_m:
        return None
    literal = lit_m.group(2)
    # De-double the quote character if PowerShell escaping is used
    q = lit_m.group(1)
    literal = literal.replace(q + q, q)
    # De-backtick common escapes
    literal = literal.replace("`n", "\n").replace("`t", "\t").replace("`r", "\r")
    if cmd in _SAFE_BUILTINS:
        return literal
    return None


# ── Main op ───────────────────────────────────────────────────────
@op("powershell-normalize",
    "PowerShell command-line normalizer + runtime simulator",
    "Semantic Evaluation",
    "Deterministically emulates PowerShell's argument parsing stage before "
    "execution. Normalizes mixed-case executable and parameter names, converts "
    "comma-separated token obfuscation to spaces (outside quoted strings), "
    "canonicalizes execution-policy values, and — for safe built-ins like "
    "Write-Host / Write-Output / Echo / Out-Host — produces a deterministic "
    "Runtime Output (Simulation). Never emulates Invoke-Expression, external "
    "binaries, network activity, or anything with side effects.",
    # v1.5.3 · accepts-contract declaration. This op is a text
    # transform on PowerShell / cmd source; it MUST NOT run on binary
    # artefacts (shellcode, gzip bytes, PE images) because it will
    # silently rewrite them into a "normalised" text string and
    # corrupt every downstream decoder in the recipe.
    accepts=["powershell_script", "cmd_script", "text"])
def op_powershell_normalize(data: str, args: Dict[str, Any] | None = None) -> str:
    src = (data or "").strip()
    if not src:
        return "(powershell-normalize · empty input)"

    tokens = _tokenize(src)
    # Squash multi-seps
    flat: List[Tuple[str, str]] = []
    prev_sep = False
    for k, v in tokens:
        if k == "sep":
            if prev_sep:
                continue
            prev_sep = True
        else:
            prev_sep = False
        flat.append((k, v))

    # Build normalized command
    trace: List[str] = []
    out_parts: List[str] = []
    exe_seen = False
    for idx, (k, v) in enumerate(flat):
        if k == "sep":
            out_parts.append(" ")
            continue
        if k == "quoted":
            out_parts.append(v)
            continue
        # k == 'raw'
        if not exe_seen:
            new = _normalize_exe(v)
            if new != v:
                trace.append(f"exe: '{v}' → '{new}'")
            out_parts.append(new)
            exe_seen = True
            continue
        if v.startswith("-"):
            new = _normalize_param(v)
            if new != v:
                trace.append(f"param: '{v}' → '{new}'")
            out_parts.append(new)
        else:
            new = _normalize_value(v)
            if new != v:
                trace.append(f"value: '{v}' → '{new}'")
            out_parts.append(new)

    reconstructed = "".join(out_parts).strip()
    # Detect if any comma-normalization actually happened
    if "," in src and "," not in reconstructed:
        trace.insert(0, "comma-token-separator: `,` → ` ` (outside quoted strings)")

    # Try to simulate safe built-in output when the -Command payload is a
    # simple string literal argument.
    sim: str | None = None
    m_cmd = re.search(r"""-Command\s+(?P<q>['"])(?P<payload>.*)(?P=q)\s*$""",
                       reconstructed, re.IGNORECASE | re.DOTALL)
    if m_cmd:
        sim = _simulate_safe_builtin(m_cmd.group("payload"))

    # ARB PR-2.1 · Governance Rule 12 · Canonical Artifact Consistency.
    # Also handle -EncodedCommand <base64>: decode UTF-16LE per Microsoft's
    # docs and run the same safe-builtin simulator on the decoded payload.
    # Without this branch the normalizer would emit a "not attempted"
    # message even for benign encoded payloads like Write-Host "hello",
    # producing a wrapper-only view that Rule 12 explicitly forbids.
    encoded_decoded: str | None = None
    if sim is None:
        m_enc = re.search(
            r"""-EncodedCommand\s+(?P<b64>[A-Za-z0-9+/=]{4,})\s*$""",
            reconstructed,
            re.IGNORECASE,
        )
        if m_enc:
            b64 = m_enc.group("b64")
            try:
                # Standard PowerShell EncodedCommand is base64 of UTF-16LE.
                raw = base64.b64decode(b64 + "=" * (-len(b64) % 4),
                                        validate=False)
                decoded = raw.decode("utf-16-le")
                encoded_decoded = decoded
                sim = _simulate_safe_builtin(decoded)
            except (binascii.Error, UnicodeDecodeError, ValueError):
                # Malformed / mis-encoded payload — let downstream
                # decoders surface the error instead of pretending here.
                encoded_decoded = None

    # Banner
    lines = ["▼ POWERSHELL NORMALIZATION & RUNTIME RECONSTRUCTION (RC4.3 · deterministic)"]
    if trace:
        lines.append("Normalization steps:")
        for i, s in enumerate(trace, 1):
            lines.append(f"  Step {i}: {s}")
    lines.append("")
    # ── ARB Canonical Artifact Contract (Rule 12) ──────────────────────
    # Once -EncodedCommand is successfully decoded, the decoded payload
    # BECOMES the primary Reconstructed Command. The base64 wrapper is
    # retained below as *supporting evidence*, not as the canonical
    # artifact. This aligns Auto Investigate with the Decode button:
    # both surfaces present the decoded payload as the primary command.
    if encoded_decoded is not None:
        lines.append("Reconstructed Command (canonical · post-decode):")
        for L in encoded_decoded.splitlines() or [encoded_decoded]:
            lines.append(f"  {L}")
        lines.append("")
        lines.append("Wrapper Evidence (retained for context · T1027.010):")
        lines.append(f"  {reconstructed}")
    else:
        lines.append("Reconstructed Command:")
        lines.append(f"  {reconstructed}")
    lines.append("")
    if sim is not None:
        lines.append("Runtime Output (Simulation · deterministic):")
        for L in sim.splitlines() or [sim]:
            lines.append(f"  {L}")
        lines.append("")
        # ── ARB Governance Rule 13 · Evidence-backed behavior claims ──
        # Only surface a behavior line when the corresponding evidence
        # was actually observed. Never claim "Mixed-case obfuscation"
        # on a normal-cased input, "Comma-separated token obfuscation"
        # without a comma-splice step, or "Case-insensitive normalization"
        # without a case-normalize step in the trace.
        _obs_mixed_case = any("mixed-case" in t.lower() or "casing" in t.lower() for t in trace)
        _obs_comma      = any("comma" in t.lower() for t in trace)
        _obs_case_norm  = any("case" in t.lower() for t in trace)
        _behaviors: list[str] = []
        if _obs_mixed_case:
            _behaviors.append("  · Mixed-case obfuscation")
        if _obs_comma:
            _behaviors.append("  · Comma-separated token obfuscation")
        if _obs_case_norm and not _obs_mixed_case:
            _behaviors.append("  · Case-insensitive PowerShell normalization")
        if encoded_decoded is not None:
            _behaviors.append("  · Base64 UTF-16LE EncodedCommand wrapper (T1027.010)")
        _behaviors.append("  · Safe built-in — no malicious behavior")
        lines.append("Behavior:")
        lines.extend(_behaviors)
    else:
        lines.append("Runtime Output (Simulation): "
                      "not attempted — payload is not a safe built-in "
                      "(Write-Host / Write-Output / Echo / Out-Host with a "
                      "single literal string argument).")
    return "\n".join(lines) + "\n"
