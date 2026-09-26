"""PowerShell / CMD wrapper extractor plugin.

Recognises common script wrappers and returns their inner payload:

    Wrapper                                          → extracts
    ─────────────────────────────────────────────────────────────
    [Byte[]]$x = [Convert]::FromBase64String('B64') → B64
    powershell -e[nc[odedCommand]] B64              → B64
    powershell -c "IEX (New-Object ...('URL'))"     → URL
    powershell -Command "..."                       → inner cmd
    cmd /c "..."                                    → inner cmd
    mshta vbscript:CreateObject("...")               → the vbscript body
    hta:application ... <script>...</script>        → the script body

Also emits MCIP intelligence signals when the wrapper matches a specific
technique (T1059.001 PowerShell, T1059.003 CMD, T1218.005 mshta, etc.).

This plugin has category="reconstruct" — it does not transform bytes, it
peels a syntactic wrapper. Highest priority in the orchestrator when a
wrapper is detected (fingerprint.wrapper_type is set by L0).
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

from engine.decoder_base import BaseDecoder
from engine.models import (
    AnalysisContext,
    DetectResult,
    Fingerprint,
    LolbasHit,
    MitreHint,
    PluginResult,
    TradecraftFlag,
)
from engine.registry import DecoderRegistry


# --------------------------------------------------------------------------- #
# Regex catalogue — hot-path, sorted by specificity
# --------------------------------------------------------------------------- #
_RX_FROM_B64 = re.compile(
    r"""\[?(?:System\.Convert|Convert)\]?::FromBase64String\(\s*['"]([^'"]+)['"]\s*\)""",
    re.IGNORECASE,
)
_RX_PS_ENCODED = re.compile(
    r"""(?:powershell(?:\.exe)?|pwsh)\s+[^\n]*?(?:-e(?:nc(?:oded)?(?:command)?)?)\s+([A-Za-z0-9+/=]{16,})""",
    re.IGNORECASE,
)
_RX_PS_CMD = re.compile(
    r"""(?:powershell(?:\.exe)?|pwsh)\s+[^\n]*?(?:-c(?:ommand)?)\s+['"]?(.+?)['"]?\s*$""",
    re.IGNORECASE | re.DOTALL,
)
_RX_CMD_C = re.compile(
    r"""\bcmd(?:\.exe)?\s+/[cCkK]\s+['"]?(.+?)['"]?\s*$""",
    re.IGNORECASE | re.DOTALL,
)
_RX_MSHTA_VBS = re.compile(
    r"""mshta(?:\.exe)?\s+["']?vbscript:(.+?)["']?\s*$""",
    re.IGNORECASE | re.DOTALL,
)
_RX_MSHTA_HTTP = re.compile(
    r"""mshta(?:\.exe)?\s+["']?(https?://\S+)["']?""",
    re.IGNORECASE,
)
_RX_DOWNLOAD_STRING = re.compile(
    r"""(?:DownloadString|DownloadFile|DownloadData|Invoke-WebRequest|IWR|IRM|Invoke-RestMethod)\s*\(\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)
_RX_NET_WEBCLIENT = re.compile(
    r"""New-Object\s+(?:System\.)?Net\.WebClient""",
    re.IGNORECASE,
)

# Python -c "exec(...b64decode(b'BLOB')...)" — RC2.2 hotfix
# Handles common malware wrappers like:
#   python -c "exec(__import__('base64').b64decode(b'aW1w...').decode())"
#   python3 -c "exec(import('base64').b64decode(b'aW1w...'))"
#   -c "exec(...)"           (extracted from higher wrappers)
_RX_PY_EXEC_B64 = re.compile(
    r"""
    (?:python[0-9._]*\s+)?           # optional python(3) prefix
    -c\s+["']?                        # -c "…
    \s*exec\s*\(                     # exec(
    .{0,240}?                         # __import__('base64') / import('base64')
                                      # (allow nested parens, chr(N) obfuscation)
    \.b64decode\s*\(\s*               # .b64decode(
    b?['"]([A-Za-z0-9+/=_\-]{20,})['"]# b'BLOB'
    """,
    re.IGNORECASE | re.VERBOSE | re.DOTALL,
)
# Python -c "exec(BLOB)" — plain exec of a code string
_RX_PY_EXEC_PLAIN = re.compile(
    r"""(?:python[0-9._]*\s+)?-c\s+["']?\s*exec\s*\(\s*["']([^"']{20,})["']""",
    re.IGNORECASE,
)


def _strip_cmd_carets(text: str) -> str:
    """CMD's ^ is a line-continuation/escape character; when parsed, CMD removes
    every unescaped ^ from the command line. Real attackers use it to obfuscate
    keywords like p^ow^ER^s^HE^LL. This mimics CMD's parser: strip lone ^ that
    aren't preceded by another ^."""
    if "^" not in text:
        return text
    out = []
    i = 0
    while i < len(text):
        c = text[i]
        if c == "^" and i + 1 < len(text):
            out.append(text[i + 1])
            i += 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


# PowerShell backticks are the escape character. Attackers wedge them
# between letters (`p`o`w`e`r`s`h`e`l`l) to defeat keyword regexes.
# Outside a string context, PS strips the backtick unless it's a
# recognised escape (`n `r `t `0 `a `b `f `v `` `" `' ).
_RX_PS_BACKTICK = re.compile(r"`(?![nrt0abfv`\"'])")


def _strip_ps_backticks(text: str) -> str:
    if "`" not in text:
        return text
    return _RX_PS_BACKTICK.sub("", text)


def _normalize(text: str) -> str:
    """Apply CMD `^` and PowerShell `` ` `` obfuscation strips before matching."""
    out = text
    if "^" in out:
        out = _strip_cmd_carets(out)
    if "`" in out:
        out = _strip_ps_backticks(out)
    return out


# --------------------------------------------------------------------------- #
# Wrapper strategies (ordered by specificity)
# --------------------------------------------------------------------------- #
def _try_wrappers(payload: str) -> Tuple[str, str, List[MitreHint], List[LolbasHit]]:
    """Return (inner, wrapper_name, mitre_hints, lolbas_hits) or ("", "", [], [])."""
    # 0) Normalize CMD ^ + PowerShell ` obfuscation before pattern matching so
    #    `cmd /c p^ow^ER^s^HE^LL -e <b64>` OR `p`ow`ers`hell -e <b64>` are
    #    both seen as `powershell -e <b64>`. We keep the original for the
    #    FromBase64String branch (which is inside quotes) and use normalized
    #    for the cmd / powershell shell-argument patterns.
    normalized = _normalize(payload) if ("^" in payload or "`" in payload) else payload

    # 1) [Convert]::FromBase64String('...') is the most specific
    m = _RX_FROM_B64.search(payload)
    if m:
        return m.group(1), "FromBase64String", [
            MitreHint(id="T1059.001", technique="Command and Scripting Interpreter: PowerShell",
                      tactic="Execution",
                      evidence="[Convert]::FromBase64String() wrapper",
                      source="archetype"),
            MitreHint(id="T1027", technique="Obfuscated Files or Information",
                      tactic="Defense Evasion",
                      evidence="Base64-encoded PowerShell payload",
                      source="archetype"),
        ], [LolbasHit(binary="powershell.exe", technique_id="T1059.001",
                      evidence="[Convert]::FromBase64String wrapper")]

    # 2) powershell -EncodedCommand (works on caret-stripped payload too)
    m = _RX_PS_ENCODED.search(normalized)
    if m:
        return m.group(1), "PowerShell -EncodedCommand", [
            MitreHint(id="T1059.001", technique="PowerShell",
                      tactic="Execution",
                      evidence="powershell -EncodedCommand wrapper",
                      source="archetype"),
            MitreHint(id="T1027", technique="Obfuscated Files or Information",
                      tactic="Defense Evasion",
                      evidence="Base64-encoded command line",
                      source="archetype"),
        ], [LolbasHit(binary="powershell.exe", technique_id="T1059.001",
                      evidence="-EncodedCommand parameter")]

    # 3) DownloadString / Invoke-WebRequest URL
    m = _RX_DOWNLOAD_STRING.search(payload)
    if m:
        return m.group(1), "PowerShell DownloadString URL", [
            MitreHint(id="T1105", technique="Ingress Tool Transfer",
                      tactic="Command and Control",
                      evidence="Net.WebClient/IWR/IRM URL fetch",
                      source="archetype"),
            MitreHint(id="T1059.001", technique="PowerShell", tactic="Execution",
                      evidence="PowerShell remote-fetch pattern",
                      source="archetype"),
        ], [LolbasHit(binary="powershell.exe", technique_id="T1105",
                      evidence="Net.WebClient DownloadString")]

    # 4) mshta with URL
    m = _RX_MSHTA_HTTP.search(payload)
    if m:
        return m.group(1), "mshta URL", [
            MitreHint(id="T1218.005", technique="Signed Binary Proxy Execution: Mshta",
                      tactic="Defense Evasion",
                      evidence="mshta fetching remote URL", source="archetype"),
        ], [LolbasHit(binary="mshta.exe", technique_id="T1218.005",
                      evidence="mshta remote-fetch pattern")]

    # 5) mshta vbscript
    m = _RX_MSHTA_VBS.search(payload)
    if m:
        return m.group(1), "mshta vbscript", [
            MitreHint(id="T1218.005", technique="Mshta",
                      tactic="Defense Evasion",
                      evidence="mshta vbscript: prefix", source="archetype"),
        ], [LolbasHit(binary="mshta.exe", technique_id="T1218.005",
                      evidence="mshta vbscript: wrapper")]

    # 6) powershell -Command
    m = _RX_PS_CMD.search(normalized)
    if m and m.group(1).strip() != normalized.strip():
        return m.group(1).strip(), "PowerShell -Command", [
            MitreHint(id="T1059.001", technique="PowerShell",
                      tactic="Execution",
                      evidence="powershell -Command wrapper", source="archetype"),
        ], [LolbasHit(binary="powershell.exe", technique_id="T1059.001",
                      evidence="-Command parameter")]

    # 7) cmd /c ...
    m = _RX_CMD_C.search(normalized)
    if m and m.group(1).strip() != normalized.strip():
        return m.group(1).strip(), "cmd /c", [
            MitreHint(id="T1059.003", technique="Windows Command Shell",
                      tactic="Execution",
                      evidence="cmd /c wrapper", source="archetype"),
        ], [LolbasHit(binary="cmd.exe", technique_id="T1059.003",
                      evidence="/c parameter")]

    # 8) Python -c "exec(...b64decode(b'BLOB')...)" — very common malware
    m = _RX_PY_EXEC_B64.search(payload)
    if m:
        return m.group(1), "Python exec(b64decode(...))", [
            MitreHint(id="T1059.006", technique="Command and Scripting Interpreter: Python",
                      tactic="Execution",
                      evidence="python -c \"exec(...b64decode(...))\" wrapper",
                      source="archetype"),
            MitreHint(id="T1027", technique="Obfuscated Files or Information",
                      tactic="Defense Evasion",
                      evidence="Base64-encoded Python source",
                      source="archetype"),
        ], [LolbasHit(binary="python.exe", technique_id="T1059.006",
                      evidence="python -c exec(base64.b64decode())")]

    # 9) Python -c "exec('...')" — plain exec of code string
    m = _RX_PY_EXEC_PLAIN.search(payload)
    if m:
        return m.group(1), "Python exec()", [
            MitreHint(id="T1059.006", technique="Python",
                      tactic="Execution",
                      evidence="python -c \"exec(...)\" wrapper",
                      source="archetype"),
        ], [LolbasHit(binary="python.exe", technique_id="T1059.006",
                      evidence="python -c exec()")]

    return "", "", [], []


# --------------------------------------------------------------------------- #
# Plugin
# --------------------------------------------------------------------------- #
class WrapperExtractDecoder(BaseDecoder):
    id = "extract-wrapper"
    name = "PowerShell / CMD Wrapper Extract"
    category = "reconstruct"
    cost = 1                                # cheap regex work
    tags = ("powershell", "cmd", "mshta", "hta", "wrapper", "unwrap")
    schema_version = "1.0"

    def detect(self, payload: str, fingerprint: Fingerprint, ctx: AnalysisContext) -> DetectResult:
        if not payload or len(payload) < 12:
            return DetectResult(confidence=0.0, why="Too short for a wrapper")
        # Use the L0 wrapper_type hint when available
        if fingerprint.wrapper_type in {"powershell", "cmd", "mshta", "hta"}:
            base_conf = 0.9
        else:
            base_conf = 0.6
        # Quick literal probe — only fire if a wrapper regex actually matches
        inner, name, _, _ = _try_wrappers(payload)
        if not inner:
            return DetectResult(confidence=0.0, why="No known wrapper matched")
        return DetectResult(
            confidence=min(0.95, base_conf + 0.05),
            why=f"Wrapper detected: {name}",
            args={"wrapper": name},
        )

    def decode(self, payload: str, args: Dict[str, Any], ctx: AnalysisContext) -> PluginResult:
        inner, name, mitre, lolbas = _try_wrappers(payload)
        if not inner:
            return PluginResult(output=payload, notes=["No wrapper matched at decode time"])
        tradecraft = []
        # High-severity wrappers get an extra tradecraft flag to boost the
        # risk score above the "needs_review" floor.
        if "Python exec" in name:
            tradecraft = [TradecraftFlag(
                flag="python-exec-b64", severity="high",
                evidence=f"{name} wrapper — code smuggled through base64",
            )]
        elif "FromBase64String" in name or "-EncodedCommand" in name:
            tradecraft = [TradecraftFlag(
                flag="ps-encodedcommand-b64", severity="medium",
                evidence=f"{name} wrapper — PowerShell base64 execution",
            )]
        elif "DownloadString" in name or "mshta URL" in name:
            tradecraft = [TradecraftFlag(
                flag="remote-payload-fetch", severity="high",
                evidence=f"{name} — payload fetched from remote URL",
            )]
        return PluginResult(
            output=inner,
            mitre_hints=mitre,
            lolbas_hits=lolbas,
            tradecraft=tradecraft,
            notes=[f"Extracted from wrapper: {name}"],
            explanation=f"Unwrapped {name}; inner payload passed to next decoder.",
        )


DecoderRegistry.register(WrapperExtractDecoder())
