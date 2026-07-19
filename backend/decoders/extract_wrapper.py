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


# --------------------------------------------------------------------------- #
# Wrapper strategies (ordered by specificity)
# --------------------------------------------------------------------------- #
def _try_wrappers(payload: str) -> Tuple[str, str, List[MitreHint], List[LolbasHit]]:
    """Return (inner, wrapper_name, mitre_hints, lolbas_hits) or ("", "", [], [])."""
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

    # 2) powershell -EncodedCommand
    m = _RX_PS_ENCODED.search(payload)
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
    m = _RX_PS_CMD.search(payload)
    if m and m.group(1).strip() != payload.strip():
        return m.group(1).strip(), "PowerShell -Command", [
            MitreHint(id="T1059.001", technique="PowerShell",
                      tactic="Execution",
                      evidence="powershell -Command wrapper", source="archetype"),
        ], [LolbasHit(binary="powershell.exe", technique_id="T1059.001",
                      evidence="-Command parameter")]

    # 7) cmd /c ...
    m = _RX_CMD_C.search(payload)
    if m and m.group(1).strip() != payload.strip():
        return m.group(1).strip(), "cmd /c", [
            MitreHint(id="T1059.003", technique="Windows Command Shell",
                      tactic="Execution",
                      evidence="cmd /c wrapper", source="archetype"),
        ], [LolbasHit(binary="cmd.exe", technique_id="T1059.003",
                      evidence="/c parameter")]

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
        return PluginResult(
            output=inner,
            mitre_hints=mitre,
            lolbas_hits=lolbas,
            notes=[f"Extracted from wrapper: {name}"],
            explanation=f"Unwrapped {name}; inner payload passed to next decoder.",
        )


DecoderRegistry.register(WrapperExtractDecoder())
