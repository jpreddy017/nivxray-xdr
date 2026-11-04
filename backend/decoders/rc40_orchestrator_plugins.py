"""RC4.0 Orchestrator plugins — deterministic pattern-locked decoders (Feb 2026).

Wraps the 6 new deterministic decoders in `decoders/ps_inline_eval.py`,
`decoders/batch_envvar_substitute.py`, and `decoders/ps_reverse_swap.py` as
first-class `BaseDecoder` plugins that the RC2.2 Orchestrator can pick as
candidates. Each returns HIGH confidence (0.98) so it decisively wins the
candidate race against generic `ps-reconstruct` (0.9) on payloads that
literally match its signature.

These plugins delegate to the existing `@op` functions so behaviour stays
identical between the `magic_decoder` and `Orchestrator` code paths.
"""
from __future__ import annotations

import re
from typing import Any, Dict

from engine.decoder_base import BaseDecoder
from engine.models import (
    AnalysisContext,
    DetectResult,
    Fingerprint,
    MitreHint,
    PluginResult,
    TradecraftFlag,
)
from engine.registry import DecoderRegistry


# ── Signature regexes (shared with magic_decoder rules) ────────────────────
_HEX_CSV_SIG = re.compile(
    r"""\$\w+\s*=\s*['"](?:[0-9a-fA-F]{1,2}\s*,\s*){4,}[0-9a-fA-F]{1,2}['"]""",
    re.VERBOSE,
)
_XOR_INLINE_SIG_CIPHER = re.compile(
    r"""\[byte\[\]\]\s*\(""", re.IGNORECASE
)
_XOR_INLINE_SIG_BXOR = re.compile(r"-bxor", re.IGNORECASE)
_REV_SLICE_SIG = re.compile(
    r"""\$\w+\s*\[\s*-1\s*\.\.\s*-(?:\$\w+\.Length|\d+)\s*\]""",
    re.IGNORECASE,
)
_REGEX_SWAP_SIG = re.compile(
    r"""-replace\s*['"]\([^)]+\)\\\.\([^)]+\)['"]\s*,\s*['"]\$2\.\$1['"]""",
    re.IGNORECASE,
)
_BATCH_ENVVAR_SUB_SIG = re.compile(r"""%\w+:[^=%]{0,64}=[^%]{0,64}%""")
_BATCH_SET_SIG = re.compile(r"""(?:^|[\s&])set\s+\w+\s*=""", re.IGNORECASE | re.MULTILINE)
_CMD_SUBSTR_SIG = re.compile(r"""%\w+:~-?\d+(?:,-?\d+)?%""")


# ── Helper: call the corresponding @op function ────────────────────────────
def _run_op(op_id: str, payload: str) -> str:
    from operations import run_operation
    try:
        return run_operation(op_id, payload, {})
    except Exception as e:
        return f"({op_id} · error: {e})"


class PowerShellHexCsvInlineDecoder(BaseDecoder):
    id = "powershell-hex-csv-inline"
    name = "PowerShell inline hex-CSV → char → -join"
    category = "reconstruct"
    cost = 1
    tags = ("powershell", "hex-csv", "inline-eval", "malware-loader")
    schema_version = "1.0"

    def detect(self, payload: str, fp: Fingerprint, ctx: AnalysisContext) -> DetectResult:
        if not payload or "-split" not in payload.lower() and "[char]" not in payload.lower():
            # Very cheap fast-reject — the signature requires -split OR [char]
            pass
        if _HEX_CSV_SIG.search(payload) and ("[char]" in payload.lower()
                                              or "-join" in payload.lower()
                                              or "iex" in payload.lower()):
            return DetectResult(confidence=0.98,
                                why="Inline hex-CSV literal + -split/[char]/-join/iex")
        return DetectResult(confidence=0.0, why="No hex-CSV signature")

    def decode(self, payload: str, args: Dict[str, Any], ctx: AnalysisContext) -> PluginResult:
        out = _run_op("powershell-hex-csv-inline", payload)
        if not out or out.startswith("(powershell-hex-csv-inline"):
            return PluginResult(output=payload, notes=[out or "no-op"])
        return PluginResult(
            output=out,
            notes=[f"Decoded inline hex-CSV → '{out[:60]}'"],
            mitre_hints=[MitreHint(id="T1027", technique="Obfuscated Files or Information",
                                    tactic="Defense Evasion",
                                    evidence="Inline hex-CSV → char → -join loader",
                                    source="rc40-pattern-locked")],
            tradecraft=[TradecraftFlag(flag="ps-hex-csv-inline", severity="high",
                                        evidence="PowerShell hex-CSV inline eval")],
            explanation="Peeled the `$h='hexCSV'; $c = $h -split ',' | [char][int]('0x'+$_); iex ($c -join '')` construct.",
        )


class PowerShellXorInlineKeyDecoder(BaseDecoder):
    id = "powershell-xor-inline-key"
    name = "PowerShell inline byte-array XOR"
    category = "cipher"
    cost = 1
    tags = ("powershell", "xor", "inline-key", "malware-loader")
    schema_version = "1.0"

    def detect(self, payload: str, fp: Fingerprint, ctx: AnalysisContext) -> DetectResult:
        if _XOR_INLINE_SIG_CIPHER.search(payload) and _XOR_INLINE_SIG_BXOR.search(payload):
            return DetectResult(confidence=0.98,
                                why="[byte[]](N,N,...) + -bxor inline XOR loop")
        return DetectResult(confidence=0.0, why="No inline-XOR signature")

    def decode(self, payload: str, args: Dict[str, Any], ctx: AnalysisContext) -> PluginResult:
        out = _run_op("powershell-xor-inline-key", payload)
        if not out or out.startswith("(powershell-xor-inline-key"):
            return PluginResult(output=payload, notes=[out or "no-op"])
        return PluginResult(
            output=out,
            notes=[f"Decoded inline XOR → '{out[:60]}'"],
            mitre_hints=[MitreHint(id="T1027.005", technique="Indicator Removal from Tools",
                                    tactic="Defense Evasion",
                                    evidence="Inline byte-array XOR with hardcoded key",
                                    source="rc40-pattern-locked")],
            tradecraft=[TradecraftFlag(flag="ps-xor-inline-key", severity="high",
                                        evidence="PowerShell byte-array XOR loop with inline key")],
            explanation="Deterministically XORed the ciphertext array with the extracted key.",
        )


class PowerShellReverseStringDecoder(BaseDecoder):
    id = "powershell-reverse-string"
    name = "PowerShell reverse-string via [-1..-N]"
    category = "reconstruct"
    cost = 1
    tags = ("powershell", "reverse", "slice", "malware-loader")
    schema_version = "1.0"

    def detect(self, payload: str, fp: Fingerprint, ctx: AnalysisContext) -> DetectResult:
        if _REV_SLICE_SIG.search(payload):
            return DetectResult(confidence=0.98,
                                why="Negative-index [-1..-N] reverse-slice")
        return DetectResult(confidence=0.0, why="No reverse-slice signature")

    def decode(self, payload: str, args: Dict[str, Any], ctx: AnalysisContext) -> PluginResult:
        out = _run_op("powershell-reverse-string", payload)
        if not out or out.startswith("(powershell-reverse-string"):
            return PluginResult(output=payload, notes=[out or "no-op"])
        return PluginResult(
            output=out, notes=[f"Reversed via [-1..-N] slice"],
            mitre_hints=[MitreHint(id="T1027", technique="Obfuscated Files or Information",
                                    tactic="Defense Evasion",
                                    evidence="PowerShell reverse-string slice",
                                    source="rc40-pattern-locked")],
            tradecraft=[TradecraftFlag(flag="ps-reverse-slice", severity="medium",
                                        evidence="Negative-index string reversal")],
            explanation="Rewrote the [-1..-N] slice with its reversed literal.",
        )


class PowerShellReverseRegexSwapDecoder(BaseDecoder):
    id = "powershell-reverse-regex-swap"
    name = "PowerShell -replace '(\\w+)\\.(\\w+)','$2.$1'"
    category = "reconstruct"
    cost = 1
    tags = ("powershell", "regex-swap", "reconstruct", "malware-loader")
    schema_version = "1.0"

    def detect(self, payload: str, fp: Fingerprint, ctx: AnalysisContext) -> DetectResult:
        if _REGEX_SWAP_SIG.search(payload):
            return DetectResult(confidence=0.98,
                                why="-replace '(\\w+)\\.(\\w+)','$2.$1' swap pattern")
        return DetectResult(confidence=0.0, why="No regex-swap signature")

    def decode(self, payload: str, args: Dict[str, Any], ctx: AnalysisContext) -> PluginResult:
        out = _run_op("powershell-reverse-regex-swap", payload)
        if not out or out.startswith("(powershell-reverse-regex-swap"):
            return PluginResult(output=payload, notes=[out or "no-op"])
        return PluginResult(
            output=out, notes=["Regex-swapped (\\w+).(\\w+) tokens"],
            mitre_hints=[MitreHint(id="T1027", technique="Obfuscated Files or Information",
                                    tactic="Defense Evasion",
                                    evidence="PowerShell regex-based token swap",
                                    source="rc40-pattern-locked")],
            explanation="Swapped the two \\w+ groups per the $2.$1 regex replacement.",
        )


class BatchEnvvarSubstituteDecoder(BaseDecoder):
    id = "batch-envvar-substitute"
    name = "Batch %VAR:from=to% substitution"
    category = "reconstruct"
    cost = 1
    tags = ("cmd", "batch", "envvar", "malware-loader")
    schema_version = "1.0"

    def detect(self, payload: str, fp: Fingerprint, ctx: AnalysisContext) -> DetectResult:
        if _BATCH_SET_SIG.search(payload) and (_BATCH_ENVVAR_SUB_SIG.search(payload) or re.search(r"%\w+%", payload)):
            return DetectResult(confidence=0.98,
                                why="SET var + %VAR:from=to% or %VAR% substitution")
        return DetectResult(confidence=0.0, why="No batch-envvar substitution signature")

    def decode(self, payload: str, args: Dict[str, Any], ctx: AnalysisContext) -> PluginResult:
        from decoders.batch_envvar_substitute import op_batch_envvar_substitute
        out = op_batch_envvar_substitute(payload)
        if not out or out.startswith("(batch-envvar-substitute"):
            return PluginResult(output=payload, notes=[out or "no-op"])
        return PluginResult(
            output=out, notes=["Applied CMD %VAR:from=to% substitutions"],
            mitre_hints=[MitreHint(id="T1027", technique="Obfuscated Files or Information",
                                    tactic="Defense Evasion",
                                    evidence="CMD batch envvar substitution obfuscation",
                                    source="rc40-pattern-locked")],
            tradecraft=[TradecraftFlag(flag="batch-envvar-obfuscation", severity="medium",
                                        evidence="CMD envvar substitution")],
            explanation="Expanded %VAR:from=to% and %VAR% into their resolved values.",
        )


class CmdEnvvarSubstringPickerDecoder(BaseDecoder):
    id = "cmd-envvar-substring-picker"
    name = "CMD %VAR:~start,len% substring picker"
    category = "reconstruct"
    cost = 1
    tags = ("cmd", "batch", "substring-picker", "envvar", "malware-loader")
    schema_version = "1.0"

    def detect(self, payload: str, fp: Fingerprint, ctx: AnalysisContext) -> DetectResult:
        if _CMD_SUBSTR_SIG.search(payload):
            return DetectResult(confidence=0.98,
                                why="%VAR:~start,len% substring-picker pattern")
        return DetectResult(confidence=0.0, why="No substring-picker signature")

    def decode(self, payload: str, args: Dict[str, Any], ctx: AnalysisContext) -> PluginResult:
        out = _run_op("cmd-envvar-substring-picker", payload)
        if not out or out.startswith("(cmd-envvar-substring-picker"):
            return PluginResult(output=payload, notes=[out or "no-op"])
        return PluginResult(
            output=out, notes=["Resolved %VAR:~start,len% substring slices"],
            mitre_hints=[MitreHint(id="T1027", technique="Obfuscated Files or Information",
                                    tactic="Defense Evasion",
                                    evidence="CMD substring-picker obfuscation",
                                    source="rc40-pattern-locked")],
            tradecraft=[TradecraftFlag(flag="cmd-substring-picker", severity="medium",
                                        evidence="CMD %VAR:~a,b% obfuscation")],
            explanation="Sliced env-var values per each %VAR:~start,len% picker.",
        )


DecoderRegistry.register(PowerShellHexCsvInlineDecoder())
DecoderRegistry.register(PowerShellXorInlineKeyDecoder())
DecoderRegistry.register(PowerShellReverseStringDecoder())
DecoderRegistry.register(PowerShellReverseRegexSwapDecoder())
DecoderRegistry.register(BatchEnvvarSubstituteDecoder())
DecoderRegistry.register(CmdEnvvarSubstringPickerDecoder())


# ── RC4.1 · Crypto pipeline additions ─────────────────────────────────
_RC4_KSA_SIG = re.compile(r"""0\s*\.\.\s*255""")
_FROM_B64_SIG = re.compile(r"""FromBase64String""", re.IGNORECASE)
_CRYPTO_SIG = re.compile(
    r"""aes|rijndael|chacha|descrypto|protecteddata|openssl|\bgpg\b|machineguid|rc4""",
    re.IGNORECASE,
)


class Rc4InlineDecryptDecoder(BaseDecoder):
    id = "rc4-inline-decrypt"
    name = "RC4 inline decryption"
    category = "cipher"
    cost = 1
    tags = ("powershell", "rc4", "cipher", "inline-key")
    schema_version = "1.0"

    def detect(self, payload: str, fp: Fingerprint, ctx: AnalysisContext) -> DetectResult:
        if _RC4_KSA_SIG.search(payload) and "-bxor" in payload.lower() \
                and _FROM_B64_SIG.search(payload):
            return DetectResult(confidence=0.98,
                                why="RC4 KSA (0..255) + PRGA (-bxor) + FromBase64String")
        return DetectResult(confidence=0.0, why="No RC4 KSA+PRGA signature")

    def decode(self, payload: str, args: Dict[str, Any], ctx: AnalysisContext) -> PluginResult:
        out = _run_op("rc4-inline-decrypt", payload)
        if not out or out.startswith("(rc4-inline-decrypt"):
            return PluginResult(output=payload, notes=[out or "no-op"])
        return PluginResult(
            output=out,
            notes=[f"Decrypted inline RC4 → '{out[:60]}'"],
            mitre_hints=[
                MitreHint(id="T1027", technique="Obfuscated Files or Information",
                          tactic="Defense Evasion",
                          evidence="RC4 stream cipher with inline key",
                          source="rc41-pattern-locked"),
                MitreHint(id="T1140", technique="Deobfuscate/Decode Files or Information",
                          tactic="Defense Evasion",
                          evidence="Static RC4 recovery",
                          source="rc41-pattern-locked"),
            ],
            tradecraft=[TradecraftFlag(flag="rc4-inline-key", severity="high",
                                        evidence="PowerShell RC4 with inline key")],
            explanation="Executed the RC4 KSA + PRGA in Python and recovered the plaintext.",
        )


class CryptoApiAnnotatorDecoder(BaseDecoder):
    id = "crypto-api-annotator"
    name = "Crypto API annotator (honest verdict)"
    category = "annotation"
    cost = 1
    tags = ("crypto", "annotator", "mitre")
    schema_version = "1.0"

    def detect(self, payload: str, fp: Fingerprint, ctx: AnalysisContext) -> DetectResult:
        if _CRYPTO_SIG.search(payload):
            return DetectResult(confidence=0.55,
                                why="Cryptographic API pattern detected")
        return DetectResult(confidence=0.0, why="No crypto-API signature")

    def decode(self, payload: str, args: Dict[str, Any], ctx: AnalysisContext) -> PluginResult:
        out = _run_op("crypto-api-annotator", payload)
        # Extract MITRE hints from the annotator's detected algorithms
        low = payload.lower()
        hints = []
        if "aes" in low or "rijndael" in low:
            hints.append(MitreHint(id="T1027", technique="Obfuscated Files or Information",
                                     tactic="Defense Evasion",
                                     evidence="AES / Rijndael cryptographic API",
                                     source="rc41-crypto-annotator"))
            hints.append(MitreHint(id="T1140", technique="Deobfuscate/Decode Files or Information",
                                     tactic="Defense Evasion",
                                     evidence="Symmetric-cipher decryption invoked",
                                     source="rc41-crypto-annotator"))
        if "protecteddata" in low:
            hints.append(MitreHint(id="T1555.003", technique="Credentials from Web Browsers",
                                     tactic="Credential Access",
                                     evidence="DPAPI ProtectedData.Unprotect",
                                     source="rc41-crypto-annotator"))
        if "downloadstring" in low and ("aes" in low or "rc4" in low or "chacha" in low):
            hints.append(MitreHint(id="T1071.001", technique="Web Protocols",
                                     tactic="Command and Control",
                                     evidence="C2-fetched decryption key",
                                     source="rc41-crypto-annotator"))
        if "machineguid" in low:
            hints.append(MitreHint(id="T1082", technique="System Information Discovery",
                                     tactic="Discovery",
                                     evidence="MachineGuid-derived key",
                                     source="rc41-crypto-annotator"))
        return PluginResult(
            output=out,
            notes=["Crypto-API surface annotated (honest-verdict layer)"],
            mitre_hints=hints,
        )


DecoderRegistry.register(Rc4InlineDecryptDecoder())
DecoderRegistry.register(CryptoApiAnnotatorDecoder())
