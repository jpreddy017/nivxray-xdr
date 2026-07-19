"""XOR brute-force decoder plugin — single-byte and short repeating keys.

Detects
-------
    - Binary payloads (printable_ratio < 0.85) of length ≥ 16
    - Or high-entropy printable payloads that look XOR-obfuscated

Recovery strategy (deterministic)
---------------------------------
1. For key length 1..8, find the byte-per-column that maximises the score:
       score = english_density(plain) + downstream_magic_bonus(plain)
2. Return the best key across all lengths.

Downstream magic bonus lets us prefer keys that reveal gzip / zlib / PE /
Meterpreter shellcode prologues — the canonical Empire/Cobalt-Strike
`base64(xor(gzip(script)))` and `base64(xor(shellcode))` chains.

Intelligence emitted (MCIP)
---------------------------
* `family_hints`   Meterpreter / MSFvenom stager detection via prologue match
* `mitre_hints`    T1027 (Obfuscated Files), T1055 (Process Injection)
* `iocs`           URLs / IPs / domains inside the recovered plaintext
* `tradecraft`     Amsi bypass / reflective injection markers if seen
* `explanation`    Human-readable summary
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

from engine.decoder_base import BaseDecoder
from engine.models import (
    AnalysisContext,
    DetectResult,
    FamilyHint,
    Fingerprint,
    MitreHint,
    PluginResult,
    TradecraftFlag,
)
from engine.registry import DecoderRegistry


# --------------------------------------------------------------------------- #
# Scoring helpers (deterministic; no AI)
# --------------------------------------------------------------------------- #
_COMMON_EN = {
    b"the", b"and", b"for", b"powershell", b"cmd", b"http", b"https", b"www",
    b"invoke", b"downloadstring", b"iex", b"user-agent", b"mozilla", b"windows",
    b"system", b"exe", b"dll", b"cmd.exe", b"microsoft", b"function",
}


def _english_score(b: bytes) -> float:
    if not b:
        return 0.0
    low = b.lower()
    hits = sum(1 for w in _COMMON_EN if w in low)
    printable = sum(1 for x in b if 32 <= x < 127 or x in (9, 10, 13))
    return (printable / len(b)) * 0.5 + min(1.0, hits / 4) * 0.5


# Known shellcode / archive prologues — kept small and hot-path
_MAGIC_TABLE: Tuple[Tuple[bytes, float, str], ...] = (
    (b"\x1f\x8b", 0.70, "gzip stream"),
    (b"\x78\x9c", 0.55, "zlib stream"),
    (b"\x78\xda", 0.55, "zlib stream"),
    (b"\x78\x01", 0.55, "zlib stream"),
    (b"MZ",       0.55, "PE header"),
    (b"\x7fELF",  0.55, "ELF header"),
    (b"PK\x03\x04", 0.45, "ZIP/JAR/OOXML"),
    (b"%PDF",     0.45, "PDF"),
    (b"\xfd7zXZ\x00", 0.45, "xz stream"),
    (b"BZh",      0.40, "bzip2 stream"),
    # Common Metasploit x86 stagers
    (b"\xfc\xe8\x89", 0.65, "MSFvenom x86 reverse_tcp/https stager"),
    (b"\xfc\xe8\x82", 0.65, "MSFvenom x86 stager"),
    (b"\xfc\xeb",    0.60, "MSFvenom stager (jmp variant)"),
    (b"\xfc\x48\x83\xe4\xf0", 0.65, "MSFvenom x64 stager"),
    # Cobalt Strike Beacon common prologue
    (b"\xfc\xe8\x8f", 0.60, "Cobalt-Strike Beacon stager"),
)


def _magic_bonus(b: bytes) -> Tuple[float, str]:
    for prefix, bonus, name in _MAGIC_TABLE:
        if b.startswith(prefix):
            return bonus, name
    return 0.0, ""


def _score(b: bytes) -> float:
    bonus, _ = _magic_bonus(b)
    return _english_score(b) + bonus


def _crack_single_byte(data: bytes) -> Tuple[int, float, bytes]:
    best_k, best_s, best_p = 0, -1.0, data
    for k in range(256):
        plain = bytes(x ^ k for x in data)
        s = _score(plain)
        if s > best_s:
            best_k, best_s, best_p = k, s, plain
    return best_k, best_s, best_p


def _crack_multi_byte(data: bytes, keylen: int) -> Tuple[bytes, float, bytes]:
    key = bytearray(keylen)
    for col in range(keylen):
        col_bytes = data[col::keylen]
        if not col_bytes:
            continue
        best_k, best_s = 0, -1.0
        for kbyte in range(256):
            decoded = bytes(x ^ kbyte for x in col_bytes)
            s = _english_score(decoded)
            if s > best_s:
                best_s, best_k = s, kbyte
        key[col] = best_k
    plain = bytes(b ^ key[i % keylen] for i, b in enumerate(data))
    return bytes(key), _score(plain), plain


# --------------------------------------------------------------------------- #
# Intelligence surface (MCIP)
# --------------------------------------------------------------------------- #
_IPV4 = re.compile(rb"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_URL = re.compile(rb"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+", re.IGNORECASE)
_DOMAIN = re.compile(rb"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b", re.IGNORECASE)


def _surface_intelligence(plain: bytes, magic_name: str) -> Tuple[
    Dict[str, List[str]], List[MitreHint], List[FamilyHint], List[TradecraftFlag], str
]:
    iocs: Dict[str, List[str]] = {}
    for name, rx in (("urls", _URL), ("ips", _IPV4), ("domains", _DOMAIN)):
        found = list({m.decode("latin-1") for m in rx.findall(plain)})
        if found:
            iocs[name] = found[:10]

    mitre: List[MitreHint] = []
    family: List[FamilyHint] = []
    tradecraft: List[TradecraftFlag] = []
    explanation_parts: List[str] = []

    if magic_name:
        mitre.append(MitreHint(
            id="T1027",
            technique="Obfuscated Files or Information",
            tactic="Defense Evasion",
            evidence=f"XOR-obfuscated payload recovered; downstream magic: {magic_name}",
            source="heuristic",
        ))
        explanation_parts.append(f"XOR-obfuscated {magic_name} recovered.")

    if "MSFvenom" in magic_name or "Cobalt-Strike" in magic_name or "stager" in magic_name.lower():
        fam = "Meterpreter/MSFvenom stager" if "MSFvenom" in magic_name else magic_name
        family.append(FamilyHint(
            family=fam,
            confidence=0.85,
            evidence=f"Shellcode prologue matched: {magic_name}",
            aka=["Metasploit stager"] if "MSFvenom" in magic_name else [],
        ))
        mitre.append(MitreHint(
            id="T1055.012",
            technique="Process Hollowing",
            tactic="Defense Evasion",
            evidence=f"Detected {magic_name} — typical injection stager.",
            source="heuristic",
        ))

    low = plain.lower()
    if b"amsi" in low or b"amsiscanbuffer" in low:
        tradecraft.append(TradecraftFlag(
            flag="amsi-bypass",
            severity="high",
            evidence="AMSI reference in recovered plaintext",
        ))
    if b"reflection.assembly" in low or b"loadfrom" in low:
        tradecraft.append(TradecraftFlag(
            flag="reflective-loading",
            severity="high",
            evidence=".NET reflective assembly loading in recovered plaintext",
        ))

    explanation = " ".join(explanation_parts)
    return iocs, mitre, family, tradecraft, explanation


# --------------------------------------------------------------------------- #
# Plugin
# --------------------------------------------------------------------------- #
class XorBruteDecoder(BaseDecoder):
    id = "xor-brute"
    name = "XOR Brute-Force (single + short repeating key)"
    category = "cipher"
    cost = 4                                # more expensive than base64/hex
    tags = ("xor", "meterpreter", "obfuscation")
    schema_version = "1.0"

    _MIN_LEN = 16
    _MAX_KEYLEN = 4                         # multi-byte scan cap for perf

    def detect(self, payload: str, fingerprint: Fingerprint, ctx: AnalysisContext) -> DetectResult:
        if len(payload) < self._MIN_LEN:
            return DetectResult(confidence=0.0, why="Too short for XOR brute")
        # Skip anything with plausible English word content — brute XOR of prose
        # produces garbage. Applies even at density 0 for short inputs.
        if fingerprint.english_density > 0.05:
            return DetectResult(confidence=0.0, why="Input already reads as English")
        b = payload.encode("latin-1", errors="replace")
        if not fingerprint.is_binary:
            # High-printable payloads: require length and entropy hallmarks of
            # cipher-text obfuscators. Short plaintext (< 64 chars) is skipped.
            if len(b) < 64:
                return DetectResult(confidence=0.0,
                                    why="Printable but too short to be XOR ciphertext")
            if fingerprint.entropy < 3.5:
                return DetectResult(confidence=0.0,
                                    why=f"Printable + very low entropy ({fingerprint.entropy:.2f})")
            # Look for repeating-byte hints (typical XOR null-padded blocks)
            counts = [b.count(bytes([x])) for x in range(256)]
            top = max(counts)
            if top / len(b) < 0.05:
                return DetectResult(confidence=0.10,
                                    why="High-entropy printable but no repeating-byte pattern")
            return DetectResult(
                confidence=0.45,
                why=(f"High-entropy printable payload ({len(b)}B, entropy "
                     f"{fingerprint.entropy:.2f}, repeating byte {top}× hint)"),
            )
        # Binary payload — primary candidate (base64 → binary → xor path)
        return DetectResult(
            confidence=0.65,
            why=(f"Binary payload ({len(b)} bytes, entropy "
                 f"{fingerprint.entropy:.2f}) — brute-forceable"),
        )

    def decode(self, payload: str, args: Dict[str, Any], ctx: AnalysisContext) -> PluginResult:
        b = payload.encode("latin-1", errors="replace")
        best_key, best_score, best_plain = _crack_single_byte(b)
        best_keylen = 1

        # Try short repeating keys — cheap; keeps total under a few ms per KB.
        for kl in range(2, self._MAX_KEYLEN + 1):
            k, s, p = _crack_multi_byte(b, kl)
            if s > best_score:
                best_score, best_plain, best_key, best_keylen = s, p, k, kl

        magic_bonus_val, magic_name = _magic_bonus(best_plain)

        iocs, mitre, family, tradecraft, explanation = _surface_intelligence(
            best_plain, magic_name
        )

        # Decide binary vs. text for output
        printable = sum(1 for x in best_plain if 32 <= x < 127 or x in (9, 10, 13))
        is_binary = printable / max(1, len(best_plain)) < 0.85
        out = (best_plain.decode("latin-1") if is_binary
               else best_plain.decode("utf-8", errors="replace"))

        key_hex = best_key.hex() if isinstance(best_key, bytes) else f"{best_key:02x}"
        notes = [
            f"key_len={best_keylen}, key_hex=0x{key_hex}",
            f"score={best_score:.3f}, magic_bonus={magic_bonus_val:.2f} ({magic_name or 'none'})",
        ]

        return PluginResult(
            output=out,
            output_is_binary=is_binary,
            iocs=iocs,
            mitre_hints=mitre,
            family_hints=family,
            tradecraft=tradecraft,
            notes=notes,
            explanation=explanation,
        )

    def explain(self, result: PluginResult) -> str:
        return result.explanation or "XOR brute-force key recovery attempted."


DecoderRegistry.register(XorBruteDecoder())
