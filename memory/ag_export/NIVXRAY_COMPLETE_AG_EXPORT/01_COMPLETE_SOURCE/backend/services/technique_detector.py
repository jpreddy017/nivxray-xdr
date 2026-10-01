"""IEDDE Stage 2 · Technique Detection (plugin registry).

Detects deterministic obfuscation / encoding techniques present in the
current artifact. Each technique is implemented as a self-registering
plugin so adding support for a new primitive is a single-file change.

Return shape:
    TechniqueInventory(
        techniques = [
            TechniqueSignal(name, confidence, weight, evidence=[...])
            ...
        ],
        stability_reason = "…"
    )

Rules in force:
    * Rule 19 · Positive-ID only. Every signal cites a concrete
      byte-range that supports the technique.
    * Rule 21 · Deterministic. Same input → identical inventory JSON.
    * Rule 24 · Discovery-driven. The inventory answers *what is
      present*; it does NOT choose which one to decode next
      (Stage 3 Recipe Planner owns that decision).

Design contract for a plugin:

    class MyDetector(TechniqueDetector):
        name = "base64"
        # optional: interpreter-scoped hint. Empty tuple = universal.
        interpreters: tuple[str, ...] = ()

        def detect(self, content: str, ctx: DetectionContext) -> list[Evidence]:
            ...

    register(MyDetector())
"""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from typing import Any, Callable

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass(frozen=True, order=True)
class Evidence:
    """One byte-anchored piece of evidence for a technique."""
    weight: float
    kind: str
    text: str
    span: tuple[int, int]

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "text": self.text[:120],
            "span": list(self.span),
            "weight": round(self.weight, 3),
        }


@dataclass
class TechniqueSignal:
    name: str
    evidences: list[Evidence] = field(default_factory=list)

    @property
    def confidence(self) -> float:
        if not self.evidences:
            return 0.0
        total = 0.0
        for e in sorted(self.evidences, key=lambda x: -x.weight):
            remaining = 1.0 - total
            total += remaining * e.weight
        return round(min(1.0, total), 4)

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique": self.name,
            "confidence": self.confidence,
            "evidences": [e.to_dict() for e in sorted(self.evidences)],
        }


@dataclass
class TechniqueInventory:
    techniques: list[TechniqueSignal]
    stability_reason: str

    def by_name(self, name: str) -> TechniqueSignal | None:
        return next((t for t in self.techniques if t.name == name), None)

    def names(self) -> list[str]:
        return [t.name for t in self.techniques]

    def to_dict(self) -> dict[str, Any]:
        return {
            "techniques": [t.to_dict() for t in self.techniques],
            "stability_reason": self.stability_reason,
        }


@dataclass
class DetectionContext:
    """What Stage 2 knows about the current artifact from Stage 1."""
    primary_interpreter: str
    interpreters: tuple[str, ...]      # every interpreter Stage 1 found

    def has_interpreter(self, name: str) -> bool:
        return name == self.primary_interpreter or name in self.interpreters


# ---------------------------------------------------------------------------
# Plugin base + registry
# ---------------------------------------------------------------------------


class TechniqueDetector:
    """Abstract base — subclasses set ``name`` and implement ``detect``."""
    name: str = ""
    interpreters: tuple[str, ...] = ()  # empty = universal

    def applicable(self, ctx: DetectionContext) -> bool:
        if not self.interpreters:
            return True
        return any(ctx.has_interpreter(i) for i in self.interpreters)

    def detect(self, content: str, ctx: DetectionContext) -> list[Evidence]:
        raise NotImplementedError


_REGISTRY: list[TechniqueDetector] = []


def register(detector: TechniqueDetector) -> TechniqueDetector:
    if not detector.name:
        raise ValueError("TechniqueDetector must set a non-empty .name")
    _REGISTRY.append(detector)
    return detector


def registered_names() -> list[str]:
    return sorted({d.name for d in _REGISTRY})


# ---------------------------------------------------------------------------
# Individual detector plugins
# ---------------------------------------------------------------------------


class Base64Detector(TechniqueDetector):
    name = "base64"

    _RE_QUOTED = re.compile(r"['\"]([A-Za-z0-9+/]{20,}={0,2})['\"]")
    _RE_BARE   = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{24,}={0,2})(?![A-Za-z0-9+/=])")

    def detect(self, content: str, ctx: DetectionContext) -> list[Evidence]:
        evs: list[Evidence] = []
        seen: set[tuple[int, int]] = set()
        for m in self._RE_QUOTED.finditer(content):
            s = m.group(1)
            if self._is_valid_b64(s):
                evs.append(Evidence(0.85, "quoted_b64_literal", s[:64], m.span(1)))
                seen.add(m.span(1))
        for m in self._RE_BARE.finditer(content):
            if m.span() in seen:
                continue
            s = m.group(1)
            if self._is_valid_b64(s) and len(s) >= 32:
                evs.append(Evidence(0.55, "bare_b64_run", s[:64], m.span(1)))
        return evs

    @staticmethod
    def _is_valid_b64(s: str) -> bool:
        if len(s) % 4 != 0:
            return False
        try:
            base64.b64decode(s, validate=True)
        except Exception:
            return False
        return True


class Utf16LEDetector(TechniqueDetector):
    """PowerShell -EncodedCommand payloads are UTF-16LE base64 blobs.
    Also detects raw UTF-16LE (null-byte-interleaved) content."""
    name = "utf16le"

    _RE_ENC_CMD = re.compile(r"-Enc(?:odedCommand)?\s+([A-Za-z0-9+/=]{20,})", re.IGNORECASE)
    _RE_NULL_STRIDE = re.compile(rb"(?:[\x20-\x7e]\x00){16,}")

    def detect(self, content: str, ctx: DetectionContext) -> list[Evidence]:
        evs: list[Evidence] = []
        for m in self._RE_ENC_CMD.finditer(content):
            evs.append(Evidence(0.90, "ps_encoded_command", m.group(0)[:48], m.span()))
        # Raw UTF-16LE stride detection (only for byte-string content).
        try:
            raw = content.encode("latin-1", errors="ignore")
            for m in self._RE_NULL_STRIDE.finditer(raw):
                evs.append(Evidence(0.55, "utf16le_null_stride", "<binary>", m.span()))
        except Exception:
            pass
        return evs


class HexDetector(TechniqueDetector):
    name = "hex"

    _RE_HEX_LITERAL = re.compile(r"(?:0x[0-9a-fA-F]{6,}|['\"][0-9a-fA-F]{16,}['\"])")
    _RE_HEX_ARRAY   = re.compile(r"(?:0x[0-9a-fA-F]{1,4}\s*,\s*){4,}0x[0-9a-fA-F]{1,4}")

    def detect(self, content: str, ctx: DetectionContext) -> list[Evidence]:
        evs: list[Evidence] = []
        for m in self._RE_HEX_LITERAL.finditer(content):
            evs.append(Evidence(0.60, "hex_literal", m.group(0)[:48], m.span()))
        for m in self._RE_HEX_ARRAY.finditer(content):
            evs.append(Evidence(0.75, "hex_byte_array", m.group(0)[:48], m.span()))
        return evs


class XorDetector(TechniqueDetector):
    name = "xor"

    _RE_PS_XOR = re.compile(r"\$\w+\s*-bxor\s*\$?\w+", re.IGNORECASE)
    _RE_PY_XOR = re.compile(r"ord\s*\(\s*[a-zA-Z_]\w*\s*\)\s*\^\s*\d+|chr\s*\(\s*ord\s*\(\s*\w+\s*\)\s*\^")
    _RE_JS_XOR = re.compile(r"charCodeAt\s*\(\s*\w*\s*\)\s*\^\s*\d+")

    def detect(self, content: str, ctx: DetectionContext) -> list[Evidence]:
        evs: list[Evidence] = []
        for m in self._RE_PS_XOR.finditer(content):
            evs.append(Evidence(0.80, "ps_bxor_operator", m.group(0), m.span()))
        for m in self._RE_PY_XOR.finditer(content):
            evs.append(Evidence(0.85, "python_xor_expr", m.group(0)[:48], m.span()))
        for m in self._RE_JS_XOR.finditer(content):
            evs.append(Evidence(0.80, "js_xor_charcode", m.group(0)[:48], m.span()))
        return evs


class RC4Detector(TechniqueDetector):
    name = "rc4_wrapper"

    _RE_RC4_KEY = re.compile(r"(?:RC4|Rc4|rc4)\s*\(", re.IGNORECASE)
    _RE_RC4_PS  = re.compile(r"\$s\s*=\s*0\.\.255\s*;.*?\bfor\b.*?\bmod\s*256\b", re.DOTALL)

    def detect(self, content: str, ctx: DetectionContext) -> list[Evidence]:
        evs: list[Evidence] = []
        for m in self._RE_RC4_KEY.finditer(content):
            evs.append(Evidence(0.70, "rc4_reference", m.group(0), m.span()))
        for m in self._RE_RC4_PS.finditer(content):
            evs.append(Evidence(0.90, "rc4_ksa_pattern", m.group(0)[:60], m.span()))
        return evs


class AESWrapperDetector(TechniqueDetector):
    name = "aes_wrapper"

    _RE_AES = re.compile(
        r"\b(?:AesManaged|AesCryptoServiceProvider|RijndaelManaged|Aes\.Create|CipherMode\.CBC|CryptoStream|"
        r"AES\.new|Crypto\.Cipher\.AES|EVP_aes_256_cbc|ConvertTo-SecureString\s+-Key)\b",
        re.IGNORECASE,
    )

    def detect(self, content: str, ctx: DetectionContext) -> list[Evidence]:
        return [
            Evidence(0.85, "aes_api_reference", m.group(0), m.span())
            for m in self._RE_AES.finditer(content)
        ]


class GZipDetector(TechniqueDetector):
    name = "gzip"

    _RE_B64_MARKER = re.compile(r"['\"](?:H4sI[A-Za-z0-9+/=]{20,})['\"]")
    _RE_PS_STREAM  = re.compile(r"\bGZipStream\b|\bIO\.Compression\.GZipStream\b", re.IGNORECASE)
    _RE_PY_GZIP    = re.compile(r"\bgzip\.decompress\b|\bimport\s+gzip\b")

    def detect(self, content: str, ctx: DetectionContext) -> list[Evidence]:
        evs: list[Evidence] = []
        for m in self._RE_B64_MARKER.finditer(content):
            evs.append(Evidence(0.90, "gzip_magic_in_b64", m.group(0)[:32], m.span()))
        for m in self._RE_PS_STREAM.finditer(content):
            evs.append(Evidence(0.80, "gzip_stream_api", m.group(0), m.span()))
        for m in self._RE_PY_GZIP.finditer(content):
            evs.append(Evidence(0.75, "python_gzip_api", m.group(0), m.span()))
        # Raw gzip magic bytes (0x1f 0x8b)
        raw = content.encode("latin-1", errors="ignore")
        if b"\x1f\x8b" in raw[:8]:
            i = raw.index(b"\x1f\x8b")
            evs.append(Evidence(0.95, "gzip_raw_magic", "<binary>", (i, i + 2)))
        return evs


class ZlibDetector(TechniqueDetector):
    name = "zlib"

    _RE_B64_MARKER = re.compile(r"['\"](?:eJw[A-Za-z0-9+/=]{20,})['\"]")
    _RE_PY_ZLIB    = re.compile(r"\bzlib\.decompress\b|\bimport\s+zlib\b")

    def detect(self, content: str, ctx: DetectionContext) -> list[Evidence]:
        evs: list[Evidence] = []
        for m in self._RE_B64_MARKER.finditer(content):
            evs.append(Evidence(0.85, "zlib_marker_in_b64", m.group(0)[:32], m.span()))
        for m in self._RE_PY_ZLIB.finditer(content):
            evs.append(Evidence(0.85, "python_zlib_api", m.group(0), m.span()))
        raw = content.encode("latin-1", errors="ignore")
        for marker in (b"\x78\x9c", b"\x78\xda", b"\x78\x01"):
            if marker in raw[:8]:
                i = raw.index(marker)
                evs.append(Evidence(0.95, "zlib_raw_magic", "<binary>", (i, i + 2)))
        return evs


class StringConcatDetector(TechniqueDetector):
    name = "string_concat"

    _RE_SQ_CONCAT = re.compile(r"'[^'\r\n]{0,120}'\s*\+\s*'[^'\r\n]{0,120}'")
    _RE_DQ_CONCAT = re.compile(r'"[^"\r\n]{0,120}"\s*\+\s*"[^"\r\n]{0,120}"')
    _RE_JS_TEMPLATE_ADD = re.compile(r"['\"][^'\"]{0,60}['\"]\s*\+\s*[a-zA-Z_][\w]{0,30}\s*\+\s*['\"]")

    def detect(self, content: str, ctx: DetectionContext) -> list[Evidence]:
        evs: list[Evidence] = []
        for m in self._RE_SQ_CONCAT.finditer(content):
            evs.append(Evidence(0.85, "sq_string_concat", m.group(0)[:60], m.span()))
        for m in self._RE_DQ_CONCAT.finditer(content):
            evs.append(Evidence(0.85, "dq_string_concat", m.group(0)[:60], m.span()))
        for m in self._RE_JS_TEMPLATE_ADD.finditer(content):
            evs.append(Evidence(0.60, "js_variable_concat", m.group(0)[:60], m.span()))
        return evs


class CharArrayDetector(TechniqueDetector):
    name = "char_array"

    _RE_PS_CHAR = re.compile(r"\[char\[\]\]\s*\(", re.IGNORECASE)
    _RE_JS_FROMCC = re.compile(r"String\.fromCharCode\s*\(")
    _RE_PY_CHR_JOIN = re.compile(r"''\.join\s*\(\s*chr\s*\(|bytes\s*\(\s*\[[\d,\s]+\]\s*\)")

    def detect(self, content: str, ctx: DetectionContext) -> list[Evidence]:
        evs: list[Evidence] = []
        for m in self._RE_PS_CHAR.finditer(content):
            evs.append(Evidence(0.80, "ps_char_array", m.group(0), m.span()))
        for m in self._RE_JS_FROMCC.finditer(content):
            evs.append(Evidence(0.85, "js_from_char_code", m.group(0), m.span()))
        for m in self._RE_PY_CHR_JOIN.finditer(content):
            evs.append(Evidence(0.80, "python_chr_join", m.group(0)[:40], m.span()))
        return evs


class EnvVarAssemblyDetector(TechniqueDetector):
    name = "env_var_assembly"

    _RE_PS_ENV = re.compile(r"\$env:[A-Za-z_][A-Za-z0-9_]*(?:\[\s*\d+\s*(?:,\s*\d+\s*)*\])?", re.IGNORECASE)
    _RE_CMD_VAR = re.compile(r"%[A-Za-z_][A-Za-z0-9_]*:~\d+,\d+%")

    def detect(self, content: str, ctx: DetectionContext) -> list[Evidence]:
        evs: list[Evidence] = []
        ps_matches = list(self._RE_PS_ENV.finditer(content))
        if len(ps_matches) >= 2:
            for m in ps_matches:
                evs.append(Evidence(0.65, "ps_env_reference", m.group(0), m.span()))
        for m in self._RE_CMD_VAR.finditer(content):
            evs.append(Evidence(0.80, "cmd_var_substring", m.group(0), m.span()))
        return evs


class BacktickDetector(TechniqueDetector):
    name = "ps_backtick"
    interpreters = ("powershell",)

    _RE_BACKTICK = re.compile(r"`[a-zA-Z]")

    def detect(self, content: str, ctx: DetectionContext) -> list[Evidence]:
        matches = list(self._RE_BACKTICK.finditer(content))
        if len(matches) < 2:
            return []
        return [
            Evidence(0.40, "ps_backtick_escape", m.group(0), m.span())
            for m in matches
        ]


class CaretDetector(TechniqueDetector):
    name = "cmd_caret"
    interpreters = ("cmd",)

    _RE_CARET = re.compile(r"\^[a-zA-Z0-9(&|<>%^]")

    def detect(self, content: str, ctx: DetectionContext) -> list[Evidence]:
        matches = list(self._RE_CARET.finditer(content))
        if len(matches) < 2:
            return []
        return [
            Evidence(0.40, "cmd_caret_escape", m.group(0), m.span())
            for m in matches
        ]


class ReverseDetector(TechniqueDetector):
    name = "reverse"

    _RE_PS_REVERSE = re.compile(r"-join\s*\(\s*[^\)]{0,120}?\.ToCharArray\(\)\s*\|?\s*\[\s*Array\s*\]::Reverse|\.reverse\s*\(\s*\)", re.IGNORECASE)
    _RE_PY_REVERSE = re.compile(r"\[::-1\]")
    _RE_JS_REVERSE = re.compile(r"\.split\(\s*['\"](?:[^'\"]{0,10})['\"]\s*\)\.reverse\(\s*\)")

    def detect(self, content: str, ctx: DetectionContext) -> list[Evidence]:
        evs: list[Evidence] = []
        for m in self._RE_PS_REVERSE.finditer(content):
            evs.append(Evidence(0.80, "ps_reverse", m.group(0)[:40], m.span()))
        for m in self._RE_PY_REVERSE.finditer(content):
            evs.append(Evidence(0.80, "python_slice_reverse", m.group(0), m.span()))
        for m in self._RE_JS_REVERSE.finditer(content):
            evs.append(Evidence(0.80, "js_split_reverse", m.group(0)[:40], m.span()))
        return evs


class URLEncodingDetector(TechniqueDetector):
    name = "url_encoding"

    _RE_URLENC = re.compile(r"(?:%[0-9a-fA-F]{2}){3,}")

    def detect(self, content: str, ctx: DetectionContext) -> list[Evidence]:
        return [
            Evidence(0.75, "percent_encoded_run", m.group(0)[:48], m.span())
            for m in self._RE_URLENC.finditer(content)
        ]


class UnicodeEscapeDetector(TechniqueDetector):
    name = "unicode_escape"

    _RE_U_ESC = re.compile(r"(?:\\u[0-9a-fA-F]{4}){3,}")
    _RE_X_ESC = re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}")

    def detect(self, content: str, ctx: DetectionContext) -> list[Evidence]:
        evs: list[Evidence] = []
        for m in self._RE_U_ESC.finditer(content):
            evs.append(Evidence(0.80, "u_unicode_escape_run", m.group(0)[:48], m.span()))
        for m in self._RE_X_ESC.finditer(content):
            evs.append(Evidence(0.80, "x_hex_escape_run", m.group(0)[:48], m.span()))
        return evs


class InvocationWrapperDetector(TechniqueDetector):
    """The PowerShell call-operator invocation-wrapping pattern
    `&('Cmdlet')` or `&(('a'+'b') 'arg')`."""
    name = "ps_invocation_wrapper"
    interpreters = ("powershell",)

    _RE = re.compile(r"&\s*\(\s*(?:\(\s*)?'[^'\r\n]*'")

    def detect(self, content: str, ctx: DetectionContext) -> list[Evidence]:
        return [
            Evidence(0.85, "ps_call_operator_wrap", m.group(0)[:32], m.span())
            for m in self._RE.finditer(content)
        ]


class LauncherWrapperDetector(TechniqueDetector):
    """`powershell.exe -Command "<script>"` launcher wrap."""
    name = "ps_launcher_wrapper"
    interpreters = ("powershell",)

    _RE = re.compile(
        r"(?:powershell|pwsh)(?:\.exe)?"
        r"(?:\s+-[A-Za-z]+(?:\s+[^\s\"'-][^\s]*)?)*"
        r"\s+-(?:C|c)(?:ommand)?\s+\"[^\"\r\n]+\"",
        re.IGNORECASE,
    )

    def detect(self, content: str, ctx: DetectionContext) -> list[Evidence]:
        return [
            Evidence(0.90, "ps_launcher_command_wrap", m.group(0)[:64], m.span())
            for m in self._RE.finditer(content)
        ]


# ---------------------------------------------------------------------------
# Register all built-ins
# ---------------------------------------------------------------------------


for _det in (
    Base64Detector(),
    Utf16LEDetector(),
    HexDetector(),
    XorDetector(),
    RC4Detector(),
    AESWrapperDetector(),
    GZipDetector(),
    ZlibDetector(),
    StringConcatDetector(),
    CharArrayDetector(),
    EnvVarAssemblyDetector(),
    BacktickDetector(),
    CaretDetector(),
    ReverseDetector(),
    URLEncodingDetector(),
    UnicodeEscapeDetector(),
    InvocationWrapperDetector(),
    LauncherWrapperDetector(),
):
    register(_det)


# ---------------------------------------------------------------------------
# Public entrypoint
# ---------------------------------------------------------------------------


def detect_techniques(content: str, ctx: DetectionContext | None = None) -> TechniqueInventory:
    """Run every applicable detector plugin over ``content``.

    Empty / non-string input → empty inventory + stability_reason.
    """
    if not isinstance(content, str) or not content:
        return TechniqueInventory(techniques=[], stability_reason="empty_input")

    if ctx is None:
        ctx = DetectionContext(primary_interpreter="unknown", interpreters=())

    signals: list[TechniqueSignal] = []
    for det in _REGISTRY:
        if not det.applicable(ctx):
            continue
        evs = det.detect(content, ctx)
        if evs:
            signals.append(TechniqueSignal(name=det.name, evidences=evs))

    # Deterministic ordering: highest-confidence first; ties by name.
    signals.sort(key=lambda s: (-s.confidence, s.name))

    if not signals:
        return TechniqueInventory(techniques=[], stability_reason="no_techniques_detected")

    top = signals[0]
    reason = (
        f"detected {len(signals)} technique(s); "
        f"top={top.name} @ {top.confidence:.2f}"
    )
    return TechniqueInventory(techniques=signals, stability_reason=reason)


__all__ = [
    "Evidence",
    "TechniqueSignal",
    "TechniqueInventory",
    "DetectionContext",
    "TechniqueDetector",
    "register",
    "registered_names",
    "detect_techniques",
]
