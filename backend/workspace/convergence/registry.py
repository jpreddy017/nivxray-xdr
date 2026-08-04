"""
Convergence Engine · Transformation Registry.

Every deterministic transformation in :mod:`workspace.convergence` is
tagged with a :class:`TransformationDescriptor` here. The registry
serves three purposes:

1. **Coverage reporting** \u2014 the R1 Coverage Dashboard uses this
   registry as the ground-truth transformation universe. "Transformation
   Coverage %" is measured against this universe, not a hand-maintained
   list.
2. **Cross-family attribution** \u2014 each descriptor lists the malware
   families and techniques that rely on this transformation, so the
   Dashboard can answer "which decoders unlock which families".
3. **Auditability** \u2014 downstream reporting can present the analyst
   with the full transformation universe, its documentation, and its
   provenance (families/techniques covered, MITRE mapping, version).

Contract
--------
Every registered transformation MUST be:

* implemented in one of the engine passes (``structural.py`` /
  ``content.py`` / ``decoder.py`` / ``semantic.py``);
* deterministic and pure;
* referenced by its ``name`` (matching the string that appears in
  provenance records).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Language = Literal["powershell", "cmd", "bash", "javascript", "generic"]
Category = Literal["structural", "content", "decoder", "semantic"]


@dataclass(frozen=True)
class TransformationDescriptor:
    """Declarative metadata for a single transformation."""

    name: str
    category: Category
    language: Language
    version: str
    description: str
    consumes: str
    produces: str
    families_covered: tuple[str, ...] = field(default_factory=tuple)
    techniques_covered: tuple[str, ...] = field(default_factory=tuple)
    mitre_attack: tuple[str, ...] = field(default_factory=tuple)
    deterministic: bool = True
    dependencies: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "category": self.category,
            "language": self.language,
            "version": self.version,
            "description": self.description,
            "consumes": self.consumes,
            "produces": self.produces,
            "families_covered": list(self.families_covered),
            "techniques_covered": list(self.techniques_covered),
            "mitre_attack": list(self.mitre_attack),
            "deterministic": self.deterministic,
            "dependencies": list(self.dependencies),
        }


# ---------------------------------------------------------------------------
# The full transformation universe of the Convergence Engine.
# ---------------------------------------------------------------------------
REGISTRY: tuple[TransformationDescriptor, ...] = (
    # --- Structural pass ----------------------------------------------------
    TransformationDescriptor(
        name="structural-string-concat-fold",
        category="structural",
        language="powershell",
        version="1.0",
        description="Fold `'a'+'b'` \u2192 `'ab'` for SQ (unconditionally) and DQ (only when no interpolation markers).",
        consumes="SQ / DQ string literal concatenation",
        produces="single string literal",
        families_covered=("cobalt_strike", "gootloader", "emotet", "qakbot", "darkgate", "lumma"),
        techniques_covered=("string_concat_url_obfuscation", "powershell_string_concat_obfuscation", "powershell_variable_reconstruction"),
        mitre_attack=("T1027.010", "T1140"),
    ),
    TransformationDescriptor(
        name="structural-join-operator-fold",
        category="structural",
        language="powershell",
        version="1.0",
        description="Fold `('a','b','c') -join 'sep'` \u2192 single literal.",
        consumes="PowerShell -join operator expression",
        produces="single string literal",
        families_covered=("cobalt_strike", "gootloader", "emotet"),
        techniques_covered=("env_var_reconstruction", "powershell_env_var_slicing"),
        mitre_attack=("T1027.010", "T1140"),
    ),
    TransformationDescriptor(
        name="structural-static-join-fold",
        category="structural",
        language="powershell",
        version="1.0",
        description="Fold `[String]::Join('sep', ('a',...))` \u2192 single literal.",
        consumes="[String]::Join(...) or [System.String]::Join(...) invocation",
        produces="single string literal",
        families_covered=("cobalt_strike", "gootloader", "emotet"),
        techniques_covered=("env_var_reconstruction", "powershell_env_var_slicing"),
        mitre_attack=("T1027.010", "T1140"),
    ),
    TransformationDescriptor(
        name="structural-cmd-caret-strip",
        category="structural",
        language="cmd",
        version="1.0",
        description="Strip CMD `^`-escapes between alphanumerics (`c^m^d /c p^ow^ers^he^ll`).",
        consumes="CMD caret-obfuscated invocation",
        produces="de-obfuscated CMD invocation",
        families_covered=("cobalt_strike", "emotet", "qakbot", "gootloader", "darkgate"),
        techniques_covered=("cmd_caret_powershell_handoff",),
        mitre_attack=("T1027.010", "T1059.003"),
    ),
    TransformationDescriptor(
        name="structural-js-split-reverse-join",
        category="structural",
        language="javascript",
        version="1.0",
        description="Fold `'X'.split('sep').reverse().join('sep2')` \u2192 evaluated SQ literal.",
        consumes="JS split/reverse/join call chain",
        produces="single-quoted string literal",
        families_covered=("gootloader", "socgholish", "clearfake", "chromeloader", "pikabot"),
        techniques_covered=("javascript_string_split_shuffle",),
        mitre_attack=("T1027", "T1140", "T1059.007"),
    ),
    TransformationDescriptor(
        name="structural-js-split-join",
        category="structural",
        language="javascript",
        version="1.0",
        description="Fold `'X'.split('sep').join('sep2')` \u2192 evaluated SQ literal (string-replace-all).",
        consumes="JS split/join call chain",
        produces="single-quoted string literal",
        families_covered=("gootloader", "socgholish", "chromeloader", "pikabot"),
        techniques_covered=("javascript_string_split_shuffle",),
        mitre_attack=("T1027", "T1140", "T1059.007"),
    ),
    TransformationDescriptor(
        name="structural-ps-invocation-simplify",
        category="structural",
        language="powershell",
        version="1.0",
        description="Fold PowerShell call operator invocations `&('Cmdlet') 'arg'` \u2192 `Cmdlet arg`. Handles nested parens `&(('Cmdlet') 'arg')` and composes with `structural-string-concat-fold` for `&(('Get-'+'Process') 'lsass')` \u2192 `Get-Process lsass`. Rule 19 positive-ID: fires only in PowerShell context.",
        consumes="PowerShell call operator invocation with SQ-literal primary",
        produces="canonical `Cmdlet arg1 arg2 ...` sequence",
        families_covered=("cobalt_strike", "gootloader", "emotet", "qakbot", "darkgate", "lumma"),
        techniques_covered=("powershell_call_operator_obfuscation", "powershell_invocation_wrapping"),
        mitre_attack=("T1027.010", "T1059.001"),
    ),
    # --- Content pass -------------------------------------------------------
    TransformationDescriptor(
        name="content-ps-operator-case-normalize",
        category="content",
        language="powershell",
        version="1.0",
        description="Normalize case of PS operator / CLI switches (`-jOiN` \u2192 `-join`, etc.).",
        consumes="PowerShell operator / CLI switch token",
        produces="canonical-cased operator / switch",
        families_covered=("cobalt_strike", "gootloader", "emotet"),
        techniques_covered=("powershell_case_obfuscation",),
        mitre_attack=("T1027.010",),
    ),
    TransformationDescriptor(
        name="content-env-var-case-normalize",
        category="content",
        language="powershell",
        version="1.0",
        description="Normalize env-var name casing: `$eNv:foo` \u2192 `$env:foo`.",
        consumes="PowerShell `$env:VAR` reference",
        produces="canonical-cased env-var reference",
        families_covered=("cobalt_strike", "gootloader"),
        techniques_covered=("env_var_reconstruction", "powershell_env_var_slicing"),
        mitre_attack=("T1027.010",),
    ),
    TransformationDescriptor(
        name="content-env-var-substitute",
        category="content",
        language="powershell",
        version="1.0",
        description="Substitute 13 statically-defined Windows env vars with their canonical literal path.",
        consumes="`$env:ComSpec`, `$env:Public`, `$env:ProgramFiles`, \u2026",
        produces="literal path SQ string",
        families_covered=("cobalt_strike", "gootloader", "emotet"),
        techniques_covered=("env_var_reconstruction", "powershell_env_var_slicing"),
        mitre_attack=("T1027.010", "T1140"),
    ),
    TransformationDescriptor(
        name="content-string-index-single-fold",
        category="content",
        language="powershell",
        version="1.0",
        description="Fold `'literal'[n]` \u2192 `'c'`.",
        consumes="single-index expression on SQ literal",
        produces="single-character SQ literal",
        families_covered=("cobalt_strike", "gootloader"),
        techniques_covered=("env_var_reconstruction", "powershell_env_var_slicing"),
        mitre_attack=("T1027.010",),
    ),
    TransformationDescriptor(
        name="content-string-index-range-fold",
        category="content",
        language="powershell",
        version="1.0",
        description="Fold `'literal'[a..b]` \u2192 tuple of characters.",
        consumes="range-index expression on SQ literal",
        produces="tuple of character SQ literals",
        families_covered=("cobalt_strike", "gootloader"),
        techniques_covered=("env_var_reconstruction", "powershell_env_var_slicing"),
        mitre_attack=("T1027.010",),
    ),
    TransformationDescriptor(
        name="content-string-index-list-fold",
        category="content",
        language="powershell",
        version="1.0",
        description="Fold `'literal'[a,b,c]` \u2192 tuple of characters.",
        consumes="list-index expression on SQ literal",
        produces="tuple of character SQ literals",
        families_covered=("cobalt_strike", "gootloader"),
        techniques_covered=("env_var_reconstruction", "powershell_env_var_slicing"),
        mitre_attack=("T1027.010",),
    ),
    TransformationDescriptor(
        name="content-backtick-escape-strip",
        category="content",
        language="powershell",
        version="1.0",
        description="Strip PowerShell backtick escapes between identifier characters (`I\u0060E\u0060X` \u2192 `IEX`).",
        consumes="backtick-obfuscated identifier",
        produces="canonical identifier",
        families_covered=("cobalt_strike", "gootloader", "emotet", "darkgate"),
        techniques_covered=("backtick_alias_obfuscation", "powershell_backtick_obfuscation"),
        mitre_attack=("T1027.010",),
    ),
    TransformationDescriptor(
        name="content-numeric-constant-fold",
        category="content",
        language="powershell",
        version="1.0",
        description="Fold integer arithmetic: `50+55` \u2192 `105`, `50-30` \u2192 `20`.",
        consumes="integer arithmetic expression",
        produces="integer literal",
        families_covered=(),
        techniques_covered=(),
        mitre_attack=("T1027.010",),
    ),
    # --- Decoder pass -------------------------------------------------------
    TransformationDescriptor(
        name="decoder-powershell-encoded-command",
        category="decoder",
        language="powershell",
        version="1.0",
        description="Decode PowerShell `-EncodedCommand` / `-Enc` / `-enc` base64+UTF-16LE payload.",
        consumes="PowerShell CLI invocation with -enc<...> switch",
        produces="powershell-text",
        families_covered=("cobalt_strike", "gootloader", "emotet", "qakbot", "darkgate", "lumma", "asyncrat"),
        techniques_covered=("powershell_encodedcommand_base64_utf16le", "cmd_caret_powershell_handoff"),
        mitre_attack=("T1027", "T1140", "T1059.001"),
        dependencies=("base64", "utf-16le"),
    ),
    TransformationDescriptor(
        name="decoder-frombase64string-fold",
        category="decoder",
        language="powershell",
        version="1.0",
        description="Fold `[Convert]::FromBase64String('B64')` \u2192 SQ literal (with gzip decompression).",
        consumes="[Convert]::FromBase64String(...) call",
        produces="SQ string literal of decoded content",
        families_covered=("cobalt_strike", "emotet", "gootloader"),
        techniques_covered=("nested_multi_layer_encoding",),
        mitre_attack=("T1027", "T1140"),
        dependencies=("base64", "gzip"),
    ),
    TransformationDescriptor(
        name="decoder-hex-full",
        category="decoder",
        language="generic",
        version="1.0",
        description="Decode entire artifact when it is pure hex characters (\u2265 8 chars, even length).",
        consumes="all-hex artifact",
        produces="UTF-8 / latin-1 plaintext",
        families_covered=("cobalt_strike", "gootloader", "emotet", "qakbot", "darkgate"),
        techniques_covered=("nested_multi_layer_encoding",),
        mitre_attack=("T1027", "T1140"),
    ),
    TransformationDescriptor(
        name="decoder-base64-full",
        category="decoder",
        language="generic",
        version="1.0",
        description="Decode entire artifact when it is pure base64 (mod-4 length, \u2265 12 chars). Prefers gzip.",
        consumes="all-base64 artifact",
        produces="UTF-8 / UTF-16LE / gzip-decompressed plaintext",
        families_covered=("cobalt_strike", "gootloader", "emotet", "qakbot", "lumma"),
        techniques_covered=("nested_multi_layer_encoding",),
        mitre_attack=("T1027", "T1140"),
        dependencies=("base64", "gzip", "utf-16le"),
    ),
    TransformationDescriptor(
        name="decoder-xor-byte-array",
        category="decoder",
        language="generic",
        version="1.0",
        description="Decode `0xNN,0xNN,\u2026 xor 0xNN` byte-array XOR pattern.",
        consumes="byte-array XOR expression",
        produces="XOR-decoded plaintext",
        families_covered=("bumblebee", "darkgate", "asyncrat"),
        techniques_covered=("xor_byte_array",),
        mitre_attack=("T1027",),
    ),
    TransformationDescriptor(
        name="decoder-js-unicode-escape",
        category="decoder",
        language="javascript",
        version="1.0",
        description="Fold `'\\uXXXX\\uXXXX...'` string literals \u2192 decoded SQ literal.",
        consumes="JS string of \\uXXXX escape sequences",
        produces="single-quoted string literal of decoded plaintext",
        families_covered=("gootloader", "socgholish", "clearfake", "clickfix", "chromeloader", "pikabot"),
        techniques_covered=("javascript_unicode_escape",),
        mitre_attack=("T1027", "T1140", "T1059.007"),
    ),
    TransformationDescriptor(
        name="decoder-js-atob",
        category="decoder",
        language="javascript",
        version="1.0",
        description="Fold `atob('B64')` / nested `atob(atob(...))` \u2192 decoded SQ literal.",
        consumes="JS atob() call with string-literal argument",
        produces="single-quoted string literal of decoded plaintext",
        families_covered=("gootloader", "socgholish", "clearfake", "clickfix", "chromeloader", "pikabot", "phishing_kits"),
        techniques_covered=("javascript_atob_chain",),
        mitre_attack=("T1027", "T1140", "T1059.007"),
        dependencies=("base64",),
    ),
    # --- Semantic pass ------------------------------------------------------
    TransformationDescriptor(
        name="semantic-bash-pipeline-reduce",
        category="semantic",
        language="bash",
        version="1.0",
        description="Evaluate whitelisted bash pipelines (echo | rev | base64 -d | xxd -r -p | tr | gunzip | zcat | cat | rot13).",
        consumes="left-anchored bash pipeline",
        produces="reduced plaintext output",
        families_covered=("linux_droppers",),
        techniques_covered=("bash_pipeline_obfuscation",),
        mitre_attack=("T1059.004", "T1027", "T1140"),
        dependencies=("base64", "gzip"),
    ),
    TransformationDescriptor(
        name="semantic-ps-alias-expand",
        category="semantic",
        language="powershell",
        version="1.0",
        description="Expand whitelisted PowerShell aliases (`iex`, `iwr`, `icm`, `irm`, `gc`, `gci`, `sc`, `gcm`, `gm`).",
        consumes="PowerShell alias at command position",
        produces="canonical cmdlet name",
        families_covered=("cobalt_strike", "gootloader", "emotet", "qakbot", "darkgate", "lumma"),
        techniques_covered=("iex_downloadstring_cradle", "iwr_useb_iex_pipeline", "curl_alias_useb_iex", "backtick_alias_obfuscation", "powershell_backtick_obfuscation", "powershell_iex_download_cradle", "powershell_iwr_useb_iex_pipeline"),
        mitre_attack=("T1059.001", "T1027.010"),
    ),
    TransformationDescriptor(
        name="semantic-ps-variable-propagate",
        category="semantic",
        language="powershell",
        version="1.0",
        description="Propagate single-assignment SQ variable literals: `$u='...'; ... $u ...` \u2192 substituted literal.",
        consumes="`$var = '<literal>'` binding",
        produces="substituted occurrences of `$var`",
        families_covered=("cobalt_strike", "gootloader", "emotet", "darkgate"),
        techniques_covered=("string_concat_url_obfuscation", "powershell_variable_reconstruction", "powershell_string_concat_obfuscation"),
        mitre_attack=("T1027.010",),
    ),
)


def registry_by_name() -> dict[str, TransformationDescriptor]:
    return {t.name: t for t in REGISTRY}


def languages() -> tuple[Language, ...]:
    return tuple(sorted({t.language for t in REGISTRY}))


def categories() -> tuple[Category, ...]:
    return tuple(sorted({t.category for t in REGISTRY}))


def transformations_by_language(lang: Language) -> tuple[TransformationDescriptor, ...]:
    return tuple(t for t in REGISTRY if t.language == lang)


__all__ = [
    "Category",
    "Language",
    "REGISTRY",
    "TransformationDescriptor",
    "categories",
    "languages",
    "registry_by_name",
    "transformations_by_language",
]
