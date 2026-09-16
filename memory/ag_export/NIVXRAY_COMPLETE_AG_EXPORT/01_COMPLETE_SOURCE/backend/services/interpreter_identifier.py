"""IEDDE Stage 1 · Interpreter Identification.

Deterministic identifier that inspects an artifact and answers:
    "What interpreter is this, and what evidence supports that answer?"

Non-goals of Stage 1 (deferred to later stages):
    * Stage 2 — Technique detection (base64, XOR, gzip, …)
    * Stage 3 — Recipe planning
    * Stage 4 — Execution
    * Stage 5 — Progress evaluation

Contract:
    - Zero heuristics. Every positive identification is anchored to a
      concrete signal (shebang, launcher token, syntax marker, file
      extension seen in the payload, script-host CLI, …).
    - No mutual exclusion by default: if a payload contains *both*
      `powershell.exe` and `cmd.exe`, the identifier reports both with
      independent confidence.
    - Rule 19-compliant: every signal is a *positive* identification of
      the interpreter (never "it looks like a duck because it isn't a
      cat").
    - Rule 24-aligned: this identifier is a deterministic evidence
      producer for the (future) Recipe Planner. It does NOT itself
      choose a decoder.
    - Deterministic: identical input → identical output (byte-stable
      JSON via sorted signals and stable interpreter ordering).

Return shape:
    IdentificationResult(
        primary_interpreter = "powershell",         # highest-confidence, or "unknown"
        confidence          = 0.99,                 # 0..1 for primary
        interpreters        = [                     # every interpreter with signals
            InterpreterMatch(interpreter, confidence, signals=[Signal(...)]),
            ...
        ],
        stability_reason    = "…"                   # human-readable summary
    )
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable

# ---------------------------------------------------------------------------
# Interpreter catalogue
# ---------------------------------------------------------------------------

_INTERPRETERS = (
    "powershell",
    "cmd",
    "bash",
    "python",
    "javascript",
    "vbscript",
    "perl",
    "php",
    "wmi",
    "mshta",
    "rundll32",
    "regsvr32",
)


# ---------------------------------------------------------------------------
# Signal + Match dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True, order=True)
class Signal:
    """One concrete piece of evidence that supports an interpreter.

    ``weight`` is the raw contribution before capping. Positive-ID
    launcher tokens carry the highest weight (0.7+), syntax markers
    are medium (0.2–0.5), and weak markers (e.g. file-extension
    mentions) are low (0.1). A confidence >= 0.95 requires at least
    ONE strong (>= 0.7) signal.
    """
    weight: float
    kind: str
    text: str
    span: tuple[int, int]

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "text": self.text,
            "span": list(self.span),
            "weight": round(self.weight, 3),
        }


@dataclass
class InterpreterMatch:
    interpreter: str
    signals: list[Signal] = field(default_factory=list)

    @property
    def confidence(self) -> float:
        if not self.signals:
            return 0.0
        # Bounded sum with diminishing returns so many weak signals
        # cannot spoof a strong signal.
        total = 0.0
        for s in sorted(self.signals, key=lambda x: -x.weight):
            remaining = 1.0 - total
            total += remaining * s.weight
        return round(min(1.0, total), 4)

    def to_dict(self) -> dict[str, Any]:
        return {
            "interpreter": self.interpreter,
            "confidence": self.confidence,
            "signals": [s.to_dict() for s in sorted(self.signals)],
        }


@dataclass
class IdentificationResult:
    primary_interpreter: str
    confidence: float
    interpreters: list[InterpreterMatch]
    stability_reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "primary_interpreter": self.primary_interpreter,
            "confidence": round(self.confidence, 4),
            "interpreters": [i.to_dict() for i in self.interpreters],
            "stability_reason": self.stability_reason,
        }


# ---------------------------------------------------------------------------
# Signal detectors — one class of detector per interpreter.
# Each detector returns a list[Signal].
# ---------------------------------------------------------------------------


def _find_all(pattern: re.Pattern[str], content: str) -> list[re.Match[str]]:
    return list(pattern.finditer(content))


# ── PowerShell ─────────────────────────────────────────────────────
_PS_LAUNCHER   = re.compile(r"\b(?:powershell|pwsh)(?:\.exe)?\b", re.IGNORECASE)
_PS_SWITCH     = re.compile(r"(?<![\w-])-(?:NoP(?:rofile)?|EncodedCommand|Enc|Ex(?:ecutionPolicy)?|Command|C|NonInteractive|WindowStyle|W|File|f|Sta|Mta)\b", re.IGNORECASE)
_PS_CALLOP     = re.compile(r"&\s*\(\s*'[^'\r\n]*'\s*\)")
_PS_CMDLET     = re.compile(r"\b(?:Invoke-Expression|IEX|Invoke-WebRequest|IWR|Invoke-WmiMethod|Invoke-Command|New-Object|Get-Process|Get-Item|Get-ChildItem|Get-WmiObject|Get-CimInstance|Set-Location|Add-Type|Start-Process|Set-ExecutionPolicy|ConvertTo-SecureString|Get-Content)\b")
_PS_VARIABLE   = re.compile(r"\$(?:[A-Za-z_][A-Za-z0-9_]*|env:[A-Za-z_][A-Za-z0-9_]*|\{[^}\r\n]{1,64}\})")
_PS_TYPE_ACC   = re.compile(r"\[[A-Za-z][A-Za-z0-9]*(?:\.[A-Za-z][A-Za-z0-9]*)+\]::")
_PS_PIPELINE   = re.compile(r"\|\s*(?:%|\?|foreach|where|select|out-null)\b", re.IGNORECASE)


def _detect_powershell(content: str) -> list[Signal]:
    sigs: list[Signal] = []
    for m in _find_all(_PS_LAUNCHER, content):
        sigs.append(Signal(0.85, "launcher_token", m.group(0), m.span()))
    for m in _find_all(_PS_SWITCH, content):
        sigs.append(Signal(0.35, "cli_switch", m.group(0), m.span()))
    for m in _find_all(_PS_CALLOP, content):
        sigs.append(Signal(0.45, "call_operator", m.group(0)[:32], m.span()))
    for m in _find_all(_PS_CMDLET, content):
        sigs.append(Signal(0.55, "cmdlet_reference", m.group(0), m.span()))
    for m in _find_all(_PS_TYPE_ACC, content):
        sigs.append(Signal(0.55, "type_accelerator", m.group(0), m.span()))
    for m in _find_all(_PS_PIPELINE, content):
        sigs.append(Signal(0.25, "ps_pipeline_alias", m.group(0), m.span()))
    # PS variables also appear in bash — count only if we already have
    # at least one strong PS signal above, to avoid mis-labelling bash.
    if any(s.weight >= 0.5 for s in sigs):
        for m in _find_all(_PS_VARIABLE, content):
            sigs.append(Signal(0.10, "variable_ref", m.group(0), m.span()))
    return sigs


# ── CMD ────────────────────────────────────────────────────────────
_CMD_LAUNCHER  = re.compile(r"\b(?:cmd(?:\.exe)?)\b", re.IGNORECASE)
_CMD_SWITCH    = re.compile(r"(?<![\w-])/(?:c|k|v(?::on|:off)?|r)\b", re.IGNORECASE)
_CMD_SHEBANG   = re.compile(r"^\s*@echo\s+(off|on)\b", re.IGNORECASE | re.MULTILINE)
_CMD_CARET_ESC = re.compile(r"\^[a-zA-Z0-9(&|<>%^]")
_CMD_FORVAR    = re.compile(r"%[A-Za-z_][A-Za-z0-9_]*%|%[0-9]|![A-Za-z_][A-Za-z0-9_]*!")
_CMD_BUILTIN   = re.compile(r"\b(?:setlocal|endlocal|goto|call|rem|set\s+\/[apf])\b", re.IGNORECASE)


def _detect_cmd(content: str) -> list[Signal]:
    sigs: list[Signal] = []
    for m in _find_all(_CMD_LAUNCHER, content):
        sigs.append(Signal(0.80, "launcher_token", m.group(0), m.span()))
    for m in _find_all(_CMD_SWITCH, content):
        sigs.append(Signal(0.30, "cli_switch", m.group(0), m.span()))
    for m in _find_all(_CMD_SHEBANG, content):
        sigs.append(Signal(0.70, "cmd_directive", m.group(0), m.span()))
    for m in _find_all(_CMD_CARET_ESC, content):
        sigs.append(Signal(0.20, "caret_escape", m.group(0), m.span()))
    for m in _find_all(_CMD_FORVAR, content):
        sigs.append(Signal(0.30, "variable_expansion", m.group(0), m.span()))
    for m in _find_all(_CMD_BUILTIN, content):
        sigs.append(Signal(0.35, "cmd_builtin", m.group(0), m.span()))
    return sigs


# ── Bash ───────────────────────────────────────────────────────────
_BASH_SHEBANG  = re.compile(r"^#!\s*(?:\S+/)?(?:env\s+)?(?:bash|sh|zsh|dash|ksh)\b", re.MULTILINE)
_BASH_LAUNCHER = re.compile(r"(?:^|[\s;|&])(?:bash|zsh|dash|ksh)(?:\.exe)?(?=\s|$|[;|&])", re.IGNORECASE)
_BASH_PIPE_BC  = re.compile(r"\|\s*(?:base64|xxd|tr|rev|gzip|gunzip|bunzip2|zcat|openssl|wc|head|tail|awk|sed|grep|cut|sort|uniq|bash|zsh|dash)\b")
_BASH_SUBST    = re.compile(r"\$\((?:[^)\r\n]{1,120})\)|`(?:[^`\r\n]{1,120})`")
_BASH_TEST     = re.compile(r"\[\[[^\]]*\]\]|\[[^\]]{1,60}\]")
_BASH_REDIR    = re.compile(r"(?<![|&<>])[><]\s*(?:&\s*)?[12]?(?:\s*[/\w])")


def _detect_bash(content: str) -> list[Signal]:
    sigs: list[Signal] = []
    for m in _find_all(_BASH_SHEBANG, content):
        sigs.append(Signal(0.95, "shebang", m.group(0), m.span()))
    for m in _find_all(_BASH_LAUNCHER, content):
        sigs.append(Signal(0.50, "launcher_token", m.group(0).strip(), m.span()))
    for m in _find_all(_BASH_PIPE_BC, content):
        sigs.append(Signal(0.55, "bash_pipeline", m.group(0), m.span()))
    for m in _find_all(_BASH_SUBST, content):
        sigs.append(Signal(0.35, "command_substitution", m.group(0)[:32], m.span()))
    for m in _find_all(_BASH_TEST, content):
        sigs.append(Signal(0.25, "test_expression", m.group(0)[:32], m.span()))
    return sigs


# ── Python ─────────────────────────────────────────────────────────
_PY_SHEBANG    = re.compile(r"^#!\s*(?:\S+/)?(?:env\s+)?python[0-9.]*\b", re.MULTILINE)
_PY_LAUNCHER   = re.compile(r"\bpython[0-9.]*(?:\.exe)?\b", re.IGNORECASE)
_PY_DASH_C     = re.compile(r"\bpython[0-9.]*\s+-c\s+['\"]")
_PY_IMPORT     = re.compile(r"^\s*(?:import\s+[a-zA-Z_][a-zA-Z0-9_.]*|from\s+[a-zA-Z_][a-zA-Z0-9_.]*\s+import\s+)", re.MULTILINE)
_PY_KEYWORD    = re.compile(r"\b(?:def|lambda|elif|self|__init__|__main__|print\s*\(|exec\s*\(|eval\s*\()")
_PY_SYNTAX     = re.compile(r":\s*$", re.MULTILINE)


def _detect_python(content: str) -> list[Signal]:
    sigs: list[Signal] = []
    for m in _find_all(_PY_SHEBANG, content):
        sigs.append(Signal(0.95, "shebang", m.group(0), m.span()))
    for m in _find_all(_PY_DASH_C, content):
        sigs.append(Signal(0.85, "python_dash_c", m.group(0)[:40], m.span()))
    for m in _find_all(_PY_LAUNCHER, content):
        sigs.append(Signal(0.65, "launcher_token", m.group(0), m.span()))
    for m in _find_all(_PY_IMPORT, content):
        sigs.append(Signal(0.45, "python_import", m.group(0).strip(), m.span()))
    for m in _find_all(_PY_KEYWORD, content):
        sigs.append(Signal(0.25, "python_keyword", m.group(0), m.span()))
    return sigs


# ── JavaScript ─────────────────────────────────────────────────────
_JS_LAUNCHER   = re.compile(r"\b(?:node(?:\.exe)?|cscript(?:\.exe)?|wscript(?:\.exe)?)\b", re.IGNORECASE)
_JS_KEYWORD    = re.compile(r"\b(?:function|var|let|const|=>|typeof|instanceof|new\s+ActiveXObject|WScript\.\w+|document\.|window\.)\b")
_JS_CALL_STYLE = re.compile(r"[a-zA-Z_$][\w$]*\.(?:apply|call|bind|constructor|prototype|split|join|substring|substr|charCodeAt|fromCharCode)\b")
_JS_OBJ        = re.compile(r"\bJSON\.(?:parse|stringify)\s*\(")
_JS_TEMPLATE   = re.compile(r"`[^`]*\$\{[^}]*\}[^`]*`")


def _detect_javascript(content: str) -> list[Signal]:
    sigs: list[Signal] = []
    for m in _find_all(_JS_LAUNCHER, content):
        sigs.append(Signal(0.80, "launcher_token", m.group(0), m.span()))
    for m in _find_all(_JS_KEYWORD, content):
        sigs.append(Signal(0.35, "js_keyword", m.group(0), m.span()))
    for m in _find_all(_JS_CALL_STYLE, content):
        sigs.append(Signal(0.30, "js_method_call", m.group(0), m.span()))
    for m in _find_all(_JS_OBJ, content):
        sigs.append(Signal(0.45, "json_api", m.group(0), m.span()))
    for m in _find_all(_JS_TEMPLATE, content):
        sigs.append(Signal(0.45, "template_literal", m.group(0)[:32], m.span()))
    return sigs


# ── VBScript ───────────────────────────────────────────────────────
_VBS_LAUNCHER  = re.compile(r"\b(?:cscript(?:\.exe)?|wscript(?:\.exe)?)\b", re.IGNORECASE)
_VBS_KEYWORD   = re.compile(r"\b(?:Dim|Set|Sub|End\s+Sub|End\s+Function|CreateObject|GetObject|WScript\.\w+|Option\s+Explicit|On\s+Error\s+Resume\s+Next)\b", re.IGNORECASE)
_VBS_STRING    = re.compile(r"\"[^\"\r\n]{0,120}\"\s*&\s*\"[^\"\r\n]{0,120}\"")
_VBS_COMMENT   = re.compile(r"^\s*'\s.{1,80}$|\brem\s+\S", re.MULTILINE | re.IGNORECASE)


def _detect_vbscript(content: str) -> list[Signal]:
    sigs: list[Signal] = []
    for m in _find_all(_VBS_LAUNCHER, content):
        sigs.append(Signal(0.55, "launcher_token", m.group(0), m.span()))
    for m in _find_all(_VBS_KEYWORD, content):
        sigs.append(Signal(0.55, "vbs_keyword", m.group(0), m.span()))
    for m in _find_all(_VBS_STRING, content):
        sigs.append(Signal(0.25, "vbs_string_concat", m.group(0)[:32], m.span()))
    return sigs


# ── Perl ───────────────────────────────────────────────────────────
_PERL_SHEBANG  = re.compile(r"^#!\s*(?:\S+/)?(?:env\s+)?perl[0-9.]*\b", re.MULTILINE)
_PERL_LAUNCHER = re.compile(r"\bperl[0-9.]*(?:\.exe)?\b", re.IGNORECASE)
_PERL_DASH_E   = re.compile(r"\bperl\s+-[Mem]e?\s+['\"]", re.IGNORECASE)
_PERL_KEYWORD  = re.compile(r"\b(?:use\s+strict|use\s+warnings|my\s+\$|sub\s+[a-zA-Z_]|print\s+STDERR|die\s+\"|=~)\b")
_PERL_SIGIL    = re.compile(r"(?<![\w])\$[a-zA-Z_][a-zA-Z0-9_]{0,30}(?!\})|@[a-zA-Z_][a-zA-Z0-9_]{0,30}|%[a-zA-Z_][a-zA-Z0-9_]{0,30}\{")


def _detect_perl(content: str) -> list[Signal]:
    sigs: list[Signal] = []
    for m in _find_all(_PERL_SHEBANG, content):
        sigs.append(Signal(0.95, "shebang", m.group(0), m.span()))
    for m in _find_all(_PERL_DASH_E, content):
        sigs.append(Signal(0.85, "perl_dash_e", m.group(0)[:32], m.span()))
    for m in _find_all(_PERL_LAUNCHER, content):
        sigs.append(Signal(0.60, "launcher_token", m.group(0), m.span()))
    for m in _find_all(_PERL_KEYWORD, content):
        sigs.append(Signal(0.55, "perl_keyword", m.group(0)[:32], m.span()))
    return sigs


# ── PHP ────────────────────────────────────────────────────────────
_PHP_LAUNCHER  = re.compile(r"\bphp(?:[0-9.]*)?(?:\.exe)?\b", re.IGNORECASE)
_PHP_TAG       = re.compile(r"<\?php\b|<\?=|\?>")
# PHP-exclusive tokens only — `echo`, `eval`, `assert` are shared with
# other languages and must not be matched here without a PHP-specific
# anchor (e.g. leading `$`, PHP tag, or PHP superglobal).
_PHP_KEYWORD   = re.compile(
    r"\$_(?:GET|POST|COOKIE|REQUEST|SERVER|SESSION|FILES|ENV)\b"
    r"|\bcreate_function\s*\("
    r"|\bbase64_decode\s*\(\s*['\"]"
    r"|\bgzinflate\s*\(\s*base64_decode\s*\("
)


def _detect_php(content: str) -> list[Signal]:
    sigs: list[Signal] = []
    for m in _find_all(_PHP_TAG, content):
        sigs.append(Signal(0.90, "php_tag", m.group(0), m.span()))
    for m in _find_all(_PHP_LAUNCHER, content):
        sigs.append(Signal(0.55, "launcher_token", m.group(0), m.span()))
    for m in _find_all(_PHP_KEYWORD, content):
        sigs.append(Signal(0.55, "php_keyword", m.group(0), m.span()))
    return sigs


# ── WMI (wmic.exe CLI utility only — Get-WmiObject / Invoke-WmiMethod
# are PowerShell cmdlets, not standalone WMI interpreter usage) ─────
_WMI_TOKEN     = re.compile(r"\bwmic(?:\.exe)?\b", re.IGNORECASE)


def _detect_wmi(content: str) -> list[Signal]:
    sigs: list[Signal] = []
    for m in _find_all(_WMI_TOKEN, content):
        sigs.append(Signal(0.90, "wmic_cli", m.group(0), m.span()))
    return sigs


# ── mshta / rundll32 / regsvr32 (LOLBIN launchers) ───────────────
_MSHTA_TOKEN     = re.compile(r"\bmshta(?:\.exe)?\b(?:\s+(?:vbscript:|javascript:|https?://))?", re.IGNORECASE)
_RUNDLL32_TOKEN  = re.compile(r"\brundll32(?:\.exe)?\b", re.IGNORECASE)
_REGSVR32_TOKEN  = re.compile(r"\bregsvr32(?:\.exe)?\b(?:.*?/s|.*?/u|.*?/i:https?://)?", re.IGNORECASE)


def _detect_mshta(content: str) -> list[Signal]:
    return [Signal(0.96, "lolbin_launcher", m.group(0)[:40], m.span())
            for m in _find_all(_MSHTA_TOKEN, content)]


def _detect_rundll32(content: str) -> list[Signal]:
    return [Signal(0.96, "lolbin_launcher", m.group(0), m.span())
            for m in _find_all(_RUNDLL32_TOKEN, content)]


def _detect_regsvr32(content: str) -> list[Signal]:
    return [Signal(0.96, "lolbin_launcher", m.group(0)[:40], m.span())
            for m in _find_all(_REGSVR32_TOKEN, content)]


# ---------------------------------------------------------------------------
# Registry — order matters for tie-breaking (stable sort).
# ---------------------------------------------------------------------------


_DETECTORS: dict[str, callable] = {
    "powershell": _detect_powershell,
    "cmd":        _detect_cmd,
    "bash":       _detect_bash,
    "python":     _detect_python,
    "javascript": _detect_javascript,
    "vbscript":   _detect_vbscript,
    "perl":       _detect_perl,
    "php":        _detect_php,
    "wmi":        _detect_wmi,
    "mshta":      _detect_mshta,
    "rundll32":   _detect_rundll32,
    "regsvr32":   _detect_regsvr32,
}


# ---------------------------------------------------------------------------
# Cross-interpreter negative shadows (Rule 19 refinements).
# When a payload has a *strong* signal for one interpreter, weak
# competing signals from another interpreter are attenuated to avoid
# false positives.
# ---------------------------------------------------------------------------


def _apply_negative_shadows(matches: list[InterpreterMatch]) -> list[InterpreterMatch]:
    strong: set[str] = {m.interpreter for m in matches if m.confidence >= 0.80}

    # If Perl / Python has a shebang, other unix-family shells shouldn't
    # win via their weak launcher tokens alone.
    if "perl" in strong or "python" in strong:
        for m in matches:
            if m.interpreter in {"bash",} and not any(s.weight >= 0.7 for s in m.signals):
                # Drop the light-weight bash launcher signal.
                m.signals = [s for s in m.signals if s.kind != "launcher_token"]

    # If a PHP tag is present, `php` launcher is not needed to prove PHP.
    if any(s.kind == "php_tag" for m in matches for s in m.signals if m.interpreter == "php"):
        for m in matches:
            if m.interpreter == "php":
                pass  # keep as-is

    # mshta/rundll32/regsvr32 are LOLBIN launchers — they carry their
    # target interpreter (vbscript / javascript / dll) implicitly.
    # Do NOT attenuate anything else based on them.

    return matches


# ---------------------------------------------------------------------------
# Public entrypoint
# ---------------------------------------------------------------------------


def identify(content: str) -> IdentificationResult:
    """Identify all interpreters present in ``content`` with evidence.

    Empty / non-string input → primary_interpreter="unknown", confidence=0.
    """
    if not isinstance(content, str) or not content.strip():
        return IdentificationResult(
            primary_interpreter="unknown",
            confidence=0.0,
            interpreters=[],
            stability_reason="empty_input",
        )

    matches: list[InterpreterMatch] = []
    for interp, fn in _DETECTORS.items():
        sigs = fn(content)
        if sigs:
            matches.append(InterpreterMatch(interpreter=interp, signals=sigs))

    matches = _apply_negative_shadows(matches)
    # Keep only those with any confidence after shadowing.
    matches = [m for m in matches if m.confidence > 0.0]

    # Deterministic ordering: primary sort by confidence desc, then
    # by declaration order in _INTERPRETERS (stable), then by name.
    order = {name: i for i, name in enumerate(_INTERPRETERS)}
    matches.sort(key=lambda m: (-m.confidence, order.get(m.interpreter, 999), m.interpreter))

    if not matches:
        return IdentificationResult(
            primary_interpreter="unknown",
            confidence=0.0,
            interpreters=[],
            stability_reason="no_interpreter_signals_detected",
        )

    primary = matches[0]
    stability = (
        f"identified {len(matches)} interpreter(s); "
        f"primary={primary.interpreter} @ {primary.confidence:.2f} "
        f"({len(primary.signals)} signal{'s' if len(primary.signals)!=1 else ''})"
    )
    return IdentificationResult(
        primary_interpreter=primary.interpreter,
        confidence=primary.confidence,
        interpreters=matches,
        stability_reason=stability,
    )


__all__ = [
    "Signal",
    "InterpreterMatch",
    "IdentificationResult",
    "identify",
]
