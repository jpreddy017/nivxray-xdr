"""NivXRay — Intelligent Command-Line Analysis Engine (ICAE).

Semantic parser + execution-aware decoder. Instead of treating the whole
command line as an encoded payload, this module:

    1. Identifies the interpreter (PowerShell / CMD / Bash / Python / JS /
       MSHTA / rundll32 / regsvr32 / certutil / wscript / cscript / msiexec).
    2. Tokenises the input respecting the interpreter's grammar — quoted
       strings, variables, sub-expressions, pipelines, redirections.
    3. Understands the *execution flow* — recognises when a command is
       telling another tool to decode a file (`certutil -decode`), when a
       payload is inline (`-enc BASE64`), or when a pipeline chains a
       downloader into an interpreter (`curl … | powershell`).
    4. Assigns a confidence score to every payload candidate and *only*
       auto-decodes ≥0.80 spans. Ties within 0.05 raise `needs_choice`.
    5. Recursively re-scans decoded output for further layers.
    6. Emits an analyst-focused report: original command, parsed structure,
       identified payloads, decode chains, extracted IOCs, LOLBin detection,
       MITRE ATT&CK mapping, and a behavior explanation.

The engine reasons like a SOC analyst: understand *what the command does*
before attempting to decode anything.
"""
from __future__ import annotations
import re
import shlex
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from smart_decoder import smart_decode
from magic_decoder import magic_decode
from powershell_ast import deobfuscate_ps
from amsi_detector import detect_amsi_bypass


# =============================================================================
# 1. Interpreter registry — per-interpreter arg profile
# =============================================================================
# `payload_flags`   — flags whose *value* is an inline payload we should decode
# `file_operand_flags` — flags that operate on a FILE, not an inline payload —
#                       these MUST NOT be treated as inline payloads
# `sensitive_functions` — functions/cmdlets that take an inline payload arg

@dataclass
class InterpreterProfile:
    name: str
    aliases: List[str]
    payload_flags: List[str]                    # -enc, -EncodedCommand, /c, /k, -c, …
    file_operand_flags: List[str]               # -decode, -encode, -f, -File, …
    sensitive_functions: List[str]              # FromBase64String, atob, …
    lolbin: bool = False
    high_risk_switches: List[str] = field(default_factory=list)


INTERPRETERS: Dict[str, InterpreterProfile] = {
    "powershell": InterpreterProfile(
        name="powershell",
        aliases=["powershell", "powershell.exe", "pwsh", "pwsh.exe"],
        payload_flags=[
            "-encodedcommand", "-enc", "-e", "-ec", "-en",
            "-command", "-c",
        ],
        file_operand_flags=["-file", "-f", "-psconsolefile"],
        sensitive_functions=[
            "frombase64string", "convert.frombase64string",
            "[convert]::frombase64string", "iex", "invoke-expression",
            "downloadstring", "downloaddata", "downloadfile", "getstring",
            "invoke-command", "start-process",
        ],
        high_risk_switches=[
            "-executionpolicy", "-ep", "-noprofile", "-nop",
            "-windowstyle", "-w", "hidden", "-noninteractive", "-noni",
            "-noexit",
        ],
    ),
    "cmd": InterpreterProfile(
        name="cmd",
        aliases=["cmd", "cmd.exe"],
        payload_flags=["/c", "/k"],
        file_operand_flags=[],
        sensitive_functions=[],
    ),
    "bash": InterpreterProfile(
        name="bash",
        aliases=["bash", "sh", "zsh", "/bin/bash", "/bin/sh", "/usr/bin/env"],
        payload_flags=["-c"],
        file_operand_flags=[],
        sensitive_functions=["eval", "exec", "$("],
    ),
    "python": InterpreterProfile(
        name="python",
        aliases=["python", "python2", "python3", "python.exe", "python3.exe"],
        payload_flags=["-c"],
        file_operand_flags=[],
        sensitive_functions=[
            "eval", "exec", "compile", "base64.b64decode", "codecs.decode",
        ],
    ),
    "javascript": InterpreterProfile(
        name="javascript",
        aliases=["node", "node.exe", "deno"],
        payload_flags=["-e", "--eval"],
        file_operand_flags=[],
        sensitive_functions=["eval", "atob", "buffer.from", "unescape"],
    ),
    "mshta": InterpreterProfile(
        name="mshta",
        aliases=["mshta", "mshta.exe"],
        payload_flags=[],                       # mshta consumes URL / vbscript inline
        file_operand_flags=[],
        sensitive_functions=["vbscript:", "javascript:"],
        lolbin=True,
    ),
    "rundll32": InterpreterProfile(
        name="rundll32",
        aliases=["rundll32", "rundll32.exe"],
        payload_flags=[],
        file_operand_flags=[],
        sensitive_functions=[],
        lolbin=True,
    ),
    "regsvr32": InterpreterProfile(
        name="regsvr32",
        aliases=["regsvr32", "regsvr32.exe"],
        payload_flags=[],
        file_operand_flags=[],
        sensitive_functions=[],
        lolbin=True,
        high_risk_switches=["/s", "/u", "/i", "/n", "scrobj.dll"],
    ),
    "certutil": InterpreterProfile(
        name="certutil",
        aliases=["certutil", "certutil.exe"],
        # certutil operates on files, not inline payloads. -decode / -encode
        # take a *filename*, so we must NEVER treat their operand as base64.
        payload_flags=[],
        file_operand_flags=[
            "-decode", "-encode", "-decodehex", "-encodehex",
            "-f", "-urlcache", "-split",
        ],
        sensitive_functions=[],
        lolbin=True,
    ),
    "wscript": InterpreterProfile(
        name="wscript",
        aliases=["wscript", "wscript.exe", "cscript", "cscript.exe"],
        payload_flags=[],
        file_operand_flags=[],
        sensitive_functions=[],
        lolbin=True,
    ),
    "msiexec": InterpreterProfile(
        name="msiexec",
        aliases=["msiexec", "msiexec.exe"],
        payload_flags=[],
        file_operand_flags=["/i", "/q", "/quiet", "/x"],
        sensitive_functions=[],
        lolbin=True,
    ),
    "curl": InterpreterProfile(
        name="curl",
        aliases=["curl", "curl.exe", "wget", "wget.exe"],
        payload_flags=[],
        file_operand_flags=[
            "-o", "--output", "-O", "--remote-name",
            "-d", "--data",
        ],
        sensitive_functions=[],
    ),
    "bitsadmin": InterpreterProfile(
        name="bitsadmin",
        aliases=["bitsadmin", "bitsadmin.exe"],
        payload_flags=[],
        file_operand_flags=["/transfer", "/download", "/addfile"],
        sensitive_functions=[],
        lolbin=True,
    ),
}


# Alias → interpreter key
_INTERPRETER_INDEX: Dict[str, str] = {
    a.lower(): k for k, prof in INTERPRETERS.items() for a in prof.aliases
}


def detect_interpreter(text: str) -> Optional[InterpreterProfile]:
    """Return the interpreter profile for the *first* executable token, or None."""
    if not text:
        return None
    stripped = text.lstrip()
    # Look at the first shell-safe token
    first_word = re.split(r"[\s;|&<>()]+", stripped, maxsplit=1)[0] if stripped else ""
    first_word = first_word.strip('"\'')
    if not first_word:
        return None
    key = _INTERPRETER_INDEX.get(first_word.lower())
    if key:
        return INTERPRETERS[key]
    # Try path-stripped basename (C:\Windows\System32\cmd.exe → cmd.exe)
    base = first_word.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
    key = _INTERPRETER_INDEX.get(base)
    return INTERPRETERS[key] if key else None


# =============================================================================
# 2. Pipeline + shell-aware tokenizer
# =============================================================================
_PIPE_SPLIT_RE = re.compile(
    r"(?<!\|)\|(?!\|)|(?<!&)&&|;|(?<!>)>(?!>)"
)


def split_pipeline(text: str) -> List[Dict[str, str]]:
    """Split a command line into `|`, `&&`, `;`, `>` connected segments.

    Returns a list of `{op, cmd}` entries where `op` is the connector *preceding*
    the segment (empty for the first segment). Respects quoted strings.
    """
    if not text:
        return []
    parts: List[Dict[str, str]] = []
    buf, i, quote, prev_op = [], 0, None, ""
    while i < len(text):
        c = text[i]
        if quote:
            buf.append(c)
            if c == quote and (i == 0 or text[i - 1] != "\\"):
                quote = None
            i += 1
            continue
        if c in ('"', "'"):
            quote = c
            buf.append(c); i += 1; continue
        # 2-char ops first
        if text[i:i + 2] in ("&&", "||"):
            parts.append({"op": prev_op, "cmd": "".join(buf).strip()})
            buf = []; prev_op = text[i:i + 2]; i += 2; continue
        if c in ("|", ";", ">"):
            parts.append({"op": prev_op, "cmd": "".join(buf).strip()})
            buf = []; prev_op = c; i += 1; continue
        buf.append(c); i += 1
    if buf:
        parts.append({"op": prev_op, "cmd": "".join(buf).strip()})
    return [p for p in parts if p["cmd"]]


def tokenize(cmd: str) -> List[str]:
    """Shell-aware tokenizer. Uses shlex for POSIX-ish rules, but silently
    falls back to a whitespace split when shlex raises on unbalanced quotes.
    """
    if not cmd:
        return []
    try:
        return shlex.split(cmd, posix=True)
    except ValueError:
        # Try Windows-style (posix=False leaves quotes attached)
        try:
            return shlex.split(cmd, posix=False)
        except ValueError:
            return cmd.split()


# =============================================================================
# 3. Payload span identifier — semantic + pattern with confidence scoring
# =============================================================================
_BASE64_INLINE_RE = re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b")
_HEX_STRING_RE   = re.compile(r"\b(?:0x[0-9a-fA-F]{16,}|[0-9a-fA-F]{32,})\b")
_URLENC_RE       = re.compile(r"(?:%[0-9A-Fa-f]{2}){3,}")
_UNICODE_ESC_RE  = re.compile(r"(?:\\u[0-9a-fA-F]{4}){3,}")
_CHR_CONCAT_RE   = re.compile(r"(?:chr\(\d+\)\s*\+\s*){3,}chr\(\d+\)", re.I)

# PowerShell-specific inline payload wrappers
_PS_B64_WRAPPERS = [
    re.compile(r"\[?Convert\]?::FromBase64String\s*\(\s*['\"]([^'\"]+)['\"]\s*\)", re.I),
    re.compile(r"System\.Convert::FromBase64String\s*\(\s*['\"]([^'\"]+)['\"]\s*\)", re.I),
]
_JS_B64_WRAPPERS = [
    re.compile(r"\batob\s*\(\s*['\"]([^'\"]+)['\"]\s*\)"),
    re.compile(r"\bBuffer\.from\s*\(\s*['\"]([^'\"]+)['\"]\s*,\s*['\"]base64['\"]\s*\)"),
]
_PY_B64_WRAPPERS = [
    re.compile(r"\bbase64\.b64decode\s*\(\s*['\"]([^'\"]+)['\"]\s*\)"),
    re.compile(r"\bcodecs\.decode\s*\(\s*['\"]([^'\"]+)['\"]\s*,\s*['\"]base64['\"]\s*\)"),
]


@dataclass
class PayloadSpan:
    span_text: str
    encoding: str          # base64 / hex / url / unicode / chr-concat / -enc / …
    role: str              # "encodedcommand", "frombase64string", "inline-base64", "file-operand" (ignored), …
    confidence: float
    reason: str
    offset: int = -1       # char offset in original input (best-effort)
    interpreter: Optional[str] = None


def _find_payload_spans(cmd: str, tokens: List[str],
                        prof: Optional[InterpreterProfile]) -> List[PayloadSpan]:
    spans: List[PayloadSpan] = []
    lower_tokens = [t.lower() for t in tokens]

    # ---- semantic: interpreter flag with base64 value ----
    if prof and prof.payload_flags:
        for i, tok in enumerate(lower_tokens):
            if tok in prof.payload_flags and i + 1 < len(tokens):
                nxt = tokens[i + 1]
                if len(nxt) >= 8:
                    spans.append(PayloadSpan(
                        span_text=nxt,
                        encoding="base64" if _looks_base64(nxt) else "inline-command",
                        role=f"{prof.name}{tok}",
                        confidence=0.98,
                        reason=f"Value of {prof.name} {tok} flag",
                        offset=_safe_index(cmd, nxt),
                        interpreter=prof.name,
                    ))

    # ---- semantic: PS FromBase64String / JS atob / Python base64.b64decode ----
    for pat in _PS_B64_WRAPPERS:
        for m in pat.finditer(cmd):
            spans.append(PayloadSpan(
                span_text=m.group(1), encoding="base64",
                role="[Convert]::FromBase64String argument",
                confidence=0.95,
                reason="Inline PowerShell base64 wrapper",
                offset=m.start(1), interpreter="powershell",
            ))
    for pat in _JS_B64_WRAPPERS:
        for m in pat.finditer(cmd):
            spans.append(PayloadSpan(
                span_text=m.group(1), encoding="base64",
                role="atob() argument",
                confidence=0.95,
                reason="Inline JavaScript base64 wrapper",
                offset=m.start(1), interpreter="javascript",
            ))
    for pat in _PY_B64_WRAPPERS:
        for m in pat.finditer(cmd):
            spans.append(PayloadSpan(
                span_text=m.group(1), encoding="base64",
                role="base64.b64decode argument",
                confidence=0.95,
                reason="Inline Python base64 wrapper",
                offset=m.start(1), interpreter="python",
            ))

    # ---- pattern: standalone long base64 not already claimed ----
    covered = _covered_ranges(spans, cmd)
    for m in _BASE64_INLINE_RE.finditer(cmd):
        if _overlaps(m.start(), m.end(), covered):
            continue
        # If this base64 is actually a *filename operand* (certutil -decode file.b64),
        # the interpreter profile blocks the false-positive at the semantic layer;
        # here we still need to check we're not inside a file-operand token.
        if prof and _is_inside_file_operand(m.group(0), tokens, prof):
            continue
        spans.append(PayloadSpan(
            span_text=m.group(0), encoding="base64",
            role="standalone base64", confidence=0.72,
            reason=f"Long base64-like string ({len(m.group(0))} chars) in argument position",
            offset=m.start(),
        ))

    # ---- pattern: URL-encoded / unicode / chr-concat / long hex ----
    for m in _URLENC_RE.finditer(cmd):
        if _overlaps(m.start(), m.end(), covered): continue
        spans.append(PayloadSpan(
            span_text=m.group(0), encoding="url", role="url-encoded",
            confidence=0.75, reason="URL-encoded sequence (>=3 %XX triplets)",
            offset=m.start(),
        ))
    for m in _UNICODE_ESC_RE.finditer(cmd):
        if _overlaps(m.start(), m.end(), covered): continue
        spans.append(PayloadSpan(
            span_text=m.group(0), encoding="unicode-escape",
            role="unicode escape", confidence=0.85,
            reason="Consecutive \\u00XX unicode escapes",
            offset=m.start(),
        ))
    for m in _CHR_CONCAT_RE.finditer(cmd):
        if _overlaps(m.start(), m.end(), covered): continue
        spans.append(PayloadSpan(
            span_text=m.group(0), encoding="chr-concat",
            role="chr()+chr() concat", confidence=0.80,
            reason="Character-code string concatenation",
            offset=m.start(),
        ))
    for m in _HEX_STRING_RE.finditer(cmd):
        s = m.group(0)
        if _overlaps(m.start(), m.end(), covered): continue
        if len(s) >= 32 and re.fullmatch(r"[0-9a-fA-F]+", s.lstrip("0x")):
            spans.append(PayloadSpan(
                span_text=s, encoding="hex", role="long hex string",
                confidence=0.60,
                reason=f"Long hex string ({len(s)} chars) in argument position",
                offset=m.start(),
            ))

    # dedup by (span_text, encoding) keeping the highest confidence
    key = {}
    for s in spans:
        k = (s.span_text, s.encoding)
        if k not in key or s.confidence > key[k].confidence:
            key[k] = s
    return sorted(key.values(), key=lambda x: (-x.confidence, x.offset))


def _looks_base64(s: str) -> bool:
    """Whitespace-stripped clean base64 with reasonable length."""
    s2 = re.sub(r"\s+", "", s)
    return len(s2) >= 8 and bool(re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", s2))


def _safe_index(hay: str, needle: str) -> int:
    try:
        return hay.index(needle)
    except ValueError:
        return -1


def _covered_ranges(spans: List[PayloadSpan], cmd: str) -> List[Tuple[int, int]]:
    r = []
    for s in spans:
        if s.offset >= 0:
            r.append((s.offset, s.offset + len(s.span_text)))
    return r


def _overlaps(a: int, b: int, ranges: List[Tuple[int, int]]) -> bool:
    return any(not (b <= x or a >= y) for x, y in ranges)


def _is_inside_file_operand(text: str, tokens: List[str],
                             prof: InterpreterProfile) -> bool:
    """True iff `text` sits in the position of a filename operand
    (e.g. `certutil -decode input.b64 output.exe` — `input.b64` is a filename,
    not a payload)."""
    if not prof.file_operand_flags:
        return False
    lower = [t.lower() for t in tokens]
    for i, tok in enumerate(lower):
        if tok in prof.file_operand_flags and i + 1 < len(tokens):
            if tokens[i + 1] == text:
                return True
    return False


# =============================================================================
# 4. Execution-flow classifier
# =============================================================================
_DOWNLOADER_CMDLETS = re.compile(
    r"\b(Invoke-WebRequest|iwr|Invoke-RestMethod|irm|Start-BitsTransfer|"
    r"DownloadString|DownloadData|DownloadFile|Net\.WebClient|WebRequest|"
    r"curl|wget|bitsadmin|certutil.*-urlcache)\b", re.I,
)
_EXECUTOR_CMDLETS = re.compile(
    r"\b(Invoke-Expression|IEX|Invoke-Command|icm|Start-Process|saps|"
    r"New-Service|schtasks|at\.exe|Register-ScheduledTask|WMI\.exec|"
    r"WScript\.Shell\.Run|Shell\.Application\.ShellExecute|"
    r"CreateObject\(.wscript\.shell.\)|\.Exec\(|\.Run\()\b", re.I,
)
_PERSISTENCE = re.compile(
    r"\b(schtasks|Register-ScheduledTask|New-Service|reg\s+add|"
    r"HKCU\\+Software\\+Microsoft\\+Windows\\+CurrentVersion\\+Run|"
    r"HKLM\\+Software\\+Microsoft\\+Windows\\+CurrentVersion\\+Run|"
    r"HKCU:\\+Software\\+Microsoft\\+Windows\\+CurrentVersion\\+Run)\b", re.I,
)

# Fine-grained execution-flow signals for the UI badge panel. Each entry maps
# to a single named point in the command that has security-relevant meaning.
_EXEC_FLOW_SIGNALS = [
    # (kind, label, pattern, mitre_id, severity)
    ("executor",   "Invoke-Expression",       re.compile(r"\bInvoke-Expression\b|(?<!\w)IEX(?!\w)", re.I), "T1059.001", "high"),
    ("executor",   "Invoke-Command",          re.compile(r"\bInvoke-Command\b|(?<!\w)icm(?!\w)", re.I),    "T1059.001", "high"),
    ("executor",   "Start-Process",           re.compile(r"\bStart-Process\b|(?<!\w)saps(?!\w)", re.I),    "T1059.001", "medium"),
    ("executor",   "cmd /c",                  re.compile(r"cmd(?:\.exe)?\s+/c\b", re.I),                   "T1059.003", "high"),
    ("executor",   "rundll32",                re.compile(r"\brundll32(?:\.exe)?\b", re.I),                 "T1218.011", "high"),
    ("executor",   "regsvr32",                re.compile(r"\bregsvr32(?:\.exe)?\b", re.I),                 "T1218.010", "high"),
    ("executor",   "mshta",                   re.compile(r"\bmshta(?:\.exe)?\b", re.I),                    "T1218.005", "high"),
    ("executor",   "wscript / cscript",       re.compile(r"\b[wc]script(?:\.exe)?\b", re.I),               "T1059.005", "medium"),
    ("executor",   "& call operator",         re.compile(r"(?:^|[\s;{|(])&\s*\$?[\w()]+", re.I),           "T1059.001", "medium"),
    ("downloader", "Invoke-WebRequest",       re.compile(r"\bInvoke-WebRequest\b|(?<!\w)iwr(?!\w)", re.I), "T1105",     "high"),
    ("downloader", "Invoke-RestMethod",       re.compile(r"\bInvoke-RestMethod\b|(?<!\w)irm(?!\w)", re.I), "T1105",     "high"),
    ("downloader", "Net.WebClient",           re.compile(r"\bNet\.WebClient\b", re.I),                     "T1105",     "high"),
    ("downloader", "DownloadString",          re.compile(r"\.DownloadString\b", re.I),                     "T1105",     "high"),
    ("downloader", "DownloadFile",            re.compile(r"\.DownloadFile\b", re.I),                       "T1105",     "high"),
    ("downloader", "curl / wget",             re.compile(r"\b(?:curl|wget)(?:\.exe)?\b", re.I),            "T1105",     "medium"),
    ("downloader", "bitsadmin /transfer",     re.compile(r"\bbitsadmin\b[^\n]*/transfer\b", re.I),         "T1197",     "high"),
    ("downloader", "certutil -urlcache",      re.compile(r"\bcertutil\b[^\n]*-urlcache\b", re.I),          "T1105",     "high"),
    ("persistence","schtasks /create",        re.compile(r"\bschtasks\b[^\n]*/create\b", re.I),            "T1053.005", "high"),
    ("persistence","Register-ScheduledTask",  re.compile(r"\bRegister-ScheduledTask\b", re.I),             "T1053.005", "high"),
    ("persistence","New-Service",             re.compile(r"\bNew-Service\b", re.I),                        "T1543.003", "high"),
    ("persistence","Run key",                 re.compile(r"HK(?:LM|CU)[:\\][^\n]*\\Run\b", re.I),          "T1547.001", "high"),
    ("file-decode","certutil -decode",        re.compile(r"\bcertutil\b[^\n]*-decode\b", re.I),            "T1140",     "medium"),
    ("code-exec-obj","WScript.Shell",         re.compile(r"WScript\.Shell", re.I),                         "T1059.005", "high"),
    ("code-exec-obj","Shell.Application",     re.compile(r"Shell\.Application", re.I),                     "T1218",     "medium"),
]


def _execution_flow(text: str) -> List[Dict[str, Any]]:
    """Fine-grained execution-flow badges. One entry per unique signal, with
    the first evidence snippet."""
    hits: List[Dict[str, Any]] = []
    seen = set()
    for kind, label, pat, mitre, sev in _EXEC_FLOW_SIGNALS:
        m = pat.search(text)
        if not m:
            continue
        if label in seen:
            continue
        seen.add(label)
        start = max(0, m.start() - 6)
        end   = min(len(text), m.end() + 20)
        snip  = text[start:end].strip().replace("\n", " ⏎ ")
        if len(snip) > 80: snip = snip[:80] + "…"
        hits.append({
            "kind":     kind,
            "label":    label,
            "mitre_id": mitre,
            "severity": sev,
            "evidence": snip,
            "at":       m.start(),
        })
    hits.sort(key=lambda h: h["at"])
    return hits
_URL_RE      = re.compile(r"\bhttps?://[^\s\"'<>|]{4,}", re.I)
_IP_RE       = re.compile(r"\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}\b")


def classify_behaviors(pipeline: List[Dict[str, str]],
                        cmd: str,
                        interpreter: Optional[InterpreterProfile]) -> List[Dict[str, str]]:
    """Return a list of behavior tags describing what the command *does*."""
    behaviors: List[Dict[str, str]] = []

    if _DOWNLOADER_CMDLETS.search(cmd):
        behaviors.append({"tag": "network-fetch",
                          "detail": "Command downloads remote content"})
    if _EXECUTOR_CMDLETS.search(cmd):
        behaviors.append({"tag": "in-memory-execute",
                          "detail": "Command executes downloaded/decoded payload in-memory"})
    if _PERSISTENCE.search(cmd):
        behaviors.append({"tag": "persistence",
                          "detail": "Command establishes persistence (scheduled task / registry Run key / service)"})
    if interpreter and interpreter.name == "certutil" and \
       any(t.lower() in ("-decode", "-encode") for t in tokenize(cmd)):
        behaviors.append({"tag": "file-decode",
                          "detail": "certutil is being used to decode/encode a FILE — not an inline payload"})
    if interpreter and interpreter.high_risk_switches:
        toks_lc = " ".join(cmd.split()).lower()
        hits = [s for s in interpreter.high_risk_switches if s.lower() in toks_lc]
        if hits:
            behaviors.append({"tag": "stealth-flags",
                              "detail": f"High-risk interpreter switches: {', '.join(hits)}"})

    # Pipeline: downloader → interpreter
    if len(pipeline) >= 2:
        joined_segments = [p["cmd"] for p in pipeline]
        first_dl = _DOWNLOADER_CMDLETS.search(joined_segments[0] or "")
        rest_exec = any(
            detect_interpreter(seg or "") is not None for seg in joined_segments[1:]
        )
        if first_dl and rest_exec:
            behaviors.append({"tag": "download-and-execute",
                              "detail": "Pipeline: remote fetch piped into an interpreter"})
    return behaviors


# =============================================================================
# 5. Recursive decode of a single payload span
# =============================================================================

def _decode_span(span: PayloadSpan, hint_xor_key: Optional[int] = None) -> Dict[str, Any]:
    """Run the decoder chain against a single payload span. Uses `smart_decode`
    (deterministic) plus `magic_decode` (recursive search) and returns the
    best chain."""
    text = span.span_text
    result: Dict[str, Any] = {
        "span": text[:200] + ("…" if len(text) > 200 else ""),
        "encoding": span.encoding,
        "role": span.role,
        "confidence": span.confidence,
        "chains": [],
        "final_output": "",
        "is_shellcode": False,
    }
    try:
        s = smart_decode(text)
        if s.get("steps"):
            result["chains"].append({
                "engine": "smart",
                "steps": [{"op": st["op"], "reason": st.get("reason", "")} for st in s["steps"]],
                "output": s.get("output", ""),
            })
    except Exception as e:                                # pragma: no cover
        result["chains"].append({"engine": "smart", "error": str(e)})
    try:
        m = magic_decode(text, max_depth=5, max_branches=4, top_n=3)
        for cand in m.get("top_results") or []:
            result["chains"].append({
                "engine": "magic",
                "steps": [{"op": st["op"], "args": st.get("args") or {}} for st in cand.get("chain") or []],
                "output": cand.get("output", ""),
                "score": cand.get("score_breakdown", {}).get("score"),
                "is_shellcode": cand.get("is_shellcode", False),
                "entropy": cand.get("entropy"),
            })
            if cand.get("is_shellcode"):
                # NOTE: don't propagate to `result["is_shellcode"]` here — that's
                # decided at the end based on the *chosen* final_output only,
                # otherwise a discarded shellcode branch would mis-flag a
                # script-text chain as binary.
                pass
    except Exception as e:                                # pragma: no cover
        result["chains"].append({"engine": "magic", "error": str(e)})

    # Pick the best chain: prefer non-empty step chains, then higher score,
    # then longer clean output. Never accept an empty-chain candidate as the
    # "final decoded" (it just returns the original ciphertext).
    scored = []
    for ch in result["chains"]:
        out   = ch.get("output") or ""
        steps = ch.get("steps") or []
        if not out or not steps:
            continue
        s = ch.get("score")
        if s is None:
            # smart-decoder chains lack a score — heuristic: printable ratio
            printable = sum(1 for x in out if 32 <= ord(x) < 127 or ord(x) in (9, 10, 13))
            s = printable / max(1, len(out))
        scored.append((s, len(steps), out, ch))
    if scored:
        scored.sort(key=lambda t: (-t[0], -t[1]))
        result["final_output"] = scored[0][2]

    # Re-compute is_shellcode from the CHOSEN final output only.
    try:
        from shellcode_analyzer import is_shellcode as _is_sc
        fo = result["final_output"] or ""
        raw = fo.encode("latin-1") if all(ord(c) < 256 for c in fo) \
                                   else fo.encode("utf-8", errors="replace")
        result["is_shellcode"] = _is_sc(raw)
    except Exception:
        pass

    # Hint-XOR fallback — apply an XOR key we saw in the *parent* text.
    # Used by the recursive re-analysis pass for the classic pattern where the
    # nested $var_code base64 lives inside a script containing `-bxor 35`.
    if hint_xor_key is not None:
        try:
            import base64 as _b64
            b64_str = re.sub(r"\s+", "", text)
            if re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", b64_str) and len(b64_str) >= 12:
                raw = _b64.b64decode(b64_str + "=" * (-len(b64_str) % 4), validate=False)
                xored = bytes(b ^ hint_xor_key for b in raw)
                if xored:
                    from shellcode_analyzer import is_shellcode as _is_sc2
                    latin1_str = xored.decode("latin-1")
                    result["chains"].append({
                        "engine": "hint-xor",
                        "steps": [
                            {"op": "base64-decode", "reason": "isolated inner base64"},
                            {"op": "xor", "args": {"key": f"0x{hint_xor_key:02x}"},
                             "reason": f"XOR key inherited from parent -bxor {hint_xor_key}"},
                        ],
                        "output": latin1_str,
                        "output_hex": xored.hex(),
                        "output_bytes_len": len(xored),
                    })
                    result["final_output"] = latin1_str
                    result["is_shellcode"] = _is_sc2(xored)
                    result["output_hex"] = xored.hex()
        except Exception:
            pass

    # Repeating-key XOR fallback — if we've decoded to a high-entropy buffer
    # (or nothing worked), invoke the multi-byte XOR brute-forcer explicitly.
    # This catches Cobalt-Strike PROFILE / Empire stagers whose inner layer is
    # a repeating-key XOR (not a single byte).
    #
    # GUARD: only run when we have NO successful decode chain, or the current
    # best chain has zero decode steps. Otherwise we risk overriding a correct
    # base64→utf16le output with an alpha-heavy XOR-brute misfire.
    if len(text) >= 32 and not result.get("final_output"):
        try:
            from operations import OPERATIONS as _OPS
            if "xor-brute" in _OPS:
                bx = _OPS["xor-brute"]["fn"](text, "auto")
                # header line looks like: "[xor-brute] recovered key = 0x… … score=…"
                if bx and bx.startswith("[xor-brute]") and "score=" in bx:
                    body = bx.split("\n\n", 1)[-1]
                    # Only surface if it materially beats the current best.
                    # Use a "readability" metric (letters + spaces) that's more
                    # robust than raw printable ratio — XOR-garbage often has
                    # high printable ratio but low letter density.
                    def _readability(s: str) -> float:
                        if not s: return 0.0
                        n = len(s)
                        letters = sum(1 for x in s if x.isalpha() or x == " ")
                        return letters / n
                    cur = result["final_output"] or ""
                    if _readability(body) > _readability(cur) + 0.20:
                        result["chains"].append({
                            "engine": "xor-brute",
                            "steps": [{"op": "xor-brute", "reason": bx.split("\n")[0]}],
                            "output": body,
                        })
                        result["final_output"] = body
        except Exception:
            pass
    return result


# =============================================================================
# 6. IOC / LOLBin / MITRE from parsed context
# =============================================================================
_MITRE_RULES = [
    # (regex, technique_id, name)
    (re.compile(r"-enc(oded)?(command)?\b", re.I),                "T1059.001", "PowerShell Encoded Command"),
    (re.compile(r"\bFromBase64String\b", re.I),                   "T1027",     "Obfuscated / base64 payload"),
    (re.compile(r"\batob\s*\(", re.I),                            "T1027",     "Obfuscated / base64 payload"),
    (re.compile(r"\bIEX\b|Invoke-Expression", re.I),              "T1059.001", "PowerShell in-memory execution"),
    (re.compile(r"\bDownloadString\b", re.I),                     "T1105",     "Ingress Tool Transfer"),
    (re.compile(r"\b(?:curl|wget|bitsadmin|Invoke-WebRequest)\b.*(?:-o|--output|-O|/transfer|/download|-OutFile)", re.I | re.S),
                                                                    "T1105",     "Ingress Tool Transfer"),
    (re.compile(r"\bcurl\b.*\bhttps?://.*\|", re.I),              "T1105",     "Ingress Tool Transfer"),
    (re.compile(r"\bcertutil.*-urlcache|-decode\b", re.I),        "T1140",     "Deobfuscate / Decode Files"),
    (re.compile(r"\brundll32\b", re.I),                           "T1218.011", "Signed Binary Proxy (rundll32)"),
    (re.compile(r"\bregsvr32\b", re.I),                           "T1218.010", "Signed Binary Proxy (regsvr32)"),
    (re.compile(r"\bmshta\b", re.I),                              "T1218.005", "Mshta"),
    (re.compile(r"\bschtasks\b|Register-ScheduledTask", re.I),    "T1053.005", "Scheduled Task"),
    (re.compile(r"\bWScript\.Shell\b", re.I),                     "T1059.005", "Visual Basic"),
    (re.compile(r"\bhttps?://", re.I),                            "T1071.001", "Application Layer Protocol: Web"),
    (re.compile(r"\bbitsadmin\b", re.I),                          "T1197",     "BITS Jobs"),
]


def extract_iocs(text: str) -> Dict[str, List[str]]:
    """Extract lightweight IOCs from any decoded / raw text buffer."""
    def _uniq(xs):
        seen, out = set(), []
        for x in xs:
            if x not in seen: seen.add(x); out.append(x)
        return out
    urls    = _uniq(_URL_RE.findall(text))
    ips     = _uniq(_IP_RE.findall(text))
    url_hosts = set()
    for u in urls:
        try:
            url_hosts.add(u.split("//", 1)[1].split("/", 1)[0].split(":", 1)[0].lower())
        except Exception:
            pass
    dom_re = re.compile(r"\b(?!\d+$)[a-z0-9][a-z0-9-]{0,62}(?:\.[a-z0-9][a-z0-9-]{0,62})+\.(?:com|net|org|io|ai|gov|edu|co|ru|cn|us|uk|de|xyz|top|info|biz|club|shop|online|site|app|dev|pw|cc|to|ly|me|tv|su)\b", re.I)
    domains = _uniq([d for d in dom_re.findall(text) if d.lower() not in url_hosts])
    file_paths = _uniq(re.findall(r"(?:[a-zA-Z]:\\|/)[^\s\"'<>|]{4,}\.(?:exe|dll|ps1|vbs|js|bat|hta|cmd|scr|msi|zip|rar|7z|txt|dat|bin|tmp|pdb)\b", text))
    regkeys = _uniq(re.findall(r"\b(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_[A-Z_]+)[:\\][^\s\"'<>|]{4,}", text, re.I))
    md5     = _uniq(re.findall(r"\b[a-f0-9]{32}\b", text, re.I))
    sha1    = _uniq(re.findall(r"\b[a-f0-9]{40}\b", text, re.I))
    sha256  = _uniq(re.findall(r"\b[a-f0-9]{64}\b", text, re.I))
    return {
        "urls": urls, "ips": ips, "domains": domains,
        "file_paths": file_paths, "regkeys": regkeys,
        "hashes": {"md5": md5, "sha1": sha1, "sha256": sha256},
    }


def map_mitre(all_text: str) -> List[Dict[str, str]]:
    hits = []
    seen: set = set()
    for pat, tid, name in _MITRE_RULES:
        if pat.search(all_text) and tid not in seen:
            seen.add(tid)
            hits.append({"id": tid, "name": name})
    return hits


def detect_lolbins(tokens: List[str], interpreter: Optional[InterpreterProfile]) -> List[Dict[str, str]]:
    hits = []
    seen = set()
    # Include the outer interpreter if it's a known LOLBin
    if interpreter and interpreter.lolbin and interpreter.name not in seen:
        seen.add(interpreter.name)
        hits.append({"name": interpreter.name, "role": "outer interpreter"})
    # Scan tokens for other LOLBin executables
    for tok in tokens:
        base = tok.strip('"\'').rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
        key = _INTERPRETER_INDEX.get(base)
        if key and INTERPRETERS[key].lolbin and key not in seen:
            seen.add(key)
            hits.append({"name": key, "role": "invoked binary"})
        # Also scan INSIDE multi-word tokens (e.g. PowerShell -c 'iex; rundll32
        # evil.dll,Main' becomes a single quoted token) for embedded LOLBin
        # invocations. Splits on shell/PS separators — space, semicolon, pipe,
        # comma, ampersand — and checks each sub-word against the LOLBin table.
        # Skip if the token was already a bare LOLBin name (handled above).
        if " " in base or ";" in base or "|" in base:
            for sub in re.split(r"[\s;|,&]+", tok.strip('"\'')):
                sub_base = sub.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
                sub_key = _INTERPRETER_INDEX.get(sub_base)
                if sub_key and INTERPRETERS[sub_key].lolbin and sub_key not in seen:
                    seen.add(sub_key)
                    hits.append({"name": sub_key, "role": "invoked binary (nested)"})
    return hits


# =============================================================================
# 7. Reconstruction — inline decoded content preserving syntax
# =============================================================================

def reconstruct_inline(original: str, spans: List[PayloadSpan],
                        decodes: List[Dict[str, Any]]) -> str:
    """Return the original command with each decoded span annotated inline as
    `«decoded: …»` — preserves the surrounding syntax so analysts can visually
    diff obfuscated vs decoded."""
    if not decodes:
        return original
    idx_map = {}
    for s, d in zip(spans, decodes):
        idx_map[s.span_text] = d.get("final_output") or ""
    out = original
    for span_text, decoded in idx_map.items():
        if not decoded: continue
        snippet = decoded.strip()
        if len(snippet) > 200:
            snippet = snippet[:200] + "…"
        replacement = f"{span_text} «decoded: {snippet}»"
        out = out.replace(span_text, replacement, 1)
    return out


# =============================================================================
# 8. Human-readable behavior summary
# =============================================================================

def summarize(interpreter: Optional[InterpreterProfile],
              behaviors: List[Dict[str, str]],
              iocs: Dict[str, Any],
              decodes: List[Dict[str, Any]]) -> str:
    parts = []
    if interpreter:
        parts.append(f"Runs under {interpreter.name}.")
    tags = {b["tag"] for b in behaviors}
    if "download-and-execute" in tags:
        parts.append("Pipeline downloads remote content and pipes it into an interpreter for in-memory execution.")
    else:
        if "network-fetch" in tags:
            parts.append("Performs a network fetch.")
        if "in-memory-execute" in tags:
            parts.append("Executes a payload in memory (no on-disk artifact).")
    if "persistence" in tags:
        parts.append("Establishes persistence.")
    if "file-decode" in tags:
        parts.append("Uses certutil as a file decoder (living-off-the-land).")
    if any(d.get("is_shellcode") for d in decodes):
        parts.append("At least one decoded layer produced binary shellcode — route to disassembler.")
    if iocs.get("urls"):
        parts.append(f"IOC — URLs: {', '.join(iocs['urls'][:3])}.")
    if not parts:
        parts.append("No obfuscated payload or high-risk behavior detected.")
    return " ".join(parts)


# =============================================================================
# 9. Main entry
# =============================================================================

def analyze_command(text: str,
                     force_decode_span: Optional[str] = None) -> Dict[str, Any]:
    """Full analyst-focused command-line analysis.

    Args:
        text                — the raw command line
        force_decode_span   — optional span text the analyst picked from a
                              `needs_choice` prompt. When provided, that span
                              is decoded even if its confidence is <0.80.
    """
    if not text or not text.strip():
        return {"error": "empty input"}
    text = text.strip()

    prof = detect_interpreter(text)
    pipeline = split_pipeline(text)
    # Tokenise the first (or only) segment for arg profile matching. Downstream
    # segments still contribute to behavior classification.
    primary_seg = pipeline[0]["cmd"] if pipeline else text
    tokens = tokenize(primary_seg)

    # Parsed structure ---------------------------------------------------------
    executable = tokens[0] if tokens else ""
    switches = [t for t in tokens[1:] if t.startswith(("-", "/"))]
    non_switches = [t for t in tokens[1:] if not t.startswith(("-", "/"))]
    parsed_structure = {
        "interpreter":       prof.name if prof else "generic",
        "executable":        executable,
        "switches":          switches,
        "arguments":         non_switches,
        "pipeline_segments": [p["cmd"] for p in pipeline],
        "pipeline_ops":      [p["op"]  for p in pipeline if p["op"]],
        "token_count":       len(tokens),
    }

    # Payload spans ------------------------------------------------------------
    spans = _find_payload_spans(text, tokens, prof)
    # Filter out spans that sit inside file-operand tokens (certutil -decode file.b64)
    if prof:
        spans = [s for s in spans if not _is_inside_file_operand(s.span_text, tokens, prof)]

    # Confidence gate + tie detection ------------------------------------------
    high_conf = [s for s in spans if s.confidence >= 0.80]
    needs_choice = False
    choice_reason = ""
    if high_conf:
        top = high_conf[0].confidence
        near = [s for s in high_conf if abs(s.confidence - top) <= 0.05]
        if len(near) >= 2 and force_decode_span is None:
            # Multiple tied candidates — surface to the analyst.
            needs_choice = True
            choice_reason = f"Multiple payload candidates tied within 0.05 confidence of {top:.2f}"

    # Decoding decision --------------------------------------------------------
    to_decode: List[PayloadSpan] = []
    if force_decode_span:
        for s in spans:
            if s.span_text == force_decode_span:
                to_decode.append(s); break
    elif not needs_choice:
        to_decode = high_conf

    decodes: List[Dict[str, Any]] = [_decode_span(s) for s in to_decode]

    # ----- Recursive re-analysis of decoded payloads --------------------
    # If a decoded output *itself* contains new inline payloads (nested
    # FromBase64String, -Enc value, atob(...), long base64, hex strings, etc.),
    # feed it back through the pipeline. This trains the analyzer to peel
    # every layer without the analyst needing to click twice.
    _MAX_NESTED = 3
    _seen_span_hashes = {hash((s.span_text, s.encoding)) for s in to_decode}
    frontier = list(decodes)
    # For each freshly-decoded output, capture any XOR key referenced in its
    # own body so we can carry it forward when we peel nested payloads.
    from payload_sanitizer import find_xor_key as _find_xor_key
    for _pass in range(_MAX_NESTED):
        next_frontier: List[Dict[str, Any]] = []
        for d in frontier:
            payload = d.get("final_output") or ""
            if d.get("is_shellcode") or not payload:
                continue
            if len(payload) < 32:
                continue
            parent_xor = _find_xor_key(payload)
            nested_spans = _find_payload_spans(payload, tokenize(payload), prof)
            nested_spans = [s for s in nested_spans if s.confidence >= 0.80
                            and hash((s.span_text, s.encoding)) not in _seen_span_hashes]
            for ns in nested_spans:
                _seen_span_hashes.add(hash((ns.span_text, ns.encoding)))
                sub = _decode_span(ns, hint_xor_key=parent_xor)
                sub["role"] = f"nested · {ns.role} (in {d['role']})"
                sub["nested_from"] = d.get("role")
                decodes.append(sub)
                next_frontier.append(sub)
        frontier = next_frontier
        if not frontier:
            break

    # PowerShell AST deobfuscation — post-decode polish. Apply to (a) the raw
    # command if the interpreter is PowerShell, and (b) each decoded output
    # so nested obfuscation gets resolved too.
    ast_report: Dict[str, Any] = {"applied": False, "transformations": [],
                                   "bindings": {}, "final": ""}
    # Trigger AST deobfuscation when we recognise the interpreter as PowerShell
    # OR when the raw text carries strong PowerShell syntax markers even in the
    # absence of an explicit `powershell.exe` prefix.
    ps_hints = bool(re.search(
        r"(?:\$\w+\s*=|\[Convert\]::|\[char\]\d|\bIEX\b|\bInvoke-Expression\b|"
        r"FromBase64String|-bxor|-f\s*['\"]|\.Replace\s*\(|`[a-zA-Z0-9])",
        text,
    ))
    if (prof and prof.name == "powershell") or ps_hints:
        combined = "\n".join([text] + [d.get("final_output") or "" for d in decodes])
        deob = deobfuscate_ps(combined)
        if deob["transformations"]:
            ast_report = {
                "applied":         True,
                "transformations": deob["transformations"],
                "bindings":        deob["bindings"],
                "final":           deob["output"],
            }
            # If the deobfuscated output differs materially from the raw
            # command, treat it as an additional "decode chain" so it flows
            # into IOC extraction, MITRE mapping and behavior classification.
            if deob["output"] and deob["output"] != combined:
                decodes.append({
                    "span": text[:200] + ("…" if len(text) > 200 else ""),
                    "encoding": "ps-ast",
                    "role": "PowerShell AST deobfuscation",
                    "confidence": 0.90,
                    "chains": [{
                        "engine": "ps-ast",
                        "steps": [{"op": t["kind"], "reason": t.get("detail", "")}
                                  for t in deob["transformations"]],
                        "output": deob["output"],
                    }],
                    "final_output": deob["output"],
                    "is_shellcode": False,
                })

    # AMSI / ETW bypass detection — scan the raw command AND every decoded /
    # deobfuscated layer. Bypasses commonly hide inside base64 wrappers.
    scan_text = "\n".join(
        [text] + [d.get("final_output") or "" for d in decodes] + [ast_report.get("final") or ""]
    )
    amsi = detect_amsi_bypass(scan_text)

    # Aggregate IOCs / MITRE / behaviors ---------------------------------------
    combined_text = "\n".join([text] + [d.get("final_output") or "" for d in decodes]
                              + [ast_report.get("final") or ""])
    iocs        = extract_iocs(combined_text)

    # Merge IOCs from any shellcode buffers via the binary IOC extractor —
    # catches C2 IPs / user-agents embedded in raw shellcode strings.
    try:
        from shellcode_analyzer import extract_iocs as _binary_iocs
        for d in decodes:
            if not d.get("is_shellcode"):
                continue
            fo = d.get("final_output") or ""
            raw = fo.encode("latin-1") if all(ord(c) < 256 for c in fo) \
                                       else fo.encode("utf-8", errors="replace")
            b = _binary_iocs(raw)
            # merge unique
            for k in ("urls", "ips", "domains", "regkeys", "mutexes", "imports"):
                for v in b.get(k) or []:
                    if v not in iocs.get(k, []):
                        iocs.setdefault(k, []).append(v)
            for h in ("md5", "sha1", "sha256"):
                for v in (b.get("hashes") or {}).get(h) or []:
                    if v not in iocs["hashes"].get(h, []):
                        iocs["hashes"].setdefault(h, []).append(v)
    except Exception:
        pass
    behaviors   = classify_behaviors(pipeline, text, prof)
    exec_flow   = _execution_flow(combined_text)
    if amsi["detected"]:
        behaviors.append({
            "tag":    "amsi-bypass",
            "detail": f"AMSI/ETW bypass detected ({amsi['severity']}): "
                      f"{amsi['techniques'][0]['name']}",
        })
    mitre       = map_mitre(combined_text)
    # Add MITRE mapping surfaced by the AMSI detector (with dedup)
    seen_mitre = {m["id"] for m in mitre}
    for t in amsi["techniques"]:
        mid = t["mitre_id"]
        if mid not in seen_mitre:
            seen_mitre.add(mid)
            mitre.append({"id": mid, "name": "Impair Defenses (Disable/Modify Tools)"
                                          if mid == "T1562.001"
                                          else "Impair Defenses (Indicator Blocking)"
                                          if mid == "T1562.006"
                                          else mid})
    lolbins     = detect_lolbins(tokens, prof)
    inline      = reconstruct_inline(text, to_decode, decodes)
    summary     = summarize(prof, behaviors, iocs, decodes)

    return {
        "original_command":       text,
        "parsed_structure":       parsed_structure,
        "identified_payloads":    [
            {
                "span":       s.span_text,
                "encoding":   s.encoding,
                "role":       s.role,
                "confidence": round(s.confidence, 3),
                "reason":     s.reason,
                "offset":     s.offset,
                "auto_decoded": s in to_decode,
            } for s in spans
        ],
        "needs_choice":           needs_choice,
        "choice_reason":          choice_reason,
        "decode_chains":          decodes,
        "final_decoded_inline":   inline,
        "ast_deobfuscation":      ast_report,
        "amsi_bypass":            amsi,
        "iocs":                   iocs,
        "lolbins":                lolbins,
        "mitre":                  mitre,
        "behaviors":              behaviors,
        "execution_flow":         exec_flow,
        "behavior_summary":       summary,
        "raw_tokens":             tokens,
    }
