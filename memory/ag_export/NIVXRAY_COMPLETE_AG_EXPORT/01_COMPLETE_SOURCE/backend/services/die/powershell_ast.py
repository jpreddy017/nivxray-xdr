"""
DIE · PowerShell Semantic AST
──────────────────────────────
Deterministic PowerShell analyzer built for security intelligence, not
compiler correctness.  Emits a structured record with everything a SOC
analyst needs to reason about a PowerShell payload without running it:

    { "tokens":       [ ... ],
      "statements":   [ ... ],
      "cmdlets":      [ {name, verb, noun, params, position}, ... ],
      "variables":    [ "$name", ... ],
      "pipelines":    [ [cmdlet_idx, cmdlet_idx, ...], ...],
      "flags":        { ... boolean signals ...},
      "techniques":   [ "encoded-command", "iex-invocation", ... ],
      "lolbins":      [ "certutil.exe", ... ],
      "iocs":         [ IOC records ],
      "complexity":   { "obfuscation_score": 0..100, ... },
    }

The AST is intentionally lean — we tokenize deterministically, do rule-
based semantic classification, and never invoke a real PowerShell
runtime.  Every technique flag maps back to a MITRE technique ID so
downstream analyzers can promote it into the CEM without further
processing.
"""
from __future__ import annotations
import base64
import re
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple

from .lolbas import lolbas_lookup
from .ioc_semantic import extract_iocs

# ── tokenization ──────────────────────────────────────────────────
# Deterministic PowerShell lexer.  Emits the smallest set of token
# kinds the security semantics layer needs — this is not a compiler
# tokenizer.
_TOKEN_SPEC: List[Tuple[str, str]] = [
    ("COMMENT",     r"\#[^\n]*"),
    ("STRING_S",    r"'(?:''|[^'])*'"),
    ("STRING_D",    r'"(?:`.|[^"])*"'),
    ("HERESTRING",  r"@['\"](?:.|\n)*?['\"]@"),
    ("NUMBER",      r"\b0x[0-9a-fA-F]+\b|\b\d+\b"),
    ("OP",          r"->|\|\||&&|-eq|-ne|-lt|-le|-gt|-ge|-and|-or|-not|-band|-bor|-xor|-shl|-shr|-replace|-match|-split|-join|-in|-notin|-contains|-notcontains|-like|-notlike|-is|-isnot|-as|::|\+=|-=|\*=|/=|%=|\+\+|--|=>|\.\.|\||;|&|="),
    ("BRACKET",     r"[\(\)\{\}\[\]]"),
    ("VAR",         r"\$(?:\{[^}]+\}|[A-Za-z_][\w:]*)"),
    ("PARAM",       r"-[A-Za-z][A-Za-z0-9]*(?::[^\s]*)?"),
    ("WORD",        r"[A-Za-z_][\w\-\.]*"),
    ("WS",          r"[ \t\r\n]+"),
    ("BACKTICK",    r"`."),
    ("MISC",        r"."),
]
_MASTER_RE = re.compile("|".join(f"(?P<{n}>{p})" for n, p in _TOKEN_SPEC))

# PowerShell verbs — deterministic list so we can recognize cmdlets by
# name shape (Verb-Noun) without a full dictionary.  Selected to cover
# the top ~95% of security-relevant activity.
_VERBS = {
    "add","clear","close","copy","enter","exit","find","format","get",
    "hide","join","lock","move","new","open","optimize","push","pop",
    "redo","remove","rename","reset","resize","search","select","set",
    "show","skip","split","step","switch","undo","unlock","update","use",
    "watch","backup","checkpoint","compare","complete","compress",
    "confirm","convert","deny","export","import","initialize","limit",
    "merge","mount","out","publish","restore","save","stop","start",
    "suspend","resume","invoke","measure","test","trace","wait",
    "debug","register","unregister","enable","disable","install",
    "uninstall","protect","unprotect","approve","request","submit",
    "encode","decode","download","upload",
}

_INVOKE_ALIASES = {"iex","invoke-expression","icm","invoke-command","&"}
_DOWNLOAD_HINTS = {
    "invoke-webrequest","iwr","curl","wget","invoke-restmethod","irm",
    "start-bitstransfer","new-object","system.net.webclient",
    "downloadstring","downloadfile","downloaddata",
}
_AMSI_HINTS = {
    "amsiutils","amsicontext","amsiscanbuffer","amsi_initfailed",
    "system.management.automation.amsiutils",
}
_REFLECTION_HINTS = {
    "system.reflection.assembly","reflection.emit","reflection.dynamicmethod",
    "system.runtime.interopservices.marshal","virtualalloc","virtualprotect",
    "kernel32.dll","user32.dll",
}
_ENCODED_FLAGS = {"-e","-en","-enc","-enco","-encod","-encode","-encoded","-encodedc","-encodedco",
                  "-encodedcom","-encodedcomm","-encodedcomma","-encodedcomman","-encodedcommand"}
_HIDDEN_FLAGS  = {"-w","-wi","-win","-wind","-windo","-window","-windows","-windowst","-windowsty",
                  "-windowstyl","-windowstyle"}
_NO_PROFILE    = {"-nop","-noprof","-noprofi","-noprofil","-noprofile"}
_BYPASS        = {"-executionpolicy","-ep","-exec"}

@dataclass
class Cmdlet:
    name: str
    verb: Optional[str]
    noun: Optional[str]
    params: Dict[str, Any] = field(default_factory=dict)
    position: int = 0

@dataclass
class Token:
    kind: str
    value: str
    pos: int


# ── tokenizer ─────────────────────────────────────────────────────
def _tokenize(src: str) -> List[Token]:
    out: List[Token] = []
    for m in _MASTER_RE.finditer(src):
        kind = m.lastgroup or "MISC"
        val  = m.group()
        if kind in ("WS", "COMMENT", "BACKTICK"):
            continue
        out.append(Token(kind, val, m.start()))
    return out


# ── parser (structural, not semantic-perfect) ─────────────────────
def _split_statements(tokens: List[Token]) -> List[List[Token]]:
    stmts: List[List[Token]] = []
    cur: List[Token] = []
    for t in tokens:
        if t.kind == "OP" and t.value in (";", "\n"):
            if cur:
                stmts.append(cur); cur = []
            continue
        cur.append(t)
    if cur:
        stmts.append(cur)
    return stmts


def _split_pipelines(stmt: List[Token]) -> List[List[Token]]:
    out: List[List[Token]] = []
    cur: List[Token] = []
    for t in stmt:
        if t.kind == "OP" and t.value == "|":
            if cur:
                out.append(cur); cur = []
            continue
        cur.append(t)
    if cur:
        out.append(cur)
    return out


def _extract_cmdlet(pipeline: List[Token], idx: int) -> Optional[Cmdlet]:
    # First non-string, non-var word/param is the cmdlet name (or an
    # alias like ``&``).  Params follow, alternating -Name value.
    head: Optional[str] = None
    params: Dict[str, Any] = {}
    i = 0
    while i < len(pipeline):
        t = pipeline[i]
        if head is None:
            if t.kind in ("WORD",):
                head = t.value
                i += 1
                continue
            if t.kind == "OP" and t.value == "&":
                head = "&"
                i += 1
                continue
            if t.kind == "VAR":
                head = t.value
                i += 1
                continue
            i += 1
            continue
        if t.kind == "PARAM":
            key = t.value.lstrip("-").split(":", 1)[0].lower()
            val: Any = True
            if ":" in t.value:
                val = t.value.split(":", 1)[1]
            elif i + 1 < len(pipeline) and pipeline[i+1].kind not in ("PARAM",):
                nxt = pipeline[i+1]
                if nxt.kind in ("STRING_S","STRING_D","HERESTRING"):
                    val = _unquote(nxt.value)
                else:
                    val = nxt.value
                i += 1
            params[key] = val
        i += 1
    if head is None:
        return None
    verb, noun = None, None
    if "-" in head and head.count("-") == 1:
        v, n = head.split("-", 1)
        if v.lower() in _VERBS:
            verb, noun = v.lower(), n.lower()
    return Cmdlet(name=head, verb=verb, noun=noun, params=params, position=idx)


def _unquote(s: str) -> str:
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "'\"":
        return s[1:-1]
    return s


# ── obfuscation scoring ───────────────────────────────────────────
def _obfuscation_score(src: str, tokens: List[Token]) -> int:
    score = 0
    if src.count("`") > 5: score += 15
    if src.count("^") > 5: score += 8
    if src.count("+") > 20: score += 8
    if src.count("{") + src.count("}") > 30: score += 6
    if re.search(r"\[char\]\s*\d+", src, re.I): score += 12
    if re.search(r"\[convert\]::frombase64string", src, re.I): score += 20
    if re.search(r"\.\s*replace\s*\(", src, re.I): score += 8
    if re.search(r"-join", src, re.I): score += 8
    if re.search(r"-f\s+[\d,\s\{\}\"']+", src, re.I): score += 10
    if re.search(r"\$env:", src, re.I): score += 4
    if len(tokens) > 0:
        var_count  = sum(1 for t in tokens if t.kind == "VAR")
        word_count = sum(1 for t in tokens if t.kind == "WORD")
        if word_count and var_count / max(1, word_count) > 0.5:
            score += 10
    return min(100, score)


# ── high-level analyzer ───────────────────────────────────────────
def parse_powershell(src: str) -> Dict[str, Any]:
    """Return the deterministic semantic AST for ``src``.

    ``src`` is treated as untrusted analyst input — this function does
    NOT execute or eval anything.
    """
    if not isinstance(src, str):
        src = str(src or "")

    tokens = _tokenize(src)
    statements = _split_statements(tokens)

    cmdlets: List[Cmdlet] = []
    pipelines: List[List[int]] = []
    for stmt in statements:
        pipeline_indices: List[int] = []
        for pipe_stage in _split_pipelines(stmt):
            c = _extract_cmdlet(pipe_stage, len(cmdlets))
            if c is not None:
                cmdlets.append(c)
                pipeline_indices.append(c.position)
        if pipeline_indices:
            pipelines.append(pipeline_indices)

    variables = sorted({t.value for t in tokens if t.kind == "VAR"})

    lower = src.lower()
    flags = {
        "encoded_command":   any(f in lower.split() for f in _ENCODED_FLAGS)
                             or bool(re.search(r"-e(?:nc(?:od(?:ed(?:command)?)?)?)?\s+[A-Za-z0-9+/=]{20,}", src, re.I)),
        "hidden_window":     any(f in lower for f in _HIDDEN_FLAGS)
                             and "hidden" in lower,
        "no_profile":        any(f in lower for f in _NO_PROFILE),
        "bypass_policy":     ("bypass" in lower and any(f in lower for f in _BYPASS))
                             or "unrestricted" in lower,
        "iex_invocation":    any(a in lower for a in _INVOKE_ALIASES),
        "download_cradle":   any(a in lower for a in _DOWNLOAD_HINTS),
        "amsi_bypass":       any(a in lower for a in _AMSI_HINTS),
        "reflection_load":   any(a in lower for a in _REFLECTION_HINTS),
        "clipboard_access":  "get-clipboard" in lower or "set-clipboard" in lower,
        "obfuscated_join":   "-join" in lower and ("[char]" in lower or "[byte]" in lower),
    }

    # Extract base64 payloads following -EncodedCommand.
    b64_payloads: List[str] = []
    for m in re.finditer(r"-e(?:nc(?:od(?:ed(?:command)?)?)?)?\s+([A-Za-z0-9+/=]{20,})",
                         src, re.I):
        b64_payloads.append(m.group(1))
    # Standalone base64 chunks embedded via [Convert]::FromBase64String("...")
    for m in re.finditer(r"frombase64string\(\s*['\"]([A-Za-z0-9+/=]+)['\"]", src, re.I):
        b64_payloads.append(m.group(1))

    decoded_previews: List[Dict[str, str]] = []
    for p in b64_payloads[:16]:
        try:
            raw = base64.b64decode(p, validate=False)
            # UTF-16LE is the default for -EncodedCommand.  Try UTF-16
            # first, then UTF-8, then latin-1 preview.
            for enc in ("utf-16-le", "utf-8", "latin-1"):
                try:
                    txt = raw.decode(enc)
                    decoded_previews.append({"b64": p[:80],
                                             "encoding": enc,
                                             "preview": txt[:400]})
                    break
                except UnicodeDecodeError:
                    continue
        except Exception:
            continue

    techniques = _techniques_from_flags(flags, decoded_previews)
    lolbins = _find_lolbins(src, cmdlets)
    iocs = extract_iocs(src, source="raw")
    for prev in decoded_previews:
        iocs.extend(extract_iocs(prev["preview"], source="decoded"))

    return {
        "tokens":     [asdict(Token(kind=t.kind, value=t.value, pos=t.pos))
                       for t in tokens[:400]],
        "token_count":     len(tokens),
        "statement_count": len(statements),
        "cmdlets":         [asdict(c) for c in cmdlets],
        "variables":       variables,
        "pipelines":       pipelines,
        "flags":           flags,
        "techniques":      techniques,
        "lolbins":         lolbins,
        "iocs":            _dedupe_iocs(iocs),
        "encoded_payloads": decoded_previews,
        "complexity": {
            "obfuscation_score": _obfuscation_score(src, tokens),
            "token_count":       len(tokens),
            "cmdlet_count":      len(cmdlets),
            "pipeline_count":    len(pipelines),
        },
    }


# ── helpers ───────────────────────────────────────────────────────
def _techniques_from_flags(flags: Dict[str, bool],
                            payloads: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if flags["encoded_command"] or payloads:
        out.append({"id": "T1027", "name": "Obfuscated Files or Information",
                    "evidence": "PowerShell -EncodedCommand or Base64 payload."})
    if flags["iex_invocation"]:
        out.append({"id": "T1059.001", "name": "PowerShell",
                    "evidence": "Invoke-Expression / IEX / & alias."})
    if flags["download_cradle"]:
        out.append({"id": "T1105", "name": "Ingress Tool Transfer",
                    "evidence": "Download cradle (WebClient / iwr / curl)."})
    if flags["amsi_bypass"]:
        out.append({"id": "T1562.001", "name": "Disable or Modify Tools",
                    "evidence": "AMSI reference — bypass pattern."})
    if flags["reflection_load"]:
        out.append({"id": "T1620", "name": "Reflective Code Loading",
                    "evidence": "System.Reflection.Assembly / VirtualAlloc."})
    if flags["hidden_window"]:
        out.append({"id": "T1564.003", "name": "Hide Artifacts: Hidden Window",
                    "evidence": "-WindowStyle Hidden."})
    if flags["bypass_policy"]:
        out.append({"id": "T1562.001", "name": "Disable or Modify Tools",
                    "evidence": "ExecutionPolicy Bypass / Unrestricted."})
    return out


def _find_lolbins(src: str, cmdlets: List[Cmdlet]) -> List[Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    # Look at every WORD-like token for a LOLBAS hit.
    for m in re.finditer(r"[A-Za-z][\w\-]*\.exe", src, re.I):
        entry = lolbas_lookup(m.group(0))
        if entry:
            out[m.group(0).lower()] = {"binary": m.group(0).lower(),
                                       **entry}
    for c in cmdlets:
        entry = lolbas_lookup(c.name)
        if entry:
            out[c.name.lower()] = {"binary": c.name.lower(), **entry}
    return sorted(out.values(), key=lambda x: x["binary"])


def _dedupe_iocs(iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: Dict[str, Dict[str, Any]] = {}
    for i in iocs:
        key = f"{i['kind']}:{i['value']}"
        prev = seen.get(key)
        if prev is None or prev["confidence"] < i["confidence"]:
            seen[key] = i
    return sorted(seen.values(), key=lambda x: (x["kind"], x["value"]))
