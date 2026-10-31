"""
DIE · JavaScript semantic AST
─────────────────────────────
Deterministic JS analyser focused on malicious/security-relevant
patterns: ActiveXObject abuse, XHR/fetch download cradles, eval,
Function-constructor code loading, WScript.Shell RCE, and encoded
payload embedding.  Not a full ECMAScript parser.
"""
from __future__ import annotations
import re
from typing import Any, Dict, List

from .lolbas import lolbas_lookup
from .ioc_semantic import extract_iocs, summarize_iocs

_STRING_RE = re.compile(r"'(?:\\'|[^'])*'|\"(?:\\\"|[^\"])*\"")
_VAR_RE    = re.compile(r"\b(?:var|let|const)\s+([A-Za-z_$][\w$]*)")
_CALL_RE   = re.compile(r"\b([A-Za-z_$][\w$\.]*)\s*\(")

_ACTIVEX_HINTS = ("activexobject", "wscript.shell", "scripting.filesystemobject",
                  "shell.application", "msxml2.xmlhttp", "winhttp.winhttprequest",
                  "adodb.stream", "wbemscripting.swbemlocator")
_DOWNLOAD_HINTS = ("xmlhttprequest", "fetch(", "axios.", "wscript.shell",
                   "adodb.stream", "responsebody", "responsetext")
_EVAL_HINTS     = ("eval(", "function(", "new function(", "settimeout('", "settimeout(\"")
_EXEC_HINTS     = (".run(", ".exec(", ".shellexecute", ".createobject")
_OBFUSC_HINTS   = ("string.fromcharcode", "unescape(", "atob(", "btoa(",
                   "parseint(", "\\x", "\\u00")


def parse_javascript(src: str) -> Dict[str, Any]:
    if not isinstance(src, str):
        src = str(src or "")

    lower = src.lower()
    strings = [m.group(0) for m in _STRING_RE.finditer(src)]
    vars_declared = sorted({m.group(1) for m in _VAR_RE.finditer(src)})
    calls = sorted({m.group(1).lower() for m in _CALL_RE.finditer(src)})

    flags = {
        "activex_abuse":     any(h in lower for h in _ACTIVEX_HINTS),
        "download_cradle":   any(h in lower for h in _DOWNLOAD_HINTS),
        "eval_or_function":  any(h in lower for h in _EVAL_HINTS),
        "shell_exec":        any(h in lower for h in _EXEC_HINTS),
        "obfuscation":       any(h in lower for h in _OBFUSC_HINTS),
        "createobject":      "createobject(" in lower,
        "hex_strings":       lower.count("\\x") > 8,
        "long_strings":      any(len(s) > 400 for s in strings),
    }

    techniques = _techniques(flags)
    lolbins = _find_lolbins(src, strings)
    iocs = extract_iocs(src, source="raw")

    return {
        "language":       "javascript",
        "declarations":   vars_declared,
        "calls":          calls,
        "string_count":   len(strings),
        "flags":          flags,
        "techniques":     techniques,
        "lolbins":        lolbins,
        "iocs":           iocs,
        "iocs_summary":   summarize_iocs(iocs),
        "complexity": {
            "obfuscation_score":
                min(100,
                    (25 if flags["hex_strings"] else 0)
                    + (15 if flags["long_strings"] else 0)
                    + (20 if flags["eval_or_function"] else 0)
                    + (10 if flags["obfuscation"] else 0)
                    + (10 if len(calls) > 20 else 0)),
            "call_count": len(calls),
        },
    }


def _techniques(flags: Dict[str, bool]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if flags["activex_abuse"] or flags["shell_exec"]:
        out.append({"id": "T1059.007", "name": "JavaScript",
                    "evidence": "ActiveXObject / WScript.Shell RCE."})
    if flags["download_cradle"]:
        out.append({"id": "T1105", "name": "Ingress Tool Transfer",
                    "evidence": "XHR / fetch / ADODB.Stream download."})
    if flags["eval_or_function"] or flags["obfuscation"]:
        out.append({"id": "T1027", "name": "Obfuscated Files or Information",
                    "evidence": "eval / Function constructor / fromCharCode / atob."})
    if flags["createobject"]:
        out.append({"id": "T1218.005", "name": "Mshta / Script-host Proxy",
                    "evidence": "CreateObject('...') script-host abuse."})
    return out


def _find_lolbins(src: str, strings: List[str]) -> List[Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    joined = src + " " + " ".join(strings)
    for m in re.finditer(r"[A-Za-z][\w\-]*\.exe", joined, re.I):
        e = lolbas_lookup(m.group(0))
        if e:
            k = m.group(0).lower()
            out[k] = {"binary": k, **e}
    return sorted(out.values(), key=lambda x: x["binary"])
