"""
DIE · VBScript semantic AST
───────────────────────────
Deterministic VBScript analyser.  Focuses on the security-relevant
constructs analysts encounter in phishing lures and initial-access
scripts: CreateObject/GetObject, WScript.Shell.Run, ADODB.Stream
writes, WMI abuse, and On Error Resume Next masking.
"""
from __future__ import annotations
import re
from typing import Any, Dict, List

from .lolbas import lolbas_lookup
from .ioc_semantic import extract_iocs, summarize_iocs

_DIM_RE    = re.compile(r"\bDim\s+([A-Za-z_][\w]*)", re.I)
_SET_RE    = re.compile(r"\bSet\s+([A-Za-z_][\w]*)\s*=\s*Create[Oo]bject\s*\(\s*['\"]([^'\"]+)['\"]", re.I)
_SUB_RE    = re.compile(r"\bSub\s+([A-Za-z_][\w]*)", re.I)
_FUNC_RE   = re.compile(r"\bFunction\s+([A-Za-z_][\w]*)", re.I)
_CALL_RE   = re.compile(r"\bCall\s+([A-Za-z_][\w.]*)", re.I)

_SHELL_HINTS    = ("wscript.shell", "shell.application")
_FSO_HINTS      = ("scripting.filesystemobject", "adodb.stream")
_HTTP_HINTS     = ("msxml2.xmlhttp", "winhttp.winhttprequest",
                   "msxml2.serverxmlhttp", "responsebody", "responsetext")
_WMI_HINTS      = ("winmgmts:", "swbemlocator", "getobject(\"winmgmts")
_ERROR_MASK     = ("on error resume next",)


def parse_vbscript(src: str) -> Dict[str, Any]:
    if not isinstance(src, str):
        src = str(src or "")

    lower = src.lower()
    dims   = sorted({m.group(1) for m in _DIM_RE.finditer(src)})
    sets   = [{"var": m.group(1), "type": m.group(2)} for m in _SET_RE.finditer(src)]
    subs   = sorted({m.group(1) for m in _SUB_RE.finditer(src)})
    funcs  = sorted({m.group(1) for m in _FUNC_RE.finditer(src)})
    calls  = sorted({m.group(1) for m in _CALL_RE.finditer(src)})

    flags = {
        "shell_execute":      any(h in lower for h in _SHELL_HINTS),
        "filesystem_write":   any(h in lower for h in _FSO_HINTS),
        "download_cradle":    any(h in lower for h in _HTTP_HINTS),
        "wmi_abuse":          any(h in lower for h in _WMI_HINTS),
        "error_masking":      any(h in lower for h in _ERROR_MASK),
        "createobject_count": lower.count("createobject("),
    }

    techniques = _techniques(flags)
    lolbins = _find_lolbins(src)
    iocs = extract_iocs(src, source="raw")

    return {
        "language":     "vbscript",
        "declarations": dims,
        "objects":      sets,
        "subs":         subs,
        "functions":    funcs,
        "calls":        calls,
        "flags":        flags,
        "techniques":   techniques,
        "lolbins":      lolbins,
        "iocs":         iocs,
        "iocs_summary": summarize_iocs(iocs),
        "complexity": {
            "obfuscation_score":
                min(100,
                    (20 if flags["error_masking"] else 0)
                    + (15 if flags["createobject_count"] > 3 else 0)
                    + (10 if flags["shell_execute"] else 0)
                    + (15 if flags["download_cradle"] else 0)
                    + (10 if flags["wmi_abuse"] else 0)),
            "sub_count":  len(subs),
            "func_count": len(funcs),
        },
    }


def _techniques(flags: Dict[str, bool]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if flags["shell_execute"]:
        out.append({"id": "T1059.005", "name": "Visual Basic",
                    "evidence": "WScript.Shell.Run / Shell.Application invocation."})
    if flags["download_cradle"]:
        out.append({"id": "T1105", "name": "Ingress Tool Transfer",
                    "evidence": "MSXML2.XMLHTTP / WinHTTP download."})
    if flags["filesystem_write"]:
        out.append({"id": "T1105", "name": "Ingress Tool Transfer",
                    "evidence": "ADODB.Stream / FileSystemObject writeout."})
    if flags["wmi_abuse"]:
        out.append({"id": "T1047", "name": "Windows Management Instrumentation",
                    "evidence": "GetObject('winmgmts:')."})
    if flags["error_masking"]:
        out.append({"id": "T1027", "name": "Obfuscated Files or Information",
                    "evidence": "On Error Resume Next — error masking."})
    return out


def _find_lolbins(src: str) -> List[Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for m in re.finditer(r"[A-Za-z][\w\-]*\.exe", src, re.I):
        e = lolbas_lookup(m.group(0))
        if e:
            k = m.group(0).lower()
            out[k] = {"binary": k, **e}
    return sorted(out.values(), key=lambda x: x["binary"])
