"""Batch / CMD env-var substitution decoders (RC4.0 Pattern 4 · Feb 2026).

Handles the CMD.EXE `%VAR:from=to%` substitution obfuscation:

    set p=c_a_l_c_._e_x_e && start "" %p:_=%

The `%p:_=%` construct expands `%p%` and strips every underscore. Attackers
inject arbitrary separator chars so an AV/EDR string-scanner sees only
`c_a_l_c_._e_x_e` and misses `calc.exe`.

Also handles `%SystemRoot:~0,1%`-style substring pickers (Pattern 6):

    %SystemRoot:~0,1%%TEMP:~-1,1%…   → C\\    (concatenation of substrings)

The substring picker plugin knows the classic Windows env vars (SystemRoot,
TEMP, ProgramFiles, ComSpec, PATH, USERPROFILE, WINDIR, APPDATA) and returns
the concatenated result deterministically.
"""
from __future__ import annotations

import re
from typing import Any, Dict, Optional

from operations import op


# ── Pattern 4 · SET var + %var:from=to% substitution ───────────────────────
#
# The `SET var=…` and `%var:from=to%` may live in different segments of a
# multi-line batch file, so we scan the ENTIRE input for both.

_SET_RE = re.compile(r"""(?:^|[\s&])set\s+(\w+)\s*=\s*([^\r\n&|<>]+?)(?=\s*(?:&&?|\|\|?|$|\r|\n))""",
                     re.IGNORECASE | re.MULTILINE)
_SUB_RE = re.compile(r"""%(\w+):([^=%]{0,64})=([^%]{0,64})%""")


@op("batch-envvar-substitute",
    "Batch %VAR:from=to% string substitution",
    "Malware Loaders",
    "Decodes CMD.EXE variable-substitution obfuscation: `set p=c_a_l_c_._e_x_e "
    "&& start \"\" %p:_=%` → `start \"\" calc.exe`. Extracts every `SET VAR=...` "
    "assignment, applies `%VAR:from=to%` substitutions deterministically, and "
    "rewrites the command line so string-scanning IOC extractors see the real "
    "target executable / URL.")
def op_batch_envvar_substitute(data: str, args: Dict[str, Any] | None = None) -> str:
    src = data or ""

    # Extract SET assignments — {var_name: value}
    env: Dict[str, str] = {}
    for m in _SET_RE.finditer(src):
        env[m.group(1).lower()] = m.group(2).strip().strip('"').strip("'")

    if not env or not _SUB_RE.search(src):
        return "(batch-envvar-substitute · no set-var + %VAR:from=to% pattern)"

    def _resolve_sub(match: re.Match) -> str:
        var = match.group(1).lower()
        frm = match.group(2)
        to  = match.group(3)
        val = env.get(var)
        if val is None:
            return match.group(0)
        return val.replace(frm, to) if frm else val

    # Also resolve bare `%VAR%` expansion for the same env.
    def _resolve_bare(match: re.Match) -> str:
        var = match.group(1).lower()
        return env.get(var, match.group(0))

    # Multi-pass — `%a%%b%` cascades.
    prev = None
    out = src
    passes = 0
    while out != prev and passes < 6:
        prev = out
        out = _SUB_RE.sub(_resolve_sub, out)
        out = re.sub(r"%(\w+)%", _resolve_bare, out)
        passes += 1

    return out if out != src else "(batch-envvar-substitute · substitution produced no change)"


# ── Pattern 6 · CMD env-var substring picker ─────────────────────────────
#
# `%SystemRoot:~0,1%` slices character index 0 (length 1) from SystemRoot=`C:\Windows`
# → `C`.  Attackers concatenate multiple slices to spell out arbitrary strings:
#
#    %SystemRoot:~0,1%%TEMP:~-1,1%   → e.g.  "C\\"
#
# We provide sensible defaults for the classic Windows env vars so the decode
# yields a deterministic result. Values match a stock Windows 10/11 install.

_DEFAULT_WINENV: Dict[str, str] = {
    "systemroot":      r"C:\Windows",
    "windir":          r"C:\Windows",
    "comspec":         r"C:\Windows\System32\cmd.exe",
    "programfiles":    r"C:\Program Files",
    "programfilesx86": r"C:\Program Files (x86)",
    "temp":            r"C:\Users\Public\AppData\Local\Temp",
    "tmp":             r"C:\Users\Public\AppData\Local\Temp",
    "userprofile":     r"C:\Users\Public",
    "appdata":         r"C:\Users\Public\AppData\Roaming",
    "localappdata":    r"C:\Users\Public\AppData\Local",
    "path":            r"C:\Windows\System32;C:\Windows;C:\Windows\System32\Wbem",
    "public":          r"C:\Users\Public",
    "systemdrive":     r"C:",
    "computername":    "COMPUTER",
    "username":        "user",
}

_SUBSTR_RE = re.compile(r"""%(\w+):~\s*(-?\d+)\s*(?:,\s*(-?\d+))?\s*%""")


@op("cmd-envvar-substring-picker",
    "CMD %VAR:~start,len% substring concat",
    "Malware Loaders",
    "Decodes CMD.EXE substring-picker obfuscation: `%SystemRoot:~0,1%` → `C`, "
    "`%ComSpec:~-1,1%` → last char of ComSpec. Uses stock Windows env-var "
    "defaults to deterministically evaluate every `%VAR:~a,b%` slice and "
    "returns the concatenated resulting command line so IOC/LOLBAS extractors "
    "see the reconstructed target.")
def op_cmd_envvar_substring_picker(data: str, args: Dict[str, Any] | None = None) -> str:
    src = data or ""

    # Allow analyst to override defaults via args.env = {"NAME": "VALUE"}
    env = dict(_DEFAULT_WINENV)
    if args and isinstance(args.get("env"), dict):
        for k, v in args["env"].items():
            env[k.lower()] = str(v)

    # Also honour any inline `set var=val` assignments in the payload.
    for m in _SET_RE.finditer(src):
        env[m.group(1).lower()] = m.group(2).strip().strip('"').strip("'")

    if not _SUBSTR_RE.search(src):
        return "(cmd-envvar-substring-picker · no %VAR:~start,len% pattern)"

    def _slice(match: re.Match) -> str:
        var = match.group(1).lower()
        try:
            start = int(match.group(2))
        except Exception:
            return match.group(0)
        length_str = match.group(3)
        val = env.get(var)
        if val is None:
            return match.group(0)  # unknown var — leave literal
        # Handle negative start (from end of string, CMD semantics).
        if start < 0:
            start = max(0, len(val) + start)
        if length_str is None:
            return val[start:]
        try:
            length = int(length_str)
        except Exception:
            return match.group(0)
        if length < 0:
            # `%V:~a,-N%` means "from index a to N chars from end".
            end = len(val) + length
            return val[start:end] if end > start else ""
        return val[start:start + length]

    out = _SUBSTR_RE.sub(_slice, src)
    return out if out != src else "(cmd-envvar-substring-picker · no substitution applied)"
