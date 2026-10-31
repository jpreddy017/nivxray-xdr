"""
DIE · Bash semantic AST
───────────────────────
Deterministic Linux shell analyser.  Focuses on the security-relevant
patterns analysts see in droppers, initial-access, and post-exploit
scripts: curl-to-pipe cradles, eval/exec chains, base64 decode chains,
persistence via cron/systemd/service, and shadow-file tampering.
"""
from __future__ import annotations
import re
from typing import Any, Dict, List

from .lolbas import lolbas_lookup
from .ioc_semantic import extract_iocs, summarize_iocs

_VAR_RE   = re.compile(r"\$\{?[A-Za-z_][\w]*\}?")
_FN_RE    = re.compile(r"\b([A-Za-z_][\w]*)\s*\(\s*\)\s*\{", re.M)

_PIPE_TO_SHELL_RE = re.compile(
    r"(?:curl|wget|fetch)[^\|;\n]+\|\s*(?:bash|sh|/bin/(?:bash|sh)|zsh|dash)",
    re.I,
)
_B64_DECODE_RE = re.compile(r"base64\s+-d\b|base64\s+--decode\b", re.I)
_EVAL_HINTS    = ("eval ", "eval\t", "eval$", "eval\"", "exec ", "$(",
                  "`", "python -c", "perl -e", "ruby -e")
_PERSIST_HINTS = ("cron", "crontab", "systemd", "systemctl", "/etc/rc.local",
                  "/etc/init.d", ".bashrc", ".profile", "authorized_keys")
_SHADOW_HINTS  = ("/etc/shadow", "/etc/passwd", "chmod 777", "chmod +x")


def parse_bash(src: str) -> Dict[str, Any]:
    if not isinstance(src, str):
        src = str(src or "")

    lower = src.lower()
    variables = sorted({m.group(0) for m in _VAR_RE.finditer(src)})
    functions = sorted({m.group(1) for m in _FN_RE.finditer(src)})

    flags = {
        "pipe_to_shell":     bool(_PIPE_TO_SHELL_RE.search(src)),
        "base64_decode":     bool(_B64_DECODE_RE.search(src)),
        "eval_or_exec":      any(h in lower for h in _EVAL_HINTS),
        "persistence":       any(h in lower for h in _PERSIST_HINTS),
        "shadow_tamper":     any(h in lower for h in _SHADOW_HINTS),
        "reverse_shell":     bool(re.search(r"/dev/tcp/|/dev/udp/|bash\s+-i\s+>|/dev/null\s+2>&1", src, re.I)),
        "download_cradle":   any(w in lower for w in ("curl ", "wget ", "fetch ")),
    }

    techniques = _techniques(flags)
    iocs = extract_iocs(src, source="raw")

    return {
        "language":     "bash",
        "variables":    variables,
        "functions":    functions,
        "flags":        flags,
        "techniques":   techniques,
        "iocs":         iocs,
        "iocs_summary": summarize_iocs(iocs),
        "complexity": {
            "obfuscation_score":
                min(100,
                    (25 if flags["base64_decode"] else 0)
                    + (25 if flags["pipe_to_shell"] else 0)
                    + (20 if flags["eval_or_exec"] else 0)
                    + (15 if flags["reverse_shell"] else 0)),
            "var_count": len(variables),
            "fn_count":  len(functions),
        },
    }


def _techniques(flags: Dict[str, bool]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if flags["pipe_to_shell"] or flags["download_cradle"]:
        out.append({"id": "T1105", "name": "Ingress Tool Transfer",
                    "evidence": "curl/wget download cradle."})
    if flags["reverse_shell"]:
        out.append({"id": "T1059.004", "name": "Unix Shell",
                    "evidence": "bash /dev/tcp reverse-shell pattern."})
    if flags["persistence"]:
        out.append({"id": "T1053.003", "name": "Cron",
                    "evidence": "cron/systemd/rc-local persistence."})
    if flags["shadow_tamper"]:
        out.append({"id": "T1003.008", "name": "OS Credential Dumping",
                    "evidence": "/etc/shadow or /etc/passwd access."})
    if flags["base64_decode"] or flags["eval_or_exec"]:
        out.append({"id": "T1027", "name": "Obfuscated Files or Information",
                    "evidence": "base64 -d and/or eval chain."})
    return out
