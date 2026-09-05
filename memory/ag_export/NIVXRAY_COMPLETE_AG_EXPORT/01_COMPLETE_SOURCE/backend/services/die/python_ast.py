"""
DIE · Python semantic AST
─────────────────────────
Deterministic Python analyser focused on security-relevant patterns:
dynamic exec/eval, subprocess use, base64/marshal/pickle decode
chains, __import__ tricks, and requests / urllib download cradles.
"""
from __future__ import annotations
import re
from typing import Any, Dict, List

from .ioc_semantic import extract_iocs, summarize_iocs

_IMPORT_RE = re.compile(r"^(?:from\s+([\w\.]+)\s+import|import\s+([\w\.]+))",
                        re.M)
_FN_RE     = re.compile(r"^\s*def\s+([A-Za-z_][\w]*)\s*\(", re.M)
_CLASS_RE  = re.compile(r"^\s*class\s+([A-Za-z_][\w]*)", re.M)

_DYNAMIC_EXEC = ("exec(", "eval(", "compile(", "__import__(", "marshal.loads",
                 "pickle.loads")
_SUBPROC      = ("subprocess.popen", "subprocess.call", "subprocess.run",
                 "os.system", "os.popen", "os.execv", "commands.getoutput")
_HTTP_DL      = ("requests.get", "requests.post", "urllib.request",
                 "urllib2.urlopen", "urlretrieve", "http.client",
                 "httpx.get", "httpx.post")
_ENCODE_HINTS = ("base64.b64decode", "codecs.decode", "zlib.decompress",
                 "gzip.decompress", "bytes.fromhex", ".decode('base64'",
                 "codecs.encode")


def parse_python(src: str) -> Dict[str, Any]:
    if not isinstance(src, str):
        src = str(src or "")

    lower = src.lower()
    imports = sorted({(m.group(1) or m.group(2))
                      for m in _IMPORT_RE.finditer(src)})
    funcs   = sorted({m.group(1) for m in _FN_RE.finditer(src)})
    classes = sorted({m.group(1) for m in _CLASS_RE.finditer(src)})

    flags = {
        "dynamic_exec":     any(h in lower for h in _DYNAMIC_EXEC),
        "subprocess_use":   any(h in lower for h in _SUBPROC),
        "http_download":    any(h in lower for h in _HTTP_DL),
        "encoded_payload":  any(h in lower for h in _ENCODE_HINTS),
        "compiled_bytecode": "marshal" in lower or "pyc" in lower,
        "getattr_indirect": lower.count("getattr(") > 3,
    }

    techniques = _techniques(flags)
    iocs = extract_iocs(src, source="raw")

    return {
        "language":     "python",
        "imports":      imports,
        "functions":    funcs,
        "classes":      classes,
        "flags":        flags,
        "techniques":   techniques,
        "iocs":         iocs,
        "iocs_summary": summarize_iocs(iocs),
        "complexity": {
            "obfuscation_score":
                min(100,
                    (25 if flags["dynamic_exec"] else 0)
                    + (20 if flags["encoded_payload"] else 0)
                    + (10 if flags["getattr_indirect"] else 0)
                    + (10 if flags["compiled_bytecode"] else 0)
                    + (10 if len(imports) > 20 else 0)),
            "import_count": len(imports),
            "fn_count":     len(funcs),
        },
    }


def _techniques(flags: Dict[str, bool]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if flags["dynamic_exec"] or flags["encoded_payload"]:
        out.append({"id": "T1027", "name": "Obfuscated Files or Information",
                    "evidence": "Python exec/eval or base64/marshal decode chain."})
    if flags["subprocess_use"]:
        out.append({"id": "T1059.006", "name": "Python",
                    "evidence": "subprocess / os.system RCE."})
    if flags["http_download"]:
        out.append({"id": "T1105", "name": "Ingress Tool Transfer",
                    "evidence": "requests / urllib download."})
    return out
