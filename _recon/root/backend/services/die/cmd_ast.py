"""
DIE · CMD / Batch semantic AST
──────────────────────────────
Deterministic Windows Command-Prompt analyser.  Emits the same shape
as the PowerShell AST so downstream consumers (Analyst Narrative
Generator · DKP enrichment · CEM emitter) treat all languages
uniformly.
"""
from __future__ import annotations
import re
from typing import Any, Dict, List

from .lolbas import lolbas_lookup
from .ioc_semantic import extract_iocs, summarize_iocs

# ── deterministic regexes ─────────────────────────────────────────
_VAR_RE      = re.compile(r"%[A-Za-z_][\w:]*%|![A-Za-z_][\w:]*!")
_LABEL_RE    = re.compile(r"^\s*:[A-Za-z_][\w]*", re.M)
_CMD_KEYWORDS = {
    "set","call","start","if","else","for","goto","echo","rem","del",
    "copy","move","xcopy","rename","md","mkdir","rd","rmdir","type",
    "cd","chdir","pushd","popd","exit","pause","cls","assoc","attrib",
    "cmd","shift","choice","find","findstr","sort","more","fc","tree",
    "verify","time","date","tasklist","taskkill","sc","net","netstat",
    "ipconfig","nslookup","ping","tracert","route","arp","hostname",
}

_HIDDEN_HINTS   = ("/min", "/hide", "/b ", "/b\n")
_ELEVATION      = ("runas", "-verb runas")
_DOWNLOAD_HINTS = ("curl", "wget", "certutil", "bitsadmin", "powershell", "iwr",
                   "invoke-webrequest", "start-bitstransfer")
_PERSISTENCE    = ("schtasks", "reg add", "wmic startup", "startup")
_SHADOW_DELETE  = ("vssadmin delete", "wbadmin delete", "bcdedit /set")
# ADR-0010e §10 item 4 · T1562.004 signature (owner sign-off 2026-08-12)
# `netsh advfirewall … state off` (any profile / all profiles) is the
# canonical MITRE-attested Disable-or-Modify-System-Firewall pattern.
# Matches the technique in `netsh advfirewall set (allprofiles|
# currentprofile|domainprofile|privateprofile|publicprofile) state off`
# and the equivalent `netsh firewall set opmode disable` legacy syntax.
_NETSH_FW_DISABLE_RE = re.compile(
    r"netsh\s+"
    r"(?:advfirewall\s+set\s+"
    r"(?:allprofiles|currentprofile|domainprofile|privateprofile|publicprofile)"
    r"\s+state\s+off"
    r"|firewall\s+set\s+opmode\s+disable)",
    re.I,
)
_LOLBIN_RE      = re.compile(r"[A-Za-z][\w\-]*\.exe", re.I)


def parse_cmd(src: str) -> Dict[str, Any]:
    """Deterministic CMD / Batch semantic extraction."""
    if not isinstance(src, str):
        src = str(src or "")

    lower = src.lower()
    lines = [ln.strip() for ln in src.splitlines() if ln.strip()]

    # Command chain heuristic — split on & && || | but keep piped
    # left-hand for later semantic pass.
    chains: List[str] = []
    for ln in lines:
        parts = re.split(r"&&|\|\||[&|]", ln)
        for p in parts:
            p = p.strip()
            if p:
                chains.append(p)

    # Extract commands / verbs
    commands: List[Dict[str, Any]] = []
    for idx, seg in enumerate(chains):
        first = seg.split()[0].lower() if seg.split() else ""
        commands.append({
            "text":  seg,
            "verb":  first if first in _CMD_KEYWORDS else None,
            "position": idx,
        })

    variables = sorted({m.group(0) for m in _VAR_RE.finditer(src)})
    labels    = [m.group(0).strip() for m in _LABEL_RE.finditer(src)]

    flags = {
        "hidden_window":     any(h in lower for h in _HIDDEN_HINTS),
        "elevation":         any(h in lower for h in _ELEVATION),
        "download_cradle":   any(h in lower for h in _DOWNLOAD_HINTS),
        "persistence":       any(h in lower for h in _PERSISTENCE),
        "shadow_delete":     any(h in lower for h in _SHADOW_DELETE),
        "delayed_expansion": "!" in src and any(v.startswith("!") for v in variables),
        "caret_obfuscation": src.count("^") >= 5,
        "wmic_exec":         "wmic" in lower and ("process call create" in lower
                                                   or "call create" in lower),
        "netsh_fw_disable":  bool(_NETSH_FW_DISABLE_RE.search(src)),
    }

    techniques = _techniques(flags)
    lolbins = _find_lolbins(src)
    iocs = extract_iocs(src, source="raw")

    return {
        "language":        "cmd",
        "commands":        commands,
        "variables":       variables,
        "labels":          labels,
        "chain_length":    len(chains),
        "flags":           flags,
        "techniques":      techniques,
        "lolbins":         lolbins,
        "iocs":            iocs,
        "iocs_summary":    summarize_iocs(iocs),
        "complexity": {
            "obfuscation_score":
                min(100,
                    (30 if flags["caret_obfuscation"] else 0)
                    + (15 if flags["delayed_expansion"] else 0)
                    + (10 if len(variables) > 8 else 0)
                    + (10 if len(chains) > 6 else 0)
                    + (10 if flags["wmic_exec"] else 0)),
            "chain_count":  len(chains),
            "var_count":    len(variables),
        },
    }


def _techniques(flags: Dict[str, bool]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if flags["download_cradle"]:
        out.append({"id": "T1105", "name": "Ingress Tool Transfer",
                    "evidence": "CMD download cradle (curl/certutil/bitsadmin/powershell)."})
    if flags["shadow_delete"]:
        out.append({"id": "T1490", "name": "Inhibit System Recovery",
                    "evidence": "vssadmin / wbadmin / bcdedit shadow-copy tamper."})
    if flags["persistence"]:
        out.append({"id": "T1053.005", "name": "Scheduled Task/Job",
                    "evidence": "schtasks / reg-add persistence."})
    if flags["wmic_exec"]:
        out.append({"id": "T1047", "name": "Windows Management Instrumentation",
                    "evidence": "wmic process call create — remote/local execution."})
    if flags["hidden_window"]:
        out.append({"id": "T1564.003", "name": "Hidden Window",
                    "evidence": "start /b or /min hidden execution."})
    if flags["caret_obfuscation"]:
        out.append({"id": "T1027", "name": "Obfuscated Files or Information",
                    "evidence": "CMD caret escaping / obfuscation."})
    if flags["netsh_fw_disable"]:
        out.append({"id": "T1562.004",
                    "name": "Impair Defenses: Disable or Modify System Firewall",
                    "evidence": "netsh advfirewall … state off — Windows Firewall disabled."})
    return out


def _find_lolbins(src: str) -> List[Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for m in _LOLBIN_RE.finditer(src):
        e = lolbas_lookup(m.group(0))
        if e:
            k = m.group(0).lower()
            out[k] = {"binary": k, **e}
    return sorted(out.values(), key=lambda x: x["binary"])
