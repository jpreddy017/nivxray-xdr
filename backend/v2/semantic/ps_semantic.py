"""NivXRay PowerShell EncodedCommand Semantic Decoder (v3).

Turns a raw `powershell.exe -EncodedCommand <b64>` command line into a
fully decoded, semantically classified analyst report.

Pipeline:
    Raw command line
      → extract -EncodedCommand blob
      → Base64 decode
      → UTF-16LE decode
      → PowerShell AST (light regex-based tokenizer)
      → alias normalization (Start → Start-Process, iex → Invoke-Expression, …)
      → artifact extraction (URLs, IPs, cmdlets, args, files, registry)
      → host classification (loopback vs external)
      → behavior classification (Open Local Service, Download & Execute, …)
      → weighted verdict score (evidence-driven, not rule-triggered)
      → MITRE mapping (behavior-based only)

Deterministic — no LLM. Every conclusion traces back to a token in the
recovered script.
"""
from __future__ import annotations

import base64
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

# Phase 9.4 · NivXRay Semantic Intelligence
from v2.semantic.ps_ast import parse as _ast_parse, Script as _AstScript
from v2.semantic.ps_behaviors import (
    extract_behaviors as _extract_behaviors_v2,
    build_evidence_graph as _build_evidence_graph,
)
from v2.semantic.ps_decode_trace import DecodeTrace as _DecodeTrace
from v2.semantic.ps_verdict import compute_verdict as _compute_verdict_v2
from v2.semantic.ps_recovery import (
    recover_powershell_from_b64 as _recover_ps,
    looks_like_powershell as _looks_like_powershell,
)
from v2.semantic.ps_deobfuscate import deobfuscate as _deobfuscate
from v2.semantic.ps_storyline import build_storyline as _build_storyline

# ── Alias normalization table (PowerShell built-ins) ──────────────
_ALIASES = {
    "start": "Start-Process", "saps": "Start-Process",
    "ii": "Invoke-Item", "iex": "Invoke-Expression",
    "iwr": "Invoke-WebRequest", "curl": "Invoke-WebRequest", "wget": "Invoke-WebRequest",
    "irm": "Invoke-RestMethod",
    "ls": "Get-ChildItem", "dir": "Get-ChildItem", "gci": "Get-ChildItem",
    "cat": "Get-Content", "gc": "Get-Content", "type": "Get-Content",
    "cp": "Copy-Item", "copy": "Copy-Item", "cpi": "Copy-Item",
    "mv": "Move-Item", "move": "Move-Item", "mi": "Move-Item",
    "rm": "Remove-Item", "del": "Remove-Item", "erase": "Remove-Item", "ri": "Remove-Item",
    "sal": "Set-Alias", "sc": "Set-Content",
    "ni": "New-Item", "md": "New-Item", "mkdir": "New-Item",
    "pwd": "Get-Location", "cd": "Set-Location", "sl": "Set-Location",
    "echo": "Write-Output", "write": "Write-Output",
    "sleep": "Start-Sleep",
    "kill": "Stop-Process", "spps": "Stop-Process",
    "ps": "Get-Process", "gps": "Get-Process",
    "gu": "Get-Unique",
    "gsv": "Get-Service", "sv": "Set-Variable",
    "ac": "Add-Content",
    "select": "Select-Object", "where": "Where-Object", "foreach": "ForEach-Object",
    "sort": "Sort-Object", "group": "Group-Object", "measure": "Measure-Object",
    "tee": "Tee-Object",
}

# ── Behavior signature table (cmdlet → {category, weight, mitre}) ─
_BEHAVIOR_SIGS = {
    "Invoke-Expression":  {"cat": "Script Execution",       "w": 30, "mitre": ["T1059.001"]},
    "Invoke-WebRequest":  {"cat": "Download",               "w": 25, "mitre": ["T1105"]},
    "Invoke-RestMethod":  {"cat": "Download",               "w": 25, "mitre": ["T1105"]},
    "DownloadString":     {"cat": "Download",               "w": 30, "mitre": ["T1105"]},
    "DownloadFile":       {"cat": "Download",               "w": 30, "mitre": ["T1105"]},
    "DownloadData":       {"cat": "Download",               "w": 30, "mitre": ["T1105"]},
    "Start-Process":      {"cat": "Process Execution",      "w":  5, "mitre": []},
    "Start-Job":          {"cat": "Background Job",         "w": 10, "mitre": []},
    "New-Object":         {"cat": "Object Instantiation",   "w":  3, "mitre": []},
    "Add-Type":           {"cat": "Reflection / .NET Compile", "w": 35, "mitre": ["T1055", "T1027.004"]},
    "VirtualAlloc":       {"cat": "Memory Injection",       "w": 40, "mitre": ["T1055"]},
    "WriteProcessMemory": {"cat": "Memory Injection",       "w": 40, "mitre": ["T1055"]},
    "CreateThread":       {"cat": "Memory Injection",       "w": 40, "mitre": ["T1055"]},
    "CreateRemoteThread": {"cat": "Process Injection",      "w": 45, "mitre": ["T1055"]},
    "Set-MpPreference":   {"cat": "AMSI/Defender Tamper",   "w": 40, "mitre": ["T1562.001"]},
    "Register-ScheduledTask":  {"cat": "Persistence · Scheduled Task", "w": 35, "mitre": ["T1053.005"]},
    "New-ScheduledTask":       {"cat": "Persistence · Scheduled Task", "w": 35, "mitre": ["T1053.005"]},
    "New-Service":             {"cat": "Persistence · Service",        "w": 35, "mitre": ["T1543.003"]},
    "Set-ItemProperty":        {"cat": "Registry Modification",        "w": 15, "mitre": []},
    "New-ItemProperty":        {"cat": "Registry Modification",        "w": 15, "mitre": []},
    "Get-Credential":          {"cat": "Credential Access",            "w": 45, "mitre": ["T1056.002"]},
    "ConvertTo-SecureString":  {"cat": "Credential Access",            "w": 20, "mitre": []},
    "Get-WmiObject":           {"cat": "System Discovery",             "w":  8, "mitre": ["T1082"]},
    "Get-CimInstance":         {"cat": "System Discovery",             "w":  8, "mitre": ["T1082"]},
    "whoami":                  {"cat": "System Discovery",             "w":  5, "mitre": ["T1033"]},
    "Start-Sleep":             {"cat": "Timing / Sleep",               "w":  2, "mitre": []},
    "Invoke-Item":             {"cat": "Open Local Resource",          "w":  3, "mitre": []},
}

_URL_RE   = re.compile(r"https?://[^\s\"'<>\x00]{4,300}", re.I)
_HOST_RE  = re.compile(r"(?:(?<=://)|^)([A-Za-z0-9._-]+)(?::(\d+))?", re.I)
_IP_RE    = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_REG_RE   = re.compile(r"HK(?:CU|LM|CR|U|CC)[\\:][^\s\"']{3,200}", re.I)
_FILE_RE  = re.compile(r"[A-Za-z]:\\[^\s\"']{3,200}")
_ENCODED_RE = re.compile(
    r"-(?:enc(?:o(?:d(?:e(?:d(?:c(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?)?)?)?)?)?)\b\s+([A-Za-z0-9+/=]{16,})",
    re.I,
)


@dataclass
class SemanticArtifact:
    kind: str                        # url | ip | host | file | registry | cmdlet | arg
    value: str
    classification: str = ""         # loopback | private | external | local | …
    evidence: str = ""


@dataclass
class SemanticResult:
    detected: bool = False
    recovered_script: str = ""
    ast: list[dict] = field(default_factory=list)      # [{cmdlet, args:[...], line}]
    artifacts: list[SemanticArtifact] = field(default_factory=list)
    behaviors: list[dict] = field(default_factory=list)  # [{category, evidence, weight, mitre[]}]
    verdict: str = "unknown"
    verdict_reason: str = ""
    confidence: int = 0
    risk_score: int = 0
    mitre_ids: list[str] = field(default_factory=list)
    decode_outcome: str = "unsupported_encoding"
    # ── Phase 9.4 · Semantic Intelligence ────────────────────────
    behaviors_v2: list[dict] = field(default_factory=list)     # NivXRay-native taxonomy
    evidence_graph: dict = field(default_factory=dict)          # {nodes, edges}
    decode_timeline: list[dict] = field(default_factory=list)   # explainable decoder trace
    verdict_breakdown: dict = field(default_factory=dict)       # risk/behavior/ioc/obfuscation
    ast_tree: dict = field(default_factory=dict)                # rich AST for UI
    resolved_variables: dict = field(default_factory=dict)      # constant-folded values
    decode_error: dict = field(default_factory=dict)            # {status, attempts, causes, ...}
    deobfuscation: dict = field(default_factory=dict)           # recursive decode chain (2026-07-25)
    storyline: dict = field(default_factory=dict)                # behavior storyline (2026-07-27)

    def to_dict(self) -> dict:
        return {
            "detected":         self.detected,
            "recovered_script": self.recovered_script,
            "ast":              self.ast,
            "artifacts": [
                {"kind": a.kind, "value": a.value,
                 "classification": a.classification, "evidence": a.evidence}
                for a in self.artifacts
            ],
            "behaviors":      self.behaviors,
            "verdict":        self.verdict,
            "verdict_reason": self.verdict_reason,
            "confidence":     self.confidence,
            "risk_score":     self.risk_score,
            "mitre_ids":      self.mitre_ids,
            "decode_outcome": self.decode_outcome,
            # Phase 9.4
            "behaviors_v2":      self.behaviors_v2,
            "evidence_graph":    self.evidence_graph,
            "decode_timeline":   self.decode_timeline,
            "verdict_breakdown": self.verdict_breakdown,
            "ast_tree":          self.ast_tree,
            "resolved_variables": self.resolved_variables,
            "decode_error":      self.decode_error,
            "deobfuscation":     self.deobfuscation,
            "storyline":         self.storyline,
        }


# ── Host classification ───────────────────────────────────────────
def classify_host(host: str) -> str:
    """Return loopback | private | link_local | external | invalid."""
    if not host:
        return "invalid"
    h = host.strip().strip("[]").lower()
    if h in ("localhost", "::1"):
        return "loopback"
    try:
        ip = ipaddress.ip_address(h)
        if ip.is_loopback:      return "loopback"
        if ip.is_private:       return "private"
        if ip.is_link_local:    return "link_local"
        if ip.is_multicast:     return "multicast"
        if ip.is_reserved:      return "reserved"
        return "external"
    except ValueError:
        # Domain — classify by known-suffix
        if h.endswith(".local") or h.endswith(".internal") or h.endswith(".lan"):
            return "private"
        return "external"


# ── Extract & decode -EncodedCommand ─────────────────────────────
def extract_encoded_blob(cmdline: str) -> str | None:
    m = _ENCODED_RE.search(cmdline)
    if not m:
        return None
    blob = m.group(1)
    # Trim trailing tokens if the b64 ran into the next flag
    for i in range(len(blob), 15, -1):
        cand = blob[:i]
        if len(cand) % 4 == 0:
            return cand
    return blob


def decode_powershell_encoded(cmdline: str) -> str | None:
    """Return the recovered PowerShell script or None.

    STRICT: never returns latin-1 garbage. Delegates to the deterministic
    `recover_powershell_from_b64()` chain which validates every candidate
    with `looks_like_powershell()`.
    """
    blob = extract_encoded_blob(cmdline)
    if not blob:
        return None
    report = _recover_ps(blob)
    if report.status == "ok":
        return report.recovered_script.strip() or None
    return None


# ── Light PowerShell AST ─────────────────────────────────────────
_CMDLET_LINE = re.compile(
    r"(?ms)^\s*(?:&\s*)?"
    r"(?P<cmdlet>[A-Za-z][A-Za-z0-9\-]*|[a-z]+)"
    r"(?P<args>[^;\r\n]*)"
)


def parse_ast(script: str) -> list[dict]:
    """Very light regex-based cmdlet extractor. Splits on `;` and newlines."""
    if not script:
        return []
    ast: list[dict] = []
    for i, line in enumerate(re.split(r"[;\r\n]", script)):
        line = line.strip()
        if not line:
            continue
        m = _CMDLET_LINE.match(line)
        if not m:
            continue
        cmdlet = m.group("cmdlet")
        args_text = (m.group("args") or "").strip()
        norm = _ALIASES.get(cmdlet.lower(), cmdlet)
        # Break argument list on whitespace outside quotes.
        args = re.findall(r'"[^"]*"|\'[^\']*\'|\S+', args_text)
        args = [a.strip('"\'') for a in args]
        ast.append({"line_no": i, "raw": line, "cmdlet": norm,
                    "alias": cmdlet if cmdlet.lower() in _ALIASES else "",
                    "args": args})
    return ast


# ── Artifact extraction ──────────────────────────────────────────
def extract_artifacts(script: str, ast: list[dict]) -> list[SemanticArtifact]:
    out: list[SemanticArtifact] = []
    seen: set[tuple[str, str]] = set()

    def _add(kind: str, value: str, cls: str = "", evidence: str = ""):
        k = (kind, value)
        if k in seen:
            return
        seen.add(k)
        out.append(SemanticArtifact(kind=kind, value=value,
                                    classification=cls, evidence=evidence))

    for u in _URL_RE.findall(script):
        try:
            parsed = urlparse(u)
            host = parsed.hostname or ""
            port = str(parsed.port) if parsed.port else ""
        except Exception:
            host, port = "", ""
        cls  = classify_host(host)
        _add("url", u, cls,
             f"URL discovered in recovered script; host `{host}` classified as {cls}.")
        if host:
            _add("host", host, cls, f"Extracted from URL {u!r}.")
        if port:
            _add("port", port, "", f"Port from {u!r}.")
    for ip in _IP_RE.findall(script):
        cls = classify_host(ip)
        _add("ip", ip, cls, f"IPv4 literal in script; classified as {cls}.")
    for rk in _REG_RE.findall(script):
        _add("registry", rk, "", "Registry path referenced in script.")
    for fp in _FILE_RE.findall(script):
        _add("file", fp, "", "File path referenced in script.")
    for step in ast:
        _add("cmdlet", step["cmdlet"], "",
             f"AST step: `{step['raw'][:120]}`")
    return out


# ── Behavior classification & weighted verdict ───────────────────
def classify_behaviors(script: str, ast: list[dict],
                       artifacts: list[SemanticArtifact]) -> list[dict]:
    """Match cmdlets + string patterns to the behavior signature table."""
    behaviors: list[dict] = []
    seen: set[str] = set()

    def _push(cat: str, evidence: str, weight: int, mitre: list[str]):
        if cat in seen:
            return
        seen.add(cat)
        behaviors.append({"category": cat, "evidence": evidence,
                          "weight": weight, "mitre": mitre})

    lower = script.lower()
    for step in ast:
        sig = _BEHAVIOR_SIGS.get(step["cmdlet"])
        if sig:
            _push(sig["cat"], f"AST cmdlet `{step['cmdlet']}` on line {step['line_no']+1}",
                  sig["w"], sig["mitre"])
    # Substring scan for method calls (`.DownloadString`, `.VirtualAlloc`, …)
    for token, sig in _BEHAVIOR_SIGS.items():
        if "." + token.lower() in lower or token.lower() + "(" in lower:
            _push(sig["cat"], f"Method call `{token}` in script text",
                  sig["w"], sig["mitre"])
    # Refine "Process Execution → Open Local Resource" when target is loopback
    has_ext_url = any(a.kind == "url" and a.classification == "external" for a in artifacts)
    has_local_url = any(a.kind == "url" and a.classification == "loopback" for a in artifacts)
    if has_local_url and not has_ext_url:
        for b in behaviors:
            if b["category"] == "Process Execution":
                b["category"] = "Open Local Service"
                b["weight"] = 0
    if has_ext_url:
        _push("External Network Communication",
              "Recovered script references external URL(s).", 20, ["T1071.001"])
    elif has_local_url:
        _push("Open Local Service",
              "Recovered script targets a loopback / local URL — "
              "no external network communication observed.",
              0, [])
    return behaviors


def score_verdict(behaviors: list[dict], artifacts: list[SemanticArtifact],
                  encoded_present: bool) -> tuple[str, int, str, int]:
    score = 0
    reasons: list[str] = []
    if encoded_present:
        score += 10
        reasons.append("PowerShell EncodedCommand present (+10)")
    for b in behaviors:
        score += b["weight"]
        if b["weight"]:
            reasons.append(f"{b['category']} (+{b['weight']})")
    # Loopback resolves to zero-risk unless combined with high-weight behavior.
    if any(a.classification == "loopback" for a in artifacts if a.kind in ("url", "ip", "host")):
        if score <= 20:
            reasons.append("All observed network targets are loopback (no external comms)")
    # Verdict bands
    # Feb-2026 · The bar for `suspicious` is intentionally low: any
    # EncodedCommand puts the sample in the SUSPICIOUS bucket even when
    # the recovered script is benign — because the ENCODING itself is a
    # defense-evasion signal that warrants analyst review. Only samples
    # with no encoding AND no notable behaviours fall to `informational`.
    if score >= 70:
        verdict = "malicious"
    elif score >= 30:
        verdict = "suspicious"
    elif encoded_present or score >= 10:
        verdict = "suspicious"      # bare encoded + benign body → still SUSPICIOUS
    else:
        verdict = "informational"
    confidence = min(95, 50 + min(45, len(behaviors) * 10))
    return verdict, score, "; ".join(reasons) or "no notable indicators", confidence


# ── Negative evidence detector ───────────────────────────────────
_NEG_EVIDENCE_TABLE = [
    ("Download",                  r"downloadstring|downloadfile|invoke-webrequest|invoke-restmethod|"
                                  r"\.downloaddata|curl\s|wget\s|certutil\s+-urlcache|bitsadmin"),
    ("Persistence",               r"scheduled\s*task|registry\s+run|hklm\\.*run|hkcu\\.*run|"
                                  r"new-service|register-scheduledtask|new-scheduledtask|"
                                  r"schtasks|new-item.*startup"),
    ("Process injection",         r"virtualalloc|writeprocessmemory|createremotethread|"
                                  r"createthread|ntmapviewofsection|reflection\.assembly::load|"
                                  r"add-type.*bytes"),
    ("Credential access",         r"mimikatz|sekurlsa|lsass|convertto-securestring|"
                                  r"get-credential|dpapi|ntds\.dit|sam\.hive|"
                                  r"sharphound|kerberoast"),
    ("External network communication",
                                  r"https?://(?!(?:localhost|127\.|10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[01])\.))"),
    ("Anti-forensics / log tampering",
                                  r"clear-eventlog|wevtutil\s+cl|set-mppreference|amsiinit"),
]


def negative_evidence(script: str) -> list[dict]:
    """Return a checklist of behaviours we EXPLICITLY did NOT observe
    in the recovered script. Analysts use this to know what was checked."""
    low = script.lower()
    out: list[dict] = []
    for label, pattern in _NEG_EVIDENCE_TABLE:
        observed = bool(re.search(pattern, low))
        out.append({"category": label, "observed": observed,
                    "check": pattern})
    return out


# ── NivXRay Investigation Summary block ──────────────────────────
def format_summary_block(sr: "SemanticResult") -> str:
    """Analyst-facing box-drawn summary — exactly the format the user
    approved. Returns a multi-line string suitable for copy-paste into
    a ticket or Slack message."""
    if not sr.detected:
        return ""
    bar = "━" * 66
    lines: list[str] = [bar, "NIVXRAY INVESTIGATION SUMMARY", bar, ""]
    # Classification + confidence
    verdict_pretty = {
        "malicious":      "Malicious",
        "suspicious":     "Suspicious",
        "needs_review":   "Needs Review",
        "informational":  "Informational",
        "unknown":        "Unknown",
    }.get(sr.verdict, sr.verdict.title())
    lines.append(f"Classification    {verdict_pretty}")
    lines.append(f"Confidence        {sr.confidence}%")
    lines.append("")
    # Primary finding — cmdlet + encoded flag
    if sr.ast:
        first = sr.ast[0]
        primary = f"PowerShell executed with {'Base64-encoded ' if 'base64' in (sr.decode_outcome or '').lower() or True else ''}command."
        # Actually always show 'Base64-encoded' since we came through EncodedCommand path
        primary = "PowerShell executed with Base64-encoded command."
        lines.append(f"Primary Finding")
        lines.append(f"  {primary}")
        lines.append("")
    # Recovered behavior
    ext_urls = [a for a in sr.artifacts if a.kind == "url" and a.classification == "external"]
    loop_urls = [a for a in sr.artifacts if a.kind == "url" and a.classification == "loopback"]
    if loop_urls and not ext_urls:
        beh = f"Decoded command launches a local HTTP endpoint ({loop_urls[0].value})."
    elif ext_urls:
        beh = f"Decoded command references external endpoint ({ext_urls[0].value})."
    elif sr.ast:
        first = sr.ast[0]
        beh = f"Decoded command invokes `{first['cmdlet']}`."
    else:
        beh = "Decoded content did not yield a recognisable command."
    lines.append("Recovered Behavior")
    lines.append(f"  {beh}")
    lines.append("")
    # Evidence checklist (positive)
    lines.append("Evidence")
    positive = ["Encoded PowerShell", "Decoded successfully"]
    if any(a.kind == "url" for a in sr.artifacts):    positive.append("URL extracted")
    if loop_urls:                                     positive.append(f"Localhost ({loop_urls[0].value.split('://')[1].split(':')[0]})")
    if ext_urls:                                      positive.append(f"External URL: {ext_urls[0].value}")
    if any(a.kind == "ip"   for a in sr.artifacts):   positive.append("IP address(es) extracted")
    if any(a.kind == "file" for a in sr.artifacts):   positive.append("File path(s) referenced")
    for p in positive:
        lines.append(f"  ✓ {p}")
    # Negative evidence — what we checked and did NOT find
    for ne in negative_evidence(sr.recovered_script):
        if not ne["observed"]:
            lines.append(f"  ✗ No {ne['category'].lower()} observed")
    lines.append("")
    # Reason
    lines.append("Reason for Verdict")
    if sr.verdict == "suspicious" and loop_urls and not ext_urls:
        lines.append("  Suspicious because an encoded PowerShell command was")
        lines.append("  executed. However, the recovered command only opens a")
        lines.append("  localhost endpoint. Available telemetry does not")
        lines.append("  demonstrate malicious post-exploitation.")
    elif sr.verdict == "malicious":
        lines.append(f"  Malicious — {sr.verdict_reason}")
    else:
        lines.append(f"  {sr.verdict_reason}")
    lines.append("")
    # Analyst action
    lines.append("Analyst Action")
    if sr.verdict == "suspicious" and loop_urls and not ext_urls:
        lines.append("  Review parent process, WinRM activity, child processes,")
        lines.append("  and network telemetry before confirming malicious activity.")
    elif sr.verdict == "malicious":
        lines.append("  Escalate to Tier-2. Isolate host if not already contained.")
        lines.append("  Rotate any exposed credentials and audit lateral movement.")
    else:
        lines.append("  Retain for correlation; no immediate action required.")
    lines.append("")
    lines.append(bar)
    return "\n".join(lines)


# ── LOLBAS binaries catalogue (non-PowerShell command-line LOLBINs) ─
# Maps a LOLBAS binary name (lowercase, without .exe) to the analyst-
# facing display name, its ATT&CK sub-technique, and the primary
# behavior tag from the NivXRay taxonomy. When a command line contains
# one of these binaries but no PowerShell markers, the Workspace still
# investigates it deterministically.
_LOLBAS_CATALOGUE: dict[str, dict[str, Any]] = {
    "mshta":       {"display": "mshta.exe",       "mitre": ["T1218.005"],
                    "behaviors": ["lolbin_abuse", "defense_evasion"]},
    "rundll32":    {"display": "rundll32.exe",    "mitre": ["T1218.011"],
                    "behaviors": ["lolbin_abuse", "defense_evasion"]},
    "regsvr32":    {"display": "regsvr32.exe",    "mitre": ["T1218.010"],
                    "behaviors": ["lolbin_abuse", "defense_evasion"]},
    "cscript":     {"display": "cscript.exe",     "mitre": ["T1059.007", "T1218"],
                    "behaviors": ["lolbin_abuse"]},
    "wscript":     {"display": "wscript.exe",     "mitre": ["T1059.005", "T1218"],
                    "behaviors": ["lolbin_abuse"]},
    "certutil":    {"display": "certutil.exe",    "mitre": ["T1140", "T1105"],
                    "behaviors": ["lolbin_abuse", "payload_decode"]},
    "bitsadmin":   {"display": "bitsadmin.exe",   "mitre": ["T1197", "T1105"],
                    "behaviors": ["lolbin_abuse", "bits_download"]},
    "msiexec":     {"display": "msiexec.exe",     "mitre": ["T1218.007"],
                    "behaviors": ["lolbin_abuse"]},
    "installutil": {"display": "installutil.exe", "mitre": ["T1218.004"],
                    "behaviors": ["lolbin_abuse", "defense_evasion"]},
    "regasm":      {"display": "regasm.exe",      "mitre": ["T1218.009"],
                    "behaviors": ["lolbin_abuse", "defense_evasion"]},
    "regsvcs":     {"display": "regsvcs.exe",     "mitre": ["T1218.009"],
                    "behaviors": ["lolbin_abuse", "defense_evasion"]},
    "msbuild":     {"display": "msbuild.exe",     "mitre": ["T1127.001"],
                    "behaviors": ["lolbin_abuse", "defense_evasion"]},
}

_LOLBAS_RE = re.compile(
    r"(?i)\b(" + "|".join(re.escape(k) for k in _LOLBAS_CATALOGUE) + r")(?:\.exe)?\b"
)


def _analyze_lolbas(cmdline: str, r: SemanticResult) -> SemanticResult:
    """Deterministic investigator for non-PowerShell LOLBAS command lines.

    Runs when `_PS_MARKER_RE` fails on the input but a known LOLBAS
    binary is present. The command line IS the payload — no decode
    happens. Extracts artifacts (URLs, hosts, files, registry keys),
    emits LOLBAS-specific behavior tags with MITRE mappings, computes
    the verdict, and builds an executive summary so the Workspace
    always has an analyst-ready investigation.
    """
    m = _LOLBAS_RE.search(cmdline)
    if not m:
        return r
    binary_key = m.group(1).lower()
    entry = _LOLBAS_CATALOGUE[binary_key]

    trace = _DecodeTrace()
    trace.add("lolbas_scanner", status="applied",
              reason=(f"Detected LOLBAS binary `{entry['display']}` in a "
                      f"non-PowerShell command line; the command itself is "
                      f"the payload — no decode required."),
              input_val=cmdline, output_val=cmdline)

    r.detected = True
    r.recovered_script = cmdline.strip()
    r.decode_outcome = "fully_decoded"

    # Extract IOCs (URLs, IPs, hosts, files, registry) — the same
    # regex-based extractor used for PowerShell scripts works on any
    # text so we get URL classification for free.
    r.ast = []  # non-PS AST is out of scope; entity extraction only
    r.artifacts = extract_artifacts(cmdline, r.ast)

    # The LOLBAS binary itself is an analyst-facing IOC — surface it
    # as a `file` artifact so downstream IOC panels always show
    # something for LOLBAS samples whose arguments are not URLs
    # (e.g. `mshta.exe "javascript:..."` or `rundll32.exe javascript:...`).
    seen_files = {a.value for a in r.artifacts if a.kind == "file"}
    if entry["display"] not in seen_files:
        r.artifacts.append(SemanticArtifact(
            kind="file", value=entry["display"],
            classification="lolbas",
            evidence=(f"LOLBAS binary `{entry['display']}` invoked directly — "
                       "IOC surfaced so analysts can pivot on this indicator."),
        ))

    # Emit LOLBAS behavior tags. Every LOLBAS binary carries at least
    # `lolbin_abuse` (T1218). Some carry additional tags for their
    # specific abuse patterns (e.g. certutil → payload_decode).
    from v2.semantic.ps_behaviors import _mk, TAXONOMY
    v2_behaviors = []
    for bid in entry["behaviors"]:
        if bid not in TAXONOMY:
            continue
        v2_behaviors.append(_mk(
            bid, confidence=90,
            rationale=(f"LOLBAS binary `{entry['display']}` invoked directly "
                       "on the command line — a well-documented Windows "
                       "living-off-the-land technique."),
        ))
    # External URL / host adds C2 / download tags
    has_external = any(a.classification == "external"
                        for a in r.artifacts if a.kind in ("url", "host"))
    if has_external and "remote_script_download" in TAXONOMY:
        v2_behaviors.append(_mk(
            "remote_script_download", confidence=85,
            rationale=(f"`{entry['display']}` references an external URL — "
                       "consistent with remote payload retrieval via "
                       "living-off-the-land binary."),
        ))
    if has_external and "external_network" in TAXONOMY:
        v2_behaviors.append(_mk(
            "external_network", confidence=85,
            rationale="External URL / host observed in LOLBAS command line.",
        ))

    r.behaviors_v2 = [b.to_dict() for b in v2_behaviors]
    trace.add("behavior_extractor_v2", status="applied",
              reason=(f"Extracted {len(v2_behaviors)} LOLBAS behavior "
                      "tag(s) from the command line."),
              input_val=cmdline,
              output_val=", ".join(b.id for b in v2_behaviors) or "(none)")

    # Union MITRE (behaviors + LOLBAS-specific)
    mitre_ids = set(entry["mitre"]) | {m for b in v2_behaviors for m in b.mitre}
    r.mitre_ids = sorted(mitre_ids)

    # Legacy behaviors list (for backward compat with older UI code)
    r.behaviors = [
        {"category": "LOLBIN Abuse",
         "evidence": f"`{entry['display']}` invoked directly on the command line",
         "weight": 40, "mitre": entry["mitre"]}
    ]
    if has_external:
        r.behaviors.append({
            "category": "External Network Communication",
            "evidence": "Command references an external URL / host.",
            "weight": 20, "mitre": ["T1071.001"],
        })

    # Verdict via the v2 engine (same one PowerShell uses) so scoring
    # stays consistent across both entry paths.
    ext_urls = sum(1 for a in r.artifacts
                    if a.kind == "url" and a.classification == "external")
    ext_ips  = sum(1 for a in r.artifacts
                    if a.kind == "ip"  and a.classification == "external")
    ioc_stats = {
        "external_urls":  ext_urls,
        "external_ips":   ext_ips,
        "ti_hits":        0,
        "hashes":         0,
        "decoder_layers": len(trace.steps),
    }
    breakdown = _compute_verdict_v2(v2_behaviors, ioc_stats,
                                     trace.to_list(),
                                     encoded_present=False)
    r.verdict_breakdown = breakdown.to_dict()
    r.verdict = breakdown.verdict
    r.risk_score = breakdown.risk_score
    r.confidence = breakdown.confidence
    r.verdict_reason = (f"LOLBAS binary `{entry['display']}` detected. "
                          "Verdict derived from behavior + IOC evidence.")

    # Storyline so Workspace has an executive summary + attack narrative
    r.storyline = _build_storyline(
        recovered_script=r.recovered_script,
        behaviors_v2=r.behaviors_v2,
        artifacts=[{"kind": a.kind, "value": a.value,
                    "classification": a.classification,
                    "evidence": a.evidence} for a in r.artifacts],
        deobfuscation={"stages": [], "final": r.recovered_script,
                        "boundary_op": None, "stopped_reason": "lolbas_direct_execution"},
        verdict_breakdown=r.verdict_breakdown,
    )

    # Populate the shape the audit / UI expect
    r.deobfuscation = {
        "stages": [],
        "final": r.recovered_script,
        "boundary_op": None,
        "stopped_reason": "lolbas_direct_execution",
    }
    r.decode_timeline = trace.to_list()
    return r


# ── Public entrypoint ────────────────────────────────────────────
def analyze(cmdline: str) -> SemanticResult:
    """Full deterministic semantic pass over a PowerShell command line."""
    r = SemanticResult()
    if not cmdline:
        return r
    # Detect PowerShell content by more than just the literal word
    # `powershell` — analysts frequently paste naked scripts (no
    # `powershell.exe` wrapper) using String.Format `-f`, `[String]::Join`,
    # `[Convert]::ToInt16`, `Invoke-Expression`, or cmdlet patterns like
    # `Verb-Noun`. Any strong PowerShell marker triggers analysis so the
    # Workspace and Auto-Investigate produce the same output on the same
    # sample (2026-07-27 · SOC user).
    _PS_MARKER_RE = re.compile(
        r"(?ix)"
        r"\bpowershell(?:\.exe)?\b"                          # explicit exe
        r"|\bpwsh(?:\.exe)?\b"                                # PowerShell 7+
        r"|-encodedcommand\b|-enc\b|-ec\b"                    # encoded-command flags
        r"|\biex\b|\binvoke-expression\b|\binvoke-webrequest\b|\binvoke-restmethod\b"
        r"|\[string\]::(?:join|format)\b"                     # .NET String static ops
        r"|\[char\s*\[\s*\]\s*\]|\[char\]\s*\("                # char[] / [char]( ... )
        r"|\[convert\]::(?:toint16|toint32|frombase64string)\b"
        r"|\[system\.text\.encoding\]::"                       # PS-specific .NET path
        r"|\[type\]\(\s*['\"]"                                 # [Type]("Foo") type coercion
        r"|\[reflection\.assembly\]|\[activator\]::"
        # Generic PowerShell Verb-Noun cmdlets (Get-Process, Where-Object,
        # ForEach-Object, Set-Variable, New-Item, Test-Path, etc.). This
        # is the analyst-visible signature — audit sample
        # `plain_get_process` was previously silently dropped because
        # `Get-Process` did not match any of the enumerated patterns above.
        r"|\b(?:Get|Set|New|Add|Remove|Clear|Copy|Move|Rename|Test|Start|Stop|"
        r"Restart|Suspend|Resume|Write|Read|Out|Import|Export|ConvertTo|"
        r"ConvertFrom|Select|Where|ForEach|Sort|Group|Measure|Format|"
        r"Compare|Enter|Exit|Invoke|Register|Unregister|Enable|Disable|"
        r"Install|Uninstall|Update|Publish|Save|Show|Hide|Send|Receive|"
        r"Push|Pop|Trace|Debug|Wait|Watch|Split|Join|Find|Search|"
        r"Resolve|Protect|Unprotect|Grant|Revoke|Lock|Unlock)-[A-Z][A-Za-z0-9]+\b"
    )
    if not _PS_MARKER_RE.search(cmdline):
        # Not PowerShell — but the Workspace must still investigate
        # non-PowerShell LOLBAS command lines (mshta, rundll32, regsvr32,
        # cscript, wscript, certutil, bitsadmin, msiexec, installutil,
        # regasm, regsvcs, msbuild). These bypass PowerShell entirely
        # yet remain among the most-abused Windows LOLBINs. The audit
        # revealed all six LOLBAS samples produced no analyst output at
        # all — no verdict, no IOCs, no executive summary. This path
        # closes that gap.
        return _analyze_lolbas(cmdline, r)
    encoded_blob = extract_encoded_blob(cmdline)
    encoded = encoded_blob is not None

    # ── Phase 9.4 · Explainable Decode Trace ─────────────────────
    trace = _DecodeTrace()
    trace.add("input_scanner", status="applied",
              reason=("Detected `powershell.exe` invocation in command line; "
                      "beginning semantic decode pipeline."),
              input_val=cmdline, output_val=cmdline)
    if encoded:
        trace.add("extract_encodedcommand", status="applied",
                  reason=("Located `-EncodedCommand` flag; extracted "
                          f"{len(encoded_blob)}-char Base64 blob."),
                  input_val=cmdline, output_val=encoded_blob or "")
    else:
        trace.skipped("extract_encodedcommand",
                      reason="No `-EncodedCommand` flag present in the command line.",
                      input_val=cmdline)

    script = None
    recovery_report = None
    if encoded:
        recovery_report = _recover_ps(encoded_blob)
        # Fold every recovery attempt into the timeline as its own step.
        # Base64 attempt
        trace.add("base64_decode",
                  status=("applied" if recovery_report.b64_status == "succeeded"
                          else "failed"),
                  reason=recovery_report.b64_reason,
                  input_val=encoded_blob or "",
                  output_val=(recovery_report.hex_preview or ""),
                  meta={"b64_bytes": recovery_report.b64_bytes,
                        "hex_preview": recovery_report.hex_preview})
        # Each decoder attempt from the recovery chain
        for att in recovery_report.attempts:
            if att.decoder == "base64_decode":
                continue    # already emitted above
            trace.add(
                att.decoder,
                status=("applied" if att.status == "succeeded"
                        else ("skipped" if att.status == "skipped" else "failed")),
                reason=att.reason,
                input_val="",
                output_val="",
                meta=att.meta,
            )
        if recovery_report.status == "ok":
            script = recovery_report.recovered_script
        else:
            # Halt semantic analysis — return a structured decode_error.
            r.decode_outcome = "decode_error"
            r.detected = True   # PowerShell WAS present, but we couldn't decode it
            r.decode_error = {
                "status":               recovery_report.status,
                "b64_bytes":            recovery_report.b64_bytes,
                "b64_status":           recovery_report.b64_status,
                "b64_reason":           recovery_report.b64_reason,
                "attempts":             [a.to_dict() for a in recovery_report.attempts],
                "possible_causes":      list(recovery_report.possible_causes),
                "first_invalid_offset": recovery_report.first_invalid_offset,
                "invalid_reason":       recovery_report.invalid_reason,
                "hex_preview":          recovery_report.hex_preview,
                "blob_length":          len(encoded_blob or ""),
                "partial_recovery":     dict(recovery_report.partial_recovery),
                "confidence_band":      recovery_report.confidence_band,
                "confidence_reason":    recovery_report.confidence_reason,
                "recovered_layers":     recovery_report.recovered_layers,
            }
            r.verdict = "unknown"
            r.verdict_reason = ("Decode failure — no decoder in the recovery "
                                 "chain produced valid PowerShell text. "
                                 "Semantic analysis intentionally halted.")
            r.confidence = 0
            r.risk_score = 0
            trace.add("semantic_halt", status="skipped",
                      reason=("Recovery chain exhausted without producing a "
                              "valid PowerShell script — AST, behavior "
                              "extraction, and verdict scoring intentionally "
                              "skipped to avoid rendering binary garbage."),
                      input_val="", output_val="")
            r.decode_timeline = trace.to_list()
            return r
    else:
        # Not encoded — try to use the raw tail
        m = re.search(r"powershell(?:\.exe)?\s+(.*)", cmdline, re.I | re.S)
        if m:
            candidate = m.group(1).strip()
            ok, why = _looks_like_powershell(candidate, min_len=3)
            if ok:
                script = candidate
                trace.add("bare_ps_extract", status="applied",
                          reason=("Non-encoded PowerShell; using the raw tail "
                                  "after `powershell.exe`."),
                          input_val=cmdline, output_val=script)
            else:
                trace.add("bare_ps_extract", status="failed",
                          reason=f"raw tail after `powershell.exe` rejected: {why}",
                          input_val=cmdline)
        # Naked PowerShell — no `powershell.exe` wrapper. Analysts often
        # paste scripts directly. Accept the raw cmdline as the script
        # when it exhibits strong PowerShell markers (locked with SOC
        # user 2026-07-27 so /workspace matches /auto-investigate).
        if script is None:
            candidate = (cmdline or "").strip()
            ok, why = _looks_like_powershell(candidate, min_len=3)
            if ok:
                script = candidate
                trace.add("naked_ps_extract", status="applied",
                          reason=("No `powershell.exe` wrapper detected — "
                                  "treating the raw input as a naked "
                                  "PowerShell script."),
                          input_val=cmdline, output_val=script)
        if script is None:
            r.decode_outcome = "unsupported_encoding"
            trace.skipped("ps_ast_parser",
                          reason="No decodable script content — pipeline halts.",
                          input_val=cmdline)
            r.decode_timeline = trace.to_list()
            return r
    r.detected = True
    r.recovered_script = (script or "").strip()

    # ── Recursive deterministic deobfuscation (2026-07-25) ────────
    # Runs safe .NET-style transforms (String.Format, concat, octal/hex/
    # decimal char reconstruction, Convert.FromBase64String, alias
    # expansion) until fixed-point or an execution boundary is hit.
    # The FINAL text becomes the recovered_script for AST/behavior work.
    _deob = _deobfuscate(r.recovered_script)
    r.deobfuscation = _deob.to_dict()
    _deob_behavior_hints: list[str] = []
    if _deob.stages:
        r.recovered_script = _deob.final.strip()
        trace.add("deobfuscator", status="applied",
                  reason=(f"Recursive deterministic decode chain ran "
                          f"{len(_deob.stages)} stage(s); stopped: "
                          f"{_deob.stopped_reason}."),
                  input_val=script, output_val=r.recovered_script,
                  meta={"stages":  [s.to_dict() for s in _deob.stages],
                         "boundary": _deob.boundary_op})
        # Preserve OBFUSCATION-TECHNIQUE behavior signals — the raw
        # script contained these tricks even though the deobfuscator has
        # unwrapped them. Analysts must still see the obfuscation posture.
        for st in _deob.stages:
            t = st.technique.lower()
            if "format" in t or "concat" in t:
                _deob_behavior_hints.append("string_reconstruction")
            if "char" in t or "octal" in t or "hex" in t or "decimal" in t or "binary" in t:
                _deob_behavior_hints.append("char_array_join")
                _deob_behavior_hints.append("payload_decode")
            if "base64" in t:
                _deob_behavior_hints.append("payload_decode")

    # ── Phase 9.4 · Semantic AST parse ────────────────────────────
    ast_script: _AstScript = _ast_parse(r.recovered_script)
    trace.add("ps_ast_parser", status="applied",
              reason=(f"Parsed recovered script into an AST with "
                      f"{len(ast_script.statements)} statement(s) and "
                      f"{len(ast_script.tokens)} token(s)."),
              input_val=r.recovered_script,
              output_val=str(len(ast_script.statements)),
              meta={"statements": len(ast_script.statements),
                    "tokens": len(ast_script.tokens),
                    "resolved_vars": len(ast_script.variables)})

    # Legacy AST (backward-compat) — flat regex-based cmdlet list
    r.ast = parse_ast(r.recovered_script)
    r.artifacts = extract_artifacts(r.recovered_script, r.ast)
    r.behaviors = classify_behaviors(r.recovered_script, r.ast, r.artifacts)
    verdict, score, reason, conf = score_verdict(r.behaviors, r.artifacts, encoded)
    r.verdict = verdict
    r.risk_score = min(100, score)
    r.verdict_reason = reason
    r.confidence = conf
    r.mitre_ids = sorted({m for b in r.behaviors for m in b["mitre"]})
    r.decode_outcome = "fully_decoded" if r.ast else "partially_decoded"

    # ── Phase 9.4 · NivXRay-native behavior extraction ────────────
    v2_behaviors = _extract_behaviors_v2(ast_script)
    # Inject deobfuscation-technique hints as synthetic behaviors so the
    # OBFUSCATION posture is preserved even when the deobfuscator has
    # already unwrapped the tricks.
    if _deob_behavior_hints:
        from v2.semantic.ps_behaviors import _mk, TAXONOMY   # local import
        existing_ids = {b.id for b in v2_behaviors}
        for hint in dict.fromkeys(_deob_behavior_hints):
            if hint in existing_ids or hint not in TAXONOMY:
                continue
            v2_behaviors.append(_mk(
                hint, confidence=85,
                rationale=("Detected during deterministic deobfuscation — "
                           "the raw script used this obfuscation trick "
                           "before it was unwrapped by the decode chain."),
            ))
    # Inject the `encoded_command` behavior when the input carried a
    # `-EncodedCommand` flag. After decoding, the flag itself is gone
    # from the recovered script so the AST-based behavior extractor
    # cannot see it — but analysts still need to see that the payload
    # was obfuscated at the command-line layer (T1027 + T1059.001).
    if encoded:
        from v2.semantic.ps_behaviors import _mk, TAXONOMY   # local import
        existing_ids = {b.id for b in v2_behaviors}
        if "encoded_command" in TAXONOMY and "encoded_command" not in existing_ids:
            v2_behaviors.append(_mk(
                "encoded_command", confidence=95,
                rationale=("Command line invoked PowerShell with an "
                           "`-EncodedCommand` Base64 payload — a classic "
                           "obfuscation / defense-evasion technique."),
            ))
    r.behaviors_v2 = [b.to_dict() for b in v2_behaviors]
    trace.add("behavior_extractor_v2", status="applied",
              reason=(f"Extracted {len(v2_behaviors)} NivXRay-native "
                      "behavior tag(s) from AST + text-level signals."),
              input_val=r.recovered_script,
              output_val=", ".join(b.id for b in v2_behaviors) or "(none)")

    # IOC statistics for the verdict engine
    ext_urls = sum(1 for a in r.artifacts
                    if a.kind == "url" and a.classification == "external")
    ext_ips  = sum(1 for a in r.artifacts
                    if a.kind == "ip"  and a.classification == "external")
    ioc_stats = {
        "external_urls":   ext_urls,
        "external_ips":    ext_ips,
        "ti_hits":         0,
        "hashes":          0,
        "decoder_layers":  len(trace.steps),
    }
    breakdown = _compute_verdict_v2(v2_behaviors, ioc_stats,
                                     trace.to_list(),
                                     encoded_present=encoded)
    r.verdict_breakdown = breakdown.to_dict()

    # Evidence graph
    r.evidence_graph = _build_evidence_graph(ast_script, v2_behaviors,
                                              decoder_layers=trace.to_list())
    r.ast_tree = ast_script.to_dict()
    r.resolved_variables = dict(ast_script.variables)
    r.decode_timeline = trace.to_list()

    # Union MITRE with v2 behaviors — never regress detection.
    r.mitre_ids = sorted(set(r.mitre_ids)
                          | {m for b in v2_behaviors for m in b.mitre})

    # ── Behavior Storyline (2026-07-27) ───────────────────────────
    # Deterministic, evidence-driven narrative built from the final
    # decoded payload plus behaviors + artifacts + deob chain.
    r.storyline = _build_storyline(
        recovered_script=r.recovered_script,
        behaviors_v2=r.behaviors_v2,
        artifacts=[{"kind": a.kind, "value": a.value,
                    "classification": a.classification,
                    "evidence": a.evidence} for a in r.artifacts],
        deobfuscation=r.deobfuscation,
        verdict_breakdown=r.verdict_breakdown,
    )
    return r
