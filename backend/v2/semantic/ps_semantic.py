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
    """Return the recovered PowerShell script or None."""
    blob = extract_encoded_blob(cmdline)
    if not blob:
        return None
    try:
        raw = base64.b64decode(blob, validate=False)
    except Exception:
        return None
    # PS -EncodedCommand is UTF-16LE by contract; fall back to utf-8 if needed.
    for enc in ("utf-16-le", "utf-8", "latin-1"):
        try:
            text = raw.decode(enc)
            if text and text.isprintable() or "\n" in text or any(c.isalpha() for c in text):
                return text.strip()
        except Exception:
            continue
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
    if score >= 70:
        verdict = "malicious"
    elif score >= 40:
        verdict = "suspicious"
    elif score >= 15:
        verdict = "needs_review"
    else:
        verdict = "informational"
    confidence = min(95, 60 + min(35, len(behaviors) * 8))
    return verdict, score, "; ".join(reasons) or "no notable indicators", confidence


# ── Public entrypoint ────────────────────────────────────────────
def analyze(cmdline: str) -> SemanticResult:
    """Full deterministic semantic pass over a PowerShell command line."""
    r = SemanticResult()
    if not cmdline or not re.search(r"powershell", cmdline, re.I):
        return r
    encoded = extract_encoded_blob(cmdline) is not None
    script = decode_powershell_encoded(cmdline)
    if script is None:
        # Not encoded — still try to parse the tail after `powershell.exe`.
        m = re.search(r"powershell(?:\.exe)?\s+(.*)", cmdline, re.I | re.S)
        if m:
            script = m.group(1)
        else:
            r.decode_outcome = "unsupported_encoding"
            return r
    r.detected = True
    r.recovered_script = script.strip()
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
    return r
