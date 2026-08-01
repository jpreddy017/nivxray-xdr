"""Recursive Artifact Discovery Engine · RADE (2026-08-01).

Per operator directive:

    "Replace hardcoded command-line extraction with a generic recursive
     artifact discovery engine capable of detecting executable content
     throughout normalized vendor telemetry."

RADE walks any input (JSON tree, XML, KV pairs, plain text) recursively
and surfaces every string that looks like executable content. Each
per-vendor adapter previously had to enumerate its own field names —
`CommandLine`, `process_command_line`, `cmdline`, `cmdLine`,
`processCommandLine`, `ScriptBlockText`, `EncodedCommand`, `Arguments`
— and inevitably missed vendor variants. RADE removes that failure
mode by scanning both by NAME (regex over field keys) and by VALUE
(regex over string content).

Return shape:

    DiscoveredArtifact
        path: str            # dotted JSON path
        name: str            # field key that surfaced it
        value: str           # raw content
        kind: str            # "command_line" | "script" | "encoded_command"
                             # | "url" | "ip" | "hash_sha256" | "base64_blob"
                             # | "pe_header"
        confidence: float    # 0.0 .. 1.0

`discover_artifacts()` is deterministic, JSON-serialisable, and MUST
NOT raise for any input — it either finds artifacts or returns [].
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Iterable, List, Optional


# ── Field-name signals ────────────────────────────────────────────────
# Every key seen in production vendor JSON telemetry that carries an
# executable command line.  Match is case-insensitive and matches the
# key EXACTLY (not a substring) so a benign field like `description`
# is not accidentally scanned for command content.
_CMD_KEYS: List[re.Pattern] = [
    re.compile(rf"^{k}$", re.IGNORECASE)
    for k in (
        # PowerShell / cmd
        "CommandLine", "command_line", "commandline", "cmdLine", "cmdline",
        "cmd", "OriginalCommand", "OriginalCommandLine",
        "ProcessCommandLine", "process_command_line", "processCommandLine",
        "ParentCommandLine", "parent_command_line", "parentCommandLine",
        # Script blocks
        "ScriptBlockText", "script_block_text", "scriptBlockText",
        "ScriptBlock", "script", "Script",
        # Encoded
        "EncodedCommand", "encoded_command", "encodedCommand",
        # Args
        "Arguments", "arguments", "args", "Args",
        # Vendor-specific
        "Payload", "payload",
        "trigger_command", "TriggerCommand",
        # Scheduled tasks / services
        "Command", "Exec", "exec",
    )
]

# ── Value-content signals ────────────────────────────────────────────
_VALUE_SIGNALS: List[tuple] = [
    # Command shells — start-anchored so we don't false-positive on
    # prose that mentions PowerShell.
    (re.compile(r"^\s*(?:powershell(?:\.exe)?|pwsh)\b", re.IGNORECASE),
     "command_line", 0.9),
    (re.compile(r"^\s*cmd(?:\.exe)?\s+/", re.IGNORECASE),
     "command_line", 0.9),
    (re.compile(r"^\s*(?:bash|sh|zsh|dash)\s+-[a-z]", re.IGNORECASE),
     "command_line", 0.85),
    (re.compile(r"^\s*(?:curl|wget|fetch)\s+", re.IGNORECASE),
     "command_line", 0.8),
    (re.compile(r"^\s*(?:wmic|reg|schtasks|bitsadmin|certutil|"
                r"rundll32|regsvr32|mshta|msiexec|nslookup|netsh|"
                r"vssadmin|net\s+(?:user|group|localgroup))\b",
                re.IGNORECASE),
     "command_line", 0.85),
    # Strong PowerShell payload indicators anywhere in the string.
    (re.compile(r"-EncodedCommand\s+[A-Za-z0-9+/=]{20,}", re.IGNORECASE),
     "encoded_command", 0.95),
    (re.compile(r"\bIEX\s*\(", re.IGNORECASE),
     "script", 0.85),
    (re.compile(r"\bInvoke-Expression\b", re.IGNORECASE),
     "script", 0.85),
    (re.compile(r"\bDownloadString\s*\(", re.IGNORECASE),
     "script", 0.9),
    (re.compile(r"\bInvoke-WebRequest\b|\bInvoke-RestMethod\b", re.IGNORECASE),
     "script", 0.75),
    # Reverse shell one-liners.
    (re.compile(r"/dev/tcp/\d", re.IGNORECASE), "command_line", 0.9),
    # PE binary as base64 (MZ header base64-encoded starts with TVqQ).
    (re.compile(r"\bTVqQ[A-Za-z0-9+/]{20,}", ), "pe_header", 0.85),
    # Bare PE header (rare).
    (re.compile(r"^MZ[\x00-\xff]{58}PE\x00\x00", re.DOTALL), "pe_header", 0.95),
]

# ── IOC value signals ────────────────────────────────────────────────
_IOC_SIGNALS: List[tuple] = [
    (re.compile(r"https?://[^\s\"'<>()\\]+", re.IGNORECASE), "url", 0.9),
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"), "ip", 0.7),
    (re.compile(r"\b[a-f0-9]{64}\b", re.IGNORECASE), "hash_sha256", 0.95),
    (re.compile(r"\b[a-f0-9]{40}\b", re.IGNORECASE), "hash_sha1", 0.9),
    (re.compile(r"\b[a-f0-9]{32}\b", re.IGNORECASE), "hash_md5", 0.85),
]


@dataclass
class DiscoveredArtifact:
    path: str
    name: str
    value: str
    kind: str
    confidence: float

    def to_dict(self) -> dict:
        return asdict(self)


# ── Walk helpers ─────────────────────────────────────────────────────

def _walk(node: Any, path: str, out: List[DiscoveredArtifact],
           seen_values: set) -> None:
    """Depth-first traversal of a Python object tree."""
    if isinstance(node, dict):
        for k, v in node.items():
            key_hit = any(pat.match(str(k)) for pat in _CMD_KEYS)
            new_path = f"{path}.{k}" if path else str(k)
            if key_hit and isinstance(v, str) and v.strip():
                _emit(new_path, str(k), v, "command_line",
                       confidence=0.85, out=out, seen=seen_values)
            _walk(v, new_path, out, seen_values)
    elif isinstance(node, (list, tuple)):
        for i, v in enumerate(node):
            _walk(v, f"{path}[{i}]", out, seen_values)
    elif isinstance(node, str):
        _scan_string(node, path, out, seen_values)


def _scan_string(s: str, path: str, out: List[DiscoveredArtifact],
                  seen: set) -> None:
    if not s or len(s) > 20000:
        return
    for pat, kind, conf in _VALUE_SIGNALS:
        m = pat.search(s)
        if m:
            _emit(path, path.split(".")[-1] if "." in path else path,
                  s if len(s) < 2000 else s[:2000],
                  kind, conf, out, seen)
            break  # one strong signal per string is enough for command
    # IOC signals — collect all, they're additive.
    for pat, kind, conf in _IOC_SIGNALS:
        for m in pat.finditer(s):
            _emit(path, path.split(".")[-1] if "." in path else path,
                  m.group(0), kind, conf, out, seen)


def _emit(path: str, name: str, value: str, kind: str,
           confidence: float, out: List[DiscoveredArtifact],
           seen: set) -> None:
    key = (kind, value.strip())
    if key in seen:
        return
    seen.add(key)
    out.append(DiscoveredArtifact(
        path=path, name=name, value=value.strip(),
        kind=kind, confidence=confidence,
    ))


# ── Public API ───────────────────────────────────────────────────────

def discover_artifacts(raw_input: str) -> List[DiscoveredArtifact]:
    """Recursively discover executable content in `raw_input`.

    Handles: JSON (dict / list), XML-like tags, plain strings. Never
    raises — safe for any input.
    """
    out: List[DiscoveredArtifact] = []
    seen: set = set()
    if not raw_input or not isinstance(raw_input, str):
        return out

    # 1. Try to parse as JSON first (most vendor telemetry).
    parsed = None
    stripped = raw_input.strip()
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            parsed = json.loads(stripped)
        except (json.JSONDecodeError, ValueError):
            parsed = None

    if parsed is not None:
        _walk(parsed, "", out, seen)
        return out

    # 2. Try to find JSON blocks inline (mixed text + JSON).
    #    e.g. logs that carry a `{...}` payload after a header line.
    for m in re.finditer(r"\{[^{}]{20,}?\}", raw_input, re.DOTALL):
        try:
            sub = json.loads(m.group(0))
            _walk(sub, f"inline[{m.start()}]", out, seen)
        except (json.JSONDecodeError, ValueError):
            continue

    # 3. XML-ish content: extract text between `<Data Name='X'>...</Data>`
    #    tags used by Sysmon, and generic `<tag>...</tag>` payloads.
    if "<Data " in raw_input or "<Event" in raw_input:
        for m in re.finditer(
            r"<Data\s+Name=['\"]([^'\"]+)['\"]>([^<]+)</Data>",
            raw_input, re.IGNORECASE
        ):
            name, val = m.group(1), m.group(2)
            if any(p.match(name) for p in _CMD_KEYS) and val.strip():
                _emit(f"Data[{name}]", name, val, "command_line",
                      0.85, out, seen)
            _scan_string(val, f"Data[{name}]", out, seen)
        for m in re.finditer(r"<([A-Za-z][A-Za-z0-9_]{2,40})>([^<]{4,})</\1>",
                              raw_input):
            _scan_string(m.group(2), f"xml[{m.group(1)}]", out, seen)

    # 4. Plain text — scan the whole payload as one string.
    _scan_string(raw_input, "input", out, seen)
    return out


# ── Integration helper: emit canonical `cmd=` lines ──────────────────

def augment_canonical_text(canonical_text: str, raw_input: str) -> str:
    """Append `cmd=<value>` lines for every command-line artifact
    RADE discovered but the ingress adapter dropped. Idempotent — if
    the canonical text already carries the same command value, skip.

    Called by `apply_ingress_gate` so both `/decode/smart` and
    `/v2/auto-investigate` pipelines see the same command inventory.
    """
    artefacts = discover_artifacts(raw_input)
    if not artefacts:
        return canonical_text
    lines: List[str] = []
    existing = canonical_text.lower()
    seen_this_call: set = set()
    for a in artefacts:
        if a.kind not in ("command_line", "encoded_command", "script"):
            continue
        val = a.value.strip()
        if not val:
            continue
        # Idempotent: already surfaced by the vendor adapter?
        if val.lower()[:120] in existing:
            continue
        key = val.lower()[:120]
        if key in seen_this_call:
            continue
        seen_this_call.add(key)
        lines.append(f"discovered[{a.path}] cmd={val}")
    if not lines:
        return canonical_text
    marker = "\n# recursive-artifact-discovery\n"
    return canonical_text.rstrip() + marker + "\n".join(lines)


__all__ = [
    "DiscoveredArtifact",
    "discover_artifacts",
    "augment_canonical_text",
]
