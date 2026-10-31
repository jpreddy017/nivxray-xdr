"""
DIE · Preprocessor · Artifact Extractor
───────────────────────────────────────
Deterministic multi-pattern extractor that walks the normalized
input and emits ``Artifact`` records with provenance.

The extractor is **pass-through complete** — it never rewrites,
never dedupes, never re-orders during extraction.  Deduplication and
routing happen in later stages so the raw evidence stays intact.

Supported types (Phase 1):

    · command         — CLI invocations (native & lolbin verbs)
    · executable      — .exe / .dll references
    · dll             — .dll (subtype of executable when standalone)
    · registry        — HKLM/HKCU/HKCR/HKU paths
    · unc_path        — \\\\server\\share style
    · file_path       — Windows / Unix absolute paths
    · url             — http(s) / ftp / file
    · ip              — IPv4 (basic IPv6)
    · hash            — MD5 / SHA1 / SHA256
    · env_var         — %VAR% / $env:VAR / $VAR
    · service         — sc.exe create ... / New-Service ...
    · scheduled_task  — schtasks / Register-ScheduledTask
    · lolbin          — LOLBAS binaries mentioned by name
    · network_endpoint — host:port / ip:port
"""
from __future__ import annotations
import re
from typing import List, Set

from .input_normalizer import NormalizedInput
from .models import Artifact


# ── Regex library (compiled once) ─────────────────────────────────
#
# Order in this list DOES matter — earlier patterns win the offset,
# later patterns skip overlapping ranges.  This keeps a single
# command like `powershell.exe -enc ...` from being double-emitted
# as executable + command.
#

# LOLBAS + RMM + built-in Windows utilities analysts recognise on sight.
_LOLBIN_NAMES = (
    # Native LOLBAS
    "powershell", "pwsh", "cmd", "wmic", "vssadmin", "wbadmin", "bcdedit",
    "certutil", "bitsadmin", "regsvr32", "rundll32", "mshta", "msiexec",
    "schtasks", "sc", "reg", "netsh", "tasklist", "taskkill", "net",
    "whoami", "hostname", "ipconfig", "systeminfo", "arp", "nltest",
    "quser", "query", "nslookup", "tracert", "ping", "route",
    "psexec", "paexec", "psinfo", "psloglist", "pssession",
    "ssh", "scp", "curl", "wget",
    # Windows admin & compression
    "tar", "expand", "makecab", "compact", "xcopy", "robocopy",
    "forfiles", "findstr", "attrib", "cipher", "runas",
    # Browsers (living-off-the-land: extension loading, headless launch)
    "msedge", "chrome", "iexplore", "firefox", "brave",
    # Python / language runtimes (portable-runtime deployments)
    "python", "python3", "pythonw", "node", "npm", "npx",
    "ruby", "perl", "java",
    # RMM tools (legitimate admin, abused by attackers)
    "anydesk", "screenconnect", "simplehelp", "splashtop", "optitune",
    "teamviewer", "atera", "kaseya", "n-able", "connectwise",
    # Post-exploitation frameworks
    "bruteratel", "cobaltstrike",
    # Data movers
    "rclone", "megasync", "winscp",
    # Java-based ecosystem tools
    "jwrapper", "javaw",
)
_LOLBIN_ALIASES = {
    "quick assist":     "quickassist",
    "quickassist":      "quickassist",
    "quick-assist":     "quickassist",
    "brute ratel":      "bruteratel",
    "cobalt strike":    "cobaltstrike",
    "cobalt-strike":    "cobaltstrike",
    "screen connect":   "screenconnect",
    "screen-connect":   "screenconnect",
    "any desk":         "anydesk",
    "simple help":      "simplehelp",
}
_LOLBIN_SET = set(_LOLBIN_NAMES) | set(_LOLBIN_ALIASES.values())

# Executable / DLL — dotted binary name preceded by non-word char.
_EXE_RE = re.compile(r"(?<![\w./\\])([A-Za-z][\w\-]{0,60}\.exe)\b", re.IGNORECASE)
_DLL_RE = re.compile(r"(?<![\w./\\])([A-Za-z][\w\-]{0,60}\.dll)\b", re.IGNORECASE)

# Registry paths (HKLM / HKCU / HKCR / HKU  → optional subkey).
_REG_RE = re.compile(
    r"(?<!\w)(HK(?:LM|CU|CR|U|CC)|HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG))"
    r"([\\/][^\s\"'<>`\)\]\}]{1,200})",
    re.IGNORECASE,
)

# UNC paths.
_UNC_RE = re.compile(r"\\\\[A-Za-z0-9._-]{1,64}(?:\\[^\s\"'`<>]{1,120})+")

# Windows abs paths (C:\..., D:\...) and Unix (/usr/...).
_WIN_PATH_RE = re.compile(
    r"(?<![\w/])([A-Za-z]:\\[^\s\"'`<>|]{2,200})"
)
_UNIX_PATH_RE = re.compile(
    r"(?<![\w:])(/(?:usr|etc|opt|var|home|tmp|root|proc|bin|sbin)(?:/[^\s\"'`<>|]{1,120})+)"
)

# URLs.
_URL_RE = re.compile(
    r"\b(?P<scheme>https?|ftp|file|smb|ws|wss)://[^\s\"'<>\)\]\}]{1,500}",
    re.IGNORECASE,
)

# IPv4 (fast) + IPv6 (basic).
_IPV4_RE = re.compile(
    r"(?<!\d)((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})(?!\d)"
)
_IPV6_RE = re.compile(r"(?<![\w:])((?:[a-fA-F0-9]{1,4}:){2,7}[a-fA-F0-9]{1,4})(?!\w)")

# Hashes.
_HASH_RE = re.compile(
    r"(?<![A-Fa-f0-9])"
    r"(?P<md5>[A-Fa-f0-9]{32}|(?P<sha1>[A-Fa-f0-9]{40})|(?P<sha256>[A-Fa-f0-9]{64}))"
    r"(?![A-Fa-f0-9])"
)

# Env vars.
_ENV_WIN_RE  = re.compile(r"%([A-Z_][A-Z0-9_]{1,40})%", re.IGNORECASE)
_ENV_PS_RE   = re.compile(r"\$env:([A-Za-z_][\w]{1,40})", re.IGNORECASE)
_ENV_BASH_RE = re.compile(r"\$([A-Z_][A-Z0-9_]{1,40})\b")

# host:port for likely network endpoints.
_NETEP_RE = re.compile(
    r"\b((?:[a-zA-Z0-9._-]{2,120}|\d+\.\d+\.\d+\.\d+):\d{2,5})\b"
)

# Scheduled tasks / services.
_SCHTASK_RE = re.compile(
    r"(?i)(?:schtasks(?:\.exe)?\s+/create[^\n]*|register-scheduledtask[^\n]*)"
)
_SVC_RE = re.compile(
    r"(?i)(?:sc(?:\.exe)?\s+(?:create|config|start|stop|delete)[^\n]*|"
    r"new-service[^\n]*)"
)

# Command / verb-based extraction.  We look for lines that BEGIN
# with (or contain, after whitespace boundary) an entry from
# ``_LOLBIN_NAMES`` — this is the deterministic "hidden command"
# detector for prose.
#
# Lookbehind allows path separators (`/`, `\`) so quoted absolute
# paths like `"C:\Program Files (x86)\...\msedge.exe"` match cleanly;
# `-` is still forbidden so we do not match `some-cmd`.
_LOLBIN_HINT_RE = re.compile(
    r"(?<![\w-])"
    r"(" + "|".join(sorted(_LOLBIN_NAMES, key=len, reverse=True)) + r")"
    r"(?:\.exe)?\b",
    re.IGNORECASE,
)

# Implicit PowerShell command — a line that starts with PowerShell /
# cmd.exe switches but no executable prefix (attacker pastes often
# strip the leading `powershell.exe`).  When these are present at
# the head of a line we synthesise a `powershell` command so the
# stage builder can classify it.
_IMPLICIT_PS_HEAD_RE = re.compile(
    r"^\s*(?:-(?:NoProfile|NonInteractive|ExecutionPolicy|WindowStyle|"
    r"Command|EncodedCommand|File|nop|nol|w|WhatIf|Version|PSConsoleFile)"
    r"\b)",
    re.IGNORECASE,
)
_IMPLICIT_CMD_HEAD_RE = re.compile(r"^\s*/[cCsSkK]\s+", re.IGNORECASE)


# ── Extraction helpers ────────────────────────────────────────────
def _push(artifacts: List[Artifact], type_: str, subtype, raw: str,
          norm: str, ni: NormalizedInput, start: int, end: int,
          confidence: float = 1.0, attributes=None) -> None:
    art = Artifact.build(
        type_=type_, subtype=subtype,
        raw=raw, normalized=norm,
        line_number=ni.line_number(start),
        start=ni.raw_offset(start),
        end=ni.raw_offset(end),
        confidence=confidence, attributes=attributes,
    )
    artifacts.append(art)


def _extract_regex(artifacts: List[Artifact], ni: NormalizedInput, occupied: Set[int],
                   rx: re.Pattern, type_: str, subtype_fn=None,
                   norm_fn=None, confidence: float = 1.0) -> None:
    for m in rx.finditer(ni.text):
        s, e = m.span()
        # skip if this range overlaps something already extracted.
        if any(o in occupied for o in range(s, e)):
            continue
        raw = m.group(0)
        norm = norm_fn(m) if norm_fn else raw
        subtype = subtype_fn(m) if subtype_fn else None
        _push(artifacts, type_, subtype, raw, norm, ni, s, e, confidence)
        for o in range(s, e):
            occupied.add(o)


def _hash_subtype(m) -> str:
    length = len(m.group(0))
    return {32: "md5", 40: "sha1", 64: "sha256"}.get(length, "unknown")


def _url_subtype(m) -> str:
    return m.group("scheme").lower()


def _reg_subtype(m) -> str:
    hive = m.group(1).upper()
    return {
        "HKLM": "HKLM", "HKEY_LOCAL_MACHINE": "HKLM",
        "HKCU": "HKCU", "HKEY_CURRENT_USER": "HKCU",
        "HKCR": "HKCR", "HKEY_CLASSES_ROOT": "HKCR",
        "HKU":  "HKU",  "HKEY_USERS": "HKU",
        "HKCC": "HKCC", "HKEY_CURRENT_CONFIG": "HKCC",
    }.get(hive, hive)


# ── Command extraction ────────────────────────────────────────────
# A "command" is anything that looks like an executable name (or
# alias) followed on the same line by tokens the analyst would
# recognise as arguments.  We deliberately extract on a *line*
# granularity so we don't merge unrelated verbs from different
# paragraphs.
def _extract_commands(artifacts: List[Artifact], ni: NormalizedInput, occupied: Set[int]) -> None:
    lines = ni.text.split("\n")
    # Build an offset lookup so we don't have to re-count.
    cursor = 0
    for line_idx, line in enumerate(lines):
        line_start = cursor
        cursor += len(line) + 1     # +1 for the newline
        stripped = line.strip()
        if not stripped:
            continue

        # Handle "verb aliases" (Quick Assist, Brute Ratel …) — swap
        # them into a canonical single-token form for the extractor.
        working = stripped
        for phrase, canonical in _LOLBIN_ALIASES.items():
            # Case-insensitive word-boundary swap.
            working = re.sub(rf"(?i)\b{re.escape(phrase)}\b", canonical, working)

        # Any lolbin hit anywhere on the line?
        hits = list(_LOLBIN_HINT_RE.finditer(working))
        if not hits:
            # Implicit-executable fallback (2026-03-01) — a line that
            # starts with PowerShell / cmd switches but omits the
            # `powershell.exe` prefix is still a command.  Synthesise
            # the executable so the family recognizer can classify it.
            if _IMPLICIT_PS_HEAD_RE.match(working):
                working = "powershell.exe " + working
                hits = list(_LOLBIN_HINT_RE.finditer(working))
            elif _IMPLICIT_CMD_HEAD_RE.match(working):
                working = "cmd.exe " + working
                hits = list(_LOLBIN_HINT_RE.finditer(working))
            if not hits:
                continue

        first = hits[0]
        # If the line has additional structure after the lolbin, treat
        # the whole line as a single command.  If not (bare RMM name),
        # emit an executable artifact instead.
        remainder = working[first.end():].strip()
        raw_full = stripped

        # Compute offsets on the ORIGINAL normalized line (not the
        # aliased ``working`` variant).  If the alias changed the
        # length we fall back to the line start.
        line_leading_ws = len(line) - len(line.lstrip())
        norm_start = line_start + line_leading_ws
        norm_end   = line_start + len(line.rstrip())
        if any(o in occupied for o in range(norm_start, norm_end)):
            continue

        binary_norm = first.group(0).lower()
        exe_family = _LOLBIN_ALIASES.get(binary_norm, binary_norm)

        # Deterministic "prose fragment" filter (2026-02-28 Analyst
        # Acceptance Pass): if the lolbin hit isn't at position 0 AND
        # the line lacks CLI switches (`/`, `-`, `--`, quoted args)
        # AND lacks a recognised family, then the token is embedded
        # inside an analyst sentence — skip it to avoid emitting
        # noisy stages like "reverse · SSH tunnels".
        line_has_cli_flag = bool(re.search(r"(?:\s|^)(?:[/-][A-Za-z]|--[a-z]|\"|')", working))
        is_prose_fragment = (
            first.start() > 0
            and not line_has_cli_flag
            and " " in remainder
        )
        if is_prose_fragment:
            # Still emit a lolbin artifact so the tool is remembered.
            _push(
                artifacts, "lolbin", exe_family, raw_full, exe_family,
                ni, norm_start, norm_end,
                confidence=0.6,
                attributes={"line": line_idx + 1, "context": "prose"},
            )
            for o in range(norm_start, norm_end):
                occupied.add(o)
            continue

        is_command = bool(remainder) or (len(hits) > 1) or (
            len(raw_full.split()) >= 2
        )

        if is_command:
            _push(
                artifacts, "command", exe_family, raw_full, raw_full,
                ni, norm_start, norm_end,
                confidence=0.9 if remainder else 0.75,
                attributes={"executable": exe_family, "line": line_idx + 1},
            )
        else:
            # Bare tool mention → lolbin artifact only.
            _push(
                artifacts, "lolbin", exe_family, raw_full, exe_family,
                ni, norm_start, norm_end,
                confidence=0.85,
                attributes={"line": line_idx + 1},
            )
        for o in range(norm_start, norm_end):
            occupied.add(o)


# ── Public API ────────────────────────────────────────────────────
def extract(ni: NormalizedInput) -> List[Artifact]:
    """Extract every recognizable artifact from ``ni.text``.

    Ordering: commands run FIRST because they cover the largest
    ranges and downstream extractors avoid re-emitting sub-parts.
    """
    artifacts: List[Artifact] = []
    occupied: Set[int] = set()

    # 1) Commands / bare tools.
    _extract_commands(artifacts, ni, occupied)

    # 2) Executables / DLLs (only those NOT already inside a command
    #    range).
    _extract_regex(artifacts, ni, occupied, _EXE_RE, "executable",
                   norm_fn=lambda m: m.group(1).lower(),
                   subtype_fn=lambda m: "exe", confidence=0.9)
    _extract_regex(artifacts, ni, occupied, _DLL_RE, "dll",
                   norm_fn=lambda m: m.group(1).lower(),
                   subtype_fn=lambda m: "dll", confidence=0.85)

    # 3) Registry, UNC, paths, URLs, IPs, hashes, env vars,
    #    scheduled tasks and services.
    _extract_regex(artifacts, ni, occupied, _REG_RE, "registry",
                   norm_fn=lambda m: m.group(0),
                   subtype_fn=_reg_subtype, confidence=0.95)
    _extract_regex(artifacts, ni, occupied, _UNC_RE, "unc_path")
    _extract_regex(artifacts, ni, occupied, _WIN_PATH_RE, "file_path",
                   subtype_fn=lambda m: "windows")
    _extract_regex(artifacts, ni, occupied, _UNIX_PATH_RE, "file_path",
                   subtype_fn=lambda m: "unix")
    _extract_regex(artifacts, ni, occupied, _URL_RE, "url",
                   subtype_fn=_url_subtype)
    _extract_regex(artifacts, ni, occupied, _IPV4_RE, "ip",
                   subtype_fn=lambda m: "v4")
    _extract_regex(artifacts, ni, occupied, _IPV6_RE, "ip",
                   subtype_fn=lambda m: "v6", confidence=0.7)
    _extract_regex(artifacts, ni, occupied, _HASH_RE, "hash",
                   subtype_fn=_hash_subtype)
    _extract_regex(artifacts, ni, occupied, _ENV_WIN_RE, "env_var",
                   subtype_fn=lambda m: "windows",
                   norm_fn=lambda m: m.group(1).upper())
    _extract_regex(artifacts, ni, occupied, _ENV_PS_RE, "env_var",
                   subtype_fn=lambda m: "powershell",
                   norm_fn=lambda m: m.group(1))
    _extract_regex(artifacts, ni, occupied, _SCHTASK_RE, "scheduled_task")
    _extract_regex(artifacts, ni, occupied, _SVC_RE, "service")
    _extract_regex(artifacts, ni, occupied, _NETEP_RE, "network_endpoint",
                   confidence=0.7)

    # Ordering — deterministic — by (line_number, start_offset, type).
    artifacts.sort(key=lambda a: (a.line_number, a.start_offset, a.type))
    return artifacts
