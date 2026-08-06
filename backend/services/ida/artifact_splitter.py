"""
IDA · Artifact Splitter (IDA-2)
────────────────────────────────
Frozen 2026-03-01 · P0.

The Artifact Splitter turns a **mixed paste** into a deterministic
list of typed artifacts.  Every artifact carries its own type,
value, canonical form, and IDA-7 provenance (source offsets) so
downstream engines route each piece to the right analyzer:

    Artifact 1 (PowerShell) → DIE
    Artifact 2 (URL)        → IDA · URL Fetcher (IDA-3, next slice)
    Artifact 3 (Hash)       → IOCE · OSINT lookup
    Artifact 4 (Registry)   → CIA · Registry Analyzer
    …

Rules honoured:
  · Deterministic.  Same paste → identical artifact list, identical
    ordering, identical offsets.
  · Provenance-first.  Every artifact records `source.offset`,
    `source.length`, `source.line`, `source.extractor` so the
    Evidence projection can highlight the exact excerpt without
    re-parsing.
  · Non-destructive.  The full raw paste stays on `SSOT.input.raw`.
    The splitter only *classifies slices*; it never rewrites the
    input.
  · Additive.  New artifact types plug into `_EXTRACTORS` — no
    consumer needs to know they exist.
"""
from __future__ import annotations
import re
from dataclasses import dataclass, asdict, field
from typing import Any, Dict, List, Optional


# ══════════════════════════════════════════════════════════════════
# 1. Artifact dataclass
# ══════════════════════════════════════════════════════════════════
@dataclass
class Artifact:
    """One typed slice of the analyst's paste."""
    id:         str
    type:       str                                   # url · hash · ip · domain · registry_key · file_path · command · yara_rule · sigma_rule · cve · plain
    value:      str                                   # verbatim slice
    canonical:  str                                   # normalized copy (lowercased URL host, HKLM → HKEY_LOCAL_MACHINE, etc.)
    source:     Dict[str, Any] = field(default_factory=dict)   # IDA-7 provenance
    metadata:   Dict[str, Any] = field(default_factory=dict)   # per-type extras (hash-kind, registry-hive, cve-year, …)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ══════════════════════════════════════════════════════════════════
# 2. Regex atoms
# ══════════════════════════════════════════════════════════════════
# The atoms are deliberately conservative — high precision, so the
# splitter never mis-labels a substring of a command as a standalone
# artifact.  Determinism is enforced by iterating the extractors in a
# fixed priority order and consuming each match once.
_RE_URL = re.compile(
    r"\b(?:https?|ftp|ftps|smb|s3)://[^\s'\"<>()\[\]{}]+",
    re.IGNORECASE,
)

# hash lengths: MD5 = 32, SHA-1 = 40, SHA-256 = 64, SHA-512 = 128
_RE_HASH = re.compile(r"\b([A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}|[A-Fa-f0-9]{128})\b")

_RE_IPV4 = re.compile(
    r"\b(?<![\w.])((?:25[0-5]|2[0-4]\d|[01]?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)){3})(?![\w.])\b"
)

# Domain — deliberately loose, but excludes 1-char TLDs and common file extensions.
# NOTE: case-sensitive (no `re.I`) so mixed-case programming identifiers like
# `WinHttp.WinHttpRequest`, `subprocess.Popen`, `System.Net.WebClient` are
# NEVER matched.  DNS is case-insensitive but always written lowercase in
# real threat-report IOCs.
_RE_DOMAIN = re.compile(
    r"\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})\b",
)

# Windows registry hive.  Case-insensitive on hive, preserves case on subkey.
_RE_REGISTRY = re.compile(
    r"\b(HK(?:LM|CU|CR|U|CC)|HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG))"
    r"[\\/][\w\\/. \-\(\)]+",
    re.I,
)

# Windows file path — drive letter or UNC or %env% prefix, plus at least one segment.
# Deliberately excludes spaces so a prose sentence like "drops C:\foo on host"
# doesn't gobble the trailing words.  Spaces-in-paths are handled when
# they arrive quoted (a later slice).
_RE_FILE_PATH = re.compile(
    r"(?:[A-Za-z]:\\|\\\\[\w.\-]+\\|%[A-Z_]+%\\?)[\w\\/.\-\(\)]+"
)

_RE_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)

# YARA / Sigma – markers that identify a rule block.
_RE_YARA_RULE_LINE  = re.compile(r"^\s*rule\s+[A-Za-z_][\w]*\s*(?::[\w\s,]+)?\s*\{", re.M)
_RE_SIGMA_MARKER    = re.compile(r"^\s*(logsource|detection)\s*:\s*$", re.M | re.I)


# Command lines — a small set of interpreter/LOLBAS heads that
# indicate a command artifact.  Only used when the whole *line* looks
# executable (starts with the head or contains an interpreter switch).
_RE_COMMAND_LINE = re.compile(
    r"^\s*(?:powershell|pwsh|cmd|bash|sh|python3?w?|node|wscript|cscript|"
    r"mshta|rundll32|regsvr32|certutil|bitsadmin|msiexec|schtasks|"
    r"net\s+(?:use|user|group)|reg\s+(?:add|delete|query)|vssadmin|"
    r"wmic|curl|wget|nltest|whoami|hostname|ipconfig|ping|nslookup)"
    r"(?:\.exe)?\b",
    re.IGNORECASE,
)


# ══════════════════════════════════════════════════════════════════
# 3. Canonicalisers (IDA-5 slice · normalization contract)
# ══════════════════════════════════════════════════════════════════
def _canon_url(value: str) -> str:
    v = value.strip().rstrip(".,;:)]}\"'")
    # Lowercase scheme + host; keep path/query verbatim
    m = re.match(r"(?i)^([a-z]+://)([^/]+)(.*)$", v)
    if not m:
        return v
    scheme, host, rest = m.groups()
    host = host.lower().rstrip(".")
    return f"{scheme.lower()}{host}{rest}"


def _canon_domain(value: str) -> str:
    return value.strip().rstrip(".").lower()


def _canon_ip(value: str) -> str:
    return value.strip()


def _canon_hash(value: str) -> str:
    return value.strip().lower()


_REG_HIVE_MAP = {
    "HKLM": "HKEY_LOCAL_MACHINE",
    "HKCU": "HKEY_CURRENT_USER",
    "HKCR": "HKEY_CLASSES_ROOT",
    "HKU":  "HKEY_USERS",
    "HKCC": "HKEY_CURRENT_CONFIG",
}


def _canon_registry(value: str) -> str:
    v = value.strip().replace("/", "\\")
    # Expand short hive to full form (deterministic)
    head, _, tail = v.partition("\\")
    head_up = head.upper()
    if head_up in _REG_HIVE_MAP:
        return f"{_REG_HIVE_MAP[head_up]}\\{tail}"
    return v


def _canon_file_path(value: str) -> str:
    return value.strip()


def _canon_cve(value: str) -> str:
    return value.strip().upper()


def _canon_command(value: str) -> str:
    # Collapse whitespace only — never rewrite the command itself.
    return re.sub(r"\s+", " ", value.strip())


# ══════════════════════════════════════════════════════════════════
# 4. Extractors — deterministic priority order
# ══════════════════════════════════════════════════════════════════
def _hash_kind(v: str) -> str:
    return {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}[len(v)]


def _classify_ip(v: str) -> str:
    """Return 'private' | 'loopback' | 'public'."""
    parts = [int(p) for p in v.split(".")]
    if parts[0] == 127:
        return "loopback"
    if parts[0] == 10:
        return "private"
    if parts[0] == 192 and parts[1] == 168:
        return "private"
    if parts[0] == 172 and 16 <= parts[1] <= 31:
        return "private"
    if parts[0] == 169 and parts[1] == 254:
        return "link-local"
    return "public"


# Rejected TLDs: things that look domain-shaped but are actually
# executable/office/archive file extensions.  Prevents `notepad.exe`
# from being classified as a domain.
_DOMAIN_TLD_BLOCKLIST = {
    # Windows binaries / scripts
    # NOTE: `.com` (DOS executable) intentionally OMITTED — the
    # collision with the `.com` TLD is far more costly than the rare
    # DOS-COM extension seen in modern threat reports.  Same for
    # `.url` (Windows shortcut vs non-existent `.url` TLD).
    "exe", "dll", "sys", "bat", "cmd", "ps1", "psm1", "psd1", "vbs",
    "vbe", "js", "jse", "hta", "wsf", "wsh", "cpl", "scr",
    "msi", "msp", "mst", "reg", "lnk", "inf",
    # Office / documents
    "docx", "docm", "doc", "dotx", "dotm", "dot",
    "xlsx", "xlsm", "xls", "xlsb", "xltx", "xltm",
    "pptx", "pptm", "ppt", "potx", "potm", "pps", "ppsx", "ppsm",
    "pdf", "rtf", "one",
    # Archives
    "zip", "rar", "7z", "tar", "gz", "bz2", "xz", "iso", "cab", "img",
    "arj", "lz", "lzma", "tgz", "tbz", "txz",
    # Text / logs / configs
    "txt", "log", "tmp", "bin", "cfg", "conf", "ini", "toml",
    "json", "xml", "yaml", "yml", "html", "htm", "css", "csv", "tsv",
    "rst",
    # Media
    "png", "jpg", "jpeg", "gif", "webp", "svg", "ico", "bmp",
    "wav", "mp3", "mp4", "avi", "mov", "mkv", "webm", "flv", "wmv",
    # Source / build outputs (excluding TLDs that ARE public: .io, .app)
    "pyc", "pyd", "class", "jar", "elf", "obj",
    # Scripting / automation (extension-only, non-TLD)
    "ahk", "au3", "lua", "tcl", "pl", "sh", "bash", "zsh",
    "kt", "cs", "vb", "asm",
    # Web / build assets
    "map", "lock",
}


# Hosting-infrastructure suffixes.  Domains ending in ANY of these are
# suppressed from IOC extraction because they belong to shared cloud
# providers — the analyst hits pure noise, not attacker infrastructure.
# Threat vendors host their OWN reports on these platforms; extracting
# them as "IOCs" pollutes the intelligence surface.
#
# NOTE: this is a *suffix* match (checked with endswith after canonising
# to lowercase).  Adding a suffix here is safe — it never blocks
# extraction of tighter matches like `evil.<parent>.com`.
_HOSTING_INFRA_SUFFIXES = (
    # AWS
    ".amazonaws.com", ".cloudfront.net", ".aws.amazon.com",
    ".execute-api.amazonaws.com", ".elb.amazonaws.com",
    ".s3.amazonaws.com", ".awsstatic.com",
    # GCP
    ".googleusercontent.com", ".appspot.com", ".googleapis.com",
    ".run.app", ".firebaseio.com", ".firebaseapp.com",
    ".web.app", ".cloudfunctions.net",
    # Azure
    ".azurewebsites.net", ".azureedge.net", ".windows.net",
    ".blob.core.windows.net", ".azurefd.net", ".trafficmanager.net",
    ".cloudapp.net", ".cloudapp.azure.com",
    # CDN / SaaS platforms
    ".akamaihd.net", ".akamaized.net", ".akamai.net",
    ".fastly.net", ".fastlylb.net",
    ".cdn77.org", ".stackpathcdn.com", ".stackpathdns.com",
    ".jsdelivr.net", ".unpkg.com",
    ".herokuapp.com", ".netlify.app", ".vercel.app", ".pages.dev",
    ".github.io", ".gitlab.io", ".bitbucket.io",
    ".readthedocs.io", ".readthedocs.org",
    # Analytics / DoH — pure infrastructure, not payload delivery
    ".googletagmanager.com", ".google-analytics.com",
    ".doubleclick.net", ".cloudflareinsights.com",
    # Common vendor CDNs surfaced by threat-report authors themselves
    ".hubspotusercontent-na1.net", ".hs-scripts.com",
    ".marketo.com", ".marketo.net",
)


def _is_hosting_infra(domain: str) -> bool:
    """True when `domain` belongs to a shared cloud / CDN / SaaS
    platform and MUST NOT be treated as an IOC (noise suppression)."""
    d = (domain or "").lower().strip(".")
    for suffix in _HOSTING_INFRA_SUFFIXES:
        # ".amazonaws.com" matches "foo.s3.us-east-1.amazonaws.com"
        # AND "amazonaws.com" itself, but not "notamazonaws.com".
        if d.endswith(suffix) or d == suffix.lstrip("."):
            return True
    return False


# Public-TLD allowlist (IANA gTLDs + widely-used ccTLDs).  The domain
# extractor consults this list AFTER the case-sensitive regex has
# matched; anything whose TLD is not on this list is rejected as a
# non-domain (typically a programming identifier — `subprocess.popen`,
# `os.path.join` — or a filename with a bespoke extension).
#
# We intentionally exclude ambiguous TLDs like `.zip`, `.mov`, `.new`,
# `.py`, `.rb`, `.sh` because in analyst text those are almost always
# file extensions or code identifiers, not real domains.
_PUBLIC_TLDS = {
    # Legacy gTLDs
    "com", "net", "org", "edu", "gov", "mil", "int", "info", "biz",
    "name", "pro", "aero", "coop", "museum", "jobs", "mobi", "tel",
    "asia", "cat",
    # New gTLDs — the ones threat actors and vendors actually use
    "app", "dev", "io", "ai", "co", "cloud", "site", "online", "store",
    "shop", "tech", "xyz", "top", "live", "link", "click", "download",
    "space", "world", "network", "systems", "solutions", "services",
    "security", "software", "digital", "email", "media", "news",
    "blog", "wiki", "team", "group", "company", "agency", "expert",
    "consulting", "finance", "law", "health", "care", "clinic",
    "energy", "engineering", "capital", "ventures", "fund",
    # ccTLDs — commonly seen in threat reports & analyst pastes.
    "ac", "ad", "ae", "af", "ag", "ai", "al", "am", "ao", "ar", "as",
    "at", "au", "aw", "az", "ba", "bb", "bd", "be", "bg", "bh", "bi",
    "bj", "bm", "bn", "bo", "br", "bs", "bt", "bw", "by", "bz", "ca",
    "cc", "cd", "cf", "cg", "ch", "ci", "ck", "cl", "cm", "cn", "co",
    "cr", "cu", "cv", "cw", "cx", "cy", "cz", "de", "dj", "dk", "dm",
    "do", "dz", "ec", "ee", "eg", "es", "et", "eu", "fi", "fj", "fm",
    "fo", "fr", "ga", "gb", "gd", "ge", "gf", "gg", "gh", "gi", "gl",
    "gm", "gn", "gp", "gq", "gr", "gt", "gu", "gw", "gy", "hk", "hn",
    "hr", "ht", "hu", "id", "ie", "il", "im", "in", "iq", "ir", "is",
    "it", "je", "jm", "jo", "jp", "ke", "kg", "kh", "ki", "km", "kn",
    "kp", "kr", "kw", "ky", "kz", "la", "lb", "lc", "li", "lk", "lr",
    "ls", "lt", "lu", "lv", "ly", "ma", "mc", "md", "me", "mg", "mh",
    "mk", "ml", "mm", "mn", "mo", "mp", "mq", "mr", "ms", "mt", "mu",
    "mv", "mw", "mx", "my", "mz", "na", "nc", "ne", "nf", "ng", "ni",
    "nl", "no", "np", "nr", "nu", "nz", "om", "pa", "pe", "pf", "pg",
    "ph", "pk", "pl", "pm", "pn", "pr", "ps", "pt", "pw", "py", "qa",
    "re", "ro", "rs", "ru", "rw", "sa", "sb", "sc", "sd", "se", "sg",
    "sh", "si", "sk", "sl", "sm", "sn", "so", "sr", "ss", "st", "sv",
    "sy", "sz", "tc", "td", "tf", "tg", "th", "tj", "tk", "tl", "tm",
    "tn", "to", "tr", "tt", "tv", "tw", "tz", "ua", "ug", "uk", "us",
    "uy", "uz", "va", "vc", "ve", "vg", "vi", "vn", "vu", "wf", "ws",
    "ye", "yt", "za", "zm", "zw",
}

# Ambiguous ccTLDs that collide with common file extensions used in
# threat-report samples.  `foo.py` is virtually always a Python file,
# not a Paraguay domain.  Same for `.sh` (shell), `.so` (shared lib),
# `.rs` (Rust), `.md` (Markdown).  Remove them so the extractor sides
# with the file-extension interpretation.  (If a real .py / .sh domain
# ever needs to be flagged, we'll handle it via structural heuristics.)
_PUBLIC_TLDS.difference_update({"py", "sh", "so", "rs", "md", "cd",
                                  "im", "gg", "je", "ai" if False else "gs"})
# NOTE: `.ai` is kept because it's overwhelmingly domain-first in
# modern threat reports (OpenAI / Copilot copycats etc).


def _is_public_tld(tld: str) -> bool:
    return (tld or "").lower() in _PUBLIC_TLDS


# ══════════════════════════════════════════════════════════════════
# 5. Public entry point
# ══════════════════════════════════════════════════════════════════
def split_artifacts(text: str) -> List[Artifact]:
    """Deterministically split a mixed paste into typed artifacts.

    Ordering is fixed for reproducibility:
      1. Command lines (highest fidelity — start-of-line + head)
      2. URLs
      3. Registry keys
      4. File paths (Windows)
      5. Hashes (MD5 / SHA-1 / SHA-256 / SHA-512)
      6. CVEs
      7. IPv4 addresses
      8. Domains (only when not part of a URL / already-consumed span)
      9. YARA / Sigma rule blocks
    Every extractor consumes the byte range it matched so no two
    artifacts overlap (except commands, which are line-scoped and
    always emitted alongside atomic artifacts on the same line).
    """
    if not text:
        return []

    consumed: List[tuple] = []  # (start, end) ranges already claimed
    artifacts: List[Artifact] = []
    counter = [0]  # mutable so nested helpers can bump it

    def _next_id(prefix: str) -> str:
        counter[0] += 1
        return f"art-{counter[0]:03d}-{prefix}"

    def _overlaps(start: int, end: int) -> bool:
        for cs, ce in consumed:
            if not (end <= cs or start >= ce):
                return True
        return False

    def _claim(start: int, end: int) -> None:
        consumed.append((start, end))

    def _line_of(offset: int) -> int:
        return text.count("\n", 0, offset) + 1

    # ── 1. Command lines ──────────────────────────────────────────
    # Line-scoped: a command occupies its full line, but its inner
    # URLs / hashes / paths still surface as separate artifacts.
    for m in re.finditer(r"^[^\n]+$", text, re.M):
        raw_line = m.group(0)
        if not _RE_COMMAND_LINE.search(raw_line):
            continue
        start, end = m.start(), m.end()
        artifacts.append(Artifact(
            id=_next_id("cmd"),
            type="command",
            value=raw_line,
            canonical=_canon_command(raw_line),
            source={
                "offset":    start,
                "length":    end - start,
                "line":      _line_of(start),
                "extractor": "ida.command",
            },
            metadata={},
        ))
        # NB: do NOT claim command range — inner IOCs still surface.

    # ── 2. URLs ────────────────────────────────────────────────────
    from .url_intent import classify_url_intent as _url_intent
    for m in _RE_URL.finditer(text):
        raw = m.group(0)
        canonical = _canon_url(raw)
        # trim trailing punctuation from the raw slice too
        strip_len = len(raw) - len(raw.rstrip(".,;:)]}\"'"))
        start, end = m.start(), m.end() - strip_len
        intent = _url_intent(canonical)
        # Drop URLs whose host is shared cloud / CDN infrastructure —
        # they are noise, not attacker IOCs.
        if _is_hosting_infra(intent.get("host") or ""):
            continue
        artifacts.append(Artifact(
            id=_next_id("url"),
            type="url",
            value=raw[: end - start],
            canonical=canonical,
            source={
                "offset":    start,
                "length":    end - start,
                "line":      _line_of(start),
                "extractor": "ida.url",
            },
            metadata={
                "scheme":     canonical.split("://", 1)[0],
                "host":       intent["host"],
                "intent":     intent["intent"],
                "acquirable": intent["acquirable"],
                "vendor":     intent["vendor"],
                "reasoning":  intent["reasoning"],
            },
        ))
        _claim(start, end)

    # ── 3. Registry keys ──────────────────────────────────────────
    for m in _RE_REGISTRY.finditer(text):
        start, end = m.start(), m.end()
        if _overlaps(start, end):
            continue
        raw = text[start:end].rstrip(".,;:")
        end = start + len(raw)
        canonical = _canon_registry(raw)
        artifacts.append(Artifact(
            id=_next_id("reg"),
            type="registry_key",
            value=raw,
            canonical=canonical,
            source={
                "offset":    start,
                "length":    end - start,
                "line":      _line_of(start),
                "extractor": "ida.registry",
            },
            metadata={"hive": canonical.split("\\", 1)[0]},
        ))
        _claim(start, end)

    # ── 4. File paths ──────────────────────────────────────────────
    for m in _RE_FILE_PATH.finditer(text):
        start, end = m.start(), m.end()
        if _overlaps(start, end):
            continue
        raw = text[start:end].rstrip(".,;:")
        end = start + len(raw)
        artifacts.append(Artifact(
            id=_next_id("path"),
            type="file_path",
            value=raw,
            canonical=_canon_file_path(raw),
            source={
                "offset":    start,
                "length":    end - start,
                "line":      _line_of(start),
                "extractor": "ida.file_path",
            },
            metadata={},
        ))
        _claim(start, end)

    # ── 5. Hashes ──────────────────────────────────────────────────
    for m in _RE_HASH.finditer(text):
        start, end = m.start(), m.end()
        if _overlaps(start, end):
            continue
        raw = m.group(0)
        artifacts.append(Artifact(
            id=_next_id("hash"),
            type="hash",
            value=raw,
            canonical=_canon_hash(raw),
            source={
                "offset":    start,
                "length":    end - start,
                "line":      _line_of(start),
                "extractor": "ida.hash",
            },
            metadata={"kind": _hash_kind(raw)},
        ))
        _claim(start, end)

    # ── 6. CVEs ────────────────────────────────────────────────────
    for m in _RE_CVE.finditer(text):
        start, end = m.start(), m.end()
        if _overlaps(start, end):
            continue
        raw = m.group(0)
        artifacts.append(Artifact(
            id=_next_id("cve"),
            type="cve",
            value=raw,
            canonical=_canon_cve(raw),
            source={
                "offset":    start,
                "length":    end - start,
                "line":      _line_of(start),
                "extractor": "ida.cve",
            },
            metadata={"year": int(raw.split("-")[1])},
        ))
        _claim(start, end)

    # ── 7. IPv4 ────────────────────────────────────────────────────
    for m in _RE_IPV4.finditer(text):
        start, end = m.start(), m.end()
        if _overlaps(start, end):
            continue
        raw = m.group(1)
        artifacts.append(Artifact(
            id=_next_id("ip"),
            type="ip",
            value=raw,
            canonical=_canon_ip(raw),
            source={
                "offset":    start,
                "length":    end - start,
                "line":      _line_of(start),
                "extractor": "ida.ipv4",
            },
            metadata={"scope": _classify_ip(raw), "version": 4},
        ))
        _claim(start, end)

    # ── 8. Domains ────────────────────────────────────────────────
    for m in _RE_DOMAIN.finditer(text):
        start, end = m.start(), m.end()
        if _overlaps(start, end):
            continue
        raw = m.group(1)
        tld = raw.rsplit(".", 1)[-1].lower()
        if tld in _DOMAIN_TLD_BLOCKLIST:
            continue
        # Real domains have a PUBLIC TLD.  Reject programming
        # identifiers (`subprocess.popen`, `os.path.join`) and bespoke
        # file extensions that slipped past the file-ext blocklist.
        if not _is_public_tld(tld):
            continue
        # Suppress AWS / CloudFront / Azure / GCP / CDN hosting
        # infrastructure — these are noise, not attacker IOCs.
        if _is_hosting_infra(raw):
            continue
        artifacts.append(Artifact(
            id=_next_id("dom"),
            type="domain",
            value=raw,
            canonical=_canon_domain(raw),
            source={
                "offset":    start,
                "length":    end - start,
                "line":      _line_of(start),
                "extractor": "ida.domain",
            },
            metadata={"tld": tld},
        ))
        _claim(start, end)

    # ── 9. YARA / Sigma rule blocks (single artifact per block) ───
    for m in _RE_YARA_RULE_LINE.finditer(text):
        start = m.start()
        # Find the matching closing brace for the rule.
        depth = 0
        end = start
        for i in range(m.end() - 1, len(text)):
            ch = text[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        else:
            end = len(text)
        raw = text[start:end]
        artifacts.append(Artifact(
            id=_next_id("yara"),
            type="yara_rule",
            value=raw,
            canonical=raw.strip(),
            source={
                "offset":    start,
                "length":    end - start,
                "line":      _line_of(start),
                "extractor": "ida.yara",
            },
            metadata={},
        ))

    if _RE_SIGMA_MARKER.search(text):
        # Sigma is a whole-document artifact — emit one entry.
        artifacts.append(Artifact(
            id=_next_id("sigma"),
            type="sigma_rule",
            value=text.strip(),
            canonical=text.strip(),
            source={
                "offset":    0,
                "length":    len(text),
                "line":      1,
                "extractor": "ida.sigma",
            },
            metadata={},
        ))

    # ── Sort deterministically by (line, offset) so ordering is
    # the analyst's reading order, not extractor priority order.
    artifacts.sort(key=lambda a: (a.source["line"], a.source["offset"], a.type))

    # Renumber ids after sort so the numeric prefix matches the
    # final artifact order.  Preserves the "art-###-kind" contract.
    for idx, a in enumerate(artifacts, start=1):
        prefix = a.id.rsplit("-", 1)[-1]
        a.id = f"art-{idx:03d}-{prefix}"

    return artifacts


# ══════════════════════════════════════════════════════════════════
# 6. Aggregate summary helper
# ══════════════════════════════════════════════════════════════════
def summarise(artifacts: List[Artifact]) -> Dict[str, int]:
    """Return a `{type: count}` map — cheap for SSOT surfacing."""
    out: Dict[str, int] = {}
    for a in artifacts:
        out[a.type] = out.get(a.type, 0) + 1
    return out
