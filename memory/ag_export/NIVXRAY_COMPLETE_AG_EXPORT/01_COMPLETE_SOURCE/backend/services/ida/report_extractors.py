"""
IDA · Threat Report Extractors (IDA-4) + Content Understanding (IDA-3.5)
────────────────────────────────────────────────────────────────────────
Frozen 2026-03-01 · P0.

Once IDA-3 has acquired a threat-report article, IDA-4 walks the
article body and extracts every investigation-worthy signal:

    · Commands       — powershell / cmd / bash / lolbas lines
    · IOCs           — urls · hashes · ips · domains · registry keys
                       · file paths (via IDA-2 splitter over the body)
    · MITRE ATT&CK   — technique IDs referenced anywhere in the text
    · CVEs           — CVE identifiers
    · Threat actor   — named-entity extraction against a known-actor
                       list + fallback "UNC####" / "APT##" patterns
    · Malware        — named-entity against a curated malware list
    · Timeline       — dated-event bullets ("On 22 July 2026, …")
    · YARA / Sigma   — rule blocks embedded in the article
    · Capabilities   — mentions of persistence, credential access,
                       lateral movement, ransomware, etc.

IDA-3.5 (Content Understanding) is co-located: it produces a
`document_profile` block summarising vendor, sections, capabilities,
timeline presence, MITRE presence, YARA/Sigma presence — the
"table of contents" the analyst can trust before diving in.

All deterministic.  No LLM.  No network.
"""
from __future__ import annotations
import re
from typing import Any, Dict, List, Optional, Tuple

from .artifact_splitter import split_artifacts


# ══════════════════════════════════════════════════════════════════
# 1. Regex library
# ══════════════════════════════════════════════════════════════════
_RE_MITRE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_RE_CVE   = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)

# Threat actor patterns.  Named actors first (curated list), then
# generic UNC / APT / FIN / TA patterns as fallback.
_KNOWN_ACTORS: Tuple[str, ...] = (
    "Scattered Spider", "Muddled Libra", "0ktapus",
    "Lazarus", "Kimsuky", "APT29", "APT28", "APT41", "APT10", "APT34",
    "FIN7", "FIN8", "FIN11", "FIN12",
    "TA505", "TA542", "TA551", "TA544", "TA577",
    "Wizard Spider", "Cozy Bear", "Fancy Bear",
    "Emotet", "Qakbot", "IcedID", "TrickBot",
    "Cobalt Strike", "Sliver", "BruteRatel",
    "BlackCat", "ALPHV", "BlackBasta", "Conti", "Ryuk", "REvil",
    "LockBit", "Play", "Akira", "8Base", "Medusa", "Rhysida",
    "Storm-0303", "Storm-1811", "Storm-1567", "Storm-2372", "Storm-2077",
)
_RE_GENERIC_ACTOR = re.compile(r"\b(?:UNC|APT|TA|FIN|Storm)-?\d{2,4}\b")

# ── MITRE ATT&CK Tactic IDs — NEVER threat actors ──────────────────
# Published MITRE ATT&CK tactic identifiers (Enterprise + Mobile + ICS).
# The generic actor regex above matches `TA\d{2,4}`, which false-positives
# on these tactic ids (e.g. `TA0002` = "Execution" tactic, not an actor).
# This deny-list is the authoritative filter used by `_extract_actors`.
# Distinguishing rule: MITRE tactic IDs are `TA` + 4-digit zero-padded
# number (TA0001..TA0043).  Real Proofpoint TA-numbered actors are
# `TA` + 3-digit number without a leading zero (TA505, TA544, TA577…).
_MITRE_TACTIC_IDS: frozenset = frozenset({
    # Enterprise ATT&CK
    "TA0001", "TA0002", "TA0003", "TA0004", "TA0005", "TA0006",
    "TA0007", "TA0008", "TA0009", "TA0010", "TA0011",
    "TA0040", "TA0042", "TA0043",
    # Mobile ATT&CK (subset, TA0027..TA0038)
    "TA0027", "TA0028", "TA0029", "TA0030", "TA0031", "TA0032",
    "TA0033", "TA0034", "TA0035", "TA0036", "TA0037", "TA0038",
    # ICS ATT&CK (TA0100..TA0111 range)
    "TA0100", "TA0101", "TA0102", "TA0103", "TA0104", "TA0105",
    "TA0106", "TA0107", "TA0108", "TA0109", "TA0110", "TA0111",
})
# Structural rule: any TAxxxx that starts with `TA0` and has exactly 4
# digits is a MITRE tactic id shape — filter even ids we haven't listed.
_RE_MITRE_TACTIC_SHAPE = re.compile(r"^TA0\d{3}$")

_KNOWN_MALWARE: Tuple[str, ...] = (
    "Emotet", "Qakbot", "IcedID", "TrickBot", "Bumblebee", "Danabot",
    "GootLoader", "SocGholish", "Pikabot", "Latrodectus",
    "Cobalt Strike", "Sliver", "BruteRatel", "NightHawk", "Meterpreter",
    "Mimikatz", "LaZagne", "SharpHound", "BloodHound",
    "RClone", "MegaSync",
    "BlackCat", "ALPHV", "BlackBasta", "Conti", "Ryuk", "REvil",
    "LockBit", "Play", "Akira", "Medusa", "Rhysida", "Chaos",
    "Edgecution", "AnyDesk", "ScreenConnect", "TeamViewer", "SimpleHelp",
    "Quick Assist", "QuickAssist",
)

# Capability terms with a small curated set (deterministic, precision-first)
_CAPABILITY_TERMS: Dict[str, Tuple[str, ...]] = {
    "initial_access":     ("phishing", "spear phishing", "vishing", "smishing",
                            "email bombing", "IT impersonation", "quick assist",
                            "help desk social engineering"),
    "execution":          ("powershell", "cmd", "wscript", "cscript", "python",
                            "autohotkey", "javascript", "wsh", "mshta"),
    "persistence":        ("registry run key", "scheduled task", "startup folder",
                            "service", "wmi event subscription", "native messaging"),
    "privilege_escalation": ("uac bypass", "token impersonation", "sedebug"),
    "defense_evasion":    ("obfuscation", "base64", "encoded", "signed binary",
                            "living off the land", "lolbas"),
    "credential_access":  ("mimikatz", "lsass", "credential dump", "browser credential",
                            "keychain", "vaults"),
    "discovery":          ("net user", "net group", "nltest", "adfind", "sharphound",
                            "bloodhound", "whoami"),
    "lateral_movement":   ("psexec", "wmic", "smb", "remote service", "smbexec",
                            "rdp", "psremoting"),
    "collection":         ("clipboard", "screen capture", "keylogger", "email harvest"),
    "command_and_control": ("cobalt strike beacon", "sliver", "reverse shell",
                            "c2", "beacon"),
    "exfiltration":       ("rclone", "megasync", "curl", "wget", "http upload"),
    "impact":             ("ransomware", "encryptor", "wiper", "extortion"),
}


# Section headers a threat report typically has.  Presence signals that
# IDA-3.5 has a rich document.  Longest-first so the matcher is stable.
_SECTION_HEADERS: Tuple[str, ...] = (
    "Executive Summary", "Key Findings", "Attack Chain",
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Command and Control", "Exfiltration", "Impact",
    "Recommendations", "Mitigation", "Indicators of Compromise", "IOCs",
    "Detection", "YARA Rules", "Sigma Rules",
    "Timeline", "Attribution", "Threat Actor", "Malware Analysis",
    "MITRE ATT&CK", "Techniques",
)


# ══════════════════════════════════════════════════════════════════
# 2. Public API
# ══════════════════════════════════════════════════════════════════
def understand_document(article_text: str, meta: Dict[str, Any]) -> Dict[str, Any]:
    """IDA-3.5 · Content Understanding.

    Produces a shallow `document_profile{}` block describing WHAT
    the article contains before IDA-4 walks it in detail.  Cheap
    (single-pass regex scans).  Analyst-visible.
    """
    text = article_text or ""
    if not text.strip():
        return {"ok": False, "reason": "empty article"}

    sections = _detect_sections(text)
    mitre_present = bool(_RE_MITRE.search(text))
    cve_present   = bool(_RE_CVE.search(text))
    yara_present  = "rule " in text and " condition:" in text
    sigma_present = "detection:" in text and "logsource:" in text
    timeline_present = _has_timeline(text)

    capabilities: List[str] = []
    lower = text.lower()
    for cap, terms in _CAPABILITY_TERMS.items():
        if any(t in lower for t in terms):
            capabilities.append(cap)

    return {
        "ok":               True,
        "vendor":           meta.get("sitename") or "",
        "title":            meta.get("title") or "",
        "author":           meta.get("author") or "",
        "published_date":   meta.get("published_date") or "",
        "language":         meta.get("language") or "",
        "char_count":       len(text),
        "word_count":       len(text.split()),
        "sections":         sections,
        "capabilities":     capabilities,
        "mitre_present":    mitre_present,
        "cve_present":      cve_present,
        "yara_present":     yara_present,
        "sigma_present":    sigma_present,
        "timeline_present": timeline_present,
    }


def extract_all(article_text: str,
                structured_blocks: Optional[List[str]] = None) -> Dict[str, Any]:
    """IDA-4 · walk the article body + structured blocks once and emit
    every extractor's output.  The result plugs straight into SSOT as
    `report_extraction{}`.

    `structured_blocks` are raw text pulled from `<code>`, `<pre>`,
    `<td>`, and `<li>` HTML containers by IDA-3.  Threat-report
    authors publish command samples and IOCs in exactly those
    containers; without them we'd miss e.g. `"C:\\Program Files
    (x86)\\...msedge.exe" --headless=new` because trafilatura strips
    the surrounding HTML.
    """
    text = article_text or ""
    blocks = list(structured_blocks or [])

    if not text.strip() and not blocks:
        return _empty_extraction()

    # For prose-oriented extractors (capabilities, timeline, MITRE,
    # actor, malware) we search the article + joined blocks so nothing
    # published inside tables is missed.
    joined = text + "\n\n" + "\n".join(blocks)

    # For IOC extraction we run the IDA-2 artifact splitter on the
    # joined text as well — hashes / URLs / IPs / domains / registry
    # keys / file paths / CVEs the article mentions become first-class
    # artifacts with provenance.
    body_artifacts = [a.to_dict() for a in split_artifacts(joined)]

    mitre    = _extract_mitre(joined)
    cves     = _extract_cves(joined)
    actors   = _extract_actors(joined)
    malware  = _extract_malware(joined)
    commands = _extract_commands(text, blocks)
    timeline = _extract_timeline(joined)
    yara     = _extract_yara(joined)
    sigma    = _extract_sigma(joined)
    hash_ctx = _extract_hash_context(joined, blocks)

    # ── Stage 5 · Deterministic Behavior Generation ──────────────
    # Convert commands / malware / LOLBAS / CVE evidence into
    # canonical Behavior objects, then derive additional MITRE
    # techniques from those Behaviors.  Purely deterministic
    # lookups — no prose inference, nothing invented.
    from .behaviors import generate_behaviors, collect_mitre_from_behaviors
    behaviors = generate_behaviors({
        "commands":         commands,
        "malware_families": malware,
        "body_artifacts":   body_artifacts,
        "cves":             cves,
    })
    _seen_mitre = {m["id"] for m in mitre}
    for m in collect_mitre_from_behaviors(behaviors):
        if m["id"] not in _seen_mitre:
            mitre.append(m)
            _seen_mitre.add(m["id"])

    return {
        "body_artifacts":     body_artifacts,
        "mitre_techniques":   mitre,
        "cves":               cves,
        "threat_actors":      actors,
        "malware_families":   malware,
        "commands":           commands,
        "timeline":           timeline,
        "yara_rules":         yara,
        "sigma_rules":        sigma,
        "hash_context":       hash_ctx,
        # New in P0.3 · Stage 5 · Behavior Generation.
        "behaviors":          [b.to_dict() for b in behaviors],
        "totals": {
            "artifacts": len(body_artifacts),
            "mitre":     len(mitre),
            "cves":      len(cves),
            "actors":    len(actors),
            "malware":   len(malware),
            "commands":  len(commands),
            "timeline":  len(timeline),
            "yara":      len(yara),
            "sigma":     len(sigma),
            "behaviors": len(behaviors),
        },
    }


def _extract_hash_context(text: str,
                            blocks: List[str]) -> Dict[str, Dict[str, str]]:
    """Build a hash → {filename, description} lookup from IOC tables.

    Threat reports render hashes in tables like:
        | Filename        | SHA256           | Description       |
        | wininit.exe     | 5540f27f...      | Renamed rclone    |

    trafilatura collapses the row into one line.  We look for a
    filename token (word.ext) within 200 chars of every hash and take
    the first non-hash sentence-like chunk as its description.
    """
    ctx: Dict[str, Dict[str, str]] = {}
    hash_re     = re.compile(r"\b([A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}|[A-Fa-f0-9]{128})\b")
    # Common attacker-tool file extensions.
    filename_re = re.compile(
        r"\b([A-Za-z0-9_.\-]{1,60}"
        r"\.(?:exe|dll|ps1|vbs|js|bat|cmd|sh|py|scr|msi|zip|rar|7z|iso|lnk|bin|elf|app|dmg|apk))\b",
        re.I,
    )
    # Scan article text + every structured block (tables live in blocks).
    corpora = [text] + list(blocks or [])
    for corpus in corpora:
        for m in hash_re.finditer(corpus):
            h = m.group(1).lower()
            if h in ctx:
                continue
            # Window ±200 chars around the hash.
            i = m.start()
            j = m.end()
            left  = corpus[max(0, i - 200): i]
            right = corpus[j: j + 200]
            fn_left  = filename_re.findall(left)
            fn_right = filename_re.findall(right)
            filename = ""
            if fn_left:
                filename = fn_left[-1]      # closest filename before hash
            elif fn_right:
                filename = fn_right[0]      # closest filename after hash
            # Description: take the tail of the right window up to 120
            # chars, stripping leading punctuation/pipes.
            desc = right.lstrip(" |\t,;:-—").strip()
            # Remove any inline hashes / paths so the description reads
            # as prose.
            desc = re.sub(r"[A-Fa-f0-9]{32,128}", "", desc)
            desc = re.sub(r"\s+", " ", desc).strip(" |\t,;:-—.")
            desc = desc[:120]
            if filename or desc:
                ctx[h] = {"filename": filename, "description": desc}
    return ctx


# ══════════════════════════════════════════════════════════════════
# 3. Extractors (deterministic, precision-first)
# ══════════════════════════════════════════════════════════════════
def _detect_sections(text: str) -> List[str]:
    """Return the headers we can confidently detect (order-preserving)."""
    seen: List[str] = []
    for h in _SECTION_HEADERS:
        if re.search(rf"(?m)^\s*{re.escape(h)}\s*$", text, re.I):
            if h not in seen:
                seen.append(h)
    return seen


def _has_timeline(text: str) -> bool:
    """A timeline is present when we see ≥ 2 date-anchored bullets."""
    date_hits = re.findall(
        r"\b(?:January|February|March|April|May|June|July|August|"
        r"September|October|November|December)\s+\d{1,2}(?:,\s*\d{4})?\b",
        text, re.I,
    )
    return len(date_hits) >= 2


def _extract_mitre(text: str) -> List[Dict[str, Any]]:
    seen: Dict[str, Dict[str, Any]] = {}
    for m in _RE_MITRE.finditer(text):
        tid = m.group(0).upper()
        if tid not in seen:
            # Best-effort local excerpt (± 80 chars)
            i = m.start()
            ex = text[max(0, i - 80): i + 80].replace("\n", " ").strip()
            seen[tid] = {"id": tid, "evidence": ex, "source": "ida.report.mitre"}
    return list(seen.values())


def _extract_cves(text: str) -> List[Dict[str, Any]]:
    seen: Dict[str, Dict[str, Any]] = {}
    for m in _RE_CVE.finditer(text):
        cid = m.group(0).upper()
        seen.setdefault(cid, {
            "id":     cid,
            "year":   int(cid.split("-")[1]),
            "source": "ida.report.cve",
        })
    return list(seen.values())


def _extract_actors(text: str) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    seen: set = set()
    for actor in _KNOWN_ACTORS:
        pattern = r"\b" + re.escape(actor) + r"\b"
        if re.search(pattern, text) and actor not in seen:
            seen.add(actor)
            hits.append({"name": actor, "kind": "curated",
                          "source": "ida.report.actor"})
    for m in _RE_GENERIC_ACTOR.finditer(text):
        raw = m.group(0)
        # De-conflate MITRE ATT&CK tactic IDs (TA0001..TA0043 + ICS/Mobile
        # ranges) from real threat actors.  A tactic id like `TA0002` is
        # NEVER a threat actor and would contaminate investigator-facing
        # intelligence if surfaced here.  Two-layer filter:
        #   1. Exact match against the authoritative deny-list.
        #   2. Shape guard: `TA0\d{3}` — any TA + 4 digits starting with 0.
        norm = raw.replace("-", "")
        if norm in _MITRE_TACTIC_IDS:
            continue
        if _RE_MITRE_TACTIC_SHAPE.match(norm):
            continue
        if raw not in seen:
            seen.add(raw)
            hits.append({"name": raw, "kind": "generic",
                          "source": "ida.report.actor"})
    return hits


def _extract_malware(text: str) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    seen: set = set()
    for name in _KNOWN_MALWARE:
        # Word-boundary match — substring matches on short names like
        # "Play", "Conti", "Chaos" would false-positive on English
        # words like "displayed", "contains", "chaotic".
        pattern = r"\b" + re.escape(name) + r"\b"
        if re.search(pattern, text) and name not in seen:
            seen.add(name)
            hits.append({"name": name, "source": "ida.report.malware"})
    return hits


def _split_executable_and_args(cmdline: str) -> Tuple[str, List[str]]:
    """Split a command line into (executable, [arguments]).

    Handles three head shapes NivXRay sees in threat reports:
      · Quoted path:   `"C:\\Program Files\\foo.exe" -a -b`
      · Bare path:     `C:\\Windows\\System32\\cmd.exe /c whoami`
      · Bare basename: `powershell.exe -enc ...`   /   `wininit.exe copy ...`

    Argument tokenisation respects single- and double-quoted regions so
    quoted args (`'delete'`, `"C:\\Program Files\\x"`) survive intact.
    """
    s = cmdline.strip()

    # 1. Head — quoted path
    if s.startswith('"'):
        m = re.match(r'^"([^"]+\.exe)"\s*(.*)$', s, re.I)
        if m:
            return m.group(1), _tokenise_args(m.group(2))

    # 2. Head — bare Windows path ending in `.exe`
    m = re.match(r'^([A-Za-z]:\\[^\s,]+\.exe)(?:\s+(.*))?$', s, re.I)
    if m:
        return m.group(1), _tokenise_args(m.group(2) or "")

    # 3. Head — bare basename ending in `.exe`
    m = re.match(r'^([A-Za-z0-9_\-.]+\.exe)(?:\s+(.*))?$', s, re.I)
    if m:
        return m.group(1), _tokenise_args(m.group(2) or "")

    # 4. Head — interpreter without `.exe` (`powershell -c …`, `bash -c …`)
    m = re.match(r'^([A-Za-z0-9_\-.]+)(?:\s+(.*))?$', s)
    if m:
        return m.group(1), _tokenise_args(m.group(2) or "")

    return s, []


def _tokenise_args(rest: str) -> List[str]:
    """Split argument text into tokens, respecting `"…"` and `'…'`."""
    rest = (rest or "").strip()
    if not rest:
        return []
    tokens: List[str] = []
    buf: List[str] = []
    quote: Optional[str] = None
    for ch in rest:
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
                tokens.append("".join(buf))
                buf = []
        elif ch in ('"', "'"):
            if buf:
                tokens.append("".join(buf))
                buf = []
            quote = ch
            buf.append(ch)
        elif ch.isspace():
            if buf:
                tokens.append("".join(buf))
                buf = []
        else:
            buf.append(ch)
    if buf:
        tokens.append("".join(buf))
    return tokens


def _embedded_artifacts(cmdline: str, executable: str) -> Dict[str, List[str]]:
    """Return artifacts embedded inside a command line.

    A command line is the primary investigation object; the executable
    path, URLs, hashes, IPs, domains, and registry keys inside it are
    embedded artifacts that MUST also be surfaced so IOCE and DIE can
    correlate them independently.
    """
    from .artifact_splitter import split_artifacts
    inner = split_artifacts(cmdline) or []
    buckets: Dict[str, List[str]] = {
        "file_paths":    [executable] if executable and (
            "\\" in executable or "/" in executable
        ) else [],
        "registry_keys": [],
        "urls":          [],
        "ips":           [],
        "domains":       [],
        "hashes":        [],
    }
    for a in inner:
        atype = getattr(a, "type", None) or (a.get("type") if isinstance(a, dict) else None)
        value = getattr(a, "value", None) or (a.get("value") if isinstance(a, dict) else None)
        if not atype or not value:
            continue
        if atype == "file_path" and value not in buckets["file_paths"]:
            buckets["file_paths"].append(value)
        elif atype == "registry_key" and value not in buckets["registry_keys"]:
            buckets["registry_keys"].append(value)
        elif atype == "url" and value not in buckets["urls"]:
            buckets["urls"].append(value)
        elif atype == "ip" and value not in buckets["ips"]:
            buckets["ips"].append(value)
        elif atype == "domain" and value not in buckets["domains"]:
            buckets["domains"].append(value)
        elif atype == "hash" and value not in buckets["hashes"]:
            buckets["hashes"].append(value)
    return buckets


def _extract_commands(text: str,
                      structured_blocks: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """Command-line samples the article calls out.

    Precision + recall balance:
      1. Iterate over article lines AND every structured block (each
         `<code>`, `<pre>`, `<td>`, `<li>` from IDA-3).
      2. Strip common vendor-table prefixes like `Command Line`,
         `Command`, `Cmd`.
      3. A candidate line must satisfy BOTH gates:
           gate A · looks like it starts with a command
                     (a) a known interpreter head + space (`powershell `,
                         `cmd `, `tar.exe `, `msedge.exe `, …), OR
                     (b) a quoted Windows path ending in `.exe`
                         (`"C:\\Program Files\\...\\foo.exe"`), OR
                     (c) a bare Windows-style path ending in `.exe`
                         (`C:\\Users\\Public\\host.py`  — cmd.exe /c form)
           gate B · looks like a real command payload
                     (a switch `- ` / ` -x` / ` --foo` / ` /c` / `.exe`
                     reference / env-var / redirection / chaining)
      4. Deduplicate on the normalised command (whitespace-collapsed).
    """
    _HEAD_START = re.compile(
        r"(?i)^\s*"
        r"(?:"
        # Windows shell env-var wrappers.  Real EDR telemetry frequently
        # renders the command line with `%COMSPEC%` (expands to cmd.exe)
        # or `%SystemRoot%\system32\cmd.exe` as the head; without these
        # heads the extractor drops entire commands from vendor articles
        # (e.g. Sophos "Decoding Malicious PowerShell" 2018).  The
        # existing canonicalizer already peels these wrappers to expose
        # the inner interpreter (powershell / rundll32 / etc).
        r"%COMSPEC%|%SystemRoot%\\[Ss]ystem32\\cmd\.exe|"
        r"powershell|pwsh|cmd|bash|sh|python[3w]?|wscript|cscript|"
        r"mshta|rundll32|regsvr32|certutil|bitsadmin|msiexec|schtasks|wmic|"
        r"curl|wget|reg|net|tar|msedge|chrome|"
        r"brave|firefox|explorer|vssadmin|nltest|whoami|hostname|"
        r"ipconfig|ping|nslookup|taskkill|attrib|xcopy|robocopy|sc|psexec|"
        r"autohotkey|ahk|node|npm|yarn"
        r")"
        r"(?:\.exe)?"                        # optional .exe suffix on any head
        r"(?=\s|$)"                          # SPACE or EOL required
    )
    # Quoted path launcher: `"C:\Program Files (x86)\...\foo.exe"`
    _QUOTED_EXE_START = re.compile(r'^\s*"[A-Za-z]:\\[^"]+\.exe"', re.I)
    # Bare Windows path launcher (unquoted): `C:\WINDOWS\system32\cmd.EXE ...`
    # Some vendor write-ups (Cisco Talos, Mandiant) render commands
    # this way when transcribing EDR telemetry.
    _BARE_EXE_START = re.compile(r'^\s*[A-Za-z]:\\[^\s,]+\.exe\b', re.I)
    # Bare basename EXE start — `wininit.exe copy --max-age ...` (no drive
    # letter).  Only accepted when the line has already been proven to be
    # an EDR-tokenised command via `_EDR_TOKEN_LINE` below, otherwise this
    # would false-positive on prose like `notepad.exe was seen…`.
    _BARE_BASENAME_EXE_START = re.compile(
        r'^\s*[A-Za-z0-9_\-.]+\.exe\b', re.I,
    )
    # EDR-style comma-tokenised argument list — the whole command is
    # written as `path\to.exe, arg1, arg2, arg3`.  We detokenise it
    # so the confirm gate below sees a normal command string.
    _EDR_TOKEN_LINE = re.compile(
        r'^\s*(?:"?[A-Za-z]:\\[^"\s,]+\.exe"?|[A-Za-z0-9_\-.]+\.exe|\w+)'
        r'\s*,\s+(?:[^,\s][^,]{0,80})(?:\s*,\s+[^,\s][^,]{0,80}){2,}',
        re.I,
    )
    # Multi-invocation EDR row — several full Windows exe paths joined
    # by `, ` (e.g. `services.exe, C:\...\msiexec.exe /V, C:\...\MsiExec.exe -E`).
    # We split at each new drive-letter path so every process invocation
    # emits as its own command hit.
    _MULTI_EXE_SPLIT = re.compile(r',\s+(?=[A-Za-z]:\\)')

    # Confirm the payload is actually a command, not prose or a bare path.
    # KEY RULE: a command MUST have real content AFTER the executable —
    # `C:\...\services.exe` alone is a file path, not a command.
    _COMMAND_CONFIRM = re.compile(
        r'(?:'
        r'\s-{1,2}[A-Za-z]'               # ` -X` / ` --x`
        r'|\s/[A-Za-z]{1,4}(?:[:=]|\s|$)'  # ` /c ` / ` /min ` / ` /f `
        r'|"[A-Za-z]:\\'                   # `"C:\...`
        r'|%[A-Z_]+%'                      # env-var
        r'|2>&?1|>\s*nul|&&|\|\||;\s|\s&\s'  # redirection / chaining
        r'|\.exe\b\s+\S'                   # `.exe` followed by an argument
        r')'
    )

    # Vendor tables often render one command as one row shaped like
    # `Command Line  |  <the actual command>  |  <description>`.
    # trafilatura collapses that into `Command Line <the command> <desc>`.
    # We strip the label prefix so the detector sees the real command.
    # NOTE: We deliberately do NOT list bare `Cmd` / `Command` here —
    # those would eat the leading `cmd` of a real `cmd /c ...`
    # command.  Only the unambiguous multi-token labels are stripped.
    _LABEL_PREFIX = re.compile(
        r"^\s*(?:Command\s+Line|Terminal\s+Command|Shell\s+Command)"
        r"\s*[:\-–|]?\s+",
        re.IGNORECASE,
    )

    seen: set = set()
    hits: List[Dict[str, Any]] = []

    def _consider(raw: str, source: str, line_no: int) -> None:
        s = (raw or "").strip()
        # 2026-02-09 · Raise per-line cap from 2 KB to 32 KB so real
        # threat-report base64 blobs (Sophos "Decoding Malicious
        # PowerShell" ships a 7,552-char `-EncodedCommand` blob;
        # Cobalt Strike stagers routinely hit 10 KB) survive
        # extraction.  Below the cap the downstream recursive
        # decoder can peel base64 → utf-16-le → base64 → gzip →
        # byte-array-XOR → shellcode → C2 IP.  Above 32 KB we
        # bail — pathological blocks would starve extraction.
        if not s or len(s) > 32768 or len(s) < 10:
            return
        # Strip table-cell label prefix (`Command Line ...`)
        s = _LABEL_PREFIX.sub("", s)
        if len(s) < 10:
            return

        # Detokenise EDR-style comma argument lists BEFORE gating so a
        # `cmd.EXE, /c, wmic, product, ...` transcript from Talos or
        # Mandiant is reconstituted into a normal command string.

        # Multi-invocation EDR row: `svc.exe, C:\...\a.exe /V, C:\...\b.exe -E`
        # → split at each new drive-letter boundary and emit each
        # process invocation as its own command hit.  Runs BEFORE the
        # EDR-token check because a 2-invocation row won't have the
        # ≥3 tokens EDR detection expects.
        if _MULTI_EXE_SPLIT.search(s) and re.match(
            r'^\s*(?:"?[A-Za-z]:\\[^"\s,]+\.exe"?|[A-Za-z0-9_\-.]+\.exe)', s, re.I
        ):
            parts = _MULTI_EXE_SPLIT.split(s)
            if len(parts) >= 2:
                for part in parts:
                    part = part.strip().rstrip(",").strip()
                    if part and part != s:
                        _consider(part, source, line_no)
                return

        edr_matched = bool(_EDR_TOKEN_LINE.match(s))
        if edr_matched:
            # Single-invocation EDR row — detokenise arg commas.
            s = re.sub(r"\s*,\s+", " ", s)

        head_m  = _HEAD_START.match(s)
        quoted  = _QUOTED_EXE_START.match(s)
        bare    = _BARE_EXE_START.match(s)
        # EDR-tokenised lines already proved they are commands via the
        # `<exe>, arg, arg, arg, ...` structure — accept a bare basename
        # exe start (`wininit.exe copy --max-age ...`) too.
        basename = None
        if edr_matched and not (head_m or quoted or bare):
            basename = _BARE_BASENAME_EXE_START.match(s)
        if not (head_m or quoted or bare or basename):
            return
        if not _COMMAND_CONFIRM.search(s):
            return

        key = re.sub(r"\s+", " ", s).strip()
        if key in seen:
            return
        seen.add(key)

        if head_m:
            head_token = head_m.group(0).strip().lower()
        elif quoted:
            # quoted path — pull the basename before `.exe`
            m = re.search(r"([^\\/\"]+\.exe)\"", s, re.I)
            head_token = (m.group(1).lower() if m else "quoted-exe")
        else:
            # bare Windows path — basename before `.exe`
            m = re.search(r"([^\\/\s,]+\.exe)\b", s, re.I)
            head_token = (m.group(1).lower() if m else "bare-exe")

        executable, arguments = _split_executable_and_args(key)
        embedded = _embedded_artifacts(key, executable)

        hits.append({
            "command":            key,
            "primary_type":       "command_line",
            "executable":         executable,
            "arguments":          arguments,
            "embedded_artifacts": embedded,
            "head":               head_token,
            "purpose":            _classify_command_purpose(key, head_token),
            "line":               line_no,
            "source":             source,
        })

    # 1. Article lines
    for i, line in enumerate((text or "").splitlines(), start=1):
        _consider(line, "ida.report.command.article", i)

    # 2. Structured HTML blocks (code / pre / td / li).  Each block
    # may itself contain multiple lines.
    for j, block in enumerate(structured_blocks or [], start=1):
        for k, line in enumerate(block.splitlines(), start=1):
            _consider(line, f"ida.report.command.block[{j}]", k)

    return hits


def _extract_timeline(text: str) -> List[Dict[str, Any]]:
    """Extract dated events from the article body.  Handles:
        · Explicit date-first lines ("On July 22, ...")
        · Prefixed bullets ("• 2026-07-22 · ...")
        · Relative markers ("In late April,", "Later that day", "hours after")
        · Sentence-embedded dates ("... on July 22, the actor ...")
    """
    hits: List[Dict[str, Any]] = []
    seen_keys: set = set()

    def _add(date: str, event: str, src: str) -> None:
        d = (date or "").strip().strip(",")
        e = (event or "").strip().strip(",.:")
        if not e or len(e) < 5:
            return
        key = (d.lower(), e[:80].lower())
        if key in seen_keys:
            return
        seen_keys.add(key)
        hits.append({"date": d, "event": e[:400], "source": src})

    # 1. Explicit date-anchored lines (existing regex)
    for m in re.finditer(
        r"(?im)^(?:[\-\*•\u2022]\s*)?"
        r"(?:on\s+)?"
        r"((?:January|February|March|April|May|June|July|August|"
        r"September|October|November|December)\s+\d{1,2}(?:,\s*\d{4})?"
        r"|\d{4}-\d{2}-\d{2})"
        r"[\s,\-:—]+"
        r"(.{5,300})$",
        text,
    ):
        _add(m.group(1), m.group(2), "ida.report.timeline")

    # 2. Sentence-embedded absolute dates: "On July 22, the actor ..."
    for m in re.finditer(
        r"(?i)(?:^|[.!?]\s+|,\s+)"
        r"(?:on|in|by|around|during)?\s*"
        r"((?:January|February|March|April|May|June|July|August|"
        r"September|October|November|December)"
        r"(?:\s+\d{1,2}(?:,\s*\d{4})?)?"
        r"|\d{4}-\d{2}-\d{2})"
        r"[,\s]+"
        r"([A-Z][^.!?]{15,240}[.!?])",
        text,
    ):
        _add(m.group(1), m.group(2), "ida.report.timeline.sentence")

    # 3. Relative-time anchors: "In late April, ...", "Later that day, ...",
    # "hours after initial access, ...", "since January 2025, ..."
    _RELATIVE = (
        r"in\s+(?:early|mid|late)\s+(?:January|February|March|April|May|June|"
        r"July|August|September|October|November|December)"
        r"(?:\s+\d{4})?"
        r"|since\s+(?:January|February|March|April|May|June|July|August|"
        r"September|October|November|December)\s+\d{4}"
        r"|later\s+that\s+day"
        r"|the\s+same\s+day"
        r"|hours?\s+after\s+[a-z ]{3,30}"
        r"|over\s+\d+\s+hours?"
        r"|within\s+\d+\s+(?:hours?|days?|minutes?)"
    )
    for m in re.finditer(
        rf"(?i)(?:^|[.!?]\s+|,\s+)({_RELATIVE})"
        rf"[,\s]+([A-Z][^.!?]{{15,240}}[.!?])",
        text,
    ):
        _add(m.group(1).strip(), m.group(2), "ida.report.timeline.relative")

    return hits


def _extract_yara(text: str) -> List[Dict[str, Any]]:
    """Extract each YARA rule block."""
    hits: List[Dict[str, Any]] = []
    for m in re.finditer(r"(?m)^\s*rule\s+([A-Za-z_][\w]*)\s*(?::[\w\s,]+)?\s*\{", text):
        start = m.start()
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
        hits.append({
            "name":   m.group(1),
            "body":   text[start:end],
            "source": "ida.report.yara",
        })
    return hits


def _extract_sigma(text: str) -> List[Dict[str, Any]]:
    """Sigma blocks are Yaml; presence is a coarse signal (real
    parsing is a later slice)."""
    if "detection:" in text and "logsource:" in text:
        return [{"body": text, "source": "ida.report.sigma"}]
    return []


def _empty_extraction() -> Dict[str, Any]:
    return {
        "body_artifacts":     [],
        "mitre_techniques":   [],
        "cves":               [],
        "threat_actors":      [],
        "malware_families":   [],
        "commands":           [],
        "timeline":           [],
        "yara_rules":         [],
        "sigma_rules":        [],
        "behaviors":          [],
        "totals": {
            "artifacts": 0, "mitre": 0, "cves": 0, "actors": 0,
            "malware": 0, "commands": 0, "timeline": 0, "yara": 0, "sigma": 0,
            "behaviors": 0,
        },
    }


# ══════════════════════════════════════════════════════════════════
# Command purpose classifier — deterministic labels analysts expect
# ══════════════════════════════════════════════════════════════════
def _classify_command_purpose(cmd: str, head: str) -> str:
    """Return a short analyst-facing purpose label for a command,
    e.g. "Unzip Edgecution stager", "Python discovery",
    "Microsoft Edge launch (extension load)", "Self-deletion".
    Deterministic — matches the labels vendors publish in their
    Command-Line IOC tables.

    2026-02-08 · P0.15A · ADR-002 · Canonicalizer integration.
    Every call is first routed through the Evidence Canonicalizer
    so wrapped invocations (``cmd /S /C "schtasks …"``,
    ``powershell -EncodedCommand …``) reach the classifier with
    their real ``effective_head`` and payload.  The classifier
    itself is unchanged — it just sees a cleaner input.
    """
    # ── Canonicalise (ADR-002 §3.2) ──────────────────────────────
    # If the caller's head already matches the effective head the
    # canonicalizer would return, the peel is a no-op — no harm.
    #
    # 2026-02-09 · P1 Classifier Expansion — we ALSO retain the
    # pre-peel `original_head` / `original_cmd` so LOLBin & RMM
    # branches (mshta / rundll32 / regsvr32 / AnyDesk / …) still
    # match after the canonicalizer aggressively strips their
    # invocation.  The peeled head remains the primary signal for
    # everything the canonicalizer correctly unwraps (cmd /c,
    # powershell -c ${block}, etc.).
    original_head = head.lower()
    original_cmd  = cmd
    try:
        from services.canonicalizer import canonicalize
        cc = canonicalize(cmd)
        if cc.unwrap_depth > 0 and cc.effective_head:
            # Lowercase head so downstream `head in (...)` checks
            # (which use lowercase tuples) match.  Strip any
            # residual quotes on payload — shlex(posix=False) keeps
            # them on quoted arg tokens.
            head = cc.effective_head.lower()
            cmd  = cc.payload.strip().strip('"').strip("'")
    except Exception:
        # Canonicalizer failures MUST NOT break classification —
        # gracefully fall back to the original arguments.
        pass
    c = cmd.lower()
    oc = original_cmd.lower()

    # ── Impact / shadow copy deletion (T1490) ──────────────────────
    if "vssadmin" in head and ("delete" in c and "shadow" in c):
        return "Shadow copy deletion"
    if "wmic" in c and "shadowcopy" in c and "delete" in c:
        return "Shadow copy deletion (WMIC)"

    # ── Software uninstall via WMIC (defense evasion of security agents) ─
    if "wmic" in c and "product" in c and "uninstall" in c:
        return "Software uninstall (defense evasion)"

    # ── MSI installer execution (T1218.007) ────────────────────────
    if head in ("msiexec.exe", "msiexec") or "msiexec.exe" in c.split()[0:1]:
        if "-embedding" in c:
            return "MSI installer child (embedded)"
        if "/i " in c or " /i " in c or "/quiet" in c or "/qn" in c:
            return "MSI installation"
        return "MSI execution"

    # ── Reverse SSH tunnel (T1572) ─────────────────────────────────
    if "ssh.exe" in head or head == "ssh":
        if " -r " in (" " + c + " ") or c.strip().split(".exe", 1)[-1].lstrip().startswith("-r"):
            return "Reverse SSH tunnel"
        if " -l " in c or " -n " in c:
            return "SSH remote session"
        return "SSH client execution"

    # ── Rclone / mass copy exfil style (T1567 / T1020) ─────────────
    if "rclone" in head or ("copy" in c and "--max-age" in c) or ("--exclude" in c and "*.{" in c) \
       or ("--exclude" in c and "*{" in c):
        return "Data staging / exfil (rclone-style)"

    # ── PsExec lateral movement (T1021.002) ────────────────────────
    if "psexec" in head or "psexec" in c.split()[0:1]:
        return "Lateral movement via PsExec"
    if "impacket" in c or "wmiexec" in c or "smbexec" in c:
        return "Lateral movement via Impacket"
    # ── SMB admin-share access via `net use \\host\c$` (T1021.002) ─
    # Head=net · payload starts with `use \\<host>\<share>`.  Also
    # match `\\<host>\admin$` and IPC$ variants.
    if head in ("net", "net.exe") and (" use " in " " + c + " " or c.startswith("use ")):
        if "\\\\" in cmd or "\\\\" in original_cmd or "$" in c:
            return "SMB admin share access"

    # ── LOLBin proxy execution ─────────────────────────────────────
    # Order-sensitive: check specific proxy binaries BEFORE the
    # generic head-based branches so `rundll32.exe c:\x.dll,#1`
    # doesn't fall through to the generic "Command execution".
    #
    # Use the pre-peel `original_head` — the canonicalizer strips
    # LOLBin invocations aggressively (`mshta.exe URL` → head=URL),
    # which would otherwise defeat this branch entirely.
    if original_head in ("mshta", "mshta.exe"):
        return "Mshta proxy execution"
    if original_head in ("rundll32", "rundll32.exe"):
        # COM hijack check MUST fire before the generic rundll32
        # branch — otherwise the inprocserver32 signal is lost.
        if "comsvcs" in oc and ("minidump" in oc or "#24" in oc):
            return "LSASS memory dump (comsvcs)"
        if "inprocserver32" in oc:
            return "COM hijack (regsvr32)"   # same TTP family; keep unified label
        return "Rundll32 proxy execution"
    if original_head in ("regsvr32", "regsvr32.exe"):
        if "inprocserver32" in oc:
            return "COM hijack (regsvr32)"
        return "Regsvr32 proxy execution"
    if original_head in ("installutil", "installutil.exe"):
        return "Installutil proxy execution"
    if original_head in ("msbuild", "msbuild.exe"):
        return "MSBuild proxy execution"
    if original_head in ("wscript", "wscript.exe"):
        return "WScript execution"
    if original_head in ("cscript", "cscript.exe"):
        return "CScript execution"

    # ── Credential Access · LSASS + NTDS ───────────────────────────
    if "procdump" in head or "procdump" in c:
        if "lsass" in c:
            return "LSASS memory dump (procdump)"
        return "Process memory dump (procdump)"
    if "comsvcs" in c and ("minidump" in c or "#24" in c):
        return "LSASS memory dump (comsvcs)"
    if "mimikatz" in c:
        return "Credential dumping (mimikatz)"
    if head in ("ntdsutil", "ntdsutil.exe") or "ntdsutil" in c and "ntds" in c:
        return "NTDS.dit extraction (ntdsutil)"
    if head in ("reg", "reg.exe") and " save " in c and ("hklm\\sam" in c or "hklm\\security" in c or "hklm\\system" in c):
        return "SAM/SECURITY hive dump (reg save)"

    # ── Defense Evasion · Windows Defender tampering (T1562.001) ───
    if "add-mppreference" in c and "exclusion" in c:
        return "Windows Defender exclusion add"
    if "set-mppreference" in c and ("disable" in c or "-disable" in c):
        return "Windows Defender configure (disable)"
    if head in ("sc", "sc.exe") and "windefend" in c and (" stop " in c or " delete " in c or " config " in c):
        return "Windows Defender service tamper"

    # ── Defense Evasion · Event log clearing (T1070.001) ──────────
    if head in ("wevtutil", "wevtutil.exe") and ("cl " in c or "clear-log" in c):
        return "Event log clear (wevtutil)"
    if head.startswith("powershell") and "clear-eventlog" in c:
        return "Event log clear (PowerShell)"

    # ── Impact · Recovery inhibit (T1490) ─────────────────────────
    if head in ("bcdedit", "bcdedit.exe") and ("recoveryenabled" in c or "ignoreallfailures" in c or "bootstatuspolicy" in c):
        return "Recovery inhibit (bcdedit)"
    if head in ("wbadmin", "wbadmin.exe") and "delete" in c and ("catalog" in c or "backup" in c):
        return "Backup catalog deletion (wbadmin)"

    # ── WMI command execution (T1047 / T1021) ──────────────────────
    if head in ("wmic", "wmic.exe") or original_head in ("wmic", "wmic.exe"):
        # Some canonicalizer variants peel the payload down to the
        # bare head (`wmic`) — inspect the ORIGINAL command text so
        # `wmic process ... call getowner` still classifies.
        scan = c + " " + oc
        # Remote WMI process create → T1047 + T1021
        if "/node:" in scan and ("process call create" in scan or "call create" in scan):
            return "Remote WMI process create"
        if "process call create" in scan or "call create" in scan:
            return "WMI process create"
        # WMI process discovery — `process where … call getowner`,
        # `call terminate`, or a bare `process list` / `process get`.
        if "process" in scan and ("call getowner" in scan or "call terminate" in scan
                                        or "list" in scan or " get " in scan
                                        or "where" in scan):
            return "WMI process discovery"
    if head.startswith("powershell") and ("invoke-wmimethod" in c or "invoke-cimmethod" in c):
        if "-computername" in c or "-computer" in c:
            return "Remote WMI invoke-method"
        return "WMI invoke-method"

    # ── Lateral movement · WinRM / PSRemoting (T1021.006) ─────────
    if head.startswith("powershell") and ("enter-pssession" in c or "invoke-command" in c and "-computername" in c):
        return "WinRM / PowerShell remote session"
    if head in ("winrs", "winrs.exe"):
        return "WinRS remote command"

    # ── Discovery · commonly missed enumerations ───────────────────
    if head in ("net", "net.exe") and " view " in " " + c + " ":
        return "Net view (remote share/system discovery)"
    if head in ("arp", "arp.exe") and " -a" in c:
        return "ARP table discovery"
    if head in ("route", "route.exe") and "print" in c:
        return "Route table discovery"
    if head in ("systeminfo", "systeminfo.exe"):
        return "System information discovery"
    if head in ("quser", "quser.exe") or (head in ("query", "query.exe") and "user" in c):
        return "User session discovery (quser)"
    if head in ("dsquery", "dsquery.exe"):
        return "Active Directory query (dsquery)"

    # ── Persistence · startup folder / WMI subscription / COM hijack ─
    if "startup" in c and (" copy " in c or "\\programs\\startup" in c or "start menu\\programs\\startup" in c):
        return "Startup folder persistence"
    if head.startswith("powershell") and "__eventfilter" in c and "commandlineeventconsumer" in c:
        return "WMI event subscription persistence"
    if head in ("regsvr32", "regsvr32.exe") and "inprocserver32" in c:
        return "COM hijack (regsvr32)"

    # ── RMM / Remote-access software · T1219 ──────────────────────
    # Match ONLY on the (canonicalized) head, so an AnyDesk file
    # name appearing as an ARGUMENT to another command (e.g.
    # `schtasks /create /tn AnyDesk /tr AnyDesk.exe`) doesn't
    # short-circuit the containing command's classification.
    for rmm_key, rmm_label in (
        ("anydesk",       "AnyDesk RMM execution"),
        ("teamviewer",    "TeamViewer RMM execution"),
        ("screenconnect", "ScreenConnect RMM execution"),
        ("connectwise",   "ScreenConnect RMM execution"),
        ("atera",         "Atera RMM execution"),
        ("splashtop",     "Splashtop RMM execution"),
        ("srservice",     "Splashtop RMM execution"),
        ("logmein",       "LogMeIn RMM execution"),
        ("syncro",        "Syncro RMM execution"),
        ("ninjarmm",      "NinjaRMM execution"),
        ("kaseya",        "Kaseya RMM execution"),
    ):
        if rmm_key in head or rmm_key in original_head:
            return rmm_label

    # ── Scheduled Task (T1053.005) · Octlurk-family remote SCHTASKS ──
    if head in ("schtasks", "schtasks.exe"):
        remote = "/s " in c        # `/S <server>` is the remote flag
        if "/create" in c or "/run" in c:
            if remote:
                return "Scheduled Task remote create"
            return "Scheduled Task create"
        if "/query" in c:
            return "Scheduled Task query"
        return "Scheduled Task"

    # ── Windows Service persistence via SC (T1543.003) ─────────────
    if head in ("sc", "sc.exe"):
        if " create " in " " + c + " ":
            return "Windows Service create (persistence)"
        if " failure " in " " + c + " ":
            return "Windows Service failure-action configure"
        if " start " in " " + c + " ":
            return "Windows Service start"
        return "Windows Service configure"

    # ── Task discovery / termination ───────────────────────────────
    if head in ("tasklist", "tasklist.exe"):
        return "Process discovery (tasklist)"
    if head in ("taskkill", "taskkill.exe"):
        return "Process termination"

    # ── Discovery — net / nltest / whoami / hostname (T1087, T1018) ─
    if head in ("net", "net.exe"):
        if " group " in " " + c + " " and "domain controllers" in c:
            return "Domain-controllers enumeration"
        if " start " in " " + c + " ":
            # `net start "NgcCIntSvc"` — starting a service just installed.
            return "Windows Service start"
        if " user" in c or " group" in c or " localgroup" in c:
            return "Account / group discovery"
    if head in ("nltest", "nltest.exe"):
        return "Domain trust discovery"
    if head in ("whoami", "whoami.exe"):
        return "Current-user discovery"
    if head in ("hostname", "hostname.exe") or head in ("ipconfig", "ipconfig.exe"):
        return "Host discovery"
    if "adfind" in head or "sharphound" in head or "bloodhound" in head:
        return "Active Directory discovery"

    # ── Credential Access · secretsdump-family invocation ──────────
    # Pattern e.g. `adobe.exe user@host -no-pass -just-dc-user Administrator`
    # (impacket secretsdump.py compiled/renamed as adobe.exe on the
    # Securelist Octlurk campaign).
    if "-just-dc" in c or "-just-dc-user" in c or "secretsdump" in c:
        return "Credential dumping (secretsdump-family)"

    # ── Ping for C2 resolution / beacon check ──────────────────────
    if head in ("ping", "ping.exe") and (" -n " in c or "-n 1" in c):
        return "Ping (C2 beacon / DNS resolution)"

    # ── Registry modification (T1112) ──────────────────────────────
    if head in ("reg", "reg.exe") and " add " in c:
        if "run" in c:
            return "Registry Run-key persistence"
        return "Registry modification"

    # Unzip / archive extraction
    if "tar" in head and " -xf " in c:
        if "python" in c:
            return "Unzip Python interpreter stager"
        if ".zip" in c or "--passphrase" in c:
            return "Unzip encrypted payload archive"
        return "Archive extraction"

    # Python discovery
    if "python" in c and ("--version" in c or " -V" in cmd):
        return "Python interpreter discovery"

    # Remote-access software direct execution — handled by the
    # RMM/T1219 head-based dispatch earlier in the classifier
    # (returns "AnyDesk RMM execution" et al.).

    # Microsoft Edge launch with extension load — Edgecution TTP
    if "msedge" in head or "msedge.exe" in c:
        if "load-extension" in c and "headless" in c:
            return "Microsoft Edge launch (headless, extension load — Edgecution)"
        if "load-extension" in c:
            return "Microsoft Edge launch (extension load — Edgecution)"
        return "Microsoft Edge launch"

    # Self-deletion / cleanup
    if " del " in c and ("timeout" in c or "start /min" in c or "exit /b" in c):
        return "Self-deletion of stager"

    # PowerShell process enumeration — use the pre-peel head so
    # `powershell -c <inner>` still routes into the PowerShell
    # branch even after the canonicalizer strips the wrapper.
    # ALSO match the POST-peel head so `cmd.exe /c powershell ...`
    # (where original_head=cmd.exe) still routes correctly.
    #
    # 2026-02-09 · Env-var wrappers (e.g. `%COMSPEC% /b /c start /b /min
    # powershell -EncodedCommand …`) canonicalize away to depth-3, so
    # BOTH `original_head` and `head` lose the "powershell" marker.
    # Detect the powershell invocation directly in the pre-peel text.
    _pre_peel_ps = bool(re.search(
        r"(?i)\b(?:powershell|pwsh)(?:\.exe)?\b"
        r"[^\n]{0,200}?"                          # any switches/args in between
        r"-e(?:nc(?:od(?:ed(?:command)?)?)?)?\b", oc,
    ))
    if (original_head.startswith("powershell") or original_head.startswith("pwsh")
            or head.startswith("powershell") or head.startswith("pwsh")
            or _pre_peel_ps):
        # WMI overlays run BEFORE the generic PowerShell branches
        # so we don't classify `Invoke-WmiMethod` as "PowerShell
        # execution".
        if "invoke-wmimethod" in oc or "invoke-cimmethod" in oc:
            if "-computername" in oc or "-computer " in oc:
                return "Remote WMI invoke-method"
            return "WMI invoke-method"
        # Windows Defender tampering (Add/Set-MpPreference) — check
        # early so it wins over the generic PS labels.
        if "add-mppreference" in oc and "exclusion" in oc:
            return "Windows Defender exclusion add"
        if "set-mppreference" in oc and ("disable" in oc or "-disable" in oc):
            return "Windows Defender configure (disable)"
        if "clear-eventlog" in oc:
            return "Event log clear (PowerShell)"
        # WinRM / PowerShell Remoting
        if "enter-pssession" in oc:
            return "WinRM / PowerShell remote session"
        if "invoke-command" in oc and "-computername" in oc:
            return "WinRM / PowerShell remote session"
        # WMI event subscription persistence
        if "__eventfilter" in oc and "commandlineeventconsumer" in oc:
            return "WMI event subscription persistence"
        if "get-ciminstance" in oc and "win32_process" in oc:
            return "PowerShell process enumeration"
        if "invoke-expression" in oc or "iex " in oc or "iex(" in oc:
            if " -w hidden" in oc or "-windowstyle hidden" in oc or "-w h " in oc:
                return "PowerShell hidden window IEX"
            return "PowerShell in-memory execution"
        if "downloadstring" in oc or "invoke-webrequest" in oc or "webclient" in oc or "invoke-restmethod" in oc:
            return "PowerShell download-and-execute"
        if "encodedcommand" in oc or " -e " in oc or " -enc" in oc:
            return "PowerShell encoded command"
        if "executionpolicy bypass" in oc or ("-executionpolicy" in oc and "bypass" in oc):
            return "PowerShell execution-policy bypass"
        if " -w hidden" in oc or "-windowstyle hidden" in oc or "-w h " in oc:
            return "PowerShell hidden window"
        return "PowerShell execution"

    # cmd /c chained interpreter (usually piping into PowerShell)
    if head.startswith("cmd") and "powershell" in c and "executionpolicy bypass" in c:
        return "PowerShell execution via CMD (execution-policy bypass)"

    # cmd /c enumeration
    if head.startswith("cmd") and (" whoami" in c or " nltest" in c or " net user" in c):
        return "Host / domain reconnaissance"
    # cmd /c wmic ...
    if head.startswith("cmd") and " wmic " in c and " product" in c:
        return "Software uninstall (defense evasion)"

    # AutoHotkey stager
    if "autohotkey" in head or "ahk" in head:
        return "AutoHotkey stager"

    # curl / wget download
    if head in ("curl", "wget", "curl.exe", "wget.exe"):
        return "Download from remote resource"
    if "certutil" in head and ("-urlcache" in c or "-decode" in c):
        return "Certutil download / decode"
    if "bitsadmin" in head and " /transfer" in c:
        return "BITSAdmin download"

    # Generic reg-add persistence
    if head == "reg" and " add " in c and "run" in c:
        return "Registry Run-key persistence"

    # Generic scheduled task persistence
    if head == "schtasks" and (" /create" in c or " -create" in c):
        return "Scheduled-task persistence"

    return "Command execution"

