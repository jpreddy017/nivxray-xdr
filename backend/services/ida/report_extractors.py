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
        },
    }


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

    # Confirm the payload is actually a command, not prose.
    _COMMAND_CONFIRM = re.compile(
        r'(?:'
        r'\s-{1,2}[A-Za-z]'               # ` -X` / ` --x`
        r'|\s/[A-Za-z]{1,4}(?:[:=]|\s|$)'  # ` /c ` / ` /min ` / ` /f `
        r'|"[A-Za-z]:\\'                   # `"C:\...`
        r'|%[A-Z_]+%'                      # env-var
        r'|2>&?1|>\s*nul|&&|\|\||;\s|\s&\s'  # redirection / chaining
        r'|\.exe\b'                        # `.exe` reference
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
        if not s or len(s) > 2000 or len(s) < 10:
            return
        # Strip table-cell label prefix (`Command Line ...`)
        s = _LABEL_PREFIX.sub("", s)
        if len(s) < 10:
            return

        head_m = _HEAD_START.match(s)
        quoted = _QUOTED_EXE_START.match(s)
        if not (head_m or quoted):
            return
        if not _COMMAND_CONFIRM.search(s):
            return

        key = re.sub(r"\s+", " ", s).strip()
        if key in seen:
            return
        seen.add(key)

        if head_m:
            head_token = head_m.group(0).strip().lower()
        else:
            # quoted path — pull the basename before `.exe`
            m = re.search(r"([^\\/\"]+\.exe)\"", s, re.I)
            head_token = (m.group(1).lower() if m else "quoted-exe")

        hits.append({
            "command": key,
            "head":    head_token,
            "purpose": _classify_command_purpose(key, head_token),
            "line":    line_no,
            "source":  source,
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
    """Extract dated events.  Two shapes:
        · Explicit date-first lines ("On July 22, …")
        · Prefixed bullets ("• 2026-07-22 · …")
    """
    hits: List[Dict[str, Any]] = []
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
        hits.append({
            "date":    m.group(1).strip(),
            "event":   m.group(2).strip(),
            "source":  "ida.report.timeline",
        })
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
        "totals": {
            "artifacts": 0, "mitre": 0, "cves": 0, "actors": 0,
            "malware": 0, "commands": 0, "timeline": 0, "yara": 0, "sigma": 0,
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
    Command-Line IOC tables."""
    c = cmd.lower()

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

    # PowerShell process enumeration
    if head.startswith("powershell") or head.startswith("pwsh"):
        if "get-ciminstance" in c and "win32_process" in c:
            return "PowerShell process enumeration"
        if "invoke-expression" in c or "iex " in c:
            return "PowerShell in-memory execution"
        if "downloadstring" in c or "invoke-webrequest" in c or "webclient" in c:
            return "PowerShell download-and-execute"
        if "encodedcommand" in c or " -e " in c or " -enc" in c:
            return "PowerShell encoded command"
        return "PowerShell execution"

    # cmd /c chained interpreter (usually piping into PowerShell)
    if head.startswith("cmd") and "powershell" in c and "executionpolicy bypass" in c:
        return "PowerShell execution via CMD (execution-policy bypass)"

    # cmd /c enumeration
    if head.startswith("cmd") and (" whoami" in c or " nltest" in c or " net user" in c):
        return "Host / domain reconnaissance"

    # AutoHotkey stager
    if "autohotkey" in head or "ahk" in head:
        return "AutoHotkey stager"

    # curl / wget download
    if head in ("curl", "wget", "curl.exe", "wget.exe"):
        return "Download from remote resource"

    # Generic reg-add persistence
    if head == "reg" and " add " in c and "run" in c:
        return "Registry Run-key persistence"

    # Generic scheduled task persistence
    if head == "schtasks" and (" /create" in c or " -create" in c):
        return "Scheduled-task persistence"

    return "Command execution"

