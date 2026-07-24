"""v2/verdict/signals.py · Deterministic signal detectors.

Each detector returns a list of signal-hit dicts:
    {"signal": <key>, "reason": <str>, "evidence": <str>}

Detectors are pure functions of a single event dict (already IRG-enriched
plus optional context — chain, siblings, artefact registry). Zero I/O.

Add a new signal by writing a `def detect_XYZ(event, ctx) -> list[dict]`
and appending it to `ALL_DETECTORS` at the bottom.
"""
from __future__ import annotations
import math
import re
from .weights import MITRE_CRITICAL, MITRE_HIGH_RISK

# ── Deterministic reference tables (no regex-per-event where avoidable) ────

LOLBAS_BINS = frozenset({
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe", "bitsadmin.exe",
    "msiexec.exe", "installutil.exe", "regasm.exe", "regsvcs.exe",
    "wmic.exe", "csc.exe", "msbuild.exe", "hh.exe",
})

SHELL_LIKE = frozenset({
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "bash.exe", "wsl.exe",
})

OFFICE_PARENTS = frozenset({
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "onenote.exe", "wordpad.exe", "msaccess.exe",
})
BROWSER_PARENTS = frozenset({
    "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "opera.exe",
    "brave.exe",
})
EXPECTED_PARENT_CHILD = frozenset({
    ("wininit.exe",  "services.exe"),
    ("wininit.exe",  "lsass.exe"),
    ("services.exe", "svchost.exe"),
    ("services.exe", "spoolsv.exe"),
    ("services.exe", "wuauclt.exe"),
    ("smss.exe",     "csrss.exe"),
})

REGISTRY_PERSIST_PATHS = (
    r"\microsoft\windows\currentversion\run",
    r"\microsoft\windows\currentversion\runonce",
    r"\microsoft\windows nt\currentversion\winlogon",
    r"\microsoft\windows\currentversion\explorer\startupapproved",
)

RANSOM_NOTE_PAT = re.compile(
    r"(?i)(readme|how[_-]?to[_-]?decrypt|restore[_-]?files|recover[_-]?files|"
    r"your[_-]?files|decrypt[_-]?instructions)\.(?:txt|hta|html?|rtf)$"
)


def _bin(evt: dict) -> str:
    """Extract the binary name from an event's action/label/entity iid."""
    for k in ("action", "label"):
        s = str(evt.get(k) or "")
        m = re.search(r"([A-Za-z0-9_.\-]+\.(?:exe|dll|msi|ps1|bat|cmd|com|hta|scr))",
                      s, flags=re.IGNORECASE)
        if m:
            return m.group(1).lower()
    ent = (evt.get("entity") or {}).get("iid") or ""
    return ent.split(":")[-1].lower() if ":" in ent else ent.lower()


def _parent_bin(evt: dict) -> str:
    p = (evt.get("parent") or {}).get("iid") or (evt.get("parent") or {}).get("name") or ""
    return str(p).split(":")[-1].lower()


def _cmdline(evt: dict) -> str:
    return str(evt.get("cmdline") or evt.get("command_line") or evt.get("action") or "").lower()


def _mitre(evt: dict) -> list[str]:
    return [str(t) for t in (evt.get("mitre") or [])]


def _mitre_base(evt: dict) -> set[str]:
    return {t.split(".", 1)[0] for t in _mitre(evt) if t}


# ─── Detectors ─────────────────────────────────────────────────────────────

def detect_mitre(evt, ctx):
    hits = []
    bases = _mitre_base(evt)
    if bases & MITRE_CRITICAL:
        hits.append({"signal": "MITRE_CRITICAL", "reason": f"critical technique(s): {sorted(bases & MITRE_CRITICAL)}"})
    if bases & MITRE_HIGH_RISK:
        hits.append({"signal": "MITRE_HIGH_RISK", "reason": f"high-risk technique(s): {sorted(bases & MITRE_HIGH_RISK)}"})
    if bases and not (bases & (MITRE_CRITICAL | MITRE_HIGH_RISK)):
        hits.append({"signal": "MITRE_OTHER", "reason": f"technique(s): {sorted(bases)}"})
    return hits


def detect_rule_hit(evt, ctx):
    rule = evt.get("rule_id") or (evt.get("provenance") or {}).get("rule_id")
    if rule:
        return [{"signal": "RULE_HIT", "reason": f"rule {rule} matched"}]
    return []


def detect_suspicious_parent(evt, ctx):
    pb = _parent_bin(evt)
    cb = _bin(evt)
    if not cb:
        return []
    if pb in OFFICE_PARENTS and cb in SHELL_LIKE:
        return [{"signal": "SUSPICIOUS_PARENT", "reason": f"office parent {pb} spawned shell {cb}"}]
    if pb in BROWSER_PARENTS and cb in SHELL_LIKE:
        return [{"signal": "SUSPICIOUS_PARENT", "reason": f"browser parent {pb} spawned shell {cb}"}]
    if pb == "explorer.exe" and cb in SHELL_LIKE and "-encodedcommand" in _cmdline(evt):
        return [{"signal": "SUSPICIOUS_PARENT", "reason": f"explorer→{cb} with encoded payload"}]
    return []


def detect_lolbas_abuse(evt, ctx):
    b = _bin(evt)
    cmd = _cmdline(evt)
    if b not in LOLBAS_BINS:
        return []
    verbs = ("downloadstring", "invoke-expression", "iex", "invoke-webrequest",
             "-encodedcommand", "-enc ", "certutil -urlcache", "certutil -decode",
             "bitsadmin /transfer", "regsvr32 /s /n /u /i:http",
             "mshta http", "rundll32 javascript", "wmic os get", "wmic process call create",
             "wbadmin delete catalog", "vssadmin delete shadows")
    if any(v in cmd for v in verbs):
        return [{"signal": "LOLBAS_ABUSE", "reason": f"{b} invoked with suspicious verb"}]
    return []


def detect_encoded_powershell(evt, ctx):
    cmd = _cmdline(evt)
    if "-encodedcommand" in cmd or re.search(r"\s-e[nc]?\s+[A-Za-z0-9+/=]{40,}", cmd):
        return [{"signal": "ENCODED_POWERSHELL", "reason": "-EncodedCommand / long base64 payload"}]
    return []


def detect_obfuscation(evt, ctx):
    cmd = _cmdline(evt)
    if not cmd:
        return []
    if cmd.count("`") > 5 or cmd.count("^") > 5:
        return [{"signal": "OBFUSCATION", "reason": "high backtick/caret density"}]
    # Shannon entropy of the cmdline
    if len(cmd) > 40:
        from collections import Counter
        counts = Counter(cmd)
        H = -sum((n / len(cmd)) * math.log2(n / len(cmd)) for n in counts.values())
        if H > 5.0:
            return [{"signal": "OBFUSCATION", "reason": f"cmdline entropy {H:.2f}"}]
    return []


def detect_amsi_bypass(evt, ctx):
    cmd = _cmdline(evt)
    if "amsiutils" in cmd or "amsienable" in cmd or "system.management.automation.amsiutils" in cmd:
        return [{"signal": "AMSI_BYPASS", "reason": "AMSI bypass pattern in cmdline"}]
    return []


def detect_defender_tampering(evt, ctx):
    cmd = _cmdline(evt)
    pat = ("set-mppreference -disable", "set-mppreference -disablerealtimemonitoring",
           "sc stop windefend", "sc config windefend start= disabled",
           "mpcmdrun.exe -removedefinitions", "add-mppreference -exclusionpath")
    if any(p in cmd for p in pat):
        return [{"signal": "DEFENDER_TAMPERING", "reason": "Defender-tamper cmdline"}]
    return []


def detect_registry_persistence(evt, ctx):
    if (evt.get("lane") or "").lower() != "registry":
        return []
    key = str(evt.get("target") or evt.get("action") or "").lower()
    for p in REGISTRY_PERSIST_PATHS:
        if p in key:
            return [{"signal": "REGISTRY_PERSISTENCE", "reason": f"write to {p}"}]
    return []


def detect_scheduled_task(evt, ctx):
    cmd = _cmdline(evt)
    if "schtasks" in cmd and ("/create" in cmd or "-create" in cmd):
        return [{"signal": "SCHEDULED_TASK_CREATE", "reason": "schtasks /create"}]
    if "register-scheduledtask" in cmd:
        return [{"signal": "SCHEDULED_TASK_CREATE", "reason": "Register-ScheduledTask"}]
    return []


def detect_wmi_persistence(evt, ctx):
    cmd = _cmdline(evt)
    if "eventfilter" in cmd or "commandlineeventconsumer" in cmd:
        return [{"signal": "WMI_PERSISTENCE", "reason": "WMI event subscription"}]
    return []


def detect_backup_destruction(evt, ctx):
    cmd = _cmdline(evt)
    if "wbadmin" in cmd and ("delete catalog" in cmd or "delete backup" in cmd):
        return [{"signal": "BACKUP_DESTRUCTION", "reason": "wbadmin delete catalog/backup"}]
    return []


def detect_shadow_copy_delete(evt, ctx):
    cmd = _cmdline(evt)
    if ("vssadmin" in cmd and "delete shadows" in cmd) or "wmic shadowcopy delete" in cmd:
        return [{"signal": "SHADOW_COPY_DELETE", "reason": "shadow copy deletion"}]
    return []


def detect_ransom_note(evt, ctx):
    if (evt.get("lane") or "").lower() != "file":
        return []
    tgt = str(evt.get("target") or evt.get("action") or "")
    if RANSOM_NOTE_PAT.search(tgt):
        return [{"signal": "RANSOM_NOTE_CREATION", "reason": f"ransom-note filename {tgt}"}]
    return []


def detect_mass_encryption(evt, ctx):
    """Requires chain context — ctx['file_writes'] is a per-entity counter."""
    n = (ctx or {}).get("file_writes_60s")
    entropy_jump = (ctx or {}).get("entropy_jump")
    if isinstance(n, int) and n >= 25 and (entropy_jump is None or entropy_jump >= 0.7):
        return [{"signal": "MASS_FILE_ENCRYPTION",
                 "reason": f"{n} file writes in 60 s with entropy jump"}]
    return []


def detect_lsass_access(evt, ctx):
    cmd = _cmdline(evt)
    lane = (evt.get("lane") or "").lower()
    if "lsass" in cmd or ("lsass" in str(evt.get("target") or "").lower() and lane == "process"):
        return [{"signal": "LSASS_ACCESS", "reason": "LSASS handle acquire / mention"}]
    return []


def detect_credential_dumping(evt, ctx):
    cmd = _cmdline(evt)
    hits = []
    if "T1003" in " ".join(_mitre(evt)):
        hits.append({"signal": "CREDENTIAL_DUMPING", "reason": "T1003 tagged"})
    if "comsvcs.dll" in cmd and "minidump" in cmd:
        hits.append({"signal": "CREDENTIAL_DUMPING", "reason": "comsvcs.dll MiniDump"})
    if "procdump" in cmd and "lsass" in cmd:
        hits.append({"signal": "CREDENTIAL_DUMPING", "reason": "procdump lsass"})
    return hits


def detect_process_injection(evt, ctx):
    if "T1055" in " ".join(_mitre(evt)):
        return [{"signal": "PROCESS_INJECTION", "reason": "T1055 tagged"}]
    return []


def detect_service_created_proc(evt, ctx):
    if _parent_bin(evt) == "services.exe":
        cb = _bin(evt)
        expected = {"svchost.exe", "spoolsv.exe", "wuauclt.exe", "searchindexer.exe"}
        if cb and cb not in expected:
            return [{"signal": "SERVICE_CREATED_PROC", "reason": f"services.exe→{cb} (unexpected child)"}]
    return []


def detect_download_cradle(evt, ctx):
    cmd = _cmdline(evt)
    patterns = ("invoke-webrequest", "downloadstring", "downloadfile",
                "curl -o", "wget ", "certutil -urlcache")
    if any(p in cmd for p in patterns) and any(s in cmd for s in (";", "|iex", "| iex", "&&")):
        return [{"signal": "DOWNLOAD_CRADLE", "reason": "download+execute chain"}]
    return []


# Registration order matters for deterministic scoring.
ALL_DETECTORS = (
    detect_mitre,
    detect_rule_hit,
    detect_suspicious_parent,
    detect_lolbas_abuse,
    detect_encoded_powershell,
    detect_obfuscation,
    detect_amsi_bypass,
    detect_defender_tampering,
    detect_registry_persistence,
    detect_scheduled_task,
    detect_wmi_persistence,
    detect_backup_destruction,
    detect_shadow_copy_delete,
    detect_ransom_note,
    detect_mass_encryption,
    detect_lsass_access,
    detect_credential_dumping,
    detect_process_injection,
    detect_service_created_proc,
    detect_download_cradle,
)


# ─── Decay detectors ───────────────────────────────────────────────────────

def decay_expected_parent_child(evt, ctx):
    pb, cb = _parent_bin(evt), _bin(evt)
    if (pb, cb) in EXPECTED_PARENT_CHILD:
        return [{"signal": "EXPECTED_PARENT_CHILD", "reason": f"{pb}→{cb} is expected"}]
    return []


def decay_no_mitre(evt, ctx):
    if not _mitre(evt):
        return [{"signal": "NO_MITRE_TAGS", "reason": "no MITRE technique fired"}]
    return []


def decay_signed_microsoft(evt, ctx):
    sig = (evt.get("signature") or {}).get("issuer") or ""
    if "microsoft" in str(sig).lower() and (evt.get("signature") or {}).get("verified"):
        return [{"signal": "SIGNED_MICROSOFT_BINARY", "reason": "verified MS signer"}]
    return []


ALL_DECAY = (
    decay_expected_parent_child,
    decay_no_mitre,
    decay_signed_microsoft,
)
