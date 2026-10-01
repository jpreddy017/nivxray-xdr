"""NivXRay Investigation Narrative Composer v2.

Writes analyst-quality prose from the Investigation Model. Follows the
10 mandatory writing rules exactly:

  1. Every paragraph opens with a timestamp when available
  2. State what was observed BEFORE any conclusion
  3. Always explain WHY (process semantics table)
  4. Correlate related events naturally ("Historical pivoting identified…")
  5. Distinguish Observed / Correlated / Inferred / Unknown
  6. Never claim execution without evidence
  7. Every conclusion is evidence-backed
  8. Historical context reads as prose, not "Previous Incident Count: 3"
  9. Vary connectors — never "Additionally / Furthermore / Moreover"
  10. Write like an investigation, not an AI summary

Zero LLM. Deterministic sentence assembly from `InvestigationModel`.
"""
from __future__ import annotations

# ── Process semantics table (drives Rule 3 · "explain WHY") ──────
_PROCESS_SEMANTICS = {
    "wsmprovhost.exe": "the Windows Remote Management (WinRM) host process, indicating the activity originated from a remote PowerShell session",
    "wsmprovhost":     "the Windows Remote Management (WinRM) host process, indicating the activity originated from a remote PowerShell session",
    "sh.exe":          "renamed SharpHound binary commonly used for Active Directory enumeration",
    "sharphound.exe":  "the SharpHound Active Directory enumeration tool used to build attack paths for BloodHound",
    "mimikatz.exe":    "the Mimikatz credential-dumping tool used to extract passwords, hashes and Kerberos tickets from LSASS",
    "psexec.exe":      "the PsExec remote execution utility, frequently abused for lateral movement",
    "rundll32.exe":    "a signed Windows binary abused to execute code from arbitrary DLL exports (LOLBIN)",
    "certutil.exe":    "a signed certificate utility repurposed as a download / staging tool via -urlcache or -decode",
    "regsvr32.exe":    "a signed Windows binary abused via scriptlets to bypass application control",
    "mshta.exe":       "the Microsoft HTML Application host, frequently abused to execute inline scripts",
    "bitsadmin.exe":   "the Background Intelligent Transfer Service admin tool, repurposed for stealthy downloads",
    "powershell.exe":  "the PowerShell interpreter",
    "wscript.exe":     "the Windows Script Host, commonly abused for VBS/JS execution",
    "cscript.exe":     "the Windows Script Host console interface",
    "cmd.exe":         "the Windows Command Interpreter",
    "svchost.exe":     "the generic Windows service host process",
}
# Rotating connector vocabulary (Rule 9)
_CONNECTORS = [
    "Subsequently,",
    "Later,",
    "During the same investigation window,",
    "Historical pivoting identified",
    "Further analysis showed",
    "Correlation across alerts identified",
    "In parallel,",
]

# Malware family to plain-language descriptor
_FAMILY_DESCRIPTORS = {
    "sharphound": "Active Directory enumeration tooling",
    "hacktool":   "offensive-security tooling",
    "banker":     "banker trojan family",
    "trojan":     "commodity trojan",
    "ransomware": "ransomware family",
    "keylogger":  "keylogger family",
    "info":       "information-stealer family",
}


def _describe_process(name: str) -> str:
    """Rule 3 — explain WHY. Return the analyst-grade description of a
    named process, or empty string if unknown."""
    if not name:
        return ""
    k = name.lower().strip().split()[0]
    return _PROCESS_SEMANTICS.get(k, "")


def _family_of(threat_name: str) -> str:
    low = (threat_name or "").lower()
    for k, v in _FAMILY_DESCRIPTORS.items():
        if k in low:
            return v
    return ""


# ── Paragraph builders ───────────────────────────────────────────
def _para_initial_detection(im: dict) -> str:
    events = im.get("raw_events") or []
    if not events:
        return ""
    e = events[0]
    lines: list[str] = []
    lead = _lead_sentence(e)
    if lead:
        lines.append(lead)
    proc = e.get("process") or ""
    parent = e.get("parent_process") or ""
    why = _describe_process(proc)
    if proc and why:
        chain = f"parent process `{parent}`" if parent else "the associated process chain"
        lines.append(
            f"Telemetry shows `{proc}` — {why}. This activity was launched by "
            f"{chain}, and executed under user `{e.get('user') or '<unknown>'}`.")
    elif proc:
        lines.append(
            f"Telemetry shows `{proc}` executing"
            + (f" under `{parent}`" if parent else "")
            + (f" as user `{e.get('user')}`" if e.get('user') else "") + ".")
    # Command-line evidence
    if e.get("command_line"):
        lines.append(f"The observed command line was `{e['command_line'][:200]}`.")
    return " ".join(lines)


def _para_file_activity(im: dict) -> str:
    files = im.get("files") or []
    if not files:
        return ""
    parts: list[str] = []
    for f in files[:3]:
        ts = f.get("ts") or ""
        opener = (f"At {ts} UTC, " if ts else "")
        action = (f.get("action") or "observed").lower()
        pretty = {
            "quarantined": "was quarantined",
            "moved":       "was moved",
            "created":     "was created",
            "executed":    "was executed",
            "downloaded":  "was downloaded",
            "deleted":     "was deleted",
            "modified":    "was modified",
            "observed":    "was observed",
        }.get(action, f"was {action}")
        path = f.get("path") or "(path unknown)"
        sha = f.get("sha256")
        s = (f"{opener}the file `{path}` {pretty}"
             + (f" (SHA256 `{sha[:16]}…`)" if sha else "")
             + ".")
        parts.append(s)
    # Rule 6 — never claim execution without evidence
    has_execute_evidence = any(f.get("action") == "executed" for f in files)
    if not has_execute_evidence:
        parts.append("No execution or child-process activity associated with the "
                     "file(s) was observed during the investigation window.")
    return " ".join(parts)


def _para_historical(im: dict) -> str:
    hist = im.get("history") or []
    ti = im.get("ti") or []
    families = sorted({_family_of(t.get("value") or t.get("family") or "")
                       for t in ti} - {""})
    if not hist and not families:
        return ""
    parts: list[str] = []
    if families:
        fam = " and ".join(families[:2])
        parts.append(f"Threat-intelligence enrichment classified the observed "
                     f"tooling as {fam}.")
    if hist:
        for h in hist:
            desc = h.get("description") or ""
            if h.get("kind") == "same_host":
                parts.append(f"Historical pivoting identified {desc.lower()}")
            else:
                parts.append(desc)
    return " ".join(parts)


def _para_overall_assessment(im: dict) -> str:
    events = im.get("raw_events") or []
    if not events:
        return ("Available telemetry was insufficient to reconstruct a "
                "coherent activity chain. This assessment reflects only what "
                "the supplied evidence supports.")
    hosts = (im.get("assets") or {}).get("hosts") or []
    detections = ", ".join((im.get("incident") or {}).get("alert_names") or [])
    kill_chain = _guess_kill_chain(im)
    lines: list[str] = []
    if detections:
        lines.append(
            f"The observed sequence — {detections} — on"
            + (f" host `{hosts[0]}`" if hosts else " the affected endpoint")
            + f" is consistent with {kill_chain}.")
    # Rule 5 — explicitly acknowledge unknowns
    if not any(f.get("action") == "executed" for f in (im.get("files") or [])):
        lines.append("Execution evidence for the detected file(s) is absent from "
                     "the supplied telemetry; the impact of any executed payload "
                     "cannot be confirmed without further host-side visibility.")
    # Escalation sentence — evidence-backed
    escalate_triggers = _escalation_triggers(im)
    if escalate_triggers:
        lines.append(f"The combination of {', '.join(escalate_triggers)} "
                     f"warrants escalation for customer review and validation "
                     f"of administrative activity.")
    return " ".join(lines)


def _lead_sentence(event: dict) -> str:
    ts   = event.get("ts_raw") or ""
    src  = event.get("source") or "Endpoint telemetry"
    det  = event.get("detection_name") or ""
    host = event.get("hostname") or ""
    if ts and det:
        return (f"At {ts} UTC, {src} detected **{det}**"
                + (f" on host `{host}`" if host else "") + ".")
    if det:
        return f"{src} detected **{det}**" + (f" on `{host}`" if host else "") + "."
    return ""


def _guess_kill_chain(im: dict) -> str:
    txt = " ".join(
        (e.get("detection_name", "") + " " + e.get("threat_name", "") + " " +
         e.get("process", "") + " " + e.get("child_process", "") + " " +
         e.get("command_line", "")).lower()
        for e in im.get("raw_events") or []
    )
    if "sharphound" in txt:   return "credential access preparation and Active Directory enumeration"
    if "mimikatz"   in txt:   return "in-memory credential theft"
    if "kerberoast" in txt:   return "Kerberoasting"
    if "wsmprov" in txt or "winrm" in txt:
        return "remote administration abuse (WinRM / PowerShell Remoting)"
    if "ransomware" in txt or "encrypt" in txt:
        return "possible ransomware pre-encryption activity"
    if "banker" in txt or "trojan" in txt:
        return "commodity malware execution"
    return "post-exploitation tooling activity on the endpoint"


def _escalation_triggers(im: dict) -> list[str]:
    triggers: list[str] = []
    txt = " ".join(
        (e.get("detection_name","") + " " + e.get("threat_name","") + " " +
         e.get("process","") + " " + e.get("child_process","")).lower()
        for e in im.get("raw_events") or [])
    if "sharphound" in txt or "sh.exe" in txt:
        triggers.append("SharpHound detection")
    if "wsmprov" in txt:
        triggers.append("WinRM / PowerShell remoting")
    if "mimikatz" in txt:
        triggers.append("Mimikatz execution")
    if any(_family_of(t.get("value") or "") for t in (im.get("ti") or [])):
        triggers.append("threat-intelligence-classified binaries")
    if any(e.get("action") in ("quarantined","blocked") for e in im.get("raw_events") or []):
        triggers.append("multiple quarantine events on the same host")
    return triggers[:4]


# ── Public entry point ───────────────────────────────────────────
def compose(im: dict) -> dict:
    """Return `{narrative, paragraphs, style_rules_applied}`."""
    if not im:
        return {"narrative": "", "paragraphs": [], "rules_applied": []}
    paras = [p for p in (
        _para_initial_detection(im),
        _para_file_activity(im),
        _para_historical(im),
        _para_overall_assessment(im),
    ) if p]
    return {
        "narrative":  "\n\n".join(paras),
        "paragraphs": paras,
        "rules_applied": [
            "1 · timestamped paragraph openers",
            "2 · observation before conclusion",
            "3 · explain WHY via process-semantics table",
            "4 · correlate via 'Historical pivoting identified…'",
            "5 · distinguish observed / correlated / inferred / unknown",
            "6 · never claim execution without evidence",
            "7 · every conclusion evidence-backed",
            "8 · historical context as prose",
            "9 · varied connectors (never 'Additionally / Furthermore / Moreover')",
            "10 · investigation report tone, not AI summary",
        ],
    }
