"""
DIE · Behaviour Explainer
─────────────────────────
Frozen 2026-03-01.

Given a preprocessor Stage (or its dict form), produce a deterministic
plain-English "What this does" explanation for the analyst.  Zero LLM,
zero heuristics — every explanation is a template keyed on the
recognised command_family, expanded with concrete substrings from the
normalized command so the analyst learns what the specific paste
does, not just what the family is.

The Investigation Results renderer uses this to fill the WHAT THIS
DOES section for each stage plus an overall behaviour chain.
"""
from __future__ import annotations
import re
from typing import Any, Dict, List, Optional


# ── Per-family plain-English templates ────────────────────────────
# Each template is a list of bullet lines.  Placeholders in `{…}`
# are filled from concrete regex captures against the normalized
# command; if a capture is missing the bullet is dropped so the
# explanation only contains verified facts.
_FAMILY_BEHAVIOUR: Dict[str, Dict[str, Any]] = {
    "archive-extraction": {
        "intro": "Unpacks the contents of an archive to disk.",
        "bullets": [
            (r"tar(?:\.exe)?\s+-?[xX]", "Invokes `tar` in extract mode."),
            (r"-f\s+\"?([^\"\s]+\.(?:zip|tar|gz|7z))", "Reads the archive `{0}`."),
            (r"-C\s+\"?([^\"]+)\"?", "Extracts into the directory `{0}`."),
            (r"--passphrase\b",           "Archive is password-protected — the passphrase is supplied inline."),
        ],
        "why": "Loaders use this to stage payload files (portable runtimes, extension code, config, secrets) without touching system directories.",
    },
    "portable-runtime-deploy": {
        "intro": "Deploys a portable language runtime that will execute payload code.",
        "bullets": [
            (r"(python[- ]?\d[^\s]*)",   "Stages the portable **{0}** runtime."),
            (r"(node[- ]?\d[^\s]*)",     "Stages the portable **{0}** runtime."),
            (r"embed[- ]?amd64",         "Marks the runtime as the Windows embeddable distribution — no installer footprint on the host."),
        ],
        "why": "Portable runtimes let attackers execute Python / Node / Ruby scripts without relying on the system Python and without leaving a Program Files trail.",
    },
    "runtime-verification": {
        "intro": "Verifies the newly-deployed runtime is executable.",
        "bullets": [
            (r"(python(?:3|w)?|node|ruby|perl|java|dotnet)\s+--version",
                                          "Runs `{0} --version` to confirm the interpreter launches successfully."),
        ],
        "why": "A --version probe is a standard installer sanity check — attackers include it so the follow-on payload does not silently fail.",
    },
    "browser-extension-load": {
        "intro": "Launches a Chromium-family browser with a custom unpacked extension.",
        "bullets": [
            (r"(msedge|chrome|brave|firefox)(?:\.exe)?",  "Uses `{0}` as the host process."),
            (r"--load-extension=([^\s\"]+)",              "Loads the attacker-controlled extension from `{0}`."),
            (r"--user-data-dir=([^\s\"]+)",               "Uses an isolated user-data-dir `{0}` so the extension is not visible in the victim's normal profile."),
        ],
        "why": "Loading an unpacked extension bypasses the browser store review process and runs attacker JavaScript inside the browser's trust boundary — a common technique for cookie theft, credential capture, and data exfiltration.",
    },
    "browser-headless-launch": {
        "intro": "Runs the browser in headless mode so no window is shown to the user.",
        "bullets": [
            (r"--headless(?:=new)?",       "Passes `--headless` — the browser opens invisibly."),
            (r"--disable-gpu",             "Adds `--disable-gpu` so the process runs on servers without a display."),
        ],
        "why": "Headless execution is how attackers keep browser-based credential capture, screenshot capture, and data exfiltration invisible to the victim.",
    },
    "installer-cleanup": {
        "intro": "Removes installer / staging artifacts so forensic evidence disappears.",
        "bullets": [
            (r"\btimeout\s+(\d+)",        "Waits `{0}` seconds before deleting (lets the loader finish first)."),
            (r"\bdel\b\s+([^\s]+)",       "Deletes the file `{0}`."),
            (r"Remove-Item\b[^\n]{0,80}?-Force", "Uses `Remove-Item -Force` for silent deletion."),
            (r"Remove-Item\b[^\n]{0,80}?-Recurse", "Uses `Remove-Item -Recurse` to wipe an entire directory."),
        ],
        "why": "Cleanup at the end of a chain is a classic anti-forensics move — Prefetch, AmCache, and USN Journal are the analyst's remaining witnesses.",
    },
    "process-enumeration": {
        "intro": "Lists processes currently running on the host.",
        "bullets": [
            (r"Get-CimInstance\s+Win32_Process",  "Uses CIM to enumerate every `Win32_Process` object."),
            (r"Get-WmiObject\s+Win32_Process",    "Uses WMI to enumerate every `Win32_Process` object."),
            (r"Get-Process\b",                    "Uses the PowerShell cmdlet `Get-Process`."),
            (r"tasklist(?:\.exe)?\b",             "Uses `tasklist` — the CMD-native enumeration tool."),
        ],
        "why": "Process enumeration is a Discovery step used to identify EDR / AV / analyst tools running on the box before the next stage acts.",
    },
    "powershell-execution-policy-bypass": {
        "intro": "Prepares an unrestricted PowerShell environment for follow-on script execution.",
        "bullets": [
            (r"-ExecutionPolicy\s+Bypass",  "Passes `-ExecutionPolicy Bypass` — PowerShell will not enforce script signing for this session."),
            (r"-NoProfile\b",               "Passes `-NoProfile` — the analyst's or user's PowerShell profile is skipped so no logging shim runs."),
            (r"-NonInteractive\b",          "Passes `-NonInteractive` — no prompts are shown to the user."),
            (r"-WindowStyle\s+Hidden",      "Passes `-WindowStyle Hidden` — the PowerShell window is not shown."),
            (r"-Command\s+-\b",             "Reads the script body from stdin (`-Command -`) — the actual payload arrives on the pipeline."),
        ],
        "why": "This is the standard opening for a fileless PowerShell payload: no profile, no window, no signing enforcement, no prompts.  Whatever runs next is designed to be invisible.",
    },
    "shadow-copy-deletion": {
        "intro": "Deletes Volume Shadow Copies so local file recovery is impossible.",
        "bullets": [
            (r"vssadmin(?:\.exe)?\s+delete\s+shadows",         "Uses `vssadmin delete shadows` — the classic ransomware VSS wipe."),
            (r"Win32_ShadowCopy",                              "Uses the `Win32_ShadowCopy` WMI class to iterate individual shadow copies."),
            (r"\.Delete\s*\(",                                 "Calls `.Delete()` on each shadow-copy object — the WMI variant that evades vssadmin-based EDR signatures."),
            (r"wmic(?:\.exe)?\s+shadowcopy\s+delete",          "Uses `wmic shadowcopy delete` — the CMD-native VSS wipe."),
        ],
        "why": "Volume Shadow Copies are the last-resort local backup Windows provides.  Removing them is a defining ransomware precursor — encryption or destructive impact usually follows within minutes.",
    },
    "proxy-tamper": {
        "intro": "Disables the Windows proxy configuration and forces WinINet to reload settings immediately.",
        "bullets": [
            (r"ProxyEnable\b[^\n]{0,80}?-Value\s+0",  "Sets `ProxyEnable = 0` in `HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings`."),
            (r"ProxyServer\b[^\n]{0,80}?-Value\s+[\"']{2}",  "Clears the `ProxyServer` value."),
            (r"AutoConfigURL\b[^\n]{0,80}?-Value\s+[\"']{2}", "Clears the `AutoConfigURL` (PAC) value."),
            (r"InternetSetOption\s*\([^\n]{0,80}?39",  "Calls `InternetSetOption(39)` — `INTERNET_OPTION_SETTINGS_CHANGED`."),
            (r"InternetSetOption\s*\([^\n]{0,80}?37",  "Calls `InternetSetOption(37)` — `INTERNET_OPTION_REFRESH`."),
            (r"wininet\.dll",                          "Uses the Windows WinINet API directly (`wininet.dll`)."),
        ],
        "why": "Corporate networks route traffic through inspection proxies for TLS-level monitoring.  Clearing the proxy configuration and refreshing WinINet lets subsequent traffic bypass the enterprise inspection layer completely.",
    },
    "reverse-ssh-tunnel": {
        "intro": "Opens a reverse SSH tunnel back to attacker infrastructure.",
        "bullets": [
            (r"ssh(?:\.exe)?\b[^\n]{0,200}?\s-R\s+(\d+)",  "Uses `-R {0}` — the remote SSH host will forward inbound connections on port {0} back into the victim network."),
            (r"@([^\s\"@]+)",                              "Connects to the attacker host `{0}`."),
        ],
        "why": "Reverse tunnels let the attacker reach the victim network from an untrusted external host without needing to open ingress firewall rules — a common C2 and pivot technique.",
    },
    "registry-modification": {
        "intro": "Writes to a Windows registry value.",
        "bullets": [
            (r"(Set|New|Remove)-ItemProperty",           "Uses PowerShell's `{0}-ItemProperty` cmdlet."),
            (r"-Path\s+[\"']?(HK(?:LM|CU|CR|U|CC):[^\"'\s]+)",  "Targets registry path `{0}`."),
            (r"-Name\s+([A-Za-z0-9_]+)",                 "Modifies value name `{0}`."),
            (r"-Value\s+([^\s]+)",                       "Writes value `{0}`."),
            (r"reg(?:\.exe)?\s+(add|delete)\b",          "Uses `reg {0}` — the CMD-native registry editor."),
        ],
        "why": "Registry writes are used for persistence, defence-evasion (proxy / Defender / UAC tamper), and configuration of downstream payloads.",
    },
}


_STOP_ELLIPSIS_RE = re.compile(r"\s+")


def _fmt_bullet(pattern: str, template: str, cmd: str) -> Optional[str]:
    """Return the filled template if the pattern matches, else None."""
    m = re.search(pattern, cmd, re.IGNORECASE)
    if not m:
        return None
    groups = m.groups() or ()
    try:
        return template.format(*groups)
    except (IndexError, KeyError):
        return template


def explain_stage(stage: Dict[str, Any]) -> Dict[str, Any]:
    """Return ``{intro, bullets[], why}`` — deterministic plain-English
    explanation for a single stage.  Empty when the family is unknown
    (the Investigation Results renderer falls back to the stage
    objective in that case)."""
    fam = stage.get("command_family") or stage.get("family")
    entry = _FAMILY_BEHAVIOUR.get(fam or "")
    if not entry:
        return {"intro": stage.get("objective") or "", "bullets": [], "why": ""}
    cmd = (stage.get("normalized_command") or stage.get("raw_excerpt") or "")
    bullets: List[str] = []
    for pat, tpl in entry.get("bullets") or []:
        b = _fmt_bullet(pat, tpl, cmd)
        if b:
            bullets.append(b)
    return {
        "intro":   entry.get("intro") or "",
        "bullets": bullets,
        "why":     entry.get("why") or "",
    }


def explain_chain(stages: List[Dict[str, Any]]) -> str:
    """Return a one-paragraph plain-English narrative of the whole
    chain — an assembly of per-stage intros, ordered by stage index.
    Deterministic and safe against missing families."""
    parts: List[str] = []
    for i, s in enumerate(stages, start=1):
        e = explain_stage(s)
        intro = e["intro"] or (s.get("title") or "").strip()
        if intro:
            parts.append(f"({i}) {intro.rstrip('.')}")
    if not parts:
        return ""
    return "This chain: " + " · ".join(parts) + "."
