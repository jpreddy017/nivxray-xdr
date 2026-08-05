"""
DIE · Analyst Narrative Generator
─────────────────────────────────
Deterministic — NO LLM.

Consumes a ``PreprocessResult`` (or its dict form) and returns a
structured analyst-grade narrative bundle with the same shape a
senior SOC analyst would hand to leadership:

    {
        "executive_summary":  str,        # one-paragraph brief
        "analyst_summary":    str,        # multi-sentence analyst summary
        "recommended_actions": list[str],  # concrete containment steps
        "sigma_hunts":         list[str],  # Sigma-hunt oneliner ideas
        "yara_ideas":          list[str],  # YARA string/regex ideas
        "threat_actor_context": str,       # "commonly observed in …"
        "mitre_matrix":        list[dict], # deduped tactic → [technique]
    }

Everything is derived from the stages we already built.  Zero
LLM, zero web calls, zero randomness — same paste → same narrative.
"""
from __future__ import annotations
from collections import OrderedDict
from typing import Any, Dict, List


# Tactic-ordered kill-chain used to sort the summary.
_KILL_CHAIN_ORDER = [
    "Initial Access", "Execution", "Discovery", "Credential Access",
    "Persistence", "Defense Evasion", "Lateral Movement",
    "Command and Control", "Exfiltration", "Impact",
]


_TACTIC_HUMAN = {
    "Initial Access":     "an initial-access foothold",
    "Execution":          "code execution",
    "Discovery":          "environment discovery",
    "Credential Access":  "credential harvesting",
    "Persistence":        "persistence installation",
    "Defense Evasion":    "defence-evasion attempts",
    "Lateral Movement":   "lateral movement",
    "Command and Control": "command-and-control setup",
    "Exfiltration":       "data exfiltration",
    "Impact":             "destructive impact activity",
}


# Family → concrete Sigma-hunt idea (one-liner).
_SIGMA_HUNTS = {
    "reverse-ssh-tunnel":       "Sigma: process ssh.exe with `-R` flag from non-admin user context",
    "shadow-copy-deletion":     "Sigma: vssadmin.exe with `delete shadows` command line",
    "ad-discovery":             "Sigma: nltest.exe with `/dclist` or `/domain_trusts`",
    "host-discovery":           "Sigma: ipconfig.exe with `/all` in non-standard hours",
    "session-discovery":        "Sigma: quser.exe / query.exe user execution",
    "account-discovery":        "Sigma: net.exe with `user`, `group`, `localgroup`, `accounts` args",
    "persistence-scheduled-task": "Sigma: schtasks.exe with `/create` from unusual parent",
    "registry-modification":    "Sigma: reg.exe with `add` or `delete` targeting security keys",
    "software-uninstall":       "Sigma: wmic.exe with `product ... uninstall`",
    "msi-install":              "Sigma: msiexec.exe with `-i` or `-Embedding` from non-System32 path",
    "sync-rclone-style":        "Sigma: rclone.exe or `copy` with `--transfers`/`--max-age`",
    "rmm-remote-access":        "Sigma: process anydesk|screenconnect|simplehelp|splashtop|optitune|teamviewer|quickassist",
    "brute-ratel":              "Sigma: badger.dll load or brute-ratel string in memory",
    "psexec-lateral":           "Sigma: psexec.exe / paexec.exe execution with remote target",
    "uac-disable":              "Sigma: reg add EnableLUA=0 or Set-MpPreference -DisableRealtimeMonitoring",
    "log-clearing":             "Sigma: wevtutil.exe cl or Clear-EventLog cmdlet",
    "initial-access-social":    "Sigma: Microsoft Teams / Quick Assist launch followed by cmd.exe / powershell.exe",
}


_YARA_IDEAS = {
    "reverse-ssh-tunnel":       'YARA: string "ssh.exe -R"',
    "shadow-copy-deletion":     'YARA: string "vssadmin delete shadows"',
    "ad-discovery":             'YARA: string "nltest /dclist"',
    "host-discovery":           'YARA: string "ipconfig /all"',
    "session-discovery":        'YARA: string "quser.exe"',
    "software-uninstall":       'YARA: regex /wmic\\s+product\\s+where.*call\\s+uninstall/',
    "msi-install":              'YARA: string "msiexec.exe -Embedding"',
    "sync-rclone-style":        'YARA: regex /--transfers\\s+\\d+.*--max-age/',
    "rmm-remote-access":        'YARA: string "AnyDesk.exe" or "ScreenConnect" or "SimpleHelp"',
    "brute-ratel":              'YARA: string "badger.dll"',
    "psexec-lateral":           'YARA: string "PsExec" or "paexec.exe"',
    "log-clearing":             'YARA: string "wevtutil.exe cl" or "Clear-EventLog"',
    "registry-modification":    'YARA: regex /reg\\s+(add|delete)\\s+HK/',
    "persistence-scheduled-task": 'YARA: string "schtasks /create"',
}


_RECOMMENDATIONS = {
    "reverse-ssh-tunnel":       "Block outbound port 22 from workstations; hunt for OpenSSH clients dropped outside System32.",
    "shadow-copy-deletion":     "Isolate the host immediately — shadow-copy deletion indicates imminent or ongoing ransomware encryption.",
    "ad-discovery":             "Alert on `nltest` invocations from non-admin sessions; harden AD tiering.",
    "host-discovery":           "Correlate discovery commands with initial-access indicators from the same session.",
    "session-discovery":        "Investigate the parent process — `quser` is a lateral-movement precursor.",
    "persistence-scheduled-task": "Enumerate all scheduled tasks created in the last 24h; remove any authored by non-service accounts.",
    "registry-modification":    "Roll back UAC / Defender registry keys; alert on further modifications to `HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender`.",
    "software-uninstall":       "Investigate WMIC product uninstall attempts — likely targeting security software.",
    "msi-install":              "Block unsigned MSI execution via AppLocker / WDAC; audit `msiexec` events.",
    "sync-rclone-style":        "Block rclone binaries and known cloud storage endpoints; hunt for large egress from workstations.",
    "rmm-remote-access":        "Confirm every deployed RMM binary against the sanctioned MSP allowlist; block the rest.",
    "brute-ratel":              "Deploy the Elastic / SentinelOne / CrowdStrike Brute Ratel signatures across the fleet.",
    "psexec-lateral":           "Alert on PsExec service creation on any non-admin workstation; enable Remote Admin restrictions.",
    "uac-disable":              "Restore UAC / Defender configuration; hunt for tampered `EnableLUA`, `DisableAntiSpyware`.",
    "log-clearing":             "Enable centralised event forwarding (WEF/WEC) so cleared local logs are already off-host.",
    "initial-access-social":    "Educate users on Microsoft Teams / Quick Assist social-engineering; restrict Quick Assist via GPO.",
}


# Broad recommendations always emitted for ransomware-adjacent flows.
_RANSOMWARE_UNIVERSAL_ACTIONS = [
    "Isolate any host that observed shadow-copy deletion, log clearing, or Brute Ratel activity.",
    "Preserve endpoint memory + disk images before remediation for forensic root-cause analysis.",
    "Force enterprise-wide password reset if credential-access or discovery activity is present.",
    "Verify offline / immutable backups are intact and reachable — do NOT pay any ransom demand.",
]


def _stage_dict(stage: Any) -> Dict[str, Any]:
    if isinstance(stage, dict):
        return stage
    return stage.to_dict() if hasattr(stage, "to_dict") else {}


def generate(pre_bundle: Dict[str, Any]) -> Dict[str, Any]:
    """Return the analyst-narrative bundle for a preprocessor result."""
    stages = [_stage_dict(s) for s in (pre_bundle or {}).get("stages", []) or []]
    if not stages:
        return {
            "executive_summary":     "",
            "analyst_summary":       "",
            "recommended_actions":   [],
            "sigma_hunts":           [],
            "yara_ideas":            [],
            "threat_actor_context":  "",
            "mitre_matrix":          [],
        }

    # ── Tactic sequence in kill-chain order ─────────────────────
    tactics_seen: "OrderedDict[str, int]" = OrderedDict()
    for s in stages:
        t = s.get("tactic")
        if not t:
            continue
        tactics_seen[t] = tactics_seen.get(t, 0) + 1
    ordered_tactics = sorted(
        tactics_seen.items(),
        key=lambda kv: (
            _KILL_CHAIN_ORDER.index(kv[0]) if kv[0] in _KILL_CHAIN_ORDER else 99,
            -kv[1],
        ),
    )
    tactic_sequence = [t for (t, _) in ordered_tactics]

    # ── Executive summary ───────────────────────────────────────
    if tactic_sequence:
        readable_seq = " → ".join(tactic_sequence)
        first_human = _TACTIC_HUMAN.get(tactic_sequence[0], tactic_sequence[0])
        last_human  = _TACTIC_HUMAN.get(tactic_sequence[-1], tactic_sequence[-1])
        exec_summary = (
            f"The paste describes a {len(stages)}-stage intrusion covering "
            f"{readable_seq}. The activity begins with {first_human} and "
            f"culminates in {last_human}. "
        )
    else:
        exec_summary = f"The paste yielded {len(stages)} analyst-observable stages. "
    exec_summary += (
        "Stages were extracted deterministically from the input — no LLM "
        "narration is used."
    )

    # ── Analyst summary (multi-sentence) ────────────────────────
    family_seq = [s.get("command_family") for s in stages if s.get("command_family")]
    families_uniq = list(OrderedDict.fromkeys(family_seq))
    sentences: List[str] = []
    for tac in tactic_sequence:
        stages_in_tac = [s for s in stages if s.get("tactic") == tac]
        techniques = sorted({m for s in stages_in_tac for m in (s.get("mitre") or [])})
        actions = ", ".join(
            _clean_family(s.get("command_family") or s.get("title"))
            for s in stages_in_tac
        )
        if techniques:
            sentences.append(
                f"[{tac}] Analyst observed {actions} "
                f"({' · '.join(techniques)})."
            )
        else:
            sentences.append(f"[{tac}] Analyst observed {actions}.")
    analyst_summary = " ".join(sentences)

    # ── Sigma / YARA / Recommendations from family hits ─────────
    sigma_hunts: List[str] = []
    yara_ideas:  List[str] = []
    actions:     List[str] = []
    seen_fams = set()
    for fam in families_uniq:
        if fam in seen_fams:
            continue
        seen_fams.add(fam)
        if fam in _SIGMA_HUNTS: sigma_hunts.append(_SIGMA_HUNTS[fam])
        if fam in _YARA_IDEAS:  yara_ideas.append(_YARA_IDEAS[fam])
        if fam in _RECOMMENDATIONS: actions.append(_RECOMMENDATIONS[fam])

    # Ransomware universal add-ons.
    ransomware_signal = any(fam in {
        "shadow-copy-deletion", "log-clearing", "brute-ratel",
        "rmm-remote-access", "psexec-lateral", "software-uninstall",
        "sync-rclone-style"} for fam in families_uniq)
    if ransomware_signal:
        for a in _RANSOMWARE_UNIVERSAL_ACTIONS:
            if a not in actions:
                actions.append(a)

    # ── Threat-actor context (union of "commonly observed in") ──
    observed = OrderedDict()
    for s in stages:
        for name in (s.get("commonly_observed_in") or []):
            observed[name] = observed.get(name, 0) + 1
    if observed:
        top = [n for (n, _) in sorted(observed.items(), key=lambda x: -x[1])[:6]]
        threat_actor_context = (
            "Commonly observed in: " + ", ".join(top) + ". "
            "Not attribution — historical prevalence only."
        )
    else:
        threat_actor_context = ""

    # ── MITRE matrix (tactic → techniques) ──────────────────────
    matrix: List[Dict[str, Any]] = []
    for tac in tactic_sequence:
        techniques = sorted({m for s in stages
                              if s.get("tactic") == tac
                              for m in (s.get("mitre") or [])})
        matrix.append({"tactic": tac, "techniques": techniques})

    return {
        "executive_summary":     exec_summary,
        "analyst_summary":       analyst_summary,
        "recommended_actions":   actions,
        "sigma_hunts":           sigma_hunts,
        "yara_ideas":            yara_ideas,
        "threat_actor_context":  threat_actor_context,
        "mitre_matrix":          matrix,
    }


def _clean_family(name: str) -> str:
    if not name:
        return "activity"
    return (name or "").replace("-", " ").replace("_", " ").strip()
