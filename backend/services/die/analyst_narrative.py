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
        "attack_progression":    _attack_progression(stages, tactic_sequence),
        "behavior_summary":      _behavior_summary(stages, tactic_sequence),
        "likely_objective":      _likely_objective(families_uniq, ransomware_signal),
        "overall_assessment":    _overall_assessment(stages, tactic_sequence, families_uniq, ransomware_signal),
        "kill_chain_coverage":   _kill_chain_coverage(tactic_sequence),
        "recommended_actions":   actions,
        "sigma_hunts":           sigma_hunts,
        "yara_ideas":            yara_ideas,
        "threat_actor_context":  threat_actor_context,
        "mitre_matrix":          matrix,
    }


# ── Kill-chain phase mapping (Lockheed Martin) ────────────────────
_TACTIC_TO_KILL_CHAIN = {
    "Initial Access":     "Delivery / Exploitation",
    "Execution":          "Exploitation",
    "Discovery":          "Reconnaissance (post-compromise)",
    "Credential Access":  "Actions on Objectives",
    "Persistence":        "Installation",
    "Defense Evasion":    "Actions on Objectives",
    "Lateral Movement":   "Actions on Objectives",
    "Command and Control": "Command & Control",
    "Exfiltration":       "Actions on Objectives",
    "Impact":             "Actions on Objectives",
}


def kill_chain_for_tactic(tac: str) -> str:
    return _TACTIC_TO_KILL_CHAIN.get(tac, "Actions on Objectives")


# ── Per-stage attack progression paragraphs ───────────────────────
_STAGE_NARRATIVE = {
    "reverse-ssh-tunnel":         "The attacker established a reverse SSH tunnel, allowing covert remote control of the host while bypassing inbound firewall restrictions.",
    "shadow-copy-deletion":       "Windows Volume Shadow Copies were deleted using `vssadmin delete shadows`, dramatically reducing recovery options and typically preceding ransomware encryption.",
    "ad-discovery":               "The attacker enumerated Active Directory (domain controllers, trusts) to understand the environment before lateral movement or ransomware deployment.",
    "host-discovery":             "Network configuration and interface details were collected (`ipconfig /all`) — a standard reconnaissance step performed before lateral movement.",
    "session-discovery":          "Active user sessions on the host were enumerated (`quser` / `query user`) — usually done to identify high-privilege sessions to hijack or wait for.",
    "account-discovery":          "Local / domain accounts and groups were enumerated (`net user`, `net group`) — attacker was building a target list.",
    "persistence-scheduled-task": "A scheduled task was registered to survive reboots and defender restarts — a durable persistence primitive commonly used by ransomware crews.",
    "registry-modification":      "The Windows registry was modified — likely to weaken security controls or install persistence keys.",
    "software-uninstall":         "Security or backup software was silently uninstalled via WMIC — this reduces authentication controls and increases the likelihood of successful payload execution.",
    "msi-install":                "A payload was installed via Microsoft Installer (MSI). MSI execution often chains into rundll32 / cmd for post-installation actions.",
    "sync-rclone-style":          "A renamed rclone-style binary was used with `--transfers` / `--max-age` flags to collect and stage files — behaviour commonly associated with pre-encryption data exfiltration.",
    "rmm-remote-access":          "Legitimate Remote Monitoring & Management software was deployed for hands-on-keyboard remote control — a modern replacement for classic C2.",
    "brute-ratel":                "Brute Ratel C4 activity was observed. This commercial red-team framework has been co-opted by ransomware crews since 2022 and its beacons are highly evasive.",
    "psexec-lateral":             "PsExec was used to move laterally to another host — a well-worn primitive for spreading ransomware inside a network.",
    "uac-disable":                "UAC / Defender was tampered with, lowering host defences before payload execution.",
    "log-clearing":               "Windows event logs were cleared or deleted — the attacker was hiding forensic evidence of the intrusion.",
    "initial-access-social":      "Initial access was obtained via social engineering (Microsoft Teams / Quick Assist / fake IT support) — a fast-growing modern initial-access vector.",
    "data-exfiltration":          "Data was staged and exfiltrated from the environment.",
    "lateral-movement":           "The attacker moved laterally within the environment.",
    "ad-enumeration":             "Active Directory was enumerated prior to lateral movement.",
}


def _attack_progression(stages: List[Dict[str, Any]],
                        tactic_sequence: List[str]) -> List[Dict[str, Any]]:
    """Produce a per-stage narrative paragraph list ordered by
    kill-chain progression.  Each entry is a full analyst sentence,
    not a command dump."""
    out: List[Dict[str, Any]] = []
    for i, s in enumerate(stages, start=1):
        fam = s.get("command_family") or ""
        narrative = _STAGE_NARRATIVE.get(fam) or s.get("objective") or ""
        out.append({
            "index":       i,
            "title":       f"Stage {i} — {s.get('title', '')}",
            "narrative":   narrative,
            "tactic":      s.get("tactic"),
            "kill_chain":  kill_chain_for_tactic(s.get("tactic", "")),
            "mitre":       list(s.get("mitre") or []),
            "evidence":    list(s.get("evidence") or []),
        })
    return out


def _behavior_summary(stages: List[Dict[str, Any]],
                      tactic_sequence: List[str]) -> List[Dict[str, str]]:
    """One row per ATT&CK tactic seen — Phase → Observed Activity."""
    rows: List[Dict[str, str]] = []
    for tac in tactic_sequence:
        activities = []
        for s in stages:
            if s.get("tactic") != tac:
                continue
            fam = s.get("command_family") or ""
            n = _STAGE_NARRATIVE.get(fam) or s.get("objective") or s.get("title")
            if n and n not in activities:
                activities.append(n)
        rows.append({
            "phase":     tac,
            "kill_chain": kill_chain_for_tactic(tac),
            "activity":  " ".join(activities),
        })
    return rows


def _likely_objective(families: List[str], ransomware_signal: bool) -> List[str]:
    """Concise bullet list of what the attacker is trying to accomplish."""
    bullets: List[str] = []
    if "initial-access-social" in families or "rmm-remote-access" in families:
        bullets.append("Establish persistent remote access")
    if any(f in families for f in ("ad-discovery","host-discovery","session-discovery","account-discovery","ad-enumeration")):
        bullets.append("Understand the enterprise environment")
    if any(f in families for f in ("uac-disable","registry-modification","software-uninstall","log-clearing")):
        bullets.append("Disable security protections")
    if "sync-rclone-style" in families or "data-exfiltration" in families:
        bullets.append("Collect and exfiltrate valuable files")
    if "shadow-copy-deletion" in families:
        bullets.append("Prevent recovery from local backups")
    if ransomware_signal:
        bullets.append("Deploy the final ransomware payload")
    if not bullets:
        bullets.append("Objective unclear — insufficient signal in the paste.")
    return bullets


def _overall_assessment(stages: List[Dict[str, Any]],
                        tactic_sequence: List[str],
                        families: List[str],
                        ransomware_signal: bool) -> Dict[str, Any]:
    """Deterministic Risk / Primary Objective / Progress% / Confidence."""
    if "shadow-copy-deletion" in families or "Impact" in tactic_sequence:
        risk = "Critical"
        progress = 90
    elif ransomware_signal:
        risk = "High"
        progress = 75
    elif "Persistence" in tactic_sequence or "Command and Control" in tactic_sequence:
        risk = "High"
        progress = 55
    elif "Discovery" in tactic_sequence:
        risk = "Medium"
        progress = 30
    else:
        risk = "Low"
        progress = 10

    if ransomware_signal:
        primary = "Ransomware Deployment"
    elif "Exfiltration" in tactic_sequence or "sync-rclone-style" in families:
        primary = "Data Theft"
    elif "Command and Control" in tactic_sequence:
        primary = "Persistent Remote Access"
    else:
        primary = "Reconnaissance / Post-exploitation"

    # Confidence from stage count + family recognition rate.
    fam_count = len([s for s in stages if s.get("command_family")])
    total = max(1, len(stages))
    fam_rate = fam_count / total
    if fam_rate >= 0.75 and total >= 6: conf = "High"
    elif fam_rate >= 0.5: conf = "Medium"
    else: conf = "Low"

    return {
        "risk":                 risk,
        "primary_objective":    primary,
        "attack_progress_pct":  progress,
        "confidence":           conf,
    }


def _kill_chain_coverage(tactic_sequence: List[str]) -> List[str]:
    """Unique Kill-Chain phases hit, in Kill-Chain order."""
    order = ["Reconnaissance", "Reconnaissance (post-compromise)",
             "Weaponization", "Delivery / Exploitation",
             "Exploitation", "Installation",
             "Command & Control", "Actions on Objectives"]
    hits = {kill_chain_for_tactic(t) for t in tactic_sequence}
    return [p for p in order if p in hits]


def _clean_family(name: str) -> str:
    if not name:
        return "activity"
    return (name or "").replace("-", " ").replace("_", " ").strip()
