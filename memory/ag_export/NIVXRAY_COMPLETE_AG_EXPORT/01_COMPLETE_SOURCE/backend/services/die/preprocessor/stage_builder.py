"""
DIE · Preprocessor · Stage Builder
──────────────────────────────────
Turns extracted artifacts into ordered Stages.

Rules:
    • A ``command`` artifact → one Stage (kind="command"), tagged
      with the recognized family (if any).
    • A ``registry`` artifact → one Stage (kind="registry") when it
      is not already embedded inside a command line.
    • A ``scheduled_task`` / ``service`` artifact that isn't inside
      a command line → one Stage.
    • A bare RMM / LOLBin mention (kind="lolbin", category="rmm")
      → one Stage (kind="tool", family=rmm-remote-access) — this is
      the core reason blog posts don't get a "single flat blob"
      result any more.
    • Multiple bare RMM mentions across a paragraph fold into a
      SINGLE composite RMM Deployment stage (deterministic, they
      cluster together in analyst prose).

Every Stage carries provenance: ``line_number``, ``raw_excerpt``,
``artifact_ids``.  Downstream DIE / Attack Story never touch raw
prose again.
"""
from __future__ import annotations
from typing import Dict, List, Optional, Set

import re

from .family_recognizer import all_families, recognize_family, Family
from .models import Artifact, Stage


# ── Objective templates keyed on command_family ────────────────
# Deterministic — one-line "what this stage does" that reads like a
# senior SOC analyst's own timeline entry.
_OBJECTIVE_TEMPLATES: Dict[str, str] = {
    "reverse-ssh-tunnel":         "Establish a reverse SSH tunnel back to attacker infrastructure.",
    "shadow-copy-deletion":       "Delete Volume Shadow Copies to prevent local recovery.",
    "ad-discovery":               "Enumerate the Active Directory environment (domain controllers, trusts).",
    "ad-enumeration":             "Enumerate the Active Directory environment prior to lateral movement.",
    "host-discovery":             "Fingerprint the compromised host's network configuration.",
    "session-discovery":          "Enumerate active user sessions on the host.",
    "account-discovery":          "Enumerate local / domain accounts and groups.",
    "persistence-scheduled-task": "Register a scheduled task for persistence.",
    "registry-modification":      "Modify the Windows registry to alter host behaviour.",
    "software-uninstall":         "Silently uninstall security or backup tooling via WMIC.",
    "msi-install":                "Install a payload via Microsoft Installer (MSI).",
    "sync-rclone-style":          "Exfiltrate data using an rclone-style multi-thread sync.",
    "data-exfiltration":          "Exfiltrate sensitive data from the environment.",
    "rmm-remote-access":          "Deploy legitimate Remote Monitoring & Management software for interactive C2.",
    "brute-ratel":                "Deploy or beacon Brute Ratel C4 for post-exploitation.",
    "psexec-lateral":             "Move laterally to another host using PsExec.",
    "lateral-movement":           "Move laterally within the environment.",
    "uac-disable":                "Disable UAC / Defender to lower host defences.",
    "log-clearing":               "Clear or delete Windows event logs to erase forensic trails.",
    "initial-access-social":      "Obtain initial access via social engineering (Teams / Quick Assist / fake IT).",
    "proxy-tamper":               "Disable / clear the Windows proxy configuration and refresh WinINet to bypass corporate monitoring.",
    "portable-runtime-deploy":    "Deploy a portable language runtime (Python / Node / Ruby) to execute payload code without touching system installers.",
    "archive-extraction":         "Extract an archive to unpack downstream payload files.",
    "runtime-verification":       "Verify that the newly-deployed language runtime is executable before invoking payload code.",
    "browser-extension-load":     "Launch a browser with a custom unpacked extension to execute attacker-controlled code inside the browser's trust boundary.",
    "browser-headless-launch":    "Launch a browser in headless mode so extension activity is invisible to the user.",
    "installer-cleanup":          "Delete installer / staging artifacts to remove forensic evidence.",
    "process-enumeration":        "Enumerate running processes as an environment-discovery step.",
    "powershell-execution-policy-bypass": "Prepare an unrestricted PowerShell environment for follow-on script execution.",
}


def _title_for(family: Optional[Family], stage_kind: str, cmd: str) -> str:
    """Return a polished analyst title.

    Never emit "Stage 1", "Stage 2".  Always name the objective.
    """
    if family is not None:
        return family.label
    if cmd:
        head = cmd.strip().split()
        if head:
            exe = head[0].lower().replace(".exe", "")
            return f"{exe} · " + " ".join(head[1:])[:60] if len(head) > 1 else exe
    return {
        "registry":  "Registry Reference",
        "schedule":  "Scheduled Task Registration",
        "service":   "Windows Service Operation",
        "executable":"Executable Reference",
        "phrase":    "Analyst-observed technique",
        "tool":      "Tool Reference",
    }.get(stage_kind, "Analyst-observed activity")


def _enrichment_for(family: Optional[Family], command: str, raw: str,
                    prose_tactic: Optional[str] = None):
    """Return (objective, tactic, mitre[], evidence[], commonly_observed_in[])."""
    if family is not None:
        obj = _OBJECTIVE_TEMPLATES.get(
            family.id, family.label + ".")
        return (
            obj, family.tactic, list(family.mitre),
            [f"`{command}`" if command else raw][:1],
            list(family.commonly_observed_in),
        )
    return (
        _OBJECTIVE_TEMPLATES.get("", ""),
        prose_tactic,
        [], [f"`{command}`" if command else raw][:1], [],
    )


# ── Prose-phrase families ─────────────────────────────────────────
# Analyst prose describes techniques without a full command line
# (e.g. "UAC disabling", "logs deleted", "registry modification").
# We treat these as first-class analytical stages so the Attack
# Story reflects the analyst's own words when no CLI is available.
_PROSE_PHRASE_FAMILIES = [
    ("uac-disable",           "UAC / Defender Tamper",
     re.compile(r"(?i)\bUAC\s+disabl(?:ing|e|ed)\b|\bdisabl(?:ing|e|ed)\s+UAC\b|"
                r"\bdefender\s+disabl(?:ing|e|ed)\b"), "Defense Evasion"),
    ("registry-modification", "Registry Modification",
     re.compile(r"(?i)\bregistry\s+modificat(?:ion|ions|ed)\b|"
                r"\bmodif(?:y|ies|ied|ying)\s+the?\s+registry\b"), "Defense Evasion"),
    ("log-clearing",          "Event Log Clearing / Deletion",
     re.compile(r"(?i)\blogs?\s+deleted\b|\bdelet(?:e|ing|ed)\s+(?:event\s+)?logs?\b|"
                r"\bevent\s+log(?:s)?\s+cleared?\b"), "Defense Evasion"),
    ("shadow-copy-deletion",  "Shadow Copy Removal",
     re.compile(r"(?i)\bshadow\s+copies\s+removed\b|\bremov(?:e|ed|ing)\s+shadow\s+copies\b|"
                r"\bshadow\s+copies\s+deleted\b"), "Impact"),
    ("data-exfiltration",     "Data Exfiltration",
     re.compile(r"(?i)\bdata\s+exf(?:iltration|iltrated)\b"), "Exfiltration"),
    ("lateral-movement",      "Lateral Movement",
     re.compile(r"(?i)\blateral\s+movement\b"), "Lateral Movement"),
    ("ad-enumeration",        "Active Directory Enumeration",
     re.compile(r"(?i)\bAD\s+enumeration\b|\bactive\s+directory\s+enumeration\b"), "Discovery"),
    ("initial-access-social", "Social-Engineering Initial Access",
     re.compile(r"(?i)\b(email\s+bombing|Microsoft\s+Teams\s+impersonation|fake\s+IT\s+support|"
                r"phishing\s+lure|social\s+engineer(?:ing|ed))\b"), "Initial Access"),
]


def build_stages(artifacts: List[Artifact]) -> List[Stage]:
    stages: List[Stage] = []
    used: Set[str] = set()
    index = 1

    # ── Pass 1 · command artifacts (one stage each) ──────────────
    for art in artifacts:
        if art.type != "command" or art.id in used:
            continue
        family = recognize_family(art.normalized_text)
        # Drop noisy prose-derived commands with no recognised family
        # and no CLI signal (2026-02-28 polish pass).
        if family is None:
            has_cli_signal = bool(re.search(
                r"(?:\s|^)(?:[/-][A-Za-z]|--[a-z]|\.exe\s|\\)", art.normalized_text))
            if not has_cli_signal:
                # Preserve the artifact but skip the noisy stage — the
                # executable already carries its own lolbin artifact.
                continue
        used.add(art.id)
        title = _title_for(family, "command", art.normalized_text)
        obj, tactic, mitre, evidence, observed = _enrichment_for(
            family, art.normalized_text, art.raw_text)
        stage = Stage.build(
            index=index, kind="command", title=title,
            artifact_ids=[art.id],
            normalized_command=art.normalized_text,
            raw_excerpt=art.raw_text,
            line_number=art.line_number,
            command_family=family.id if family else None,
            confidence=art.confidence,
            objective=obj, tactic=tactic, mitre=mitre,
            evidence=evidence, commonly_observed_in=observed,
        )
        stages.append(stage)
        index += 1

    # ── Pass 2 · RMM composite stage ─────────────────────────────
    rmm_ids: List[str] = []
    rmm_lines: List[int] = []
    for art in artifacts:
        if art.id in used:
            continue
        cat = art.attributes.get("category")
        exe = (art.attributes.get("executable") or art.normalized_text or "").lower()
        if cat == "rmm" or exe.replace(".exe", "").strip() in (
            "anydesk", "screenconnect", "simplehelp", "splashtop",
            "optitune", "teamviewer", "atera", "kaseya",
            "connectwise", "n-able", "quickassist",
        ):
            rmm_ids.append(art.id)
            rmm_lines.append(art.line_number)
    if rmm_ids:
        for aid in rmm_ids:
            used.add(aid)
        rmm_family = next((f for f in all_families() if f.id == "rmm-remote-access"), None)
        rmm_names = ", ".join(
            (a.attributes.get("executable") or a.normalized_text).lower().replace(".exe", "")
            for a in artifacts if a.id in rmm_ids
        )
        stage = Stage.build(
            index=index, kind="tool", title="RMM Remote Access Deployment",
            artifact_ids=rmm_ids,
            normalized_command=None,
            raw_excerpt=", ".join(
                a.raw_text for a in artifacts if a.id in rmm_ids
            )[:200],
            line_number=min(rmm_lines) if rmm_lines else 0,
            command_family="rmm-remote-access",
            confidence=0.9,
            objective=_OBJECTIVE_TEMPLATES["rmm-remote-access"],
            tactic=rmm_family.tactic if rmm_family else "Command and Control",
            mitre=list(rmm_family.mitre) if rmm_family else ["T1219"],
            evidence=[f"Tools referenced: {rmm_names}"],
            commonly_observed_in=(list(rmm_family.commonly_observed_in) if rmm_family else []),
        )
        stages.append(stage)
        index += 1

    # ── Pass 3 · Registry / scheduled task / service stages ──────
    for art in artifacts:
        if art.id in used:
            continue
        if art.type == "registry":
            reg_family = next((f for f in all_families() if f.id == "registry-modification"), None)
            stage = Stage.build(
                index=index, kind="registry",
                title="Registry Modification",
                artifact_ids=[art.id],
                normalized_command=art.normalized_text,
                raw_excerpt=art.raw_text,
                line_number=art.line_number,
                command_family="registry-modification",
                confidence=art.confidence,
                objective=_OBJECTIVE_TEMPLATES["registry-modification"],
                tactic=reg_family.tactic if reg_family else "Defense Evasion",
                mitre=list(reg_family.mitre) if reg_family else ["T1112"],
                evidence=[f"`{art.raw_text}`"],
                commonly_observed_in=(list(reg_family.commonly_observed_in) if reg_family else []),
            )
        elif art.type == "scheduled_task":
            st_family = next((f for f in all_families() if f.id == "persistence-scheduled-task"), None)
            stage = Stage.build(
                index=index, kind="schedule",
                title="Scheduled Task Registration",
                artifact_ids=[art.id],
                normalized_command=art.normalized_text,
                raw_excerpt=art.raw_text,
                line_number=art.line_number,
                command_family="persistence-scheduled-task",
                confidence=art.confidence,
                objective=_OBJECTIVE_TEMPLATES["persistence-scheduled-task"],
                tactic=(st_family.tactic if st_family else "Persistence"),
                mitre=(list(st_family.mitre) if st_family else ["T1053.005"]),
                evidence=[f"`{art.raw_text}`"],
                commonly_observed_in=(list(st_family.commonly_observed_in) if st_family else []),
            )
        elif art.type == "service":
            stage = Stage.build(
                index=index, kind="service",
                title="Windows Service Operation",
                artifact_ids=[art.id],
                normalized_command=art.normalized_text,
                raw_excerpt=art.raw_text,
                line_number=art.line_number,
                confidence=art.confidence,
                objective="Create / modify a Windows service.",
                tactic="Persistence",
                mitre=["T1543.003"],
                evidence=[f"`{art.raw_text}`"],
            )
        elif art.type in ("lolbin",):
            # Standalone lolbin mention (PsExec, quser, vssadmin, wmic, …)
            # that hasn't already been folded into a command.  Only
            # emit when the tool name recognises a family — bare
            # lolbins with no family are just noise.
            exe = (art.attributes.get("executable") or art.normalized_text).lower().replace(".exe", "")
            family = recognize_family(exe) or recognize_family(art.normalized_text)
            if family is None:
                continue
            obj, tactic, mitre, evidence, observed = _enrichment_for(
                family, art.normalized_text, art.raw_text)
            stage = Stage.build(
                index=index, kind="tool",
                title=family.label,
                artifact_ids=[art.id],
                normalized_command=None,
                raw_excerpt=art.raw_text,
                line_number=art.line_number,
                command_family=family.id,
                confidence=art.confidence * 0.9,
                objective=obj, tactic=tactic, mitre=mitre,
                evidence=[f"Tool mentioned: `{exe}`"],
                commonly_observed_in=observed,
            )
        elif art.type == "executable" and art.subtype != "rmm":
            # Standalone exe mention (e.g. "PsExec", "JWrapper") in prose.
            exe = art.normalized_text.replace(".exe", "").lower()
            family = recognize_family(art.normalized_text)
            title = _title_for(family, "executable", art.normalized_text)
            obj, tactic, mitre, evidence, observed = _enrichment_for(
                family, art.normalized_text, art.raw_text)
            if not obj:
                obj = f"Executable `{exe}` referenced in analyst notes."
            stage = Stage.build(
                index=index, kind="executable",
                title=title,
                artifact_ids=[art.id],
                normalized_command=art.normalized_text,
                raw_excerpt=art.raw_text,
                line_number=art.line_number,
                command_family=family.id if family else None,
                confidence=art.confidence * 0.9,
                objective=obj, tactic=tactic, mitre=mitre,
                evidence=evidence, commonly_observed_in=observed,
            )
        else:
            continue
        used.add(art.id)
        stages.append(stage)
        index += 1

    # ── Pass 4 · Prose-phrase stages ─────────────────────────────
    # Scan the source text lines for analyst-prose descriptions of
    # techniques.  Only add a new stage if that family isn't already
    # represented by a real command stage.
    covered_families = {s.command_family for s in stages if s.command_family}
    prose_stages = _collect_prose_phrase_stages(
        artifacts, start_index=index, skip_families=covered_families,
    )
    stages.extend(prose_stages)
    index += len(prose_stages)

    # Renumber stages 1..N (kind=command first by original order,
    # then RMM, then others — already ordered above).
    for i, s in enumerate(stages, start=1):
        s.index = i
    return stages


def _collect_prose_phrase_stages(artifacts: List[Artifact], *,
                                 start_index: int,
                                 skip_families: set) -> List[Stage]:
    """Emit deterministic stages for concept-level phrases found in
    the raw analyst text.  These give the Attack Story stages for
    techniques the analyst *described* but never gave a CLI for.

    The raw text is reconstructed from artifact line numbers where
    possible, but we still need the original prose — we get it from
    the artifact's ``raw_text`` context is not enough, so this pass
    only fires when the phrase text is directly the artifact's own
    surrounding raw excerpt.  For a genuinely raw-only pass, callers
    can plug ``preprocess()`` — this helper is called by the same
    pipeline and receives the raw text through the artifact list.
    """
    # We deliberately DO NOT re-scan the raw text here — the
    # pipeline (see pipeline.py) handles that pass separately after
    # stage building.  Return empty list; the pipeline post-processor
    # populates prose stages using the NormalizedInput text.
    return []


# ── Public helper used by the pipeline to add prose-phrase stages
# ── AFTER stage numbering has been finalised.
def add_prose_phrase_stages(stages: List[Stage],
                            normalized_text: str,
                            line_starts: List[int]) -> List[Stage]:
    """Append prose-phrase-based stages onto ``stages``.  Idempotent —
    families already represented are skipped."""
    covered = {s.command_family for s in stages if s.command_family}
    next_idx = (stages[-1].index + 1) if stages else 1
    for fam_id, label, rx, tactic in _PROSE_PHRASE_FAMILIES:
        if fam_id in covered:
            continue
        m = rx.search(normalized_text)
        if not m:
            continue
        # Compute a line number.
        line_number = 1
        s_off = m.start()
        for i, ls in enumerate(line_starts):
            if ls > s_off:
                break
            line_number = i + 1
        excerpt = m.group(0)
        # Grab the recognized family for evidence/observed metadata.
        fam_obj = next((f for f in all_families() if f.id == fam_id), None)
        obj = _OBJECTIVE_TEMPLATES.get(fam_id, label + ".")
        stage = Stage.build(
            index=next_idx, kind="phrase", title=label,
            artifact_ids=[], normalized_command=None,
            raw_excerpt=excerpt, line_number=line_number,
            command_family=fam_id, confidence=0.65,
            objective=obj, tactic=tactic,
            mitre=list(fam_obj.mitre) if fam_obj else [],
            evidence=[f'Analyst wrote: "{excerpt}"'],
            commonly_observed_in=list(fam_obj.commonly_observed_in) if fam_obj else [],
        )
        stages.append(stage)
        covered.add(fam_id)
        next_idx += 1
    return stages


def _title_from_command(cmd: str) -> str:
    """Pick a short title from a command line."""
    head = cmd.strip().split()
    if not head:
        return "Command"
    exe = head[0].lower().replace(".exe", "")
    return f"{exe} · " + " ".join(head[1:])[:60] if len(head) > 1 else exe
