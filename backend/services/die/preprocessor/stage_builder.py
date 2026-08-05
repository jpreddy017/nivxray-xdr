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
from typing import Dict, List, Set

import re

from .family_recognizer import all_families, recognize_family
from .models import Artifact, Stage


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
        used.add(art.id)
        family = recognize_family(art.normalized_text)
        title = family.label if family else _title_from_command(art.normalized_text)
        stage = Stage.build(
            index=index, kind="command", title=title,
            artifact_ids=[art.id],
            normalized_command=art.normalized_text,
            raw_excerpt=art.raw_text,
            line_number=art.line_number,
            command_family=family.id if family else None,
            confidence=art.confidence,
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
        )
        stages.append(stage)
        index += 1

    # ── Pass 3 · Registry / scheduled task / service stages ──────
    for art in artifacts:
        if art.id in used:
            continue
        if art.type == "registry":
            stage = Stage.build(
                index=index, kind="registry",
                title=f"Registry Reference · {art.subtype or ''}".strip(" ·"),
                artifact_ids=[art.id],
                normalized_command=art.normalized_text,
                raw_excerpt=art.raw_text,
                line_number=art.line_number,
                command_family="registry-modification",
                confidence=art.confidence,
            )
        elif art.type == "scheduled_task":
            stage = Stage.build(
                index=index, kind="schedule",
                title="Scheduled Task Registration",
                artifact_ids=[art.id],
                normalized_command=art.normalized_text,
                raw_excerpt=art.raw_text,
                line_number=art.line_number,
                command_family="persistence-scheduled-task",
                confidence=art.confidence,
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
            )
        elif art.type == "executable" and art.subtype != "rmm":
            # Standalone exe mention (e.g. "PsExec", "JWrapper") in prose.
            exe = art.normalized_text.replace(".exe", "").lower()
            family = recognize_family(art.normalized_text)
            title = family.label if family else f"Executable Reference · {exe}"
            stage = Stage.build(
                index=index, kind="executable",
                title=title,
                artifact_ids=[art.id],
                normalized_command=art.normalized_text,
                raw_excerpt=art.raw_text,
                line_number=art.line_number,
                command_family=family.id if family else None,
                confidence=art.confidence * 0.9,
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
        stage = Stage.build(
            index=next_idx, kind="phrase", title=label,
            artifact_ids=[], normalized_command=None,
            raw_excerpt=excerpt, line_number=line_number,
            command_family=fam_id, confidence=0.65,
        )
        stage.__setattr__("tactic", tactic)
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
