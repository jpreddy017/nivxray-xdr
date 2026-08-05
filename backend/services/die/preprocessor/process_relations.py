"""
DIE · Preprocessor · Process Relationship Builder
─────────────────────────────────────────────────
Deterministically infers parent → child edges between the stages
we just built.

Every edge carries:
    · why (the rule that fired)
    · confidence (0.0–1.0)
    · supporting_artifact_ids (evidence pointers)

Never emit an edge without an explanation.
"""
from __future__ import annotations
from typing import Dict, List, Tuple

from .models import ProcessEdge, Stage


# Static parent → likely-child map.  Deterministic knowledge base;
# extend by adding rows only.
_PARENT_CHILD_RULES: List[Tuple[str, str, str, float]] = [
    # (parent_hint, child_hint, why, confidence)
    ("services.exe", "msiexec.exe", "services.exe launches MSI installers", 0.75),
    ("services.exe", "sc.exe",       "services.exe operates via sc.exe", 0.7),
    ("cmd.exe",      "powershell.exe","cmd.exe often spawns powershell for chained execution", 0.7),
    ("powershell.exe","rundll32.exe","powershell reflectively loads via rundll32", 0.65),
    ("cmd.exe",      "wmic.exe",     "cmd.exe hosts wmic invocations", 0.75),
    ("cmd.exe",      "vssadmin.exe", "cmd.exe hosts vssadmin invocations", 0.8),
    ("powershell.exe","vssadmin.exe","powershell hosts vssadmin invocations", 0.75),
    ("cmd.exe",      "reg.exe",      "cmd.exe hosts reg operations", 0.7),
    ("cmd.exe",      "schtasks.exe", "cmd.exe hosts schtasks operations", 0.7),
    ("wscript.exe",  "powershell.exe","wscript loader chains into powershell", 0.7),
    ("winword.exe",  "cmd.exe",      "Word macro spawns cmd.exe (phishing)", 0.6),
    ("winword.exe",  "powershell.exe","Word macro spawns powershell.exe", 0.6),
    ("msiexec.exe",  "rundll32.exe", "msiexec chains into rundll32", 0.7),
    ("psexec.exe",   "cmd.exe",      "PsExec hosts remote cmd.exe", 0.85),
    ("psexec.exe",   "powershell.exe","PsExec hosts remote powershell.exe", 0.85),
    ("quickassist",  "cmd.exe",      "Quick Assist session hands off to cmd", 0.55),
    ("quickassist",  "powershell.exe","Quick Assist session hands off to powershell", 0.55),
]


def _exe_of(stage: Stage) -> str:
    """Return a lower-cased executable-family for the stage."""
    if stage.command_family == "rmm-remote-access":
        return "quickassist"     # composite bucket
    if stage.normalized_command:
        first = stage.normalized_command.strip().split()
        if first:
            return first[0].lower().replace(".exe", "")
    return stage.title.split()[0].lower()


def build_edges(stages: List[Stage]) -> List[ProcessEdge]:
    if not stages:
        return []

    # Group stages by lower-cased executable-family for quick lookup.
    by_exe: Dict[str, List[Stage]] = {}
    for s in stages:
        by_exe.setdefault(_exe_of(s), []).append(s)

    edges: List[ProcessEdge] = []
    for parent_hint, child_hint, why, conf in _PARENT_CHILD_RULES:
        p_key = parent_hint.replace(".exe", "").lower()
        c_key = child_hint.replace(".exe", "").lower()
        parents = by_exe.get(p_key, [])
        children = by_exe.get(c_key, [])
        if not parents or not children:
            continue
        support = [a for s in parents + children for a in s.artifact_ids]
        edges.append(ProcessEdge.build(
            parent=parent_hint, child=child_hint,
            why=why, confidence=conf, supporting=support,
        ))

    # Additional heuristic: sequential command stages that appear on
    # adjacent lines in the source are given a "temporal" edge with
    # low confidence.  This lets the Attack Story render a chain
    # even when no static rule fires.
    sorted_cmd_stages = sorted(
        [s for s in stages if s.kind in ("command", "executable")],
        key=lambda s: (s.line_number, s.index),
    )
    for a, b in zip(sorted_cmd_stages, sorted_cmd_stages[1:]):
        if a.line_number and b.line_number and 0 < (b.line_number - a.line_number) <= 4:
            edges.append(ProcessEdge.build(
                parent=a.title, child=b.title,
                why="adjacent in analyst notes (temporal ordering)",
                confidence=0.4,
                supporting=list(a.artifact_ids + b.artifact_ids),
            ))
    return edges
