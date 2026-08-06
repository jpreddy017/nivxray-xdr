"""
IDA · Input Classifier (IDA-1)
──────────────────────────────
Frozen 2026-03-01 · P0.

The IDA Input Classifier extends the IUE's recognition so mixed
pastes, URL-only pastes, and IDA-owned document artifact types are
classified as first-class investigation inputs, not as "plain text".

This module is CALLED by the IUE — it never runs on its own.  The
IUE remains the sole owner of the classification decision (Rule
R14 · "IUE decides").  This module is a deterministic helper that
inspects the paste, produces an IDA verdict, and returns it to the
IUE so the IUE's plan can activate the correct engines.

Deterministic — no LLM, no network.
"""
from __future__ import annotations
from typing import Any, Dict, List

from .artifact_splitter import split_artifacts, Artifact, summarise


# Input classes IDA is responsible for.
IDA_INPUT_CLASSES = (
    "threat_report_url",   # bare URL that IDA-3 should fetch
    "mixed_artifacts",     # PowerShell + URL + Hash + Registry (etc.)
    "ioc_list",            # multiple IOCs, no commands / narrative
    "yara_ruleset",        # one or more YARA rules
    "sigma_ruleset",       # Sigma rule document
    "none",                # IDA had nothing to say (default)
)


def classify_artifact_input(text: str) -> Dict[str, Any]:
    """Deterministic IDA verdict for a paste.

    Returns:
        {
          "ida_class":   one of IDA_INPUT_CLASSES,
          "confidence":  0.0-1.0,
          "reasoning":   List[str] (analyst-visible bullets),
          "artifacts":   [Artifact.to_dict(), …],
          "summary":     {type: count},
        }
    """
    src = text or ""
    if not src.strip():
        return _empty()

    artifacts = split_artifacts(src)
    summary   = summarise(artifacts)
    reasoning: List[str] = []

    # 1. YARA / Sigma rule documents — highest priority.
    if summary.get("yara_rule", 0) > 0 and _mostly_yara(src, artifacts):
        reasoning.append(
            f"{summary['yara_rule']} YARA rule block(s) detected."
        )
        return {
            "ida_class":  "yara_ruleset",
            "confidence": 0.98,
            "reasoning":  reasoning,
            "artifacts":  [a.to_dict() for a in artifacts],
            "summary":    summary,
        }

    if summary.get("sigma_rule", 0) > 0:
        reasoning.append("Sigma rule markers (logsource / detection) detected.")
        return {
            "ida_class":  "sigma_ruleset",
            "confidence": 0.96,
            "reasoning":  reasoning,
            "artifacts":  [a.to_dict() for a in artifacts],
            "summary":    summary,
        }

    # 2. Bare URL — no commands and the URL fills the paste.
    if summary.get("url", 0) >= 1 and summary.get("command", 0) == 0 and \
       _mostly_url(src, artifacts):
        reasoning.append("Paste is a bare URL — routing to IDA URL Fetcher (IDA-3).")
        return {
            "ida_class":  "threat_report_url",
            "confidence": 0.97,
            "reasoning":  reasoning,
            "artifacts":  [a.to_dict() for a in artifacts],
            "summary":    summary,
        }

    # 3. Mixed artifacts — commands PLUS at least one atomic IOC
    # kind, or several IOC kinds without commands.
    ioc_kinds = {k for k in ("url", "hash", "ip", "domain",
                              "registry_key", "file_path", "cve") if summary.get(k, 0) > 0}
    has_command = summary.get("command", 0) > 0
    if has_command and len(ioc_kinds) >= 1:
        reasoning.append(
            f"Command lines + {len(ioc_kinds)} distinct IOC kind(s) "
            f"({', '.join(sorted(ioc_kinds))}) — mixed artifact paste."
        )
        return {
            "ida_class":  "mixed_artifacts",
            "confidence": 0.9,
            "reasoning":  reasoning,
            "artifacts":  [a.to_dict() for a in artifacts],
            "summary":    summary,
        }

    # 4. Pure IOC list — no commands, ≥2 atomic IOC kinds OR ≥3
    # atomic IOCs total.
    if not has_command and (len(ioc_kinds) >= 2 or
                            sum(summary.get(k, 0) for k in ioc_kinds) >= 3):
        reasoning.append(
            f"No commands detected; {sum(summary.get(k, 0) for k in ioc_kinds)} "
            f"IOC(s) across {len(ioc_kinds)} kind(s) — pure IOC list."
        )
        return {
            "ida_class":  "ioc_list",
            "confidence": 0.88,
            "reasoning":  reasoning,
            "artifacts":  [a.to_dict() for a in artifacts],
            "summary":    summary,
        }

    # 5. Nothing IDA-worthy.  Return artifacts (may be empty) but no
    # class change — the IUE keeps its own classification.
    return {
        "ida_class":  "none",
        "confidence": 0.0,
        "reasoning":  [],
        "artifacts":  [a.to_dict() for a in artifacts],
        "summary":    summary,
    }


# ── Helpers ───────────────────────────────────────────────────────
def _mostly_url(src: str, artifacts: List[Artifact]) -> bool:
    """True iff URL slices cover the majority of non-whitespace bytes."""
    total_ws = sum(1 for c in src if not c.isspace())
    if total_ws == 0:
        return False
    covered = sum(a.source["length"] for a in artifacts if a.type == "url")
    return covered / total_ws >= 0.6


def _mostly_yara(src: str, artifacts: List[Artifact]) -> bool:
    """True iff at least one YARA block covers >=40% of the paste."""
    yara_len = sum(a.source["length"] for a in artifacts if a.type == "yara_rule")
    return yara_len >= max(40, int(len(src) * 0.4))


def _empty() -> Dict[str, Any]:
    return {
        "ida_class":  "none",
        "confidence": 0.0,
        "reasoning":  [],
        "artifacts":  [],
        "summary":    {},
    }
