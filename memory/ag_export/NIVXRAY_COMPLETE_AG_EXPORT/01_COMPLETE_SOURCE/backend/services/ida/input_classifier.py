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
    # URL-derived classes (bare URL pastes) — split by investigative intent.
    "threat_report_url",   # vendor / advisory / blog — IDA-3 fetches
    "code_snippet_url",    # pastebin / gist — IDA-3 fetches
    "repository_url",      # github / gitlab — IDA-3 enumerates
    "file_resource_url",   # dropbox / drive / .exe download — IDA-3 safe-downloads
    "ioc_portal_url",      # virustotal / urlhaus lookup — IOC lane, not IDA
    "atomic_ioc_url",      # bare shortener, ip-only, unknown — IOC lane
    # Non-URL classes
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
        # Use the first URL's IDA URL-intent verdict (the paste is
        # mostly one URL, so the head artifact is the source of truth).
        url_art = next((a for a in artifacts if a.type == "url"), None)
        meta    = (url_art.metadata if url_art else {}) or {}
        intent  = meta.get("intent") or "atomic_ioc"
        acquirable = bool(meta.get("acquirable"))
        vendor  = meta.get("vendor")

        # Map URL intent → IDA class.
        if intent == "threat_report":
            ida_class = "threat_report_url"
            vendor_bit = f" ({vendor})" if vendor else ""
            reasoning.append(
                f"URL identified as a **threat-intelligence report**{vendor_bit} — "
                f"routing to IDA acquisition pipeline (IDA-3 → IDA-3.5 → IDA-4)."
            )
        elif intent == "code_snippet":
            ida_class = "code_snippet_url"
            reasoning.append(
                "URL identified as a **code snippet / paste** — routing to IDA acquisition "
                "so commands and embedded artifacts surface in the SSOT."
            )
        elif intent == "repository":
            ida_class = "repository_url"
            reasoning.append(
                "URL identified as a **source repository** — IDA-3 will enumerate the "
                "landing README + linked artifact files."
            )
        elif intent == "file_resource":
            ida_class = "file_resource_url"
            reasoning.append(
                "URL points at a **direct file resource** — IDA-3 will safe-download the "
                "artifact, then routing hands it back to DIE + IOCE for analysis."
            )
        elif intent == "ioc_portal":
            ida_class = "ioc_portal_url"
            reasoning.append(
                "URL is an **IOC-portal lookup** (reputation database) — routing to the "
                "IOC / OSINT lane, no page acquisition needed."
            )
        else:
            # atomic IOC URL (shortener, IP-only, unknown host/path)
            ida_class = "atomic_ioc_url"
            reasoning.append(
                "URL does not match any acquirable resource type — treating as an "
                "atomic IOC and routing to the IOC / reputation lane."
            )

        # Add the URL's own reasoning bullets so the analyst sees WHY.
        for bullet in meta.get("reasoning") or []:
            reasoning.append(bullet)

        return {
            "ida_class":   ida_class,
            "confidence":  0.97 if acquirable else 0.9,
            "reasoning":   reasoning,
            "artifacts":   [a.to_dict() for a in artifacts],
            "summary":     summary,
            "url_intent":  {
                "intent":     intent,
                "acquirable": acquirable,
                "vendor":     vendor,
                "host":       meta.get("host"),
                "scheme":     meta.get("scheme"),
            },
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
